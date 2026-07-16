"""
adaptive_psfp_rl.py
===================
Reinforcement Learning agent that learns to dynamically adjust PSFP
parameters (CIR, CBS, gate state) in response to the IsoForest +
LSTM detection pipeline output.

ARCHITECTURE OVERVIEW
---------------------

  10ms window
      │
      ▼
  feature_extractor  →  15-dim Z-score vector
      │
      ▼
  IsoForest          →  BENIGN / ANOMALOUS
      │ (if anomalous)
      ▼
  LSTM               →  BENIGN / SUSPECT / MALICIOUS
      │
      ▼
  RL Agent (PPO)     →  action: adjust CIR, CBS, or gate
      │
      ▼
  PSFP Controller    →  apply new parameters to switch


WHY REINFORCEMENT LEARNING
--------------------------
The existing pipeline (IsoForest → LSTM) gives a binary/3-class
decision per window. But the RESPONSE to that decision is a
policy problem — not a classification problem:

  - How aggressively should we rate-limit? (CIR × 0.5 or × 0.25?)
  - When is it safe to restore defaults after a false alarm?
  - Should we close the gate immediately or rate-limit first?
  - How long should the gate stay closed?

A static rule ("SUSPECT → CIR × 0.5") cannot adapt to the attack
intensity, the legitimate traffic load, or the history of detections.
RL learns a policy that maximises legitimate throughput while
minimising undetected attack traffic — directly optimising the
trade-off that the thesis claims to solve.

PPO (PROXIMAL POLICY OPTIMISATION)
------------------------------------
Algorithm: PPO-Clip (Schulman et al. 2017)
  - On-policy, discrete action space
  - Actor-Critic: shared MLP trunk, separate policy and value heads
  - Clip ratio ε = 0.2 prevents destructive policy updates
  - Dense reward every step → efficient learning without sparse signals

Implementation: from scratch using TF2/Keras — no stable-baselines3
dependency, which makes it thesis-reproducible on any Python env.

STATE SPACE (19-dim continuous)
--------------------------------
  [0:15]  Z-scored 15 features from feature_extractor output
  [15]    CIR_norm       current CIR / CIR_nominal  ∈ [0, 1]
  [16]    CBS_norm       current CBS / CBS_nominal  ∈ [0, 1]
  [17]    gate_state     0.0=open, 0.5=half, 1.0=closed
  [18]    reopen_timer   remaining reopen delay / MAX_REOPEN  ∈ [0, 1]

ACTION SPACE (discrete, 7 actions)
------------------------------------
  0  NO_OP           — hold current settings
  1  CIR_50          — setCIR(CIR_nominal × 0.50)
  2  CIR_25          — setCIR(CIR_nominal × 0.25)
  3  CBS_50          — setCBS(CBS_nominal × 0.50)
  4  GATE_HALF       — open gate 50% of cycle (250µs instead of 325µs)
  5  GATE_CLOSE      — closeGate() + start 5s auto-reopen timer
  6  RESTORE         — reset all params to Luo 2021 Table 7 defaults

REWARD FUNCTION
---------------
  +10   per legitimate frame received within WCD (throughput preserved)
  -20   per legitimate frame dropped (false positive — safety critical)
   +5   per attack frame blocked by PSFP action (true positive)
   -1   per attack frame that passed unblocked (false negative)
  -0.1  per step while gate is closed (minimise downtime)
  -2.0  per step CIR < 25% nominal (over-aggressive, disrupts safety)

EPISODE STRUCTURE
-----------------
  Each episode = one 100-step sequence (one 1s simulation run).
  Steps alternate between benign-only and mixed attack/benign traffic
  depending on the traffic scenario sampled at episode start.
  The dataset (features_thesis_raw_norm.csv) is replayed — no
  live OMNeT++ connection needed at RL training time.

OUTPUTS
-------
  models/ppo_actor.keras           — policy network (actor)
  models/ppo_critic.keras          — value network (critic)
  results/rl_training_log.csv      — reward + metrics per episode
  results/rl_eval_summary.txt      — evaluation summary for thesis
"""

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from collections import deque

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import gymnasium as gym
from gymnasium import spaces

warnings.filterwarnings('ignore')

# ── paths ─────────────────────────────────────────────────────────────────────
NORM_CSV     = Path('features_thesis_raw_norm.csv')
RAW_CSV      = Path('features_thesis_raw.csv')
ISO_MODEL    = Path('models/isoforest_model.pkl')
ISO_THRESH   = Path('models/isoforest_threshold.txt')
LSTM_MODEL   = Path('models/lstm_model.keras')
MODEL_DIR    = Path('models');   MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR   = Path('results');  RESULT_DIR.mkdir(exist_ok=True)

# ── PSFP nominal parameters (Luo 2021 Table 7, AV1 stream) ───────────────────
CIR_NOMINAL   = 22.0        # Mbps
CBS_NOMINAL   = 5004.0      # bytes
GATE_OPEN_US  = 325.0       # µs (125→450µs window)
MAX_REOPEN_S  = 5.0         # seconds before auto-reopen after GATE_CLOSE

# ── RL hyperparameters ────────────────────────────────────────────────────────
N_FEATURES    = 15
STATE_DIM     = 19           # 15 features + 4 PSFP state vars
N_ACTIONS     = 7
EPISODE_STEPS = 100          # 100 windows × 10ms = 1s per episode
N_EPISODES    = 2000
BATCH_SIZE    = 256
GAMMA         = 0.99         # discount factor
LAM           = 0.95         # GAE lambda
CLIP_EPS      = 0.2          # PPO clip ratio
LR_ACTOR      = 3e-4
LR_CRITIC     = 1e-3
UPDATE_EPOCHS = 4            # PPO inner epochs per update
ENTROPY_COEF  = 0.01         # entropy bonus (encourages exploration)
VF_COEF       = 0.5          # value loss coefficient

FEATURES = [
    'mean_IAT_us','IAT_variance_us2','mean_frame_size_B','burst_length',
    'frame_count','phase_offset_mean_us','phase_offset_std_us',
    'gate_drop_rate','meter_red_rate','queue_depth_max',
    'sync_interval_mean','sync_interval_var','correction_field_delta',
    'announce_rate','source_count',
]

ACTION_NAMES = [
    'NO_OP', 'CIR_50', 'CIR_25', 'CBS_50',
    'GATE_HALF', 'GATE_CLOSE', 'RESTORE',
]


# ═════════════════════════════════════════════════════════════════════════════
# PSFP CONTROLLER — the "plant" that the RL agent controls
# ═════════════════════════════════════════════════════════════════════════════

class PSFPController:
    """
    Models the PSFP parameter state and applies RL actions.
    In a real deployment this would issue OMNeT++ runtime parameter
    changes via opp_run --*; in this simulation it tracks state internally.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.cir          = CIR_NOMINAL
        self.cbs          = CBS_NOMINAL
        self.gate_state   = 0.0      # 0=open, 0.5=half, 1.0=closed
        self.reopen_timer = 0.0      # seconds remaining until auto-reopen
        self.step_s       = 0.010    # 10ms per step

    def apply_action(self, action: int):
        """Apply one of 7 discrete actions to PSFP parameters."""
        if action == 0:   # NO_OP
            pass
        elif action == 1:  # CIR_50
            self.cir = max(CIR_NOMINAL * 0.50, 1.0)
        elif action == 2:  # CIR_25
            self.cir = max(CIR_NOMINAL * 0.25, 1.0)
        elif action == 3:  # CBS_50
            self.cbs = max(CBS_NOMINAL * 0.50, 100.0)
        elif action == 4:  # GATE_HALF
            self.gate_state = 0.5
        elif action == 5:  # GATE_CLOSE
            self.gate_state   = 1.0
            self.reopen_timer = MAX_REOPEN_S
        elif action == 6:  # RESTORE
            self.cir          = CIR_NOMINAL
            self.cbs          = CBS_NOMINAL
            self.gate_state   = 0.0
            self.reopen_timer = 0.0

    def tick(self):
        """
        Advance time by one step (10ms).
        Auto-reopen gate when reopen_timer expires.
        """
        if self.reopen_timer > 0:
            self.reopen_timer = max(0.0, self.reopen_timer - self.step_s)
            if self.reopen_timer == 0.0:
                self.gate_state = 0.0   # auto-reopen

    def get_state_vector(self) -> np.ndarray:
        """Return normalised PSFP state (4 values, each in [0,1])."""
        return np.array([
            self.cir / CIR_NOMINAL,
            self.cbs / CBS_NOMINAL,
            self.gate_state,
            self.reopen_timer / MAX_REOPEN_S,
        ], dtype=np.float32)

    def is_gate_closed(self) -> bool:
        return self.gate_state > 0.5

    def is_cir_reduced(self) -> bool:
        return self.cir < CIR_NOMINAL * 0.9


# ═════════════════════════════════════════════════════════════════════════════
# GYMNASIUM ENVIRONMENT
# ═════════════════════════════════════════════════════════════════════════════

class TsnPsfpEnv(gym.Env):
    """
    Custom Gymnasium environment for PSFP adaptive control.

    The environment replays the 22,000-window dataset in episode-length
    chunks. At each step the agent receives the current feature window
    + PSFP state, takes an action, and receives a reward based on the
    traffic outcome simulated from those parameters.

    This is a REPLAY environment — it does not call OMNeT++ at runtime.
    The feature vectors encode attack/benign ground truth via 'label'.
    The reward function simulates what the PSFP settings would cause:
      - gate_closed blocks BOTH legitimate and attack frames
      - cir_reduced passes legitimate frames (below CIR) but slows attack
      - NO_OP passes everything (correct for benign, wrong for attack)
    """

    metadata = {'render_modes': []}

    def __init__(self, norm_df: pd.DataFrame):
        super().__init__()

        self.norm_df   = norm_df.reset_index(drop=True)
        self.psfp      = PSFPController()

        # Group windows by (config, seed-block of 100)
        self.norm_df['run_id'] = (
            self.norm_df['config'].astype(str) + '_' +
            (self.norm_df.groupby('config').cumcount() // EPISODE_STEPS
             ).astype(str)
        )
        self.run_ids  = self.norm_df['run_id'].unique().tolist()
        self._current_run   = None
        self._step_idx      = 0
        self._run_windows   = None

        self.observation_space = spaces.Box(
            low=-10.0, high=10.0,
            shape=(STATE_DIM,), dtype=np.float32
        )
        self.action_space = spaces.Discrete(N_ACTIONS)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.psfp.reset()
        self._step_idx    = 0
        # Sample a random run (episode) from the dataset
        run_id            = self.np_random.choice(self.run_ids)
        self._run_windows = (
            self.norm_df[self.norm_df['run_id'] == run_id]
            .sort_values('t_start_s')
            .reset_index(drop=True)
        )
        # Pad or trim to exactly EPISODE_STEPS
        if len(self._run_windows) < EPISODE_STEPS:
            pad = self._run_windows.iloc[
                np.random.randint(0, len(self._run_windows),
                                   EPISODE_STEPS - len(self._run_windows))
            ]
            self._run_windows = pd.concat(
                [self._run_windows, pad], ignore_index=True
            )
        self._run_windows = self._run_windows.iloc[:EPISODE_STEPS]
        obs = self._get_obs()
        return obs, {}

    def _get_obs(self) -> np.ndarray:
        """Concatenate current feature window with PSFP state."""
        feat = self._run_windows.iloc[self._step_idx][FEATURES].values.astype(np.float32)
        psfp = self.psfp.get_state_vector()
        obs  = np.concatenate([feat, psfp])
        obs  = np.clip(obs, -10.0, 10.0)
        return obs

    def _compute_reward(self, action: int, label: int) -> tuple[float, dict]:
        """
        Simulate the effect of the chosen PSFP action on this traffic window.

        Ground truth:
          label == 0  → benign traffic (must NOT be blocked)
          label != 0  → attack traffic (SHOULD be blocked/rate-limited)

        PSFP effect model:
          gate_closed  → blocks ALL frames (attack + legitimate)
          cir_reduced  → attack at 21.9Mbps partially blocked if CIR < 21Mbps
                         legitimate at ~6.4Mbps never blocked (well below CIR)
          NO_OP        → passes everything
        """
        is_attack  = (label != 0)
        gate_off   = self.psfp.is_gate_closed()
        cir_low    = self.psfp.cir <= CIR_NOMINAL * 0.25  # ≤ 5.5 Mbps
        cir_mid    = self.psfp.cir <= CIR_NOMINAL * 0.50  # ≤ 11 Mbps
        reward     = 0.0
        info       = {'blocked': False, 'fp': False, 'tp': False, 'fn': False}

        if is_attack:
            if gate_off:
                # Gate closed: attack fully blocked — TP
                reward += 5.0
                info['tp'] = True
                info['blocked'] = True
            elif cir_low:
                # CIR at 25%: attack at 21.9Mbps blocked, only 5.5Mbps passes
                reward += 3.0
                info['tp'] = True
            elif cir_mid:
                # CIR at 50%: partial blocking
                reward += 1.5
                info['tp'] = True
            else:
                # Attack passes: FN penalty
                reward -= 1.0
                info['fn'] = True
        else:
            # Benign traffic
            if gate_off:
                # FALSE POSITIVE — legitimate frame blocked — severe penalty
                reward -= 20.0
                info['fp'] = True
                info['blocked'] = True
            elif cir_low:
                # CIR 25% still passes legitimate AV1 (6.4Mbps << 5.5Mbps is tight)
                # Actually 5.5Mbps < 6.4Mbps → some legitimate frames dropped
                reward -= 5.0
                info['fp'] = True
            elif cir_mid:
                # CIR 50% = 11Mbps > 6.4Mbps → legitimate traffic fine
                reward += 10.0
            else:
                # Normal operation — legitimate frame received
                reward += 10.0

        # Per-step gate-closed penalty (minimise unnecessary downtime)
        if gate_off:
            reward -= 0.1

        # Over-aggressive CIR reduction penalty
        if self.psfp.cir < CIR_NOMINAL * 0.25:
            reward -= 2.0

        return reward, info

    def step(self, action: int):
        row    = self._run_windows.iloc[self._step_idx]
        label  = int(row['label'])

        # Apply action to PSFP controller
        self.psfp.apply_action(action)

        # Compute reward based on ground truth + PSFP state
        reward, info = self._compute_reward(action, label)

        # Advance time (triggers auto-reopen if timer expires)
        self.psfp.tick()

        self._step_idx += 1
        terminated = (self._step_idx >= EPISODE_STEPS)
        truncated  = False

        obs = self._get_obs() if not terminated else np.zeros(STATE_DIM, dtype=np.float32)

        info['label']     = label
        info['action']    = action
        info['cir']       = self.psfp.cir
        info['gate']      = self.psfp.gate_state
        info['reopen_t']  = self.psfp.reopen_timer

        return obs, reward, terminated, truncated, info


# ═════════════════════════════════════════════════════════════════════════════
# PPO ACTOR-CRITIC NETWORK
# ═════════════════════════════════════════════════════════════════════════════

def build_actor_critic(state_dim: int, n_actions: int):
    """
    Shared MLP trunk with separate actor (policy) and critic (value) heads.

    Architecture:
      Input  (state_dim,)
      Dense  256, ReLU
      Dense  128, ReLU
        ├─ Actor head:  Dense(n_actions, Softmax)  → π(a|s)
        └─ Critic head: Dense(1, linear)           → V(s)

    Using a shared trunk reduces total parameters and forces the
    representation to be useful for both policy and value estimation.
    """
    inp   = keras.Input(shape=(state_dim,), name='state_input')
    x     = layers.Dense(256, activation='relu', name='trunk_1')(inp)
    x     = layers.Dense(128, activation='relu', name='trunk_2')(x)

    # Actor
    logits = layers.Dense(n_actions, activation=None, name='policy_logits')(x)
    probs  = layers.Softmax(name='policy_probs')(logits)

    # Critic
    value  = layers.Dense(1, activation=None, name='value')(x)

    actor  = keras.Model(inp, probs,  name='actor')
    critic = keras.Model(inp, value,  name='critic')
    return actor, critic


# ═════════════════════════════════════════════════════════════════════════════
# PPO AGENT
# ═════════════════════════════════════════════════════════════════════════════

class PPOAgent:
    """
    Proximal Policy Optimisation (PPO-Clip) agent.

    Implements the PPO-Clip objective (Schulman 2017):
      L_CLIP = E[min(r_t * A_t, clip(r_t, 1-ε, 1+ε) * A_t)]
    where r_t = π(a|s) / π_old(a|s) is the probability ratio.

    Advantages are computed with Generalised Advantage Estimation (GAE):
      A_t = Σ_{k=0}^{T-t} (γλ)^k δ_{t+k}
      δ_t = r_t + γV(s_{t+1}) - V(s_t)
    """

    def __init__(self, state_dim: int, n_actions: int):
        self.actor, self.critic = build_actor_critic(state_dim, n_actions)
        self.opt_actor  = keras.optimizers.Adam(LR_ACTOR)
        self.opt_critic = keras.optimizers.Adam(LR_CRITIC)
        self.n_actions  = n_actions

    def get_action_and_value(self, state: np.ndarray):
        """Sample action from policy, return (action, log_prob, value)."""
        s     = tf.convert_to_tensor([state], dtype=tf.float32)
        probs = self.actor(s, training=False).numpy()[0]
        val   = float(self.critic(s, training=False).numpy()[0, 0])
        # Numerical safety: renormalise and clip
        probs = np.clip(probs, 1e-8, 1.0)
        probs /= probs.sum()
        action   = np.random.choice(self.n_actions, p=probs)
        log_prob = float(np.log(probs[action]))
        return int(action), log_prob, val

    def compute_gae(self, rewards, values, dones, last_value):
        """Compute Generalised Advantage Estimates."""
        advantages = np.zeros_like(rewards, dtype=np.float32)
        gae        = 0.0
        for t in reversed(range(len(rewards))):
            next_val = last_value if t == len(rewards) - 1 else values[t + 1]
            delta    = rewards[t] + GAMMA * next_val * (1 - dones[t]) - values[t]
            gae      = delta + GAMMA * LAM * (1 - dones[t]) * gae
            advantages[t] = gae
        returns = advantages + np.array(values, dtype=np.float32)
        return advantages, returns

    def update(self, states, actions, old_log_probs, advantages, returns):
        """
        Run UPDATE_EPOCHS of PPO-Clip + value function update.
        Returns (policy_loss, value_loss, entropy).
        """
        states        = tf.convert_to_tensor(states,        dtype=tf.float32)
        actions       = tf.convert_to_tensor(actions,       dtype=tf.int32)
        old_log_probs = tf.convert_to_tensor(old_log_probs, dtype=tf.float32)
        advantages    = tf.convert_to_tensor(advantages,    dtype=tf.float32)
        returns       = tf.convert_to_tensor(returns,       dtype=tf.float32)

        # Normalise advantages (reduces variance)
        advantages = (advantages - tf.reduce_mean(advantages)) / \
                     (tf.math.reduce_std(advantages) + 1e-8)

        pol_losses, val_losses, entropies = [], [], []

        for _ in range(UPDATE_EPOCHS):
            # Shuffle mini-batches
            idx = tf.random.shuffle(tf.range(tf.shape(states)[0]))
            for start in range(0, tf.shape(states)[0], BATCH_SIZE):
                b_idx    = idx[start : start + BATCH_SIZE]
                b_states = tf.gather(states,        b_idx)
                b_acts   = tf.gather(actions,       b_idx)
                b_olp    = tf.gather(old_log_probs, b_idx)
                b_adv    = tf.gather(advantages,    b_idx)
                b_ret    = tf.gather(returns,        b_idx)

                # Actor update
                with tf.GradientTape() as tape:
                    probs    = self.actor(b_states, training=True)
                    probs    = tf.clip_by_value(probs, 1e-8, 1.0)
                    dist     = tf.reduce_sum(
                        probs * tf.one_hot(b_acts, self.n_actions), axis=1
                    )
                    log_prob = tf.math.log(dist)
                    ratio    = tf.exp(log_prob - b_olp)
                    clip_r   = tf.clip_by_value(ratio, 1 - CLIP_EPS, 1 + CLIP_EPS)
                    pol_loss = -tf.reduce_mean(
                        tf.minimum(ratio * b_adv, clip_r * b_adv)
                    )
                    # Entropy bonus (encourages exploration)
                    entropy  = -tf.reduce_mean(
                        tf.reduce_sum(probs * tf.math.log(probs), axis=1)
                    )
                    total_loss = pol_loss - ENTROPY_COEF * entropy

                grads = tape.gradient(total_loss, self.actor.trainable_variables)
                self.opt_actor.apply_gradients(
                    zip(grads, self.actor.trainable_variables)
                )

                # Critic update
                with tf.GradientTape() as tape:
                    val_pred = tf.squeeze(
                        self.critic(b_states, training=True), axis=1
                    )
                    val_loss = tf.reduce_mean(tf.square(b_ret - val_pred))
                    val_loss = VF_COEF * val_loss

                grads = tape.gradient(val_loss, self.critic.trainable_variables)
                self.opt_critic.apply_gradients(
                    zip(grads, self.critic.trainable_variables)
                )

                pol_losses.append(float(pol_loss))
                val_losses.append(float(val_loss))
                entropies.append(float(entropy))

        return np.mean(pol_losses), np.mean(val_losses), np.mean(entropies)

    def save(self):
        self.actor.save(str(MODEL_DIR / 'ppo_actor.keras'))
        self.critic.save(str(MODEL_DIR / 'ppo_critic.keras'))
        print(f"  Saved: {MODEL_DIR/'ppo_actor.keras'}")
        print(f"  Saved: {MODEL_DIR/'ppo_critic.keras'}")

    def load(self):
        self.actor  = keras.models.load_model(str(MODEL_DIR / 'ppo_actor.keras'))
        self.critic = keras.models.load_model(str(MODEL_DIR / 'ppo_critic.keras'))


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING LOOP
# ═════════════════════════════════════════════════════════════════════════════

def collect_rollout(env: TsnPsfpEnv, agent: PPOAgent, n_steps: int):
    """
    Collect n_steps of experience from the environment.
    Returns trajectory buffers for PPO update.
    """
    states, actions, rewards, dones = [], [], [], []
    log_probs, values = [], []
    infos = []

    obs, _ = env.reset()

    for _ in range(n_steps):
        action, lp, val = agent.get_action_and_value(obs)
        next_obs, reward, terminated, truncated, info = env.step(action)

        states.append(obs.copy())
        actions.append(action)
        rewards.append(reward)
        dones.append(float(terminated or truncated))
        log_probs.append(lp)
        values.append(val)
        infos.append(info)

        if terminated or truncated:
            obs, _ = env.reset()
        else:
            obs = next_obs

    # Last value for GAE bootstrap
    _, _, last_val = agent.get_action_and_value(obs)

    return (np.array(states, dtype=np.float32),
            np.array(actions, dtype=np.int32),
            np.array(rewards, dtype=np.float32),
            np.array(dones, dtype=np.float32),
            np.array(log_probs, dtype=np.float32),
            np.array(values, dtype=np.float32),
            last_val,
            infos)


def train(env: TsnPsfpEnv, agent: PPOAgent, n_episodes: int):
    """Main PPO training loop — collect rollout → compute GAE → update."""

    log_rows       = []
    reward_history = deque(maxlen=50)
    best_reward    = -np.inf
    ROLLOUT_STEPS  = EPISODE_STEPS   # collect one full episode per update

    print(f"\n{'='*60}")
    print("PPO TRAINING — Adaptive PSFP Controller")
    print(f"{'='*60}")
    print(f"  State dim   : {STATE_DIM}")
    print(f"  Actions     : {N_ACTIONS}  {ACTION_NAMES}")
    print(f"  Episodes    : {n_episodes}")
    print(f"  Rollout     : {ROLLOUT_STEPS} steps / update")
    print(f"  PPO epochs  : {UPDATE_EPOCHS}")
    print(f"  Clip ε      : {CLIP_EPS}")
    print(f"  γ / λ       : {GAMMA} / {LAM}")
    print(f"{'='*60}\n")

    for episode in range(1, n_episodes + 1):
        # Collect experience
        (states, actions, rewards, dones,
         log_probs, values, last_val, infos) = collect_rollout(
            env, agent, ROLLOUT_STEPS
        )

        # GAE advantages and returns
        advantages, returns = agent.compute_gae(
            rewards, values, dones, last_val
        )

        # PPO update
        pol_loss, val_loss, entropy = agent.update(
            states, actions, log_probs, advantages, returns
        )

        # Metrics
        ep_reward    = float(np.sum(rewards))
        tp           = sum(1 for i in infos if i.get('tp', False))
        fp           = sum(1 for i in infos if i.get('fp', False))
        fn           = sum(1 for i in infos if i.get('fn', False))
        action_dist  = np.bincount(actions, minlength=N_ACTIONS)

        reward_history.append(ep_reward)
        avg_reward = np.mean(reward_history)

        log_rows.append({
            'episode':    episode,
            'reward':     ep_reward,
            'avg50':      avg_reward,
            'pol_loss':   pol_loss,
            'val_loss':   val_loss,
            'entropy':    entropy,
            'TP':         tp,
            'FP':         fp,
            'FN':         fn,
        })

        # Save best model
        if avg_reward > best_reward and episode > 50:
            best_reward = avg_reward
            agent.save()

        # Progress print
        if episode % 100 == 0 or episode == 1:
            dom_action = ACTION_NAMES[np.argmax(action_dist)]
            print(f"  Ep {episode:5d} | "
                  f"R={ep_reward:8.1f} | "
                  f"Avg50={avg_reward:8.1f} | "
                  f"TP={tp:3d} FP={fp:3d} FN={fn:3d} | "
                  f"DomAct={dom_action} | "
                  f"H={entropy:.3f}")

    print(f"\nTraining complete. Best avg50 reward: {best_reward:.1f}")
    return pd.DataFrame(log_rows)


# ═════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ═════════════════════════════════════════════════════════════════════════════

def evaluate(env: TsnPsfpEnv, agent: PPOAgent, n_eval=20):
    """
    Run n_eval episodes with greedy policy (argmax of actor).
    Report per-class action distribution and reward breakdown.
    """
    print(f"\n{'='*60}")
    print("EVALUATION — Greedy Policy")
    print(f"{'='*60}")

    all_rewards, all_tp, all_fp, all_fn = [], [], [], []
    action_counts   = np.zeros(N_ACTIONS, dtype=int)
    # Track actions taken per traffic class
    act_by_class    = {0: np.zeros(N_ACTIONS), 1: np.zeros(N_ACTIONS)}

    for ep in range(n_eval):
        obs, _ = env.reset()
        ep_reward = 0.0
        tp = fp = fn = 0

        for _ in range(EPISODE_STEPS):
            s     = tf.convert_to_tensor([obs], dtype=tf.float32)
            probs = agent.actor(s, training=False).numpy()[0]
            act   = int(np.argmax(probs))   # greedy

            obs, reward, terminated, truncated, info = env.step(act)
            ep_reward += reward
            tp += int(info.get('tp', False))
            fp += int(info.get('fp', False))
            fn += int(info.get('fn', False))
            action_counts[act] += 1
            cls_key = 1 if info.get('label', 0) != 0 else 0
            act_by_class[cls_key][act] += 1

            if terminated or truncated:
                break

        all_rewards.append(ep_reward)
        all_tp.append(tp); all_fp.append(fp); all_fn.append(fn)

    # Results
    print(f"\n  Episodes       : {n_eval}")
    print(f"  Avg reward     : {np.mean(all_rewards):.1f} ± {np.std(all_rewards):.1f}")
    print(f"  Avg TP/ep      : {np.mean(all_tp):.1f}")
    print(f"  Avg FP/ep      : {np.mean(all_fp):.1f}  ← lower is better")
    print(f"  Avg FN/ep      : {np.mean(all_fn):.1f}  ← lower is better")

    total_det  = np.sum(all_tp)
    total_miss = np.sum(all_fn)
    dr         = total_det / (total_det + total_miss + 1e-9) * 100
    fpr        = np.sum(all_fp) / (n_eval * EPISODE_STEPS) * 100
    print(f"\n  Detection rate : {dr:.2f}%")
    print(f"  False pos rate : {fpr:.2f}%")

    print(f"\n  Action distribution (greedy):")
    for i, name in enumerate(ACTION_NAMES):
        pct = action_counts[i] / action_counts.sum() * 100
        bar = '█' * int(pct // 2)
        print(f"    {name:<16} {pct:5.1f}%  {bar}")

    print(f"\n  Actions on BENIGN traffic:")
    b_total = act_by_class[0].sum()
    for i, name in enumerate(ACTION_NAMES):
        pct = act_by_class[0][i] / (b_total + 1e-9) * 100
        print(f"    {name:<16} {pct:5.1f}%")

    print(f"\n  Actions on ATTACK traffic:")
    a_total = act_by_class[1].sum()
    for i, name in enumerate(ACTION_NAMES):
        pct = act_by_class[1][i] / (a_total + 1e-9) * 100
        print(f"    {name:<16} {pct:5.1f}%")

    # Summary for thesis
    summary = [
        "RL ADAPTIVE PSFP CONTROLLER — EVALUATION SUMMARY",
        f"Algorithm        : PPO-Clip (Schulman 2017)",
        f"State dim        : {STATE_DIM} (15 features + 4 PSFP params)",
        f"Actions          : {N_ACTIONS} discrete",
        f"Episodes trained : {N_EPISODES}",
        "",
        f"Detection Rate   : {dr:.2f}%",
        f"False Pos Rate   : {fpr:.2f}%",
        f"Avg Reward/ep    : {np.mean(all_rewards):.1f}",
        "",
        "Action distribution (greedy policy):",
    ]
    for i, name in enumerate(ACTION_NAMES):
        pct = action_counts[i] / action_counts.sum() * 100
        summary.append(f"  {name:<16} {pct:.1f}%")

    (RESULT_DIR / 'rl_eval_summary.txt').write_text('\n'.join(summary))
    print(f"\n  Summary saved → {RESULT_DIR/'rl_eval_summary.txt'}")

    return np.mean(all_rewards), dr, fpr


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    tf.random.set_seed(42)
    np.random.seed(42)

    print("=" * 60)
    print("ADAPTIVE PSFP CONTROLLER — PPO REINFORCEMENT LEARNING")
    print("=" * 60)

    # Load dataset
    print("\nLoading normalised features …")
    norm_df = pd.read_csv(NORM_CSV)
    print(f"  {len(norm_df):,} windows | "
          f"{norm_df['config'].nunique()} configs | "
          f"labels: {sorted(norm_df['label'].unique().tolist())}")

    # Build environment
    env   = TsnPsfpEnv(norm_df)
    agent = PPOAgent(STATE_DIM, N_ACTIONS)

    # Train
    log_df = train(env, agent, N_EPISODES)

    # Save training log
    log_df.to_csv(RESULT_DIR / 'rl_training_log.csv', index=False)
    print(f"  Training log → {RESULT_DIR/'rl_training_log.csv'}")

    # Load best saved model and evaluate
    print("\nLoading best model for evaluation …")
    try:
        agent.load()
    except Exception:
        print("  (Using final model — best model may not have been saved yet)")

    avg_r, dr, fpr = evaluate(env, agent, n_eval=20)

    print("\n✅ RL training complete.")
    print(f"   Detection Rate: {dr:.2f}%  |  FPR: {fpr:.2f}%")
    print(f"   Models → {MODEL_DIR}/ppo_actor.keras, ppo_critic.keras")


if __name__ == '__main__':
    main()
