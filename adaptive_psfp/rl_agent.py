#!/usr/bin/env python3
"""
rl_agent.py

STATUS: Architecture stub only. No training loop implemented.

This class documents the intended interface for a future reinforcement-
learning agent that would learn to improve upon policy_engine.py's static
rule table over time. It is deliberately NOT implemented in this thesis
because a real training loop requires:

  1. Runtime PSFP parameter modification support in OMNeT++/INET
     (UNVERIFIED as of this writing -- see the feasibility check below;
     if unsupported, this entire component remains architecture-only
     regardless of remaining time).
  2. An environment wrapper exposing observe() / act() / reward() as a
     standard RL loop (e.g. Gym-style), which does not currently exist
     for this simulation.
  3. Hundreds to thousands of training episodes for convergence --
     computationally infeasible to add credibly in the remaining
     thesis timeline.
  4. Reward tuning and convergence analysis, each a non-trivial
     research task on its own.

DESIGN INTENT (for Chapter 9, future work):

    RL agent does NOT modify PSFP directly.
    RL agent learns to improve the POLICY (policy_engine.POLICY_TABLE),
    which then applies the change. This separation keeps the safe
    action-space bounds enforced in policy_engine.py intact regardless
    of what the RL agent learns -- the agent can only select among
    pre-validated, schedule-safe actions, never invent an unbounded one.

    Traffic -> IsoForest -> Classifier -> attack_type
                                              |
                                              v
                                   policy_engine.decide_action()
                                   (currently: fixed rule table)
                                              |
                                              v
                                    RLAgent.select_action()
                                   (future: learns to pick/tune the
                                    action from policy_engine's safe
                                    action space, using reward_function
                                    as its training signal)

FEASIBILITY GATE:
    Before any training loop is attempted, run:

        grep -rn "runtime\\|dynamic\\|setParam\\|par(" \\
          ~/research/omnetpp-6.4.0/samples/inet/src/inet/linklayer/ieee8021q/*.h \\
          | grep -i "gate\\|cir\\|cbs"

    If this returns nothing supporting live parameter mutation, Phase 7
    cannot be demonstrated in this simulator without modifying INET's
    C++ internals -- a materially larger undertaking than anything else
    in this thesis, and should be scoped as such in Chapter 9 rather
    than attempted.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RLAgent:
    """
    Architecture-only stub. Methods raise NotImplementedError to make
    explicit that no training has occurred -- this is intentional, not
    an oversight, and should not be silently called from a pipeline
    expecting a working agent.
    """
    state_dim: int = 5          # matches FEATURE_COLS in the detection pipeline
    action_space: Optional[list] = None  # would be populated from
                                          # policy_engine.POLICY_TABLE's
                                          # possible parameter_delta values
    learned: bool = False

    def observe(self, state):
        """
        Intended signature: state = current feature vector + current
        PSFP parameter state (post-action). Not implemented -- requires
        the environment wrapper described in the feasibility gate above.
        """
        raise NotImplementedError(
            "observe() is architecture-only. Requires an OMNeT++ "
            "environment wrapper exposing live state after a PSFP "
            "parameter change -- see module docstring feasibility gate."
        )

    def select_action(self, state):
        """
        Intended behavior: given the current state, return an action
        from policy_engine.py's safe action space (NOT an arbitrary
        action -- the RL agent tunes/selects among pre-validated,
        schedule-safe options, it does not invent new ones).

        Until trained, this should fall back to policy_engine's static
        rule table rather than fail -- fail-safe default, matching the
        fail-safe pattern used in policy_engine.decide_action() for
        unknown attack types.
        """
        raise NotImplementedError(
            "select_action() has no trained policy yet. In the interim, "
            "callers should use policy_engine.decide_action() directly "
            "(the static rule table), which this method would eventually "
            "replace/refine, not bypass."
        )

    def update(self, state, action, reward, next_state):
        """
        Intended signature: standard RL update step (e.g. Q-learning,
        policy gradient -- algorithm choice not yet made). Not
        implemented; requires (1) the environment wrapper, and (2) many
        (state, action, reward, next_state) tuples collected across
        training episodes, neither of which exist yet.
        """
        raise NotImplementedError(
            "update() is architecture-only -- see module docstring. "
            "No training loop has been run; self.learned remains False."
        )


if __name__ == "__main__":
    agent = RLAgent()
    print("RLAgent stub instantiated.")
    print(f"  state_dim = {agent.state_dim}")
    print(f"  learned   = {agent.learned}")
    print("\nThis is an architecture stub -- calling observe(), "
          "select_action(), or update() will raise NotImplementedError "
          "by design. See module docstring for the feasibility gate that "
          "determines whether a real training loop is possible in this "
          "simulator.")
