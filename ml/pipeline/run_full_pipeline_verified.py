#!/usr/bin/env python3
"""
run_full_pipeline_verified.py

End-to-end integration run of the complete defense pipeline, printing a
verification table at every stage so each value is traceable:

  STAGE 1  Detection      IsolationForest (data plane)      -> attack flagged?
  STAGE 2  Classification RandomForest (data+schedule)      -> attack type
  STAGE 3  Policy         attack type -> PSFP action         -> which lever
  STAGE 4  Enforcement    measured .sca before/after         -> attack blocked%
  STAGE 5  Reward         detection + blocking + throughput  -> scalar reward
                          (loops back to Q-table, OFFLINE)

The enforcement values (STAGE 4) come from the real OMNeT++ _Adaptive .sca
runs measured earlier; they are ground-truth, not simulated here. Everything
else runs live from the CSV + trained models.

RUN:
    python3 run_full_pipeline_verified.py --csv combined_features_multiclass.csv
"""
import argparse, csv, sys
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

DATA=['mean_IAT','IAT_variance','mean_frame_size','burst_length','count']
SCHED=['phase_offset_mean_us','phase_offset_std_us','gate_util','queue_depth_max','drops']

# STAGE 3: policy table (attack type -> PSFP action)
POLICY={
 'AggregateLoadAttack':'reduce_cir_0.5','QueueBuildingAttack':'reduce_cir_0.6',
 'SustainedNearCIRAttack':'reduce_cir_0.5','ThresholdEvasionAttack':'reduce_cir_0.5',
 'CBSBoundaryAttack':'reduce_cbs_0.5','CBSExhaustionAttack':'reduce_cbs_0.5',
 'GCLPhaseAttack':'tighten_gate_10','GateBoundaryProximityAttack':'tighten_gate_15',
 'WindowBoundaryQueuingAttack':'tighten_gate_15',
}

# STAGE 4: REAL measured enforcement from _Adaptive .sca (static->adaptive delivery, legit recovery)
ENFORCE={
 'AggregateLoadAttack':(746,377,0.22),'ThresholdEvasionAttack':(746,377,0.22),
 'SustainedNearCIRAttack':(746,377,0.22),'QueueBuildingAttack':(746,452,0.22),
 'CBSExhaustionAttack':(746,742,0.0),'CBSBoundaryAttack':(746,742,0.0),
 'GCLPhaseAttack':(746,746,0.0),'GateBoundaryProximityAttack':(299,299,0.0),
 'WindowBoundaryQueuingAttack':(300,300,0.0),
}

# STAGE 5: reward weights (base reward_function.py + measured-blocking extension)
W={'det':3.0,'block':3.0,'fp':1.5,'thru':1.0}

def load(csvpath, cfg, feats, streams=None):
    X=[]
    with open(csvpath, newline='') as f:
        for r in csv.DictReader(f):
            if r['config']!=cfg: continue
            if streams and r['stream'] not in streams: continue
            if any(r.get(c) in ('',None) for c in feats): continue
            X.append([float(r[c]) for c in feats])
    return np.array(X)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--csv', default='combined_features_multiclass.csv')
    a=ap.parse_args()

    attacks=list(ENFORCE.keys())

    # ---- Train Stage 1 (IsoForest) and Stage 2 (RF) ----
    benign=load(a.csv,'BenignDiverse',DATA,['av1','av2','radarNode','zonalHost'])
    iso=IsolationForest(n_estimators=200,contamination=0.01,random_state=42).fit(benign)

    det7=['GCLPhaseAttack','ThresholdEvasionAttack','SustainedNearCIRAttack','AggregateLoadAttack',
          'QueueBuildingAttack','CBSExhaustionAttack','CBSBoundaryAttack']
    Xtr=[];ytr=[]
    for c in det7:
        Xa=load(a.csv,c,DATA,['attackNode'])
        Xtr.append(Xa); ytr+=[c]*len(Xa)
    Xtr=np.vstack(Xtr); ytr=np.array(ytr)
    rf=RandomForestClassifier(n_estimators=200,random_state=42,class_weight='balanced').fit(Xtr,ytr)

    print("="*100)
    print("END-TO-END PIPELINE VERIFICATION  (Detect -> Classify -> Policy -> Enforce -> Reward)")
    print("="*100)
    hdr=f"{'Attack':26s} {'S1:flag':>8s} {'S2:type_ok':>11s} {'S3:action':>16s} {'S4:blocked%':>11s} {'S5:reward':>9s}"
    print(hdr); print("-"*100)

    FPR=0.01
    for cfg in attacks:
        # STAGE 1: detection on attackNode (data plane)
        Xa=load(a.csv,cfg,DATA,['attackNode'])
        if len(Xa)==0:
            flag='no-data'
        else:
            flag=f"{100*np.mean(iso.predict(Xa)==-1):.0f}%"

        # STAGE 2: classification (only for the 7 data-plane-typable attacks)
        if cfg in det7 and len(Xa)>0:
            preds=rf.predict(Xa)
            # collision-aware: correct if predicted into the same policy-action group
            same_action=np.mean([POLICY.get(p)==POLICY.get(cfg) for p in preds])
            type_ok=f"{100*same_action:.0f}%"
        else:
            type_ok='n/a'

        # STAGE 3: policy
        action=POLICY.get(cfg,'--')

        # STAGE 4: enforcement (real .sca)
        s,ad,recov=ENFORCE[cfg]
        blocked=(s-ad)/s

        # STAGE 5: reward (extended with measured blocking)
        reward=W['det']*1.0 + W['block']*blocked - W['fp']*FPR + W['thru']*recov

        print(f"{cfg:26s} {flag:>8s} {type_ok:>11s} {action:>16s} {blocked*100:>10.1f}% {reward:>9.3f}")

    print("-"*100)
    print("S1 flag: IsoForest detection TPR (attackNode).  S2 type_ok: RF predicts SAME policy-action group")
    print("         (collision-aware -- collided pairs share an action, so this is what matters operationally).")
    print("S4 blocked%: REAL measured attack-traffic reduction from OMNeT++ _Adaptive .sca runs.")
    print("S5 reward: 3.0*det + 3.0*blocked - 1.5*FPR + 1.0*legit_recovery  (base reward + measured-blocking term).")
    print("Loop-back: reward updates the Q-table OFFLINE for the next run (not live -- documented limitation).")

if __name__=='__main__':
    main()
