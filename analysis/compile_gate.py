"""Deployed pipelines (Table 6): no defence, Sharma et al. fingerprint, AssureDx issuing certified
diagnoses only, and AssureDx behind the fingerprint gate (assuredx_extra.py stage 14).

usage: python compile_gate.py <run_dir>     writes <run_dir>/summary/deployed_pipelines.csv
"""
import os, sys, json
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile_results import boot_diff

def jl(p): return pd.read_json(p, lines=True)

def main(run):
    al = pd.read_csv(f"{run}/stage4/alerts.csv").set_index("alert_id")
    R = {d: jl(f"{run}/stage7/attack_{d}.jsonl") for d in ["raw", "random"]}
    R["ae"] = jl(f"{run}/stage12/attack_fingerprint_ae.jsonl"); R["vote"] = jl(f"{run}/stage9/attack_vote.jsonl")
    R["vor"] = jl(f"{run}/stage11/voronoi_assuredx.jsonl"); R["gate"] = jl(f"{run}/stage14/attack_gate.jsonl")
    for v in R.values():
        v["eps"] = v.eps.round(4); v["eligible"] = v.eligible.astype(bool); v["success"] = v.success.astype(bool)
    rows = []
    for e in sorted(R["gate"].eps.unique()):
        g = {k: v[v.eps == e].set_index("alert_id") for k, v in R.items()}
        c = set(g["gate"].index)
        for k in ["raw", "ae", "vote", "gate"]: c &= set(g[k][g[k].eligible].index)
        c = sorted(c); f = al.loc[c, "source_file"]
        S = {"no defence": g["raw"].success.reindex(c) | g["random"].success.reindex(c).fillna(False),
             "fingerprint, Sharma et al.": g["ae"].success.reindex(c),
             "AssureDx certified diagnoses": g["vote"].success_certified_output.astype(bool).reindex(c)
                                           | g["vor"].success_certified_output.astype(bool).reindex(c),
             "AssureDx behind gate": g["gate"].success_certified_output.astype(bool).reindex(c),
             "AssureDx behind gate, always output": g["gate"].success.reindex(c)}
        r = {"eps": e, "n": len(c), "capture_groups": f.nunique(), **{k: round(v.mean(), 3) for k, v in S.items()}}
        for a, b in [("AssureDx behind gate", "fingerprint, Sharma et al."), ("AssureDx behind gate", "no defence"),
                     ("AssureDx certified diagnoses", "fingerprint, Sharma et al.")]:
            dm, lo, hi = boot_diff(S[a], S[b], f); r[f"{a} - {b}"] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
        rows.append(r)
    T = pd.DataFrame(rows); out = os.path.join(run, "summary"); os.makedirs(out, exist_ok=True)
    T.to_csv(f"{out}/deployed_pipelines.csv", index=False); print(T.T.to_string())
    ce = jl(f"{run}/stage12/clean_extra.jsonl").set_index("alert_id")
    cert = jl(f"{run}/stage9/diag_cert.jsonl"); s = json.load(open(f"{run}/stage5/summary.json"))["sigma_selected"]
    C = cert[(cert.n == 1000) & (cert.sigma.round(4) == round(s, 4))].set_index("alert_id")
    ab = C.p_lower <= 0.5; rej = ~ce.ae_accept.astype(bool).reindex(C.index)
    print(f"clean alerts routed to an analyst: fingerprint {rej.mean():.4f}, AssureDx {ab.mean():.4f}, combined {(ab | rej).mean():.4f}")

if __name__ == "__main__":
    main(sys.argv[1])
