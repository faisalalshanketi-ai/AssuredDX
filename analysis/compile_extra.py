"""Paired comparison of all defences under the strongest attack (Tables 4-7 of the paper).

usage: python compile_extra.py <run_dir>
<run_dir> is a finished assuredx_attack.py run (stages 4-10) with assuredx_extra.py stages 11-12.
Writes <run_dir>/summary/paired_all.csv and paired_mus.csv and prints them.
"""
import os, sys
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile_results import boot_diff

def jl(p): return pd.read_json(p, lines=True)

def load(run):
    R = {d: jl(f"{run}/stage7/attack_{d}.jsonl") for d in ["raw", "random", "fingerprint", "consensus", "unsmoothed"]}
    R["fp_ae"] = jl(f"{run}/stage12/attack_fingerprint_ae.jsonl")
    R["vor_u"] = jl(f"{run}/stage11/voronoi_unsmoothed.jsonl")
    R["vote"] = jl(f"{run}/stage9/attack_vote.jsonl")
    R["vor_c"] = jl(f"{run}/stage11/voronoi_assuredx.jsonl")
    for v in R.values():
        v["eps"] = v.eps.round(4); v["eligible"] = v.eligible.astype(bool); v["success"] = v.success.astype(bool)
    return R

def main(run):
    al = pd.read_csv(f"{run}/stage4/alerts.csv").set_index("alert_id")
    R = load(run); out = os.path.join(run, "summary"); os.makedirs(out, exist_ok=True)
    rows = []
    for e in sorted(R["vote"].eps.unique()):
        g = {k: v[v.eps == e].set_index("alert_id") for k, v in R.items()}
        common = set(g["vote"].index)
        for k in ["raw", "fingerprint", "fp_ae", "consensus", "unsmoothed", "vote"]:
            common &= set(g[k][g[k].eligible].index)
        c = sorted(common); files = al.loc[c, "source_file"]
        S = {"no defence": g["raw"].success.reindex(c) | g["random"].success.reindex(c).fillna(False),
             "fingerprint, supervised": g["fingerprint"].success.reindex(c),
             "fingerprint, Sharma et al.": g["fp_ae"].success.reindex(c),
             "consensus": g["consensus"].success.reindex(c),
             "unsmoothed (strongest)": g["unsmoothed"].success.reindex(c) | g["vor_u"].success.reindex(c),
             "AssureDx (strongest)": g["vote"].success.reindex(c) | g["vor_c"].success.reindex(c),
             "AssureDx certified diagnoses": g["vote"].success_certified_output.astype(bool).reindex(c)
                                           | g["vor_c"].success_certified_output.astype(bool).reindex(c)}
        r = {"eps": e, "n": len(c), "capture_groups": files.nunique()}
        r.update({k: round(v.mean(), 3) for k, v in S.items()})
        for a, b in [("AssureDx (strongest)", "no defence"), ("AssureDx (strongest)", "fingerprint, Sharma et al."),
                     ("AssureDx (strongest)", "unsmoothed (strongest)"), ("AssureDx certified diagnoses", "fingerprint, Sharma et al."),
                     ("AssureDx certified diagnoses", "unsmoothed (strongest)")]:
            dm, lo, hi = boot_diff(S[a], S[b], files); r[f"{a} - {b}"] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
        r["provably immune"] = round(g["vote"].certified_at_eps.astype(bool).reindex(c).mean(), 3)
        rows.append(r)
    T = pd.DataFrame(rows); T.to_csv(f"{out}/paired_all.csv", index=False); print(T.T.to_string())
    # multiplicative smoothing (Xue et al.) paired with no defence and with AssureDx on its alerts
    M = jl(f"{run}/stage12/attack_mus.jsonl"); M["eps"] = M.eps.round(4)
    rows = []
    for e in sorted(M.eps.unique()):
        m = M[M.eps == e].set_index("alert_id"); r_ = R["raw"][R["raw"].eps == e].set_index("alert_id")
        rn = R["random"][R["random"].eps == e].set_index("alert_id")
        c = sorted(set(m[m.eligible.astype(bool)].index) & set(r_[r_.eligible].index))
        a = m.success.astype(bool).reindex(c); b = r_.success.reindex(c) | rn.success.reindex(c).fillna(False)
        dm, lo, hi = boot_diff(a, b, al.loc[c, "source_file"])
        row = {"eps": e, "n": len(c), "masking smoother": round(a.mean(), 3), "no defence": round(b.mean(), 3),
               "smoother - no defence": f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"}
        if e in set(R["vote"].eps):
            v = R["vote"][R["vote"].eps == e].set_index("alert_id"); vc = R["vor_c"][R["vor_c"].eps == e].set_index("alert_id")
            c2 = sorted(set(m[m.eligible.astype(bool)].index) & set(v[v.eligible].index))
            cc = v.success_certified_output.astype(bool).reindex(c2) | vc.success_certified_output.astype(bool).reindex(c2)
            dm, lo, hi = boot_diff(cc, m.success.astype(bool).reindex(c2), al.loc[c2, "source_file"])
            row.update({"n_vs_AssureDx": len(c2), "AssureDx certified - smoother": f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"})
        rows.append(row)
    T = pd.DataFrame(rows); T.to_csv(f"{out}/paired_mus.csv", index=False); print(T.to_string())

if __name__ == "__main__":
    main(sys.argv[1])
