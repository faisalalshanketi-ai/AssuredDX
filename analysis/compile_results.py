"""Compile the numbers used in the manuscript from finished runs (read-only).

usage: python compile_results.py <attack_run_dir> <base_run_dir> <label> [--cic]
Writes <attack_run_dir>/paper_numbers.md and paper_numbers.json.
"""
import sys, os, json
import numpy as np, pandas as pd
from scipy.stats import binomtest

def jl(p):
    return pd.read_json(p, lines=True) if os.path.exists(p) and os.path.getsize(p) else pd.DataFrame()

def boot_diff(a, b, groups, B=2000, seed=0):
    rng = np.random.default_rng(seed); u = groups.unique()
    by = {g: np.where(groups.values == g)[0] for g in u}
    d = (a.astype(float).values - b.astype(float).values)
    bs = []
    for _ in range(B):
        idx = np.concatenate([by[g] for g in rng.choice(u, len(u))])
        bs.append(d[idx].mean())
    return float(d.mean()), float(np.quantile(bs, .025)), float(np.quantile(bs, .975))

def main(att, base, label):
    out = {"label": label}
    lines = [f"# Paper numbers: {label}", ""]
    alerts = pd.read_csv(f"{att}/stage4/alerts.csv").set_index("alert_id")
    cfg = json.load(open(f"{att}/attack_config.json")); summ = json.load(open(f"{att}/stage5/summary.json"))
    out["k"] = cfg["k"]; out["sigma"] = summ["sigma_selected"]; out["sigma_val"] = summ["sigma_val_macro_f1"]
    out["n_alerts"] = len(alerts); out["alerts_per_family"] = alerts.family.value_counts().to_dict()
    lines += [f"k = {cfg['k']}, sigma = {out['sigma']} (validation {summ['sigma_val_macro_f1']}), "
              f"alerts = {len(alerts)} {out['alerts_per_family']}", ""]

    D = {d: jl(f"{att}/stage7/attack_{d}.jsonl") for d in ["raw", "random", "consensus", "fingerprint", "unsmoothed", "assuredx"]}
    V = jl(f"{att}/stage9/attack_vote.jsonl")
    for d in list(D):
        if len(D[d]): D[d]["eligible"] = D[d]["eligible"].astype(bool); D[d]["eps"] = D[d]["eps"].round(4)
        else: D.pop(d)
    if len(V): V["eligible"] = V["eligible"].astype(bool); V["eps"] = V["eps"].round(4)
    # no-editable-field share (Edge-IIoTset)
    if "raw" in D and "found" in D["raw"]:
        ne = 1 - D["raw"].groupby("alert_id").found.max().mean()
        out["share_alerts_without_feasible_candidate"] = float(ne)
        lines += [f"Alerts with no feasible candidate under raw SHAP (any eps): {ne:.3f}", ""]

    # common eligible set across all defences incl. vote attack
    sets = [set(D[d][D[d].eligible].alert_id) for d in D if d not in ("random",)]
    common = set(D["assuredx"].alert_id) if "assuredx" in D else set(alerts.index)
    for s in sets: common &= s
    if len(V): common &= set(V[V.eligible].alert_id)
    out["n_common"] = len(common)
    files = alerts.loc[sorted(common), "source_file"]
    rows = []
    for eps in sorted(D["raw"].eps.unique()):
        g = lambda d: D[d][(D[d].eps == eps) & D[d].alert_id.isin(common)].set_index("alert_id").success.astype(bool).reindex(sorted(common))
        r = {"eps": eps}
        rs = g("raw") | g("random").fillna(False) if "random" in D else g("raw")
        r["raw_strongest"] = rs.mean()
        for d in ("fingerprint", "consensus", "unsmoothed", "assuredx"):
            if d in D: r[d] = g(d).mean()
        if len(V) and eps in set(V.eps):
            vv = V[(V.eps == eps) & V.alert_id.isin(common)].set_index("alert_id").reindex(sorted(common))
            r["assuredx_diag"] = vv.success.astype(bool).mean()
            r["assuredx_diag_certified_output"] = vv.success_certified_output.astype(bool).mean()
            r["provably_immune_diag"] = vv.certified_at_eps.astype(bool).mean()
            dm, lo, hi = boot_diff(vv.success.astype(bool), rs, files)
            r["diag_minus_raw"] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
            if "fingerprint" in D:
                dm, lo, hi = boot_diff(vv.success.astype(bool), g("fingerprint"), files)
                r["diag_minus_fp"] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
        if "assuredx" in D:
            dm, lo, hi = boot_diff(g("assuredx"), rs, files); r["set_minus_raw"] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
        rows.append(r)
    T = pd.DataFrame(rows); out["common_table"] = T.to_dict("records")
    lines += [f"## Common eligible set (n = {len(common)}, {files.nunique()} capture clusters)", "", T.round(4).to_string(index=False), ""]

    # per-defence TMR on own eligible set (from stage 8 output)
    t8 = pd.read_csv(f"{att}/stage8/tmr.csv") if os.path.exists(f"{att}/stage8/tmr.csv") else pd.DataFrame()
    if len(t8): lines += ["## Own-eligible TMR (stage 8)", "", t8.round(4).to_string(index=False), ""]
    tv = f"{att}/stage10/tmr_vote.csv"
    if os.path.exists(tv): lines += ["## Vote attack own-eligible (stage 10)", "", pd.read_csv(tv).round(4).to_string(index=False), ""]

    # clean diagnosis: smoothed diagnosis vs raw (McNemar)
    cert = jl(f"{att}/stage9/diag_cert.jsonl"); clean = jl(f"{att}/stage6/clean.jsonl").set_index("alert_id")
    if len(cert):
        C = cert[(cert.sigma.round(4) == round(out["sigma"], 4)) & (cert.n == cfg["n_cert"])].set_index("alert_id")
        a = C["class"] == C["family"]; b = clean.loc[C.index, "raw_diag"] == C["family"]
        n10, n01 = int((a & ~b).sum()), int((~a & b).sum())
        p = binomtest(n10, n10 + n01).pvalue if n10 + n01 else 1.0
        out["clean_acc_smoothed_diag"] = float(a.mean()); out["clean_acc_raw"] = float(b.mean()); out["mcnemar_p"] = float(p)
        out["clean_certified_issue_rate"] = float((C.p_lower > 0.5).mean())
        lines += [f"Clean diagnosis accuracy: smoothed {a.mean():.4f} vs raw {b.mean():.4f} "
                  f"(+{n10}/-{n01}, exact McNemar p = {p:.4f}); certified output issued for {(C.p_lower > 0.5).mean():.3f}", ""]
        lines += ["## Diagnosis certificate coverage", "", pd.read_csv(f"{att}/stage10/diag_certificate.csv").round(4).to_string(index=False), ""]
        out["cert_sec_median"] = float(C.sec.median())
    for f in ["certified_coverage", "clean_diagnosis", "fidelity", "n_sweep", "naive_smoothing"]:
        p = f"{att}/stage8/{f}.csv"
        if os.path.exists(p): lines += [f"## {f}", "", pd.read_csv(p).round(4).to_string(index=False), ""]
    # per-family TMR at eps 0.1 and 0.3 on the common set
    for eps in (0.1, 0.3):
        t = {}
        for d in ("raw", "fingerprint", "unsmoothed", "assuredx"):
            if d in D: t[d] = D[d][(D[d].eps == eps) & D[d].alert_id.isin(common)].groupby("family").success.mean()
        if len(V): t["assuredx_diag"] = V[(V.eps == eps) & V.alert_id.isin(common)].groupby("family").success.mean()
        t = pd.DataFrame(t); t["n"] = alerts.loc[sorted(common)].family.value_counts()
        lines += [f"## Per-family TMR, common set, eps = {eps}", "", t.round(3).to_string(), ""]
    # attack stealth
    r = D["raw"]; s = r[r.success.astype(bool) & r.eligible]
    if len(s) and "dW" in s:
        lines += ["Raw successful attacks: median dW " + str(s.groupby("eps").dW.median().round(4).to_dict())
                  + "; median score drift " + str(s.groupby("eps").score_drift.median().round(5).to_dict()), ""]
    # runtime
    rt = {d: float(D[d].sec.median()) for d in D}
    lines += ["Median attack seconds per alert-eps: " + str({k: round(v, 2) for k, v in rt.items()}), ""]
    json.dump(out, open(f"{att}/paper_numbers.json", "w"), indent=1, default=str)
    open(f"{att}/paper_numbers.md", "w").write("\n".join(lines))
    print("\n".join(lines))

if __name__ == "__main__":
    main(*sys.argv[1:4])
