"""Tables for the extended experiments (stages 15-20).

usage: python compile_extended.py <run_dir>
Writes <run_dir>/extended/{convergence,abstention_attack,matched_fingerprint,projected,matched_decoder}.csv
"""
import os, sys, json
import numpy as np
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile_results import boot_diff
from compile_extra import load


def jl(p):
    d = pd.read_json(p, lines=True)
    if "eps" in d: d["eps"] = d.eps.round(4)
    return d


def boot_mean(x, g, B=2000, seed=0):
    x = np.asarray(x, float); g = np.asarray(g); u = np.unique(g)
    idx = {k: np.where(g == k)[0] for k in u}; rng = np.random.default_rng(seed)
    bs = [x[np.concatenate([idx[k] for k in rng.choice(u, len(u))])].mean() for _ in range(B)]
    lo, hi = np.quantile(bs, [.025, .975])
    return f"{x.mean():.3f} [{lo:.3f}, {hi:.3f}]"


def main(run):
    out = os.path.join(run, "extended"); os.makedirs(out, exist_ok=True)
    al = pd.read_csv(f"{run}/stage4/alerts.csv").set_index("alert_id")
    R = load(run)
    def assuredx(e, ids, certified):
        v = R["vote"][R["vote"].eps == e].set_index("alert_id"); vc = R["vor_c"][R["vor_c"].eps == e].set_index("alert_id")
        col = "success_certified_output" if certified else "success"
        return v[col].astype(bool).reindex(ids) | vc[col].astype(bool).reindex(ids)

    # ---- 15 convergence ----
    p = f"{run}/stage15/convergence.jsonl"
    if os.path.exists(p):
        C = jl(p); C = C[C.eligible]; rows = []
        for (e, b, na), g in C.groupby(["eps", "budget", "n_attack"]):
            f = al.loc[g.alert_id, "source_file"].values
            r = {"eps": e, "candidates": b, "attacker samples": na, "n": len(g),
                 "TMR always output, search": boot_mean(g.search_success_always, f),
                 "TMR always output, search + decoder-aware": boot_mean(g.combined_success_always, f),
                 "TMR certified only": boot_mean(g.combined_outcome == "decoy", f),
                 "abstention": boot_mean(g.combined_outcome == "abstain", f),
                 "certified correct": boot_mean(g.combined_outcome == "correct", f),
                 "certified other": round((g.combined_outcome == "other").mean(), 3)}
            ins = g.clean_radius > e
            r["TMR certified only, R > eps (n)"] = f"{(g.combined_outcome[ins] == 'decoy').mean():.3f} ({ins.sum()})"
            r["TMR certified only, R <= eps (n)"] = f"{(g.combined_outcome[~ins] == 'decoy').mean():.3f} ({(~ins).sum()})"
            rows.append(r)
        T = pd.DataFrame(rows); T.to_csv(f"{out}/convergence.csv", index=False); print(T.to_string(index=False))

    # ---- 16 abstention attack ----
    p = f"{run}/stage16/abstention.jsonl"
    if os.path.exists(p):
        Ab = jl(p); Ab = Ab[Ab.eligible]; rows = []
        for e, g in Ab.groupby("eps"):
            f = al.loc[g.alert_id, "source_file"].values; ins = g.clean_radius > e
            rows.append({"eps": e, "n": len(g), "abstention": boot_mean(g.outcome == "abstain", f),
                         "certified wrong family": round(g.outcome.isin(["other", "decoy"]).mean(), 3),
                         "certified correct": boot_mean(g.outcome == "correct", f),
                         "abstention, R > eps (n)": f"{(g.outcome[ins] == 'abstain').mean():.3f} ({ins.sum()})",
                         "wrong family, R > eps": round(g.outcome[ins].isin(["other", "decoy"]).mean(), 3) if ins.any() else None,
                         "abstention, R <= eps (n)": f"{(g.outcome[~ins] == 'abstain').mean():.3f} ({(~ins).sum()})"})
        T = pd.DataFrame(rows); T.to_csv(f"{out}/abstention_attack.csv", index=False); print(T.to_string(index=False))

    # ---- 17 matched fingerprint ----
    p = f"{run}/stage17/attack_fingerprint_matched.jsonl"
    if os.path.exists(p):
        info = json.load(open(f"{run}/stage17/matched.json")); print(info)
        F = jl(p); rows = []
        for e in sorted(R["vote"].eps.unique()):
            fm = F[F.eps == e].set_index("alert_id"); v = R["vote"][R["vote"].eps == e].set_index("alert_id")
            c = sorted(set(fm[fm.eligible].index) & set(v[v.eligible.astype(bool)].index))
            files = al.loc[c, "source_file"]
            a = fm.success.astype(bool).reindex(c); b = assuredx(e, c, True); b2 = assuredx(e, c, False)
            d1 = boot_diff(b, a, files); d2 = boot_diff(b2, a, files)
            rows.append({"eps": e, "n": len(c), "fingerprint coverage (clean)": round(info["fingerprint_clean_acceptance_test"], 3),
                         "AssureDx coverage (clean)": round(info["assuredx_clean_certified"], 3),
                         "fingerprint, matched coverage": round(a.mean(), 3), "AssureDx certified only": round(b.mean(), 3),
                         "AssureDx always output": round(b2.mean(), 3),
                         "AssureDx certified - fingerprint": f"{d1[0]:.3f} [{d1[1]:.3f}, {d1[2]:.3f}]",
                         "AssureDx always - fingerprint": f"{d2[0]:.3f} [{d2[1]:.3f}, {d2[2]:.3f}]"})
        T = pd.DataFrame(rows); T.to_csv(f"{out}/matched_fingerprint.csv", index=False); print(T.to_string(index=False))

    # ---- 18 projected smoothing ----
    p = f"{run}/stage18/attack_proj.jsonl"
    if os.path.exists(p):
        cp = jl(f"{run}/stage18/clean_proj.jsonl"); sg = json.load(open(f"{run}/stage18/proj_sigma.json"))
        cert = jl(f"{run}/stage9/diag_cert.jsonl")
        sig = json.load(open(f"{run}/stage5/summary.json"))["sigma_selected"]
        cert = cert[(cert.n == 1000) & (cert.sigma.round(4) == round(sig, 4))].set_index("alert_id")
        clean = {"projected sigma": sg["sigma"], "accuracy": round(cp.correct.mean(), 4),
                 "AssureDx accuracy": round(cert.correct.reindex(cp.alert_id).mean(), 4),
                 "nominally certified": round((cp.p_lower > 0.5).mean(), 4),
                 "samples violating constraints": round(cp.invalid.mean(), 4),
                 "samples identical to an observed flow": round(cp.observed.mean(), 4),
                 "samples flipping the detector": round(cp.detector_flip.mean(), 4),
                 "median s per certificate": round(cp.sec.median(), 3)}
        print(clean)
        P = jl(p); rows = []
        for e, g in P.groupby("eps"):
            c = sorted(set(g.alert_id) & set(R["vote"][(R["vote"].eps == e) & R["vote"].eligible.astype(bool)].alert_id))
            gi = g.set_index("alert_id").reindex(c); files = al.loc[c, "source_file"]
            nom = gi.nominally_certified_at_eps.astype(bool)
            d = boot_diff(assuredx(e, c, True), gi.success_certified_output.astype(bool), files)
            rows.append({"eps": e, "n": len(c), "TMR always output": round(gi.success.mean(), 3),
                         "TMR certified only": round(gi.success_certified_output.mean(), 3),
                         "abstention": round((gi.outcome == "abstain").mean(), 3),
                         "AssureDx certified only": round(assuredx(e, c, True).mean(), 3),
                         "AssureDx - projected (certified only)": f"{d[0]:.3f} [{d[1]:.3f}, {d[2]:.3f}]",
                         "nominal certificates at eps": int(nom.sum()),
                         "violated nominal certificates": int((nom & (gi.outcome != "correct")).sum())})
        T = pd.DataFrame(rows); T.to_csv(f"{out}/projected.csv", index=False); print(T.to_string(index=False))
        pd.DataFrame([clean]).to_csv(f"{out}/projected_clean.csv", index=False)

    # ---- 19 matched decoder ----
    p = f"{run}/stage19/clean_matched.jsonl"
    if os.path.exists(p):
        rows = []
        for tag in ("matched", "exact"):
            q = f"{run}/stage19/clean_{tag}.jsonl"
            if not os.path.exists(q): continue
            cm = jl(q)
            rows.append({"decoder": tag, "alerts": len(cm), "configuration bank used": round(cm.matched.mean(), 3),
                         "median bank size": int(cm.bank_size.median()),
                         "decoded samples identical to an observed flow": round(cm.observed.mean(), 3),
                         "constraint violations": round(cm.invalid.mean(), 4),
                         "certified": round((cm.p_lower > 0.5).mean(), 3), "accuracy": round(cm.correct.mean(), 3),
                         "median distinct flows": int(cm.distinct.median())})
        T = pd.DataFrame(rows); T.to_csv(f"{out}/matched_decoder_clean.csv", index=False); print(T.to_string(index=False))
        q = f"{run}/stage19/attack_matched.jsonl"
        if os.path.exists(q):
            M = jl(q); rows = []
            for e, g in M.groupby("eps"):
                c = sorted(set(g[g.eligible].alert_id) & set(R["vote"][(R["vote"].eps == e) & R["vote"].eligible.astype(bool)].alert_id))
                gi = g.set_index("alert_id").reindex(c); files = al.loc[c, "source_file"]
                d = boot_diff(gi.success_certified_output.astype(bool), assuredx(e, c, True), files)
                rows.append({"eps": e, "n": len(c), "TMR always output": round(gi.success.mean(), 3),
                             "TMR certified only": round(gi.success_certified_output.mean(), 3),
                             "abstention": round((gi.outcome == "abstain").mean(), 3),
                             "AssureDx certified only": round(assuredx(e, c, True).mean(), 3),
                             "matched - AssureDx (certified only)": f"{d[0]:.3f} [{d[1]:.3f}, {d[2]:.3f}]"})
            T = pd.DataFrame(rows); T.to_csv(f"{out}/matched_decoder_attack.csv", index=False); print(T.to_string(index=False))

    # ---- 20 refusal + robust correct-diagnosis rate ----
    p = f"{run}/stage20/refusal.jsonl"
    if os.path.exists(p) and os.path.exists(f"{run}/stage16/abstention.jsonl"):
        Rf = jl(p); Ab = jl(f"{run}/stage16/abstention.jsonl").set_index(["alert_id", "eps"])
        cert = jl(f"{run}/stage9/diag_cert.jsonl"); sig = json.load(open(f"{run}/stage5/summary.json"))["sigma_selected"]
        cert = cert[(cert.n == 1000) & (cert.sigma.round(4) == round(sig, 4))].set_index("alert_id")
        clean = pd.read_json(f"{run}/stage6/clean.jsonl", lines=True).set_index("alert_id")
        F17 = jl(f"{run}/stage17/attack_fingerprint_matched.jsonl").set_index(["alert_id", "eps"])
        F12 = jl(f"{run}/stage12/attack_fingerprint_ae.jsonl").set_index(["alert_id", "eps"])
        G = jl(f"{run}/stage20/attack_gate_matched.jsonl").set_index(["alert_id", "eps"]) if os.path.exists(f"{run}/stage20/attack_gate_matched.jsonl") else None
        rows = []
        for e in sorted(Rf.eps.unique()):
            ids = sorted(set(Rf.alert_id))
            ids = [i for i in ids if clean.loc[i, "raw_diag"] == al.loc[i, "family"] and bool(cert.loc[i, "correct"])]
            files = al.loc[ids, "source_file"]
            cx_ok = np.array([bool(cert.loc[i, "p_lower"] > 0.5) and (i, e) in Ab.index and Ab.loc[(i, e), "outcome"] == "correct"
                              for i in ids]) & ~assuredx(e, ids, True).values
            r = {"eps": e, "n": len(ids), "AssureDx robust correct": boot_mean(cx_ok, files)}
            for tag, Fm in (("published", F12), ("matched", F17)):
                rf = Rf[(Rf.eps == e) & (Rf.threshold == tag)].set_index("alert_id").reindex(ids)
                mis = np.array([bool(Fm.loc[(i, e), "success"]) if (i, e) in Fm.index else False for i in ids])
                ok = rf.clean_accepted.astype(bool).values & ~rf.refused.astype(bool).values & ~mis
                r[f"fingerprint ({tag}) robust correct"] = boot_mean(ok, files)
                r[f"fingerprint ({tag}) refused under attack"] = round(rf.refused.mean(), 3)
                d = boot_diff(pd.Series(cx_ok), pd.Series(ok), files)
                r[f"AssureDx - fingerprint ({tag})"] = f"{d[0]:.3f} [{d[1]:.3f}, {d[2]:.3f}]"
            if G is not None:
                rfm = Rf[(Rf.eps == e) & (Rf.threshold == "matched")].set_index("alert_id").reindex(ids)
                gm = np.array([bool(G.loc[(i, e), "success_certified_output"]) if (i, e) in G.index else False for i in ids])
                gok = rfm.clean_accepted.astype(bool).values & ~rfm.refused.astype(bool).values & ~gm & cx_ok
                r["gate (matched) + AssureDx robust correct"] = boot_mean(gok, files)
                r["gate (matched) + AssureDx TMR certified"] = round(gm.mean(), 3)
            rows.append(r)
        T = pd.DataFrame(rows); T.to_csv(f"{out}/robust_correct.csv", index=False); print(T.T.to_string())


if __name__ == "__main__":
    main(sys.argv[1])
