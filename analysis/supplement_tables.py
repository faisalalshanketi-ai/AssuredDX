"""Supplementary Tables S8-S11 (sample flow, per-stratum results, decoded-sample audit, clean accuracy).

usage: python supplement_tables.py <results_dir> <runs_dir>
<runs_dir> holds the local runs with stage-0 splits (runs/ciciot2023, runs/edgeiiot) and the
detector bases (runs/ciciot2023_clean, runs/edgeiiot_noport) and attack runs (runs/ciciot2023_k5, runs/edgeiiot_k5).
Writes <results_dir>/<run>/extended/{sample_flow,strata,accuracy,decoder_audit}.csv.
"""
import os, sys
RESULTS, RUNS = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sys, json, numpy as np, pandas as pd
import assuredx_lib as L
from compile_results import boot_diff
jl = lambda p: pd.read_json(p, lines=True).assign(eps=lambda d: d.eps.round(4)) if "eps" in pd.read_json(p, lines=True, nrows=1) else pd.read_json(p, lines=True)
R = RESULTS
DS = {"CICIoT2023": (f"{R}/ciciot2023_k5", os.path.join(RUNS, "ciciot2023", "stage0"), os.path.join(RUNS, "ciciot2023", "stage0")),
      "Edge-IIoTset": (f"{R}/edgeiiot_k5", os.path.join(RUNS, "edgeiiot", "stage0"), os.path.join(RUNS, "edgeiiot", "stage0"))}
out = {}
def boot_mean(x, g, B=2000, seed=0):
    x = pd.Series(np.asarray(x, float)); g = pd.Series(np.asarray(g))
    u = g.unique(); idx = {k: np.where(g.values == k)[0] for k in u}; rng = np.random.default_rng(seed)
    bs = [x.values[np.concatenate([idx[k] for k in rng.choice(u, len(u))])].mean() for _ in range(B)]
    return x.mean(), np.quantile(bs, [.025, .975]), np.quantile(bs, [.05, .95])
for name, (run, s0, _) in DS.items():
    print("=" * 20, name)
    al = pd.read_csv(f"{run}/stage4/alerts.csv").set_index("alert_id")
    clean = jl(f"{run}/stage6/clean.jsonl").set_index("alert_id")
    sig = json.load(open(f"{run}/stage5/summary.json"))["sigma_selected"]
    cert = jl(f"{run}/stage9/diag_cert.jsonl")
    C = cert[(cert.n == 1000) & (cert.sigma.round(4) == round(sig, 4))].set_index("alert_id").reindex(al.index)
    sm = (C["class"] == al.family).astype(float); rw = (clean.loc[al.index, "raw_diag"] == al.family).astype(float)
    files = al.source_file
    # (A) paired accuracy difference with CI and TOST
    d, ci95, ci90 = boot_mean(sm - rw, files)
    print(f"A accuracy smoothed {sm.mean():.4f} raw {rw.mean():.4f}; diff {d:+.4f} 95%CI [{ci95[0]:+.4f},{ci95[1]:+.4f}] 90%CI [{ci90[0]:+.4f},{ci90[1]:+.4f}]")
    # (B) accuracy of certified vs uncertified outputs
    certd = C.p_lower > 0.5
    print(f"B certified share {certd.mean():.4f}; accuracy certified {sm[certd].mean():.4f} (n={certd.sum()}), uncertified {sm[~certd].mean():.4f} (n={(~certd).sum()}); raw acc on certified {rw[certd].mean():.4f}")
    for r in (0.01, 0.03, 0.1):
        m = C.radius >= r
        if m.sum(): print(f"   accuracy among certified radius>={r}: {sm[m].mean():.4f} (n={m.sum()})")
    # (C) per stratum
    te = pd.read_parquet(f"{s0}/test.parquet")
    st = pd.Series(L.stratum_of(te["Protocol Type"].values[al.row.values]), index=al.index)
    V = jl(f"{run}/stage9/attack_vote.jsonl"); VC = jl(f"{R.replace('results','results')}/{run.split('/')[-1]}/stage11/voronoi_assuredx.jsonl")
    rows = []
    for s in sorted(st.unique()):
        ids = st[st == s].index
        r = {"stratum": s, "alerts": len(ids), "clean_acc_smoothed": sm[ids].mean(), "clean_acc_raw": rw[ids].mean(),
             "certified": certd[ids].mean(), "useful@0.03": ((C.radius >= 0.03) & (sm == 1))[ids].mean()}
        for e in (0.1, 0.3):
            v = V[(V.eps == e) & V.alert_id.isin(ids)].set_index("alert_id"); vc = VC[(VC.eps == e)].set_index("alert_id").reindex(v.index)
            el = v.eligible.astype(bool)
            r[f"TMR@{e} (n)"] = f"{(v.success.astype(bool) | vc.success.astype(bool))[el].mean():.3f} ({el.sum()})" if el.sum() else "–"
            r[f"certTMR@{e}"] = f"{(v.success_certified_output.astype(bool) | vc.success_certified_output.astype(bool))[el].mean():.3f}" if el.sum() else "–"
        rows.append(r)
    P9=pd.DataFrame(rows).round(3); print("C per stratum\n", P9.to_string(index=False)); import os; od=f"{run}/extended"; os.makedirs(od,exist_ok=True); P9.to_csv(f"{od}/strata.csv",index=False)
    # (D) sample flow
    acc=[{"Quantity":"Smoothed diagnosis accuracy","Value":round(sm.mean(),4)},{"Quantity":"Raw SHAP diagnosis accuracy","Value":round(rw.mean(),4)},
         {"Quantity":"Paired difference (smoothed − raw)","Value":round(d,4)},{"Quantity":"95% capture-level CI","Value":f"[{ci95[0]:+.4f}, {ci95[1]:+.4f}]"},
         {"Quantity":"90% CI (TOST, margin ±0.05)","Value":f"[{ci90[0]:+.4f}, {ci90[1]:+.4f}]"},
         {"Quantity":"Equivalent at ±0.05","Value":"yes" if (ci90[0]>-0.05 and ci90[1]<0.05) else "no"},
         {"Quantity":f"Accuracy, certified diagnoses (n = {certd.sum()})","Value":round(sm[certd].mean(),4)},
         {"Quantity":f"Accuracy, abstentions (n = {(~certd).sum()})","Value":round(sm[~certd].mean(),4)}]
    for r_ in (0.01,0.03,0.1):
        mm=C.radius>=r_; acc.append({"Quantity":f"Accuracy, certified radius ≥ {r_} (n = {mm.sum()})","Value":round(sm[mm].mean(),4)})
    import os; os.makedirs(f"{run}/extended",exist_ok=True); pd.DataFrame(acc).to_csv(f"{run}/extended/accuracy.csv",index=False)
    flow=[{"Set":"Attacked alerts (stage 4)","Alerts":len(al)},{"Set":"Adaptive-attack subset","Alerts":int(al.adaptive_subset.sum())},{"Set":"Diagnosis-attack subset","Alerts":V.alert_id.nunique()}]
    print("D alerts", len(al), "adaptive subset", int(al.adaptive_subset.sum()), "vote subset", V.alert_id.nunique())
    for dname in ["raw", "fingerprint", "consensus", "unsmoothed", "assuredx"]:
        x = jl(f"{run}/stage7/attack_{dname}.jsonl"); x = x[x.eps == x.eps.max()]
        flow.append({"Set":f"Eligible, {dname}","Alerts":int(x.eligible.astype(bool).sum())})
        print(f"   {dname}: attacked {x.alert_id.nunique()}, eligible {int(x.eligible.astype(bool).sum())}; eligible constant across eps:",
              jl(f"{run}/stage7/attack_{dname}.jsonl").groupby("eps").eligible.apply(lambda s: s.astype(bool).sum()).nunique() == 1)
    flow.append({"Set":"Eligible, smoothed diagnosis (vote)","Alerts":int(V[V.eps == V.eps.max()].eligible.astype(bool).sum())})
    flow.append({"Set":"Clean certified share within diagnosis-attack subset","Alerts":round(certd[V.alert_id.unique()].mean(),3)})
    pd.DataFrame(flow).to_csv(f"{run}/extended/sample_flow.csv",index=False)
    print(f"   vote: eligible {int(V[V.eps == V.eps.max()].eligible.astype(bool).sum())}, clean certified among vote subset {certd[V.alert_id.unique()].mean():.3f}")
    # (E) duplicate overlap train/test
    tr = pd.read_parquet(f"{s0}/train.parquet")
    feats = json.load(open(f"{run.replace('results/ciciot2023_k5','results/detection_and_explanations/ciciot2023_clean').replace('results/edgeiiot_k5','results/detection_and_explanations/edgeiiot_noport')}/taxonomy.json"))["features"]
    key = lambda df: pd.util.hash_pandas_object(df[feats].round(6), index=False)
    trk = set(key(tr).values); tek = key(te)
    alk = tek.values[al.row.values]
    print(f"E exact duplicates of a training row: all test rows {np.isin(tek.values, list(trk)).mean():.4f}; attacked alerts {np.isin(alk, list(trk)).mean():.4f}")
    # (F) strict immunity
    for e in sorted(V.eps.unique()):
        v = V[V.eps == e]; el = v.eligible.astype(bool)
        print(f"F eps {e}: immune R>=eps {(v.clean_radius >= e)[el].mean():.4f}  R>eps {(v.clean_radius > e)[el].mean():.4f}")


# ---------------- decoded-sample audit (Table S10) ----------------
import assuredx_attack as A
import assuredx_attack as A, assuredx_lib as L
for name, base, run in [("CICIoT2023", os.path.join(RUNS, "ciciot2023_clean"), os.path.join(RUNS, "ciciot2023_k5")),
                        ("Edge-IIoTset", os.path.join(RUNS, "edgeiiot_noport"), os.path.join(RUNS, "edgeiiot_k5"))]:
    ctx = A.Ctx(base, run); bank = A._ctx_bank(ctx)
    sig = json.load(open(f"{run}/stage5/summary.json"))["sigma_selected"]
    tr = ctx.split("train"); te = ctx.split("test")
    H = lambda X: pd.util.hash_pandas_object(pd.DataFrame(np.round(X, 5)), index=False).values
    trh = set(H(tr[ctx.feats].values.astype("float64")))
    imm_tr = set(H(tr[ctx.feats].values[:, ctx.imm].astype("float64")))
    al = pd.read_csv(f"{run}/stage4/alerts.csv").sample(120, random_state=0)
    rng = np.random.default_rng(0); m = len(ctx.mut)
    tot = real = 0; per = []
    for _, a in al.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); s = bank.stratum(x0)
        Z = (x0[ctx.mut] * ctx.W)[None] + sig * rng.standard_normal((1000, m))
        idx = bank.query(s, Z); X = bank.decode(s, idx, x0)
        inval = ctx.invalid_mask(X, x0)
        h = H(X); r = np.isin(h, list(trh)).mean()
        per.append({"stratum": s, "observed": r, "invalid": inval.mean(), "distinct": len(np.unique(idx))})
    P = pd.DataFrame(per)
    print(name, "sigma", sig, "| decoded samples violating numerical constraints:", round(P.invalid.mean(), 4),
          "| decoded full vectors identical to an observed training flow:", round(P.observed.mean(), 4),
          "| median over alerts:", round(P.observed.median(), 4))
    G=P.groupby("stratum").agg(alerts=("observed", "size"), observed=("observed", "mean"), invalid=("invalid", "mean"), distinct=("distinct", "median")).round(4).reset_index()
    G.loc[len(G)]=["all",len(P),round(P.observed.mean(),4),round(P.invalid.mean(),4),P.distinct.median()]
    G.columns=["Stratum","Alerts","Share identical to an observed training flow","Share outside 0.1–99.9% training range","Median distinct bank flows"]
    out={"CICIoT2023":"ciciot2023_k5","Edge-IIoTset":"edgeiiot_k5"}[name]; import os; os.makedirs(f"{RESULTS}/{out}/extended",exist_ok=True)
    G.to_csv(f"{RESULTS}/{out}/extended/decoder_audit.csv",index=False)
    print(P.groupby("stratum").agg(alerts=("observed", "size"), observed=("observed", "mean"), invalid=("invalid", "mean"), distinct=("distinct", "median")).round(4))
