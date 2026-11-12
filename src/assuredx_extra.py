"""
AssureDx additional experiments (stages 11-13). Reads a finished assuredx_attack.py run
(stages 4-10) and writes into its stage11 / stage12 / stage13 folders only.

 11  decoder-aware attack   enumerates the bank flows an attacker can reach within the
                            budget and steers the alert into the Voronoi cell of a flow
                            that the defender's diagnoser maps to the decoy family;
                            run against the unsmoothed decoder (all alerts) and against
                            the AssureDx smoothed diagnosis (diagnosis-attack subset)
 12  published baselines    (a) unsupervised autoencoder fingerprint detector as in
                            Sharma et al. (TrustCom 2025); (b) multiplicative (masking)
                            smoothing of top-k membership as in Xue et al. (NeurIPS 2023)
 13  summary                extras_results.md and CSV tables

All stages resume: per-alert results are appended as JSON lines and skipped on re-run.
"""
import os, sys, json, time, zlib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import assuredx_lib as L
import assuredx_attack as A

EXTRA_VERSION = "2026-10-28b"

EXTRA_DEFAULTS = {
    "voronoi_candidates": 20000,       # nearest bank flows considered per alert
    "mus_lambdas": [0.25, 0.5, 0.75],  # keep probability of the masking smoother
    "mus_alerts_per_family": 15,       # alerts attacked under the masking smoother
    "mus_n_attack": 64,                # attacker's masks per candidate
    "ae_hidden": [32, 8, 32],
}


def setup(ctx):
    for k, v in EXTRA_DEFAULTS.items():
        ctx.cfg.setdefault(k, v)
    L._atomic_json(os.path.join(ctx.out, "attack_config.json"), ctx.cfg)


def seed_for(ctx, *parts):
    return int(ctx.cfg["seed"] * 1000003 + zlib.crc32("_".join(map(str, parts)).encode()) % (2**31 - 1))


# ==========================================================================
# STAGE 11 - decoder-aware (Voronoi) attack
# ==========================================================================
def voronoi_points(ctx, bank, sm, x0, eps, decoy_ids):
    """Feasible attack points: for each decoy-labelled bank flow v (nearest first), the
    point where the segment from the alert toward v crosses into v's side of the bisector
    with the alert's current nearest flow, and the furthest point toward v within eps."""
    s = sm.s
    c0 = x0[ctx.mut] * ctx.W
    app = ctx.app_mask(x0).astype(float)
    lo, hi = ctx.bounds_for(x0)
    b0 = bank.mutvals[s][bank.query(s, c0[None])[0]] * ctx.W
    pts = []
    for v in decoy_ids:
        vb = bank.mutvals[s][v] * ctx.W
        u = (vb - c0) * app
        nu = np.linalg.norm(u)
        if nu == 0: continue
        tmax = min(1.0, eps / nu)
        den = 2 * u.dot(vb - b0)
        if den > 0:
            tc = (vb.dot(vb) - b0.dot(b0) - 2 * c0.dot(vb - b0)) / den
            if 0 < tc * 1.02 <= tmax: pts.append(c0 + u * tc * 1.02)
        pts.append(c0 + u * tmax)
        if len(pts) >= ctx.cfg["budget"]: break
    if not pts: return np.zeros((0, ctx.d)), 0
    T = np.array(pts[:ctx.cfg["budget"]])
    X = np.repeat(x0[None], len(T), axis=0)
    X[:, ctx.mut] = T / ctx.W
    X = ctx.project(X, x0, lo, hi)
    ok = (ctx.dW(X, x0) <= eps * (1 + 1e-9)) & (ctx.score(X) >= ctx.thr)
    return X[ok], len(T)


def decoy_flows(ctx, bank, sm, x0, eps, clf, c):
    """Bank flows within reach (|v - x'| <= d0 + 2 eps for some x' in the ball) whose
    diagnosis under clf is the decoy, ordered by distance from the alert."""
    s = sm.s
    c0 = (x0[ctx.mut] * ctx.W)[None]
    nn = bank.nn[s]
    kk = min(ctx.cfg["voronoi_candidates"], len(bank.mutvals[s]))
    dist, ids = nn.kneighbors(c0, n_neighbors=kk)
    dist, ids = dist[0], ids[0]
    reach = dist <= dist[0] + 2 * eps + 1e-9
    ids = ids[reach]
    if len(ids) == 0: return ids, 0
    M = sm._unique_members(ids)
    diag = clf.predict(M)
    return ids[diag == c], int(reach.sum())


def stage11_voronoi(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); bank = A._ctx_bank(ctx)
    alerts = A.stage4_alerts(ctx)
    clean = A.jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    cert = A.jl_read(ctx.p("stage9", "diag_cert.jsonl"))
    cert = cert[(cert.n == cfg["n_cert"]) & (cert.sigma.round(4) == round(ctx.sigma, 4))].set_index("alert_id")
    te = ctx.split("test")

    # (a) unsmoothed decoder, all alerts, all budgets (deterministic decoder: exact check)
    out = ctx.p("stage11", "voronoi_unsmoothed.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in alerts.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        sm = A.Smoother(ctx, bank, x0, 0.0)
        for eps in cfg["eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done: continue
            ts = time.time()
            rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                   "source_file": a.source_file, "eligible": bool(clean.loc[a.alert_id, "unsmoothed_diag"] == y)}
            if ctx.app_mask(x0).sum() == 0:
                rec.update(success=False, reachable=0, decoy_flows=0, evals=0, no_editable_fields=True)
            else:
                ids, nreach = decoy_flows(ctx, bank, sm, x0, eps, D["unsmoothed"], c)
                X, nev = voronoi_points(ctx, bank, sm, x0, eps, ids)
                succ = False
                if len(X):
                    diag = D["unsmoothed"].predict(sm.unsmoothed(X))
                    succ = bool((diag == c).any())
                rec.update(success=succ, reachable=nreach, decoy_flows=int(len(ids)), evals=nev, feasible=int(len(X)))
            rec["sec"] = time.time() - ts
            A.jl_append(out, rec)
        n_new += 1
        if n_new % 50 == 0:
            L.log(f"  voronoi/unsmoothed: {n_new}/{len(alerts)} alerts ({(time.time()-t0)/n_new:.2f}s each)")
    L.log("stage 11 voronoi attack on the unsmoothed decoder done")

    # (b) AssureDx smoothed diagnosis, diagnosis-attack subset
    out = ctx.p("stage11", "voronoi_assuredx.jsonl"); done = A.jl_done(out, "key")
    sub = alerts.groupby("family").head(cfg["vote_alerts_per_family"])
    clf = D["raw"]; ci = lambda f: A.fam_index(clf, f)
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        for eps in cfg["vote_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done: continue
            ts = time.time()
            cl = cert.loc[a.alert_id]
            rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                   "source_file": a.source_file, "eligible": bool(cl["correct"]),
                   "clean_radius": float(cl["radius"]), "certified_at_eps": float(cl["radius"]) >= eps}
            sm = A.Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
            succ = succ_cert = False; nev = 0
            if ctx.app_mask(x0).sum() > 0:
                ids, _ = decoy_flows(ctx, bank, sm, x0, eps, clf, c)
                X, nev = voronoi_points(ctx, bank, sm, x0, eps, ids)
                if len(X):
                    rng = np.random.default_rng(seed_for(ctx, "vor", a.alert_id, eps))
                    J = np.empty(len(X)); hit = None
                    for b in range(0, len(X), cfg["batch"]):
                        V = sm.votes(X[b:b + cfg["batch"]], cfg["n_attack"], rng, clf)
                        J[b:b + len(V)] = V[:, ci(c)] - V.max(1) + 1.0
                        if hit is None and (V.argmax(1) == ci(c)).any():
                            hit = b + int(np.argmax(V.argmax(1) == ci(c)))
                    cands = [X[int(np.argmax(J))]] + ([X[hit]] if hit is not None else [])
                    for j, x in enumerate(cands):
                        rv = A.diag_certify(ctx, sm, x, clf, 100, cfg["n_cert"], cfg["alpha"],
                                            seed_for(ctx, "vorval", a.alert_id, eps, j))
                        if rv["class"] == c:
                            succ = True
                            if rv["p_lower"] > 0.5: succ_cert = True
            rec.update(success=succ, success_certified_output=succ_cert, evals=nev, sec=time.time() - ts)
            A.jl_append(out, rec)
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  voronoi/assuredx: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 11 voronoi attack on AssureDx done")


# ==========================================================================
# STAGE 12 - published baselines: autoencoder fingerprint, masking smoothing
# ==========================================================================
def _val_alerts(ctx):
    va = ctx.split("val")
    rva_all = np.load(os.path.join(ctx.base, "stage3", "rows_val.npy"))
    rng = np.random.default_rng(ctx.cfg["seed"] + 1)
    rva = []
    for f in ctx.families:
        r = rva_all[va["family"].values[rva_all] == f]
        rva.extend(rng.choice(r, min(len(r), ctx.cfg["diag_val_per_family"]), replace=False).tolist())
    rva = np.array(sorted(rva))
    return va[ctx.feats].values[rva].astype("float64"), va["family"].values[rva]


def ae_detector(ctx):
    """Unsupervised fingerprint detector of Sharma et al.: autoencoder trained on SHAP
    fingerprints of clean detected alerts; reconstruction error above the 99th percentile
    of clean validation alerts (1% false rejection) flags the input."""
    import joblib
    path = ctx.p("stage12", "fingerprint_ae.joblib")
    if os.path.exists(path): return joblib.load(path)
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler
    _, Xtr, _ = A.balanced_train_alerts(ctx, ctx.cfg["diag_train_per_family"], ctx.cfg["seed"])
    Xva, _ = _val_alerts(ctx)
    St = ctx.shap(Xtr); sc = StandardScaler().fit(St)
    ae = MLPRegressor(hidden_layer_sizes=tuple(ctx.cfg["ae_hidden"]), activation="relu", max_iter=500,
                      early_stopping=True, random_state=ctx.cfg["seed"]).fit(sc.transform(St), sc.transform(St))
    err = lambda S: ((ae.predict(sc.transform(S)) - sc.transform(S)) ** 2).mean(1)
    thr = float(np.quantile(err(ctx.shap(Xva)), 1 - ctx.cfg["fp_frr"]))
    det = {"ae": ae, "scaler": sc, "thr": thr}
    joblib.dump(det, path)
    L.log(f"  autoencoder fingerprint: threshold {thr:.4f}")
    return det


def ae_accept(det, S):
    Z = det["scaler"].transform(S)
    return ((det["ae"].predict(Z) - Z) ** 2).mean(1) < det["thr"]


def mus_membership(ctx, X, lam, n, rng, ref):
    """Masking smoothing (Xue et al.): each feature kept with probability lam, otherwise
    replaced by the training median; returns top-k inclusion frequencies and the masked
    samples of the first row (for the validity audit)."""
    R, d = X.shape
    S = rng.random((R, n, d)) < lam
    Z = np.where(S, X[:, None, :], ref[None, None, :]).reshape(-1, d)
    M = ctx.topk(ctx.shap(Z)).reshape(R, n, d).astype("float32")
    return M.mean(1), Z[:n]


def bank_stratum(ctx, x):
    return str(L.stratum_of(np.array([x[ctx.ix["Protocol Type"]]]))[0]) if "Protocol Type" in ctx.ix else "all"


def mus_diagnoser(ctx):
    import joblib
    path = ctx.p("stage12", "mus.joblib")
    if os.path.exists(path): return joblib.load(path)
    from sklearn.metrics import f1_score
    cfg = ctx.cfg; ref = A._ref_median(ctx)
    _, Xtr, ytr = A.balanced_train_alerts(ctx, cfg["diag_train_per_family"], cfg["seed"])
    Xva, yva = _val_alerts(ctx)
    best = None; vals = {}
    for lam in cfg["mus_lambdas"]:
        r = np.random.default_rng(seed_for(ctx, "mus_tr", lam))
        rep = lambda X: ctx.topk(np.vstack([mus_membership(ctx, X[i:i + 50], lam, cfg["n_train_expl"], r, ref)[0]
                                            for i in range(0, len(X), 50)]))
        f1v, pen, clf = A.fit_lr(cfg, rep(Xtr), ytr, rep(Xva), yva)
        vals[lam] = f1v
        L.log(f"  masking smoother lambda={lam}: val macro-F1 {f1v:.4f}")
        if best is None or f1v > best[0]: best = (f1v, lam, clf)
    out = {"lambda": best[1], "clf": best[2], "val_macro_f1": vals}
    joblib.dump(out, path)
    return out


def _extra_evaluate(orig):
    def evaluate(ctx, defence, X, fam_c, D, state, rng):
        w = ctx.cfg["mass_weight"]
        if defence == "fingerprint_ae":
            S = ctx.shap(X); M = ctx.topk(S)
            clf = D["raw"]; pr = clf.predict_proba(M)
            J = pr[:, A.fam_index(clf, fam_c)] + w * A.raw_mass(S, ctx, fam_c)
            return J, clf.classes_[pr.argmax(1)], ae_accept(D["ae"], S), {}
        if defence == "mus":
            p, _ = mus_membership(ctx, X, D["mus"]["lambda"], ctx.cfg["mus_n_attack"], rng, A._ref_median(ctx))
            M = ctx.topk(p); clf = D["mus"]["clf"]; pr = clf.predict_proba(M)
            J = pr[:, A.fam_index(clf, fam_c)] + w * A.decoy_mass_from_members(p, ctx, fam_c)
            return J, clf.classes_[pr.argmax(1)], np.ones(len(X), bool), {}
        if defence == "assuredx_gate":
            clf = D["raw"]
            V = state["smoother"].votes(X, ctx.cfg["n_attack"], rng, clf)
            ci = A.fam_index(clf, fam_c)
            J = V[:, ci] - V.max(1) + 1.0
            return J, clf.classes_[V.argmax(1)], ae_accept(D["ae"], ctx.shap(X)), {}
        return orig(ctx, defence, X, fam_c, D, state, rng)
    return evaluate


def stage12_baselines(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx)
    alerts = A.stage4_alerts(ctx)
    clean = A.jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    te = ctx.split("test"); ref = A._ref_median(ctx)
    D["ae"] = ae_detector(ctx)
    D["mus"] = mus_diagnoser(ctx)
    A.evaluate = _extra_evaluate(A.evaluate) if not getattr(A.evaluate, "_extra", False) else A.evaluate
    A.evaluate._extra = True
    lam = D["mus"]["lambda"]

    # clean evaluation of both baselines
    out = ctx.p("stage12", "clean_extra.jsonl"); done = A.jl_done(out, "alert_id")
    for _, a in alerts.iterrows():
        if a.alert_id in done: continue
        x0 = te[ctx.feats].values[a.row].astype("float64")
        S = ctx.shap(x0[None])
        rng = np.random.default_rng(seed_for(ctx, "musclean", a.alert_id))
        ts = time.time()
        p, Z = mus_membership(ctx, x0[None], lam, cfg["n_cert"], rng, ref)
        sec = time.time() - ts
        rb, ob, ib = ctx.invalid_mask(Z, x0, parts=True)
        A.jl_append(out, {"alert_id": int(a.alert_id), "family": a.family,
                          "ae_accept": bool(ae_accept(D["ae"], S)[0]),
                          "mus_diag": D["mus"]["clf"].predict(ctx.topk(p))[0],
                          "mus_overlap_raw": float((ctx.topk(p) & ctx.topk(S)).sum() / ctx.k),
                          "mus_invalid": float((rb | ob | ib).mean()), "mus_range": float(rb.mean()),
                          "mus_order": float(ob.mean()), "mus_identity": float(ib.mean()),
                          "mus_immutable": float((np.abs(Z[:, ctx.imm] - x0[ctx.imm]) > 1e-9).any(1).mean()),
                          "mus_stratum": float(np.mean([bank_stratum(ctx, z) != bank_stratum(ctx, x0) for z in Z])),
                          "mus_flip": float((ctx.score(Z) < ctx.thr).mean()), "mus_sec": sec})
    L.log("stage 12 clean evaluation of baselines done")
    ce = A.jl_read(out).set_index("alert_id")

    for defence, todo in (("fingerprint_ae", alerts),
                          ("mus", alerts.groupby("family").head(cfg["mus_alerts_per_family"]))):
        out = ctx.p("stage12", f"attack_{defence}.jsonl"); done = A.jl_done(out, "key")
        t0 = time.time(); n_new = 0
        for _, a in todo.iterrows():
            x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
            for eps in cfg["eps"]:
                key = f"{a.alert_id}_{eps}"
                if key in done: continue
                rng = np.random.default_rng(seed_for(ctx, defence, a.alert_id, eps))
                ts = time.time()
                res = A.attack_one(ctx, x0, y, c, eps, defence, D, rng)
                rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                       "defence": defence, "source_file": a.source_file, "found": res["x_adv"] is not None,
                       "evals": res["evals"]}
                if defence == "fingerprint_ae":
                    rec["eligible"] = bool(clean.loc[a.alert_id, "raw_diag"] == y and ce.loc[a.alert_id, "ae_accept"])
                    rec["success"] = res["x_hit"] is not None
                else:
                    rec["eligible"] = bool(ce.loc[a.alert_id, "mus_diag"] == y)
                    succ = False
                    for j, x in enumerate([v for v in (res["x_adv"], res["x_hit"]) if v is not None]):
                        r = np.random.default_rng(seed_for(ctx, "musval", a.alert_id, eps, j))
                        p, _ = mus_membership(ctx, x[None], lam, cfg["n_cert"], r, ref)
                        succ |= bool(D["mus"]["clf"].predict(ctx.topk(p))[0] == c)
                    rec["success"] = succ
                rec["sec"] = time.time() - ts
                A.jl_append(out, rec)
            n_new += 1
            if n_new % 20 == 0:
                L.log(f"  {defence}: {n_new}/{len(todo)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
        L.log(f"stage 12 {defence} attack done")


# ==========================================================================
# STAGE 13 - summary
# ==========================================================================
def _tmr(df, B, seed):
    E = df[df.eligible.astype(bool)].copy()
    if not len(E): return {"eligible": 0, "TMR": np.nan, "TMR_lo": np.nan, "TMR_hi": np.nan}
    E["succ"] = E.success.astype(float)
    est, lo, hi = A.cluster_boot(E, "succ", "source_file", B, seed)
    return {"eligible": len(E), "TMR": est, "TMR_lo": lo, "TMR_hi": hi}


def stage13_summary(ctx):
    cfg = ctx.cfg; B = cfg["bootstrap"]; sd = cfg["seed"]
    rd = lambda p: (lambda d: d.assign(eps=d.eps.round(4)) if len(d) else d)(A.jl_read(p))
    lines = [f"# AssureDx additional experiments ({time.strftime('%Y-%m-%d %H:%M')}, {EXTRA_VERSION})", ""]

    # decoder-aware attack
    VU = rd(ctx.p("stage11", "voronoi_unsmoothed.jsonl")); VC = rd(ctx.p("stage11", "voronoi_assuredx.jsonl"))
    SU = rd(ctx.p("stage7", "attack_unsmoothed.jsonl")); SV = rd(ctx.p("stage9", "attack_vote.jsonl"))
    rows = []
    for eps in sorted(VU.eps.unique()):
        r = {"eps": eps}
        for name, d in (("unsmoothed_random_search", SU), ("unsmoothed_decoder_aware", VU)):
            t = _tmr(d[d.eps == eps], B, sd); r[name] = t["TMR"]; r[name + "_ci"] = f"[{t['TMR_lo']:.3f}, {t['TMR_hi']:.3f}]"
        u = SU[SU.eps == eps].set_index("alert_id").success.astype(bool)
        v = VU[VU.eps == eps].set_index("alert_id")
        both = (v.success.astype(bool) | u.reindex(v.index).fillna(False))
        r["unsmoothed_strongest"] = both[v.eligible.astype(bool)].mean(); r["eligible"] = int(v.eligible.astype(bool).sum())
        rows.append(r)
    T1 = pd.DataFrame(rows); T1.to_csv(ctx.p("stage13", "voronoi_unsmoothed.csv"), index=False)
    lines += ["## Decoder-aware attack on the unsmoothed decoder (all alerts, own eligible set)", "", A.md(T1, index=False), ""]

    rows = []
    if len(VC):
        sub_ids = set(VC.alert_id)
        for eps in sorted(VC.eps.unique()):
            vc = VC[VC.eps == eps].set_index("alert_id"); el = vc.eligible.astype(bool)
            sv = SV[SV.eps == eps].set_index("alert_id").reindex(vc.index)
            vu = VU[(VU.eps == eps) & VU.alert_id.isin(sub_ids)].set_index("alert_id").reindex(vc.index)
            su = SU[(SU.eps == eps) & SU.alert_id.isin(sub_ids)].set_index("alert_id").reindex(vc.index)
            un = (vu.success.fillna(False).astype(bool) | su.success.fillna(False).astype(bool))
            cx = (vc.success.astype(bool) | sv.success.fillna(False).astype(bool))
            cert = vc.certified_at_eps.astype(bool)
            rows.append({"eps": eps, "eligible": int(el.sum()),
                         "unsmoothed_strongest": un[el].mean(),
                         "assuredx_random_search": sv.success.fillna(False).astype(bool)[el].mean(),
                         "assuredx_decoder_aware": vc.success.astype(bool)[el].mean(),
                         "assuredx_strongest": cx[el].mean(),
                         "assuredx_strongest_certified_output": (vc.success_certified_output.astype(bool)
                                                               | sv.success_certified_output.fillna(False).astype(bool))[el].mean(),
                         "provably_immune": cert[el].mean(),
                         "unsmoothed_broken_on_certified": int((un & cert & el).sum()),
                         "assuredx_broken_on_certified": int((cx & cert & el).sum()),
                         "certified_alerts": int((cert & el).sum())})
    T2 = pd.DataFrame(rows); T2.to_csv(ctx.p("stage13", "voronoi_paired.csv"), index=False)
    lines += ["## Paired comparison on the diagnosis-attack subset (strongest of both attacks)", "",
              A.md(T2, index=False), ""]

    # published baselines
    ce = A.jl_read(ctx.p("stage12", "clean_extra.jsonl"))
    clean = A.jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    if len(ce):
        import joblib
        mus = joblib.load(ctx.p("stage12", "mus.joblib"))
        ce = ce.set_index("alert_id")
        lines += [f"Autoencoder fingerprint clean acceptance: {ce.ae_accept.mean():.4f}", "",
                  f"Masking smoother: lambda = {mus['lambda']} (validation macro-F1 {mus['val_macro_f1']}); "
                  f"clean diagnostic accuracy {(ce.mus_diag == ce.family).mean():.4f} vs raw "
                  f"{(clean.loc[ce.index, 'raw_diag'] == ce.family).mean():.4f}; invalid samples {ce.mus_invalid.mean():.4f} "
                  f"(range {ce.mus_range.mean():.4f}, order {ce.mus_order.mean():.4f}, identity {ce.mus_identity.mean():.4f}); "
                  f"immutable attribute changed {ce.mus_immutable.mean():.4f}; protocol stratum changed {ce.mus_stratum.mean():.4f}; "
                  f"detector flips {ce.mus_flip.mean():.4f}; overlap with raw top-k {ce.mus_overlap_raw.mean():.4f}; "
                  f"median seconds per explanation (n = {cfg['n_cert']}) {ce.mus_sec.median():.3f}", ""]
    rows = []
    RAW = rd(ctx.p("stage7", "attack_raw.jsonl")); RND = rd(ctx.p("stage7", "attack_random.jsonl"))
    for defence in ("fingerprint_ae", "mus"):
        d = rd(ctx.p("stage12", f"attack_{defence}.jsonl"))
        if not len(d): continue
        for eps in sorted(d.eps.unique()):
            g = d[d.eps == eps]; t = _tmr(g, B, sd)
            ids = set(g.alert_id)
            rr = RAW[(RAW.eps == eps) & RAW.alert_id.isin(ids)].set_index("alert_id")
            rn = RND[(RND.eps == eps) & RND.alert_id.isin(ids)].set_index("alert_id").reindex(rr.index)
            rr = rr.assign(success=rr.success.astype(bool) | rn.success.fillna(False).astype(bool))
            tr = _tmr(rr.reset_index(), B, sd)
            rows.append({"defence": defence, "eps": eps, **t, "raw_same_alerts": tr["TMR"], "raw_eligible": tr["eligible"]})
    T3 = pd.DataFrame(rows); T3.to_csv(ctx.p("stage13", "baselines_tmr.csv"), index=False)
    lines += ["## Published baselines under adaptive attack (own eligible set; raw SHAP on the same alerts)", "",
              A.md(T3, index=False), ""]
    open(ctx.p("stage13", "extras_results.md"), "w", encoding="utf-8").write("\n".join(lines))
    print("\n".join(lines))


# ==========================================================================
# STAGE 14 - AssureDx behind the autoencoder fingerprint gate (combined pipeline)
# ==========================================================================
def _install_eval():
    if not getattr(A.evaluate, "_extra", False):
        A.evaluate = _extra_evaluate(A.evaluate); A.evaluate._extra = True


def stage14_gate(ctx):
    """Deployed pipeline: the fingerprint detector of Sharma et al. refuses suspicious alerts;
    accepted alerts receive AssureDx's certified diagnosis or an abstention. The adaptive attacker
    must stay accepted by the gate and win a decoy diagnosis; both the reference search and the
    decoder-aware attack are run, on the diagnosis-attack subset."""
    cfg = ctx.cfg
    D = A.load_defences(ctx); bank = A._ctx_bank(ctx)
    D["ae"] = ae_detector(ctx)
    _install_eval()
    alerts = A.stage4_alerts(ctx)
    cert = A.jl_read(ctx.p("stage9", "diag_cert.jsonl"))
    cert = cert[(cert.n == cfg["n_cert"]) & (cert.sigma.round(4) == round(ctx.sigma, 4))].set_index("alert_id")
    ce = A.jl_read(ctx.p("stage12", "clean_extra.jsonl")).set_index("alert_id")
    te = ctx.split("test"); clf = D["raw"]; ci = lambda f: A.fam_index(clf, f)
    out = ctx.p("stage14", "attack_gate.jsonl"); done = A.jl_done(out, "key")
    sub = alerts.groupby("family").head(cfg["vote_alerts_per_family"])
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        cl = cert.loc[a.alert_id]
        for eps in cfg["vote_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done: continue
            ts = time.time()
            sm = A.Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
            cands = []
            # (1) reference search under the gate constraint
            rng = np.random.default_rng(seed_for(ctx, "gate", a.alert_id, eps))
            res = A.attack_one(ctx, x0, y, c, eps, "assuredx_gate", D, rng, state={"smoother": sm})
            cands += [v for v in (res["x_adv"], res["x_hit"]) if v is not None]
            # (2) decoder-aware attack restricted to gate-accepted points
            nev = 0
            if ctx.app_mask(x0).sum() > 0:
                ids, _ = decoy_flows(ctx, bank, sm, x0, eps, clf, c)
                X, nev = voronoi_points(ctx, bank, sm, x0, eps, ids)
                if len(X):
                    X = X[ae_accept(D["ae"], ctx.shap(X))]
                if len(X):
                    r2 = np.random.default_rng(seed_for(ctx, "gatevor", a.alert_id, eps))
                    J = np.empty(len(X)); hit = None
                    for b in range(0, len(X), cfg["batch"]):
                        V = sm.votes(X[b:b + cfg["batch"]], cfg["n_attack"], r2, clf)
                        J[b:b + len(V)] = V[:, ci(c)] - V.max(1) + 1.0
                        if hit is None and (V.argmax(1) == ci(c)).any():
                            hit = b + int(np.argmax(V.argmax(1) == ci(c)))
                    cands += [X[int(np.argmax(J))]] + ([X[hit]] if hit is not None else [])
            succ = succ_cert = False
            for j, x in enumerate(cands):
                rv = A.diag_certify(ctx, sm, x, clf, 100, cfg["n_cert"], cfg["alpha"],
                                    seed_for(ctx, "gateval", a.alert_id, eps, j))
                if rv["class"] == c:
                    succ = True
                    if rv["p_lower"] > 0.5: succ_cert = True
            A.jl_append(out, {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                              "source_file": a.source_file,
                              "eligible": bool(cl["correct"]) and bool(ce.loc[a.alert_id, "ae_accept"]),
                              "clean_certified": bool(cl["p_lower"] > 0.5),
                              "clean_radius": float(cl["radius"]), "certified_at_eps": float(cl["radius"]) >= eps,
                              "success": succ, "success_certified_output": succ_cert,
                              "evals": res["evals"] + nev, "sec": time.time() - ts})
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  gate: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 14 combined pipeline attack done")




STAGES = {11: stage11_voronoi, 12: stage12_baselines, 13: stage13_summary, 14: stage14_gate}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", type=int, nargs="+")
    ap.add_argument("--base", required=True, help="finished stage 0-3 results folder")
    ap.add_argument("--out", required=True, help="finished assuredx_attack.py results folder (stages 4-10)")
    ap.add_argument("--quick", action="store_true", help="smoke test on a few alerts")
    a = ap.parse_args()
    ctx = A.Ctx(a.base, a.out)
    if not os.path.exists(ctx.p("stage9", "diag_cert.jsonl")):
        sys.exit("assuredx_extra.py needs a finished assuredx_attack.py run (stages 4-10) in --out; run those first.")
    setup(ctx)
    if a.quick:
        ctx.cfg.update(vote_alerts_per_family=1, mus_alerts_per_family=1, eps=[0.1, 1.0], vote_eps=[0.1, 1.0],
                       n_train_expl=16, diag_train_per_family=40, diag_val_per_family=20, bootstrap=100)
        keep = A.stage4_alerts(ctx).groupby("family").head(2)
        A.stage4_alerts = (lambda k: (lambda c: k))(keep.reset_index(drop=True))
    L.log(f"assuredx_extra {EXTRA_VERSION}: base {a.base}, run {a.out}")
    for s in a.stage:
        STAGES[s](ctx)
