"""
AssureDx extended experiments (stages 15-20). Reads a finished run of assuredx_attack.py
(stages 4-10) and assuredx_extra.py (stages 11-14) and writes into stage15 ... stage19 only.

 15  attack convergence      smoothed-diagnosis attack at search budgets 1,000 / 4,000 /
                             16,000 candidates (128 attacker samples) and 4,000 candidates
                             with 512 attacker samples, combined with the decoder-aware
                             attack; records the deployed outcome of every attacked alert
                             (certified decoy, certified correct, certified other, abstain)
 16  abstention attack       attacker maximises abstention (minimises the vote margin of
                             the smoothed diagnosis) on clean-certified correct alerts:
                             denial of diagnostic service
 17  matched coverage        Sharma et al. fingerprint with its threshold set so that its
                             clean acceptance equals AssureDx's clean certified share,
                             attacked with the reference search
 18  projected smoothing     constraint-aware Gaussian smoothing: feature-space noise
                             repaired by projection onto the constraints (input-dependent
                             repair, Proposition 2), smoothed diagnosis and nominal
                             Clopper-Pearson certificate; attacked like AssureDx
 19  matched decoder         decoder bank restricted to training flows with the alert's
                             exact immutable configuration (fallback to the protocol stratum
                             when fewer than min_bank distinct flows); clean certificates,
                             decoded-sample audit and the strongest attack
 20  refusal and gate        adaptive refusal attack on the fingerprint gate (published 1% and
                             matched thresholds); AssureDx behind the gate at the matched threshold

All stages resume: per-alert results are appended as JSON lines and skipped on re-run.
"""
import os, sys, json, time, math
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import assuredx_lib as L
import assuredx_attack as A
import assuredx_extra as X

EXT_VERSION = "2026-11-05"

EXT_DEFAULTS = {
    "conv_alerts_per_family": 8,          # stage 15 subset (taken from the diagnosis-attack subset)
    "conv_eps": [0.1, 0.3],
    "conv_configs": [[1000, 128], [4000, 128], [16000, 128], [4000, 512]],
    "abst_eps": [0.03, 0.1, 0.3, 1.0],
    "proj_alerts_per_family": 15,         # stage 18 subset
    "proj_n_attack": 64,
    "proj_val_per_family": 60,
    "match_min_bank": 50,                 # stage 19 fallback threshold
    "audit_samples": 1000,
}


def setup(ctx):
    for k, v in EXT_DEFAULTS.items():
        ctx.cfg.setdefault(k, v)
    L._atomic_json(os.path.join(ctx.out, "attack_config.json"), ctx.cfg)


def clean_cert(ctx):
    if not hasattr(ctx, "sigma"):
        ctx.sigma = json.load(open(ctx.p("stage5", "summary.json")))["sigma_selected"]
    c = A.jl_read(ctx.p("stage9", "diag_cert.jsonl"))
    return c[(c.n == ctx.cfg.get("n_cert_ref", ctx.cfg["n_cert"])) & (c.sigma.round(4) == round(ctx.sigma, 4))].set_index("alert_id")


def vote_subset(ctx, per_family):
    return A.stage4_alerts(ctx).groupby("family").head(ctx.cfg["vote_alerts_per_family"]) \
                               .groupby("family").head(per_family)


def outcome(rv, y, c):
    """Deployed output of the certified-only pipeline for one certification run."""
    if rv["p_lower"] <= 0.5: return "abstain"
    if rv["class"] == c: return "decoy"
    if rv["class"] == y: return "correct"
    return "other"


def worst_outcome(outs):
    """Adversary's choice among its candidate points: certified decoy, else abstention,
    else a certified wrong family, else the certified correct family."""
    for o in ("decoy", "abstain", "other", "correct"):
        if o in outs: return o
    return "correct"


def vote_search(ctx, sm, x0, y, c, eps, D, rng, budget, n_attack, defence="assuredx_vote"):
    saved = (ctx.cfg["budget"], ctx.cfg["n_attack"])
    ctx.cfg["budget"], ctx.cfg["n_attack"] = budget, n_attack
    try:
        res = A.attack_one(ctx, x0, y, c, eps, defence, D, rng, state={"smoother": sm})
    finally:
        ctx.cfg["budget"], ctx.cfg["n_attack"] = saved
    return [v for v in (res["x_adv"], res["x_hit"]) if v is not None], res["evals"]


def voronoi_cands(ctx, bank, sm, x0, c, eps, clf, seed):
    if ctx.app_mask(x0).sum() == 0: return [], 0
    ids, _ = X.decoy_flows(ctx, bank, sm, x0, eps, clf, c)
    P, nev = X.voronoi_points(ctx, bank, sm, x0, eps, ids)
    if not len(P): return [], nev
    rng = np.random.default_rng(seed); ci = A.fam_index(clf, c)
    J = np.empty(len(P)); hit = None
    for b in range(0, len(P), ctx.cfg["batch"]):
        V = sm.votes(P[b:b + ctx.cfg["batch"]], ctx.cfg["n_attack"], rng, clf)
        J[b:b + len(V)] = V[:, ci] - V.max(1) + 1.0
        if hit is None and (V.argmax(1) == ci).any():
            hit = b + int(np.argmax(V.argmax(1) == ci))
    return [P[int(np.argmax(J))]] + ([P[hit]] if hit is not None else []), nev


def judge(ctx, sm, cands, y, c, clf, tag, certify=None):
    """Certification run at every candidate: deployed outcome (certified-only policy) and
    whether the plurality is the decoy (always-output policy)."""
    outs, plur = [], []
    for j, x in enumerate(cands):
        rv = (certify(x, X.seed_for(ctx, tag, j)) if certify else
              A.diag_certify(ctx, sm, x, clf, 100, ctx.cfg["n_cert"], ctx.cfg["alpha"], X.seed_for(ctx, tag, j)))
        outs.append(outcome(rv, y, c)); plur.append(c is not None and rv["class"] == c)
    return outs, plur


# ==========================================================================
# STAGE 15 - attack convergence and adversarial outcomes
# ==========================================================================
def stage15_convergence(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); bank = A._ctx_bank(ctx); clf = D["raw"]
    cert = clean_cert(ctx); te = ctx.split("test")
    sub = vote_subset(ctx, cfg["conv_alerts_per_family"])
    out = ctx.p("stage15", "convergence.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        cl = cert.loc[a.alert_id]
        for eps in cfg["conv_eps"]:
            sm = A.Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
            vkey = f"{a.alert_id}_{eps}_voronoi"
            vor_outs = None
            for budget, na in cfg["conv_configs"]:
                key = f"{a.alert_id}_{eps}_{budget}_{na}"
                if key in done or not bool(cl["correct"]): continue
                ts = time.time()
                rng = np.random.default_rng(X.seed_for(ctx, "conv", a.alert_id, eps, budget, na))
                cands, ev = vote_search(ctx, sm, x0, y, c, eps, D, rng, budget, na)
                s_outs, s_pl = judge(ctx, sm, cands, y, c, clf, f"convval_{a.alert_id}_{eps}_{budget}_{na}")
                if vor_outs is None:
                    vc, _ = voronoi_cands(ctx, bank, sm, x0, c, eps, clf, X.seed_for(ctx, "convvor", a.alert_id, eps))
                    vor_outs, vor_pl = judge(ctx, sm, vc, y, c, clf, f"convvorval_{a.alert_id}_{eps}")
                A.jl_append(out, {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                                  "budget": budget, "n_attack": na, "source_file": a.source_file,
                                  "eligible": bool(cl["correct"]), "clean_certified": bool(cl["p_lower"] > 0.5),
                                  "clean_radius": float(cl["radius"]),
                                  "search_outcome": worst_outcome(s_outs) if s_outs else "correct",
                                  "voronoi_outcome": worst_outcome(vor_outs) if vor_outs else "correct",
                                  "combined_outcome": worst_outcome(s_outs + vor_outs) if (s_outs + vor_outs) else "correct",
                                  "search_success_always": bool(any(s_pl)),
                                  "combined_success_always": bool(any(s_pl) or any(vor_pl)),
                                  "evals": ev, "sec": time.time() - ts})
        n_new += 1
        L.log(f"  convergence: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.0f}s per alert)")
    L.log("stage 15 done")


# ==========================================================================
# STAGE 16 - abstention (denial-of-diagnosis) attack
# ==========================================================================
def _install_eval():
    X._install_eval()
    if getattr(A.evaluate, "_extended", False): return
    orig = A.evaluate
    def evaluate(ctx, defence, Xc, fam_c, D, state, rng):
        if defence == "assuredx_abstain":
            V = state["smoother"].votes(Xc, ctx.cfg["n_attack"], rng, D["raw"])
            top2 = np.sort(V, 1)[:, -2:]
            J = 1.0 - (top2[:, 1] - top2[:, 0])          # 1 when the vote is tied
            return J, D["raw"].classes_[V.argmax(1)], np.ones(len(Xc), bool), {}
        if defence == "proj_vote":
            V = proj_votes(ctx, Xc, ctx.cfg["proj_n_attack"], rng, D["raw"])
            ci = A.fam_index(D["raw"], fam_c)
            J = V[:, ci] - V.max(1) + 1.0
            return J, D["raw"].classes_[V.argmax(1)], np.ones(len(Xc), bool), {}
        if defence == "fingerprint_matched":
            S = ctx.shap(Xc); M = ctx.topk(S)
            clf = D["raw"]; pr = clf.predict_proba(M)
            J = pr[:, A.fam_index(clf, fam_c)] + ctx.cfg["mass_weight"] * A.raw_mass(S, ctx, fam_c)
            return J, clf.classes_[pr.argmax(1)], X.ae_accept(D["ae_matched"], S), {}
        return orig(ctx, defence, Xc, fam_c, D, state, rng)
    evaluate._extra = True; evaluate._extended = True
    A.evaluate = evaluate


def stage16_abstention(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); bank = A._ctx_bank(ctx); clf = D["raw"]; _install_eval()
    cert = clean_cert(ctx); te = ctx.split("test")
    sub = vote_subset(ctx, cfg["vote_alerts_per_family"])
    out = ctx.p("stage16", "abstention.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        cl = cert.loc[a.alert_id]
        x0 = te[ctx.feats].values[a.row].astype("float64"); y = a.family
        for eps in cfg["abst_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done: continue
            ts = time.time()
            rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "eps": eps, "source_file": a.source_file,
                   "eligible": bool(cl["correct"]) and bool(cl["p_lower"] > 0.5), "clean_radius": float(cl["radius"])}
            if not rec["eligible"] or ctx.app_mask(x0).sum() == 0:
                rec.update(outcome="correct", evals=0, no_attack=True)
            else:
                sm = A.Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
                rng = np.random.default_rng(X.seed_for(ctx, "abst", a.alert_id, eps))
                cands, ev = vote_search(ctx, sm, x0, y, None, eps, D, rng, cfg["budget"], cfg["n_attack"], "assuredx_abstain")
                outs, _ = judge(ctx, sm, cands, y, None, clf, f"abstval_{a.alert_id}_{eps}")
                rec.update(outcome=worst_outcome(outs) if outs else "correct", evals=ev)
            rec["sec"] = time.time() - ts
            A.jl_append(out, rec)
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  abstention attack: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 16 done")


# ==========================================================================
# STAGE 17 - fingerprint at matched coverage
# ==========================================================================
def stage17_matched_fingerprint(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); _install_eval()
    cert = clean_cert(ctx); te = ctx.split("test")
    alerts = A.stage4_alerts(ctx)
    clean = A.jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    det = X.ae_detector(ctx)
    target = float((cert.reindex(alerts.alert_id).p_lower > 0.5).mean())      # AssureDx clean certified share
    Xva, _ = X._val_alerts(ctx)
    Z = det["scaler"].transform(ctx.shap(Xva))
    err = ((det["ae"].predict(Z) - Z) ** 2).mean(1)
    thr = float(np.quantile(err, target))
    D["ae_matched"] = dict(det, thr=thr)
    Xt = te[ctx.feats].values[alerts.row.values].astype("float64")
    acc = X.ae_accept(D["ae_matched"], ctx.shap(Xt))
    info = {"assuredx_clean_certified": target, "threshold": thr, "threshold_1pct": det["thr"],
            "fingerprint_clean_acceptance_test": float(acc.mean())}
    L._atomic_json(ctx.p("stage17", "matched.json"), info)
    L.log(f"  matched fingerprint: {info}")
    acc = dict(zip(alerts.alert_id, acc))
    out = ctx.p("stage17", "attack_fingerprint_matched.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in alerts.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        for eps in cfg["eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done: continue
            ts = time.time()
            elig = bool(clean.loc[a.alert_id, "raw_diag"] == y and acc[a.alert_id])
            rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                   "source_file": a.source_file, "eligible": elig, "clean_accepted": bool(acc[a.alert_id])}
            if elig:
                rng = np.random.default_rng(X.seed_for(ctx, "fpm", a.alert_id, eps))
                res = A.attack_one(ctx, x0, y, c, eps, "fingerprint_matched", D, rng)
                rec.update(success=res["x_hit"] is not None, evals=res["evals"])
            else:
                rec.update(success=False, evals=0)
            rec["sec"] = time.time() - ts
            A.jl_append(out, rec)
        n_new += 1
        if n_new % 100 == 0:
            L.log(f"  matched fingerprint: {n_new}/{len(alerts)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 17 done")


# ==========================================================================
# STAGE 18 - projected Gaussian smoothing (constraint-aware, input-dependent repair)
# ==========================================================================
def proj_samples(ctx, Xc, n, rng):
    """Gaussian noise on the scaled mutable features, then projection of every sample onto
    the constraints of its own centre (ranges, immutables, order, identities)."""
    m = len(ctx.mut); R = len(Xc); out = []
    for r in range(R):
        x0 = Xc[r]
        Z = (x0[ctx.mut] * ctx.W)[None] + ctx.proj_sigma * rng.standard_normal((n, m))
        Z = Z * ctx.app_mask(x0) + (x0[ctx.mut] * ctx.W)[None] * (1 - ctx.app_mask(x0))
        S = np.repeat(x0[None], n, axis=0); S[:, ctx.mut] = Z / ctx.W
        lo, hi = ctx.bounds_for(x0)
        out.append(ctx.project(S, x0, lo, hi))
    return np.vstack(out)


def proj_votes(ctx, Xc, n, rng, clf):
    S = proj_samples(ctx, Xc, n, rng)
    lab = np.searchsorted(clf.classes_, clf.predict(ctx.topk(ctx.shap(S)))).reshape(len(Xc), n)
    K = len(clf.classes_)
    return np.stack([np.bincount(r, minlength=K) for r in lab]) / n


def proj_certify(ctx, x, clf, n0, n, alpha, seed):
    from scipy.stats import norm
    v0 = proj_votes(ctx, x[None], n0, np.random.default_rng(seed), clf)[0]; cA = int(v0.argmax())
    v = proj_votes(ctx, x[None], n, np.random.default_rng(seed + 1), clf)[0]
    pl = A.cp_lower(int(round(v[cA] * n)), n, alpha)
    R = ctx.proj_sigma * norm.ppf(pl) if pl > 0.5 else 0.0
    return {"class": clf.classes_[cA], "p_lower": pl, "radius": float(np.floor(max(R, 0) * 1e6) / 1e6)}


def proj_select_sigma(ctx, clf):
    """Noise level of the projected smoother chosen on validation alerts, as for AssureDx:
    highest accuracy of the smoothed diagnosis."""
    path = ctx.p("stage18", "proj_sigma.json")
    if os.path.exists(path):
        ctx.proj_sigma = json.load(open(path))["sigma"]; return
    Xva, yva = X._val_alerts(ctx)
    keep = pd.Series(yva).groupby(yva).head(ctx.cfg["proj_val_per_family"]).index.values
    Xva, yva = Xva[keep], yva[keep]
    acc = {}
    for sg in ctx.cfg["sigmas"]:
        ctx.proj_sigma = sg
        rng = np.random.default_rng(X.seed_for(ctx, "projsel", sg))
        V = np.vstack([proj_votes(ctx, Xva[i:i + 20], 64, rng, clf) for i in range(0, len(Xva), 20)])
        acc[sg] = float((clf.classes_[V.argmax(1)] == yva).mean())
        L.log(f"  projected smoothing sigma={sg}: validation accuracy {acc[sg]:.4f}")
    ctx.proj_sigma = max(acc, key=acc.get)
    L._atomic_json(path, {"sigma": ctx.proj_sigma, "val_accuracy": acc})


def stage18_projected(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); clf = D["raw"]; _install_eval(); bank = A._ctx_bank(ctx)
    proj_select_sigma(ctx, clf)
    te = ctx.split("test"); alerts = A.stage4_alerts(ctx)
    tr = ctx.split("train")
    H = lambda M: pd.util.hash_pandas_object(pd.DataFrame(np.round(M, 5)), index=False).values
    trh = set(H(tr[ctx.feats].values.astype("float64")))
    # clean evaluation on every alert
    out = ctx.p("stage18", "clean_proj.jsonl"); done = A.jl_done(out, "alert_id")
    t0 = time.time(); n_new = 0
    for _, a in alerts.iterrows():
        if a.alert_id in done: continue
        x0 = te[ctx.feats].values[a.row].astype("float64")
        ts = time.time()
        r = proj_certify(ctx, x0, clf, 100, cfg["n_cert"], cfg["alpha"], X.seed_for(ctx, "projclean", a.alert_id))
        S = proj_samples(ctx, x0[None], 200, np.random.default_rng(X.seed_for(ctx, "projaudit", a.alert_id)))
        A.jl_append(out, {"alert_id": int(a.alert_id), "family": a.family, "class": r["class"],
                          "correct": r["class"] == a.family, "p_lower": r["p_lower"], "radius": r["radius"],
                          "invalid": float(ctx.invalid_mask(S, x0).mean()),
                          "observed": float(np.isin(H(S), list(trh)).mean()),
                          "detector_flip": float((ctx.score(S) < ctx.thr).mean()), "sec": time.time() - ts})
        n_new += 1
        if n_new % 100 == 0:
            L.log(f"  projected smoothing, clean: {n_new}/{len(alerts)} ({(time.time()-t0)/n_new:.2f}s each)")
    cp = A.jl_read(out).set_index("alert_id")
    # attack on a subset
    sub = vote_subset(ctx, cfg["proj_alerts_per_family"])
    out = ctx.p("stage18", "attack_proj.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        cl = cp.loc[a.alert_id]
        for eps in cfg["vote_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done or not bool(cl["correct"]): continue
            ts = time.time()
            rng = np.random.default_rng(X.seed_for(ctx, "proj", a.alert_id, eps))
            res = A.attack_one(ctx, x0, y, c, eps, "proj_vote", D, rng)
            outs, pl = judge(ctx, None, [v for v in (res["x_adv"], res["x_hit"]) if v is not None], y, c, clf,
                             f"projval_{a.alert_id}_{eps}",
                             certify=lambda x, sd: proj_certify(ctx, x, clf, 100, cfg["n_cert"], cfg["alpha"], sd))
            A.jl_append(out, {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                              "source_file": a.source_file, "eligible": bool(cl["correct"]),
                              "nominal_radius": float(cl["radius"]),
                              "nominally_certified_at_eps": float(cl["radius"]) > eps,
                              "outcome": worst_outcome(outs) if outs else "correct",
                              "success": bool(any(pl)), "success_certified_output": "decoy" in outs,
                              "evals": res["evals"], "sec": time.time() - ts})
        n_new += 1
        if n_new % 10 == 0:
            L.log(f"  projected smoothing, attack: {n_new}/{len(sub)} ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 18 done")


# ==========================================================================
# STAGE 19 - configuration-matched decoder
# ==========================================================================
class MatchedBank(A.Bank):
    """Bank keyed by the alert's exact immutable configuration when the training data hold at
    least min_bank distinct mutable vectors for it, otherwise by its protocol stratum. The key
    depends only on immutable attributes, so the decoder is the same map for every input that
    the certificates compare."""
    def __init__(self, ctx, base_bank, train_df, min_bank):
        self.ctx = ctx; self.base = base_bank; self.min_bank = min_bank
        self.mutvals = dict(base_bank.mutvals); self.nn = dict(base_bank.nn)
        Xtr = train_df[ctx.feats].values.astype("float64")
        self.trk = self._keys(Xtr); self.Xtr = Xtr
        self.sizes = dict(base_bank.sizes)

    def _keys(self, Xm):
        return pd.util.hash_pandas_object(pd.DataFrame(np.round(Xm[:, self.ctx.imm], 6)), index=False).values

    def stratum(self, x0):
        from sklearn.neighbors import NearestNeighbors
        k = "cfg_" + str(self._keys(x0[None])[0])
        if k not in self.mutvals:
            M = np.unique(self.Xtr[self.trk == int(k[4:])][:, self.ctx.mut], axis=0)
            if len(M) >= self.min_bank:
                self.mutvals[k] = M; self.nn[k] = NearestNeighbors(n_neighbors=1).fit(M * self.ctx.W)
                self.sizes[k] = len(M)
            else:
                self.mutvals[k] = None
        return k if self.mutvals[k] is not None else self.base.stratum(x0)


def stage19_matched(ctx, min_bank=None, tag="matched"):
    cfg = ctx.cfg; min_bank = cfg["match_min_bank"] if min_bank is None else min_bank
    D = A.load_defences(ctx); clf = D["raw"]; base = A._ctx_bank(ctx)
    tr = ctx.split("train"); te = ctx.split("test"); alerts = A.stage4_alerts(ctx)
    bank = MatchedBank(ctx, base, tr, min_bank)
    H = lambda M: pd.util.hash_pandas_object(pd.DataFrame(np.round(M, 5)), index=False).values
    trh = set(H(tr[ctx.feats].values.astype("float64")))
    out = ctx.p("stage19", f"clean_{tag}.jsonl"); done = A.jl_done(out, "alert_id")
    t0 = time.time(); n_new = 0
    for _, a in alerts.iterrows():
        if a.alert_id in done: continue
        x0 = te[ctx.feats].values[a.row].astype("float64")
        ts = time.time()
        sm = A.Smoother(ctx, bank, x0, ctx.sigma)
        r = A.diag_certify(ctx, sm, x0, clf, 100, cfg["n_cert"], cfg["alpha"], X.seed_for(ctx, tag, a.alert_id))
        rng = np.random.default_rng(X.seed_for(ctx, tag + "audit", a.alert_id))
        s = sm.s; m = len(ctx.mut)
        Z = (x0[ctx.mut] * ctx.W)[None] + ctx.sigma * rng.standard_normal((cfg["audit_samples"], m))
        idx = bank.query(s, Z); Xd = bank.decode(s, idx, x0)
        A.jl_append(out, {"alert_id": int(a.alert_id), "family": a.family, "matched": s.startswith("cfg_"),
                          "bank_size": int(len(bank.mutvals[s])), "class": r["class"], "correct": r["class"] == a.family,
                          "p_lower": r["p_lower"], "radius": r["radius"],
                          "observed": float(np.isin(H(Xd), list(trh)).mean()),
                          "invalid": float(ctx.invalid_mask(Xd, x0).mean()),
                          "distinct": int(len(np.unique(idx))), "sec": time.time() - ts})
        n_new += 1
        if n_new % 100 == 0:
            L.log(f"  {tag} decoder, clean: {n_new}/{len(alerts)} ({(time.time()-t0)/n_new:.2f}s each)")
    if tag != "matched": return
    cm = A.jl_read(out).set_index("alert_id")
    sub = vote_subset(ctx, cfg["vote_alerts_per_family"])
    out = ctx.p("stage19", "attack_matched.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        cl = cm.loc[a.alert_id]
        for eps in cfg["vote_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in done or not bool(cl["correct"]): continue
            ts = time.time()
            sm = A.Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
            rng = np.random.default_rng(X.seed_for(ctx, "matchatk", a.alert_id, eps))
            cands, ev = vote_search(ctx, sm, x0, y, c, eps, D, rng, cfg["budget"], cfg["n_attack"])
            vc, nv = voronoi_cands(ctx, bank, sm, x0, c, eps, clf, X.seed_for(ctx, "matchvor", a.alert_id, eps))
            outs, pl = judge(ctx, sm, cands + vc, y, c, clf, f"matchval_{a.alert_id}_{eps}")
            A.jl_append(out, {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                              "source_file": a.source_file, "eligible": bool(cl["correct"]),
                              "matched": bool(cl["matched"]), "clean_radius": float(cl["radius"]),
                              "outcome": worst_outcome(outs) if outs else "correct",
                              "success": bool(any(pl)), "success_certified_output": "decoy" in outs,
                              "evals": ev + nv, "sec": time.time() - ts})
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  matched decoder, attack: {n_new}/{len(sub)} ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 19 done")


def stage19_all(ctx):
    stage19_matched(ctx)
    stage19_matched(ctx, min_bank=1, tag="exact")      # no fallback: exact configuration only (clean only)


# ==========================================================================
# STAGE 20 - refusal attack on the fingerprint gate; gated pipeline at matched coverage
# ==========================================================================
def refuse_search(ctx, x0, eps, det, rng, budget):
    """Adaptive refusal attack: hill-climbs the autoencoder reconstruction error of the SHAP
    fingerprint inside the d_W ball (detection preserved) and stops at the first rejection."""
    cfg = ctx.cfg; m = len(ctx.mut); lo, hi = ctx.bounds_for(x0)
    app = ctx.app_mask(x0).astype(float)
    if app.sum() == 0: return False, 0
    def err(Xc):
        Z = det["scaler"].transform(ctx.shap(Xc)); return ((det["ae"].predict(Z) - Z) ** 2).mean(1)
    def ball(U):
        n = np.linalg.norm(U, axis=1, keepdims=True); return U * np.minimum(1.0, eps / np.maximum(n, 1e-12))
    u_cur = np.zeros(m); e_cur = -np.inf; evals = 0
    while evals < budget:
        B = cfg["batch"]; local = rng.random(B) < cfg["p_local"]
        U = np.empty((B, m))
        U[local] = u_cur + rng.standard_normal((local.sum(), m)) * app * cfg["step_frac"] * eps / math.sqrt(app.sum())
        nl = (~local).sum()
        if nl:
            dd = rng.standard_normal((nl, m)) * app; dd /= np.linalg.norm(dd, axis=1, keepdims=True)
            U[~local] = dd * eps * rng.random((nl, 1)) ** (1 / app.sum())
        U = ball(U)
        Xc = np.repeat(x0[None], B, axis=0); Xc[:, ctx.mut] = x0[ctx.mut] + U / ctx.W
        Xc = ctx.project(Xc, x0, lo, hi); evals += B
        ok = (ctx.dW(Xc, x0) <= eps * (1 + 1e-9)) & (ctx.score(Xc) >= ctx.thr)
        if not ok.any(): continue
        e = err(Xc[ok])
        if (e >= det["thr"]).any(): return True, evals
        j = int(np.argmax(e))
        if e[j] > e_cur: e_cur = e[j]; u_cur = (Xc[ok][j, ctx.mut] - x0[ctx.mut]) * ctx.W
    return False, evals


def stage20_refusal_and_gate(ctx):
    cfg = ctx.cfg
    D = A.load_defences(ctx); _install_eval(); te = ctx.split("test")
    det = X.ae_detector(ctx)
    info = json.load(open(ctx.p("stage17", "matched.json")))
    dets = {"published": det, "matched": dict(det, thr=info["threshold"])}
    sub = vote_subset(ctx, cfg["vote_alerts_per_family"])
    out = ctx.p("stage20", "refusal.jsonl"); done = A.jl_done(out, "key")
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64")
        S0 = ctx.shap(x0[None])
        for tag, dt in dets.items():
            acc0 = bool(X.ae_accept(dt, S0)[0])
            for eps in cfg["vote_eps"]:
                key = f"{a.alert_id}_{tag}_{eps}"
                if key in done: continue
                ts = time.time()
                if acc0:
                    rng = np.random.default_rng(X.seed_for(ctx, "refuse", tag, a.alert_id, eps))
                    ref, ev = refuse_search(ctx, x0, eps, dt, rng, cfg["budget"])
                else:
                    ref, ev = True, 0
                A.jl_append(out, {"key": key, "alert_id": int(a.alert_id), "family": a.family, "threshold": tag,
                                  "eps": eps, "source_file": a.source_file, "clean_accepted": acc0,
                                  "refused": bool(ref), "evals": ev, "sec": time.time() - ts})
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  refusal attack: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.1f}s each)")
    L.log("stage 20 refusal attack done")
    # gated pipeline (fingerprint gate + AssureDx) with the matched threshold: stage 14 run into stage20
    orig_p, orig_det = ctx.p, X.ae_detector
    def p(*parts):
        if parts == ("stage14", "attack_gate.jsonl"): return orig_p("stage20", "attack_gate_matched.jsonl")
        return orig_p(*parts)
    ctx.p = p; X.ae_detector = lambda c: dets["matched"]
    n_saved = cfg["n_cert"]; cfg["n_cert"] = cfg.get("n_cert_ref", n_saved)
    try:
        X.stage14_gate(ctx)
    finally:
        ctx.p, X.ae_detector = orig_p, orig_det; cfg["n_cert"] = n_saved
    L.log("stage 20 done")


STAGES = {15: stage15_convergence, 16: stage16_abstention, 17: stage17_matched_fingerprint,
          18: stage18_projected, 19: stage19_all, 20: stage20_refusal_and_gate}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", type=int, nargs="+")
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--pilot", type=int, default=0, help="full settings on the first N alerts per family (timing)")
    a = ap.parse_args()
    ctx = A.Ctx(a.base, a.out)
    for need in (("stage9", "diag_cert.jsonl"), ("stage12", "fingerprint_ae.joblib")):
        if not os.path.exists(ctx.p(*need)):
            sys.exit(f"assuredx_extended.py needs finished stages 4-14 in --out (missing {os.path.join(*need)}).")
    X.setup(ctx); setup(ctx)
    if a.quick or a.pilot:
        q = os.path.join(a.out, "_quick" if a.quick else "_pilot"); ctx.out = q
        for d in ("stage5", "stage6", "stage9", "stage12"):
            os.makedirs(os.path.join(q, d), exist_ok=True)
            for f in os.listdir(os.path.join(a.out, d)):
                src = os.path.join(a.out, d, f)
                if os.path.isfile(src) and not os.path.exists(os.path.join(q, d, f)):
                    import shutil; shutil.copy(src, os.path.join(q, d, f))
        ctx.cfg["n_cert_ref"] = ctx.cfg["n_cert"]
    if a.pilot:
        keep = A.stage4_alerts(ctx).groupby("family").head(ctx.cfg["vote_alerts_per_family"])
        keep = keep[keep.alert_id.isin(clean_cert(ctx).query("correct").index)].groupby("family").head(a.pilot)
        A.stage4_alerts = (lambda k: (lambda c: k))(keep.reset_index(drop=True))
    if a.quick:
        ctx.cfg.update(conv_alerts_per_family=1, vote_alerts_per_family=1, proj_alerts_per_family=1,
                       proj_val_per_family=5, conv_eps=[0.3], conv_configs=[[200, 32], [400, 32]], abst_eps=[0.3], vote_eps=[0.3],
                       eps=[0.3], budget=200, n_cert=200, audit_samples=100)
        keep = A.stage4_alerts(ctx).groupby("family").head(1)
        A.stage4_alerts = (lambda k: (lambda c: k))(keep.reset_index(drop=True))
    L.log(f"assuredx_extended {EXT_VERSION}: base {a.base}, run {a.out}")
    for s in a.stage:
        t = time.time(); STAGES[s](ctx); L.log(f"stage {s} finished in {(time.time()-t)/60:.1f} min")
