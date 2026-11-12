"""
AssureDx experiments - stages 4-8: targeted explanation manipulation, defences,
certification and summary. Reads a finished stage 0-3 run (assuredx_lib.py) and writes
everything to its own results folder, so the stage 0-3 run is never modified.

  4  alerts    sample detected test alerts per family, assign decoy families
  5  defences  build the AssureDx bank decoder, choose sigma on validation, train the
               frozen diagnosers of every defence, train the fingerprint detector
  6  clean     clean explanations of every defence, AssureDx certificates (radius,
               coverage, fidelity), naive feature-space smoothing ablation
  7  attack    matched-budget targeted attacks on raw SHAP, consensus, fingerprinting,
               unsmoothed decoder and AssureDx (adaptive), for every epsilon
  8  summary   TMR with capture-level bootstrap intervals, coverage tables, results.md

All stages resume: per-alert results are appended as JSON lines and skipped on re-run.
"""
import os, sys, json, time, math, zlib
import numpy as np
import pandas as pd
from scipy.stats import norm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import assuredx_lib as L

ATTACK_VERSION = "2026-10-23b"

DEFAULTS = {
    "k": 10,
    "alerts_per_family": 120,          # stage-4 sample per family (all for smaller families)
    "adaptive_alerts_per_family": 50,  # subset attacked under AssureDx (most expensive)
    "eps": [0.01, 0.03, 0.1, 0.3, 1.0],
    "budget": 1000, "restarts": 5, "batch": 20, "p_local": 0.8, "step_frac": 0.3,
    "sigmas": [0.03, 0.1, 0.3],
    "n_train_expl": 256,               # smoothing samples per alert when training diagnosers
    "n_cert": 1000,                    # defender samples per certification run
    "n_sweep": [100, 1000, 10000],     # sampling budgets for the n-sweep (subset of alerts)
    "n_sweep_alerts": 140,
    "n_attack": 128,                   # attacker's smoothing samples per candidate
    "alpha": 0.001,
    "bank_per_stratum": 50_000,
    "diag_train_per_family": 600,      # training alerts per family for defence diagnosers
    "diag_val_per_family": 200,        # validation alerts per family (sigma selection)
    "fp_train_attacks": 300, "fp_attack_eps": 0.3, "fp_frr": 0.01,
    "naive_alerts_per_family": 60, "naive_n": 256,
    "mass_weight": 0.1,                # tie-break weight of decoy mass in the attack objective
    "bootstrap": 2000,
    "vote_alerts_per_family": 25, "vote_eps": [0.03, 0.1, 0.3, 1.0],
    "seed": 7,
}


# ==========================================================================
# context: everything the stages share
# ==========================================================================
class Ctx:
    def __init__(self, base_dir, out_dir, data_dir=None, **over):
        self.base, self.out = base_dir, out_dir
        os.makedirs(out_dir, exist_ok=True)
        cp = os.path.join(out_dir, "attack_config.json")
        cfg = dict(DEFAULTS); cfg.update({k: v for k, v in over.items() if v is not None})
        if os.path.exists(cp):
            saved = json.load(open(cp))
            for k, v in cfg.items():
                saved.setdefault(k, v)
            cfg = saved
        cfg["base_dir"] = base_dir
        L._atomic_json(cp, cfg)
        self.cfg = cfg
        bcfg = json.load(open(os.path.join(base_dir, "config.json")))
        bcfg["out_dir"] = base_dir
        self.bcfg = bcfg
        self.tax = json.load(open(os.path.join(base_dir, "stage2", "taxonomy.json")))
        self.feats = self.tax["features"]; self.d = len(self.feats)
        self.ix = {f: i for i, f in enumerate(self.feats)}
        self.mut = np.array([self.ix[f] for f in self.tax["mutable"]])
        self.imm = np.array([self.ix[f] for f in self.tax["immutable"]])
        self.ident = [f for f, v in self.tax.get("identities", {}).items() if v["used"] and f in self.ix]
        self.der_hold = np.array([self.ix[f] for f in self.tax["derived"] if f not in self.ident], dtype=int)
        self.W = np.array([self.tax["W"][f] for f in self.tax["mutable"]])
        self.lo = np.array([self.tax["lo"][f] for f in self.feats])
        self.hi = np.array([self.tax["hi"][f] for f in self.feats])
        self.order = [(self.ix[c["lo"]], self.ix[c["hi"]]) for c in self.tax.get("order_constraints", [])
                      if c["used"] and c["lo"] in self.ix and c["hi"] in self.ix]
        self.booster, self.thr = L.load_primary_detector(bcfg)
        self.app = None                       # per-stratum applicable mutable features
        if cfg.get("stratum_mutable_mask"):
            tr = L.load_split(bcfg, "train")
            st = L.stratum_of(tr["Protocol Type"].values)
            M = tr[self.tax["mutable"]].values
            self.app = {s: (M[st == s].std(0) > 0) for s in np.unique(st)}
            L._atomic_json(os.path.join(out_dir, "applicable_mutable.json"),
                           {s: [f for f, a in zip(self.tax["mutable"], v) if a] for s, v in self.app.items()})
        self.groups = json.load(open(os.path.join(base_dir, "stage3", "decoy_groups.json")))
        self.families = sorted(self.groups)
        self.k = cfg["k"]
        self._splits = {}

    def p(self, *parts):
        path = os.path.join(self.out, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def split(self, name):
        if name not in self._splits:
            self._splits[name] = L.load_split(self.bcfg, name)
        return self._splits[name]

    # ---------------- feasibility (numerical, V_num) ----------------
    def project(self, Xc, x0, lo, hi):
        X = Xc.copy()
        X[:, self.imm] = x0[self.imm]
        if len(self.der_hold): X[:, self.der_hold] = x0[self.der_hold]
        X[:, self.mut] = np.clip(X[:, self.mut], lo[self.mut], hi[self.mut])
        if all(f in self.ix for f in ("Min", "AVG", "Max")):
            t = [self.ix["Min"], self.ix["AVG"], self.ix["Max"]]
            X[:, t] = np.sort(X[:, t], axis=1)
        else:
            for a, b in self.order:
                A, B = X[:, a].copy(), X[:, b].copy()
                X[:, a], X[:, b] = np.minimum(A, B), np.maximum(A, B)
        for f in self.ident:
            i = self.ix[f]
            if f == "Tot size": X[:, i] = X[:, self.ix["AVG"]]
            elif f == "Variance": X[:, i] = X[:, self.ix["Std"]] ** 2
            elif f == "Tot sum": X[:, i] = X[:, self.ix["AVG"]] * X[:, self.ix["Number"]]
        return X

    def app_mask(self, x0):
        if self.app is None: return np.ones(len(self.mut), bool)
        s = str(L.stratum_of(np.array([x0[self.ix["Protocol Type"]]]))[0])
        return self.app.get(s, np.zeros(len(self.mut), bool))

    def bounds_for(self, x0):
        return np.minimum(self.lo, x0), np.maximum(self.hi, x0)

    def dW(self, Xc, x0):
        return np.linalg.norm((Xc[:, self.mut] - x0[self.mut]) * self.W, axis=1)

    def invalid_mask(self, X, x0, parts=False):
        """Which samples violate V_num (used by the naive-smoothing ablation).
        With parts=True returns (range, order, identity) violation masks separately."""
        lo, hi = self.bounds_for(x0)
        rng_bad = ((X < lo - 1e-9) | (X > hi + 1e-9)).any(1)
        ord_bad = np.zeros(len(X), bool)
        for a, b in self.order:
            ord_bad |= X[:, a] > X[:, b] + 1e-9
        id_bad = np.zeros(len(X), bool)
        for f in self.ident:
            i = self.ix[f]
            if f == "Tot size": ref = X[:, self.ix["AVG"]]
            elif f == "Variance": ref = X[:, self.ix["Std"]] ** 2
            else: ref = X[:, self.ix["AVG"]] * X[:, self.ix["Number"]]
            id_bad |= np.abs(X[:, i] - ref) > 1e-6 * (1 + np.abs(ref))
        if parts: return rng_bad, ord_bad, id_bad
        return rng_bad | ord_bad | id_bad

    # ---------------- model calls ----------------
    def score(self, X):
        return L.detector_score(self.booster, X)

    def shap(self, X):
        return L.tree_shap(self.booster, X) if len(X) else np.zeros((0, self.d), "float32")

    def topk(self, S):
        return L.topk_membership(S, self.k)


# ==========================================================================
# explanation methods (defences)
# ==========================================================================
def saabas(ctx, X):
    import xgboost as xgb
    return ctx.booster.predict(xgb.DMatrix(X), pred_contribs=True, approx_contribs=True)[:, :-1]

def occlusion(ctx, X, ref):
    """Score change when each feature is replaced by its training median (one batched call)."""
    n, d = X.shape
    Xo = np.repeat(X[None], d + 1, axis=0)             # copy 0 = original
    for j in range(d): Xo[j + 1, :, j] = ref[j]
    sc = ctx.score(Xo.reshape(-1, d)).reshape(d + 1, n)
    return (sc[0][None] - sc[1:]).T.astype("float32")

def consensus_membership(ctx, X, ref):
    """Tree-specific consensus: equal-weight average of feature ranks from TreeSHAP,
    Saabas and occlusion attributions, each L1-normalised."""
    ranks = []
    for A in (ctx.shap(X), saabas(ctx, X), occlusion(ctx, X, ref)):
        A = np.abs(A) / (np.abs(A).sum(1, keepdims=True) + 1e-12)
        ranks.append(np.argsort(np.argsort(-A, axis=1, kind="stable"), axis=1))
    avg = np.mean(ranks, axis=0) + 1e-6 * np.arange(X.shape[1])   # fixed tie rule
    idx = np.argsort(avg, axis=1, kind="stable")[:, :ctx.k]
    M = np.zeros(X.shape, np.uint8); np.put_along_axis(M, idx, 1, axis=1)
    return M


class Bank:
    """Fixed validity-preserving decoder: nearest training flow (label-free) in the
    W-scaled mutable space, per protocol stratum. Decoded sample = the alert's immutable
    attributes + the bank flow's mutable values, with derived fields recomputed."""
    def __init__(self, ctx, train_df, per_stratum, seed):
        from sklearn.neighbors import NearestNeighbors
        self.ctx = ctx
        X = train_df[ctx.feats].values.astype("float64")
        strata = L.stratum_of(train_df["Protocol Type"].values) if "Protocol Type" in train_df else np.array(["all"] * len(X))
        rng = np.random.default_rng(seed)
        self.mutvals, self.nn = {}, {}
        for s in np.unique(strata):
            idx = np.where(strata == s)[0]
            if len(idx) > per_stratum: idx = np.sort(rng.choice(idx, per_stratum, replace=False))
            M = np.unique(X[idx][:, ctx.mut], axis=0)     # distinct flows: no distance ties
            self.mutvals[s] = M
            self.nn[s] = NearestNeighbors(n_neighbors=1).fit(M * ctx.W)
        self.sizes = {s: len(v) for s, v in self.mutvals.items()}

    def stratum(self, x0):
        if "Protocol Type" in self.ctx.ix:
            return str(L.stratum_of(np.array([x0[self.ctx.ix["Protocol Type"]]]))[0])
        return "all"

    def query(self, s, Z):
        return self.nn[s].kneighbors(Z, return_distance=False)[:, 0]

    def local(self, s, center, rho):
        """Index restricted to bank flows within rho of center (scaled space). Queries
        whose answer could lie outside the region fall back to the full index, so the
        result is identical to query()."""
        from sklearn.neighbors import NearestNeighbors
        ids = self.nn[s].radius_neighbors(center[None], radius=rho, return_distance=False)[0]
        if len(ids) < 50:
            return None
        sub = NearestNeighbors(n_neighbors=1).fit(self.mutvals[s][ids] * self.ctx.W)
        return {"ids": ids, "nn": sub, "center": center, "rho": rho}

    def query_local(self, s, Z, loc):
        if loc is None: return self.query(s, Z)
        dist, j = loc["nn"].kneighbors(Z)
        t = np.linalg.norm(Z - loc["center"], axis=1)
        out = loc["ids"][j[:, 0]]
        miss = t + dist[:, 0] > loc["rho"]          # a closer flow might lie outside the region
        if miss.any():
            out[miss] = self.query(s, Z[miss])
        return out

    def decode(self, s, idx, x0):
        X = np.repeat(x0[None, :], len(idx), axis=0).astype("float64")
        X[:, self.ctx.mut] = self.mutvals[s][idx]
        lo, hi = self.ctx.bounds_for(x0)
        return self.ctx.project(X, x0, np.minimum(lo, X.min(0)), np.maximum(hi, X.max(0)))


class Smoother:
    """AssureDx smoothing for one alert's stratum (fixed immutable attributes).
    Caches the top-k membership of each decoded bank flow, so repeated queries within
    an alert (clean, candidates, validation) only explain new bank flows."""
    def __init__(self, ctx, bank, x0, sigma):
        self.ctx, self.bank, self.x0, self.sigma = ctx, bank, x0, sigma
        self.s = bank.stratum(x0)
        self.cache = {}
        self.shap_rows = 0
        self.loc = None

    def localise(self, eps):
        """Speed-up for repeated queries around x0 (attack search)."""
        m = len(self.ctx.mut)
        c = self.x0[self.ctx.mut] * self.ctx.W
        d0 = float(self.bank.nn[self.s].kneighbors(c[None])[0][0, 0])
        rho = eps + self.sigma * (math.sqrt(m) + 3) + 2 * d0 + 1e-9
        self.loc = self.bank.local(self.s, c, rho)

    def _unique_members(self, u):
        new = [i for i in u.tolist() if i not in self.cache]
        if new:
            Xd = self.bank.decode(self.s, np.array(new), self.x0)
            M = self.ctx.topk(self.ctx.shap(Xd))
            self.shap_rows += len(new)
            for i, m in zip(new, M): self.cache[i] = m
        return np.stack([self.cache[i] for i in u.tolist()])

    def frequencies(self, X, n, rng):
        """p-hat for each row of X (same stratum and immutables as x0), n samples each.
        All rows are sampled and queried in one call; each bank flow is explained once."""
        m = len(self.ctx.mut); R = len(X)
        Z = (X[:, self.ctx.mut] * self.ctx.W)[:, None, :] + self.sigma * rng.standard_normal((R, n, m))
        idx = self.bank.query_local(self.s, Z.reshape(-1, m), self.loc).reshape(R, n)
        u, inv = np.unique(idx, return_inverse=True)
        Mu = self._unique_members(u).astype("float32")
        out = Mu[inv.reshape(R, n)].mean(1)
        uniq_counts = [len(np.unique(r)) for r in idx] if R <= 4 else []
        return out, uniq_counts

    def votes(self, X, n, rng, clf):
        """Smoothed diagnosis: for each row of X, the fraction of n smoothing samples whose
        decoded flow receives each diagnosis (base classifier = frozen diagnoser applied to
        the decoded flow's own top-k set). Returns (R, n_classes)."""
        m = len(self.ctx.mut); R = len(X)
        Z = (X[:, self.ctx.mut] * self.ctx.W)[:, None, :] + self.sigma * rng.standard_normal((R, n, m))
        idx = self.bank.query_local(self.s, Z.reshape(-1, m), self.loc).reshape(R, n)
        u, inv = np.unique(idx, return_inverse=True)
        if not hasattr(self, "dcache"): self.dcache = {}
        new = [i for i in u.tolist() if i not in self.dcache]
        if new:
            Mn = self._unique_members(np.array(new))
            for i, c in zip(new, np.searchsorted(clf.classes_, clf.predict(Mn))): self.dcache[i] = c
        cu = np.array([self.dcache[i] for i in u.tolist()])
        lab = cu[inv.reshape(R, n)]
        K = len(clf.classes_)
        return np.stack([np.bincount(r, minlength=K) for r in lab]) / n

    def unsmoothed(self, X):
        idx = self.bank.query(self.s, X[:, self.ctx.mut] * self.ctx.W)
        u, inv = np.unique(idx, return_inverse=True)
        return self._unique_members(u)[inv]


def smoothed_batch(ctx, bank, X, sigma, n, rng, chunk=250):
    """p-hat for many alerts at once (each with its own immutable attributes): one
    neighbour query per stratum and one TreeSHAP call per chunk. sigma=0, n=1 gives
    the unsmoothed decoder."""
    m = len(ctx.mut); out = []
    for st in range(0, len(X), chunk):
        Xc = X[st:st + chunk]; A = len(Xc)
        strata = np.array([bank.stratum(x) for x in Xc])
        idx = np.empty((A, n), dtype=int)
        for s in np.unique(strata):
            rows = np.where(strata == s)[0]
            Z = (Xc[rows][:, ctx.mut] * ctx.W)[:, None, :] + sigma * rng.standard_normal((len(rows), n, m))
            idx[rows] = bank.query(s, Z.reshape(-1, m)).reshape(len(rows), n)
        dec, spans = [], []
        for a in range(A):
            u, inv = np.unique(idx[a], return_inverse=True)
            dec.append(bank.decode(strata[a], u, Xc[a])); spans.append((len(u), inv))
        M = ctx.topk(ctx.shap(np.vstack(dec))).astype("float32")
        pos = 0
        for nu, inv in spans:
            out.append(M[pos:pos + nu][inv].mean(0)); pos += nu
    return np.array(out)


def certify(p_hat, n, k, sigma, alpha, d):
    """Algorithm 1: returns (set membership, certified gap, radius) per row."""
    e = math.sqrt(math.log(2 * d / alpha) / (2 * n))
    order = np.argsort(-p_hat, axis=1, kind="stable")
    M = np.zeros(p_hat.shape, np.uint8); np.put_along_axis(M, order[:, :k], 1, axis=1)
    Lb = np.clip(p_hat - e, 0, 1); Ub = np.clip(p_hat + e, 0, 1)
    sel_lo = np.where(M == 1, Lb, np.inf).min(1)
    exc_hi = np.where(M == 0, Ub, -np.inf).max(1)
    gap = sel_lo - exc_hi
    with np.errstate(divide="ignore", invalid="ignore"):
        R = np.where(gap > 0, sigma / 2 * (norm.ppf(np.clip(sel_lo, 1e-12, 1 - 1e-12))
                                           - norm.ppf(np.clip(exc_hi, 1e-12, 1 - 1e-12))), 0.0)
    R = np.floor(np.maximum(R, 0) * 1e6) / 1e6        # round down
    return M, gap, R


# ==========================================================================
# helpers
# ==========================================================================
def jl_done(path, key="key"):
    done = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try: done.add(json.loads(line)[key])
                except Exception: pass
    return done

def jl_append(path, rec):
    with open(path, "a") as f:
        f.write(json.dumps(rec, default=L._np_default) + "\n")
        f.flush(); os.fsync(f.fileno())

def jl_read(path):
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path) as f:
        for line in f:
            try: rows.append(json.loads(line))
            except Exception: pass
    return pd.DataFrame(rows)

def fam_index(clf, fam):
    return int(np.where(clf.classes_ == fam)[0][0])

def decoy_mass_from_members(M_or_p, ctx, fam):
    g = [ctx.ix[f] for f in ctx.groups[fam] if f in ctx.ix]
    return M_or_p[:, g].sum(1) / ctx.k

def raw_mass(S, ctx, fam):
    g = [ctx.ix[f] for f in ctx.groups[fam] if f in ctx.ix]
    A = np.abs(S)
    return A[:, g].sum(1) / (A.sum(1) + 1e-9)

def balanced_train_alerts(ctx, per_family, seed):
    rows = np.load(os.path.join(ctx.base, "stage3", "rows_train.npy"))
    tr = ctx.split("train")
    fam = tr["family"].values[rows]
    rng = np.random.default_rng(seed)
    pick = []
    for f in ctx.families:
        r = rows[fam == f]
        if len(r) > per_family: r = rng.choice(r, per_family, replace=False)
        pick.extend(r.tolist())
    pick = np.array(sorted(pick))
    return pick, tr[ctx.feats].values[pick].astype("float64"), tr["family"].values[pick]

def fit_lr(cfg, Xtr, ytr, Xva, yva):
    return L._fit_diagnoser({"diag_penalties": [0.01, 0.1, 1, 10, 100]}, Xtr, ytr, Xva, yva)


# ==========================================================================
# STAGE 4 - alerts and decoys
# ==========================================================================
def stage4_alerts(ctx):
    path = ctx.p("stage4", "alerts.csv")
    if os.path.exists(path):
        L.log("stage 4 already complete"); return pd.read_csv(path)
    te = ctx.split("test")
    rows = np.load(os.path.join(ctx.base, "stage3", "rows_test.npy"))
    rng = np.random.default_rng(ctx.cfg["seed"])
    recs = []
    for f in ctx.families:
        r = rows[te["family"].values[rows] == f]
        groups = te[L.GROUP].values[r] if L.GROUP in te else np.zeros(len(r))
        order = []                                     # capture-balanced: round-robin over files
        per_g = {g: list(rng.permutation(r[groups == g])) for g in np.unique(groups)}
        while len(order) < min(ctx.cfg["alerts_per_family"], len(r)):
            for g in list(per_g):
                if per_g[g]: order.append(per_g[g].pop())
                if len(order) >= ctx.cfg["alerts_per_family"]: break
        for i in order:
            recs.append({"row": int(i), "family": f, "label": te[L.LABEL].values[i],
                         "source_file": te[L.GROUP].values[i] if L.GROUP in te else "na"})
    df = pd.DataFrame(recs)
    # decoys: uniform over families whose decoy group is not identical to the source's
    dec = []
    for f in df["family"]:
        allowed = [c for c in ctx.families if c != f and set(ctx.groups[c]) != set(ctx.groups[f])]
        dec.append(rng.choice(allowed))
    df["decoy"] = dec
    sub = []
    for f, g in df.groupby("family"):
        sub.extend(g.index[:ctx.cfg["adaptive_alerts_per_family"]].tolist())
    df["adaptive_subset"] = df.index.isin(sub)
    df["alert_id"] = np.arange(len(df))
    tmp = path + ".tmp"; df.to_csv(tmp, index=False); os.replace(tmp, path)
    L.log(f"stage 4 done: {len(df)} alerts, {df.adaptive_subset.sum()} in the adaptive subset")
    print(pd.crosstab(df.family, df.decoy))
    return df


# ==========================================================================
# STAGE 5 - defences
# ==========================================================================
def _ctx_bank(ctx):
    if not hasattr(ctx, "bank"):
        t0 = time.time()
        ctx.bank = Bank(ctx, ctx.split("train"), ctx.cfg["bank_per_stratum"], ctx.cfg["seed"])
        L.log(f"  bank decoder ready in {time.time()-t0:.1f}s: {ctx.bank.sizes}")
    return ctx.bank

def _ref_median(ctx):
    if not hasattr(ctx, "ref"):
        ctx.ref = np.median(ctx.split("train")[ctx.feats].values, axis=0)
    return ctx.ref

def stage5_defences(ctx):
    import joblib
    from sklearn.metrics import f1_score
    done = ctx.p("stage5", "DONE")
    if os.path.exists(done):
        L.log("stage 5 already complete"); return
    cfg = ctx.cfg
    bank = _ctx_bank(ctx); ref = _ref_median(ctx)
    rtr, Xtr, ytr = balanced_train_alerts(ctx, cfg["diag_train_per_family"], cfg["seed"])
    va = ctx.split("val")
    rva_all = np.load(os.path.join(ctx.base, "stage3", "rows_val.npy"))
    rng = np.random.default_rng(cfg["seed"] + 1)
    rva = []
    for f in ctx.families:
        r = rva_all[va["family"].values[rva_all] == f]
        rva.extend(rng.choice(r, min(len(r), cfg["diag_val_per_family"]), replace=False).tolist())
    rva = np.array(sorted(rva))
    Xva, yva = va[ctx.feats].values[rva].astype("float64"), va["family"].values[rva]
    summary = {}

    def train_rep(name, fn):
        path = ctx.p("stage5", f"diag_{name}.joblib")
        if os.path.exists(path):
            return joblib.load(path)
        t0 = time.time()
        Mtr, Mva = fn(Xtr), fn(Xva)
        f1v, lam, clf = fit_lr(cfg, Mtr, ytr, Mva, yva)
        joblib.dump(clf, path)
        summary[name] = {"val_macro_f1": f1v, "lambda": lam, "sec": time.time() - t0}
        L.log(f"  diagnoser {name}: val macro-F1 {f1v:.4f} ({time.time()-t0:.0f}s)")
        return clf

    train_rep("raw", lambda X: ctx.topk(ctx.shap(X)))
    train_rep("consensus", lambda X: consensus_membership(ctx, X, ref))

    def unsmoothed_fn(X):
        return ctx.topk(smoothed_batch(ctx, bank, X, 0.0, 1, np.random.default_rng(0)))
    train_rep("unsmoothed", unsmoothed_fn)

    def assuredx_fn(sigma, seed):
        def fn(X):
            return ctx.topk(smoothed_batch(ctx, bank, X, sigma, cfg["n_train_expl"],
                                           np.random.default_rng(seed)))
        return fn
    for s in cfg["sigmas"]:
        train_rep(f"assuredx_s{s}", assuredx_fn(s, cfg["seed"] + int(1000 * s)))

    # sigma chosen by validation macro-F1 of the AssureDx diagnoser (prespecified rule)
    vals = {}
    for s in cfg["sigmas"]:
        clf = joblib.load(ctx.p("stage5", f"diag_assuredx_s{s}.joblib"))
        Mva = assuredx_fn(s, cfg["seed"] + 99)(Xva)
        vals[s] = f1_score(yva, clf.predict(Mva), average="macro")
    sigma = max(vals, key=vals.get)

    # fingerprint detector (adapted baseline): clean training alerts vs attacked training alerts
    fp_path = ctx.p("stage5", "fingerprint.joblib")
    if not os.path.exists(fp_path):
        from sklearn.linear_model import LogisticRegression
        raw = joblib.load(ctx.p("stage5", "diag_raw.joblib"))
        rr = np.random.default_rng(cfg["seed"] + 5)
        pick = rr.choice(len(Xtr), min(cfg["fp_train_attacks"], len(Xtr)), replace=False)
        adv = []
        for i in pick:
            x0, y = Xtr[i], ytr[i]
            c = rr.choice([f for f in ctx.families if f != y and set(ctx.groups[f]) != set(ctx.groups[y])])
            res = attack_one(ctx, x0, y, c, cfg["fp_attack_eps"], "raw", {"raw": raw}, rr)
            if res["x_adv"] is not None: adv.append(res["x_adv"])
        Sc = ctx.shap(Xtr); Sa = ctx.shap(np.array(adv))
        F = lambda S: S / (np.abs(S).sum(1, keepdims=True) + 1e-12)
        Xf = np.vstack([F(Sc), F(Sa)]); yf = np.r_[np.zeros(len(Sc)), np.ones(len(Sa))]
        fp = LogisticRegression(max_iter=3000, class_weight="balanced").fit(Xf, yf)
        sv = fp.predict_proba(F(ctx.shap(Xva)))[:, 1]
        fp_thr = float(np.quantile(sv, 1 - cfg["fp_frr"]))
        joblib.dump({"clf": fp, "thr": fp_thr, "n_adv_train": len(adv)}, fp_path)
        summary["fingerprint"] = {"n_adv_train": len(adv), "threshold": fp_thr}
        L.log(f"  fingerprint detector: {len(adv)} attacked training alerts, threshold {fp_thr:.4f}")

    old = json.load(open(ctx.p("stage5", "summary.json"))) if os.path.exists(ctx.p("stage5", "summary.json")) else {}
    old.update(summary); old["sigma_val_macro_f1"] = vals; old["sigma_selected"] = sigma
    L._atomic_json(ctx.p("stage5", "summary.json"), old)
    open(done, "w").write(time.strftime("%Y-%m-%d %H:%M:%S"))
    L.log(f"stage 5 done: sigma = {sigma} (validation macro-F1 {vals})")


def load_defences(ctx):
    import joblib
    D = {n: joblib.load(ctx.p("stage5", f"diag_{n}.joblib")) for n in ("raw", "consensus", "unsmoothed")}
    summ = json.load(open(ctx.p("stage5", "summary.json")))
    ctx.sigma = summ["sigma_selected"]
    D["assuredx"] = joblib.load(ctx.p("stage5", f"diag_assuredx_s{ctx.sigma}.joblib"))
    for s in ctx.cfg["sigmas"]:
        D[f"assuredx_s{s}"] = joblib.load(ctx.p("stage5", f"diag_assuredx_s{s}.joblib"))
    D["fingerprint"] = joblib.load(ctx.p("stage5", "fingerprint.joblib"))
    return D


# ==========================================================================
# the targeted search (shared by every defence)
# ==========================================================================
def evaluate(ctx, defence, X, fam_c, D, state, rng):
    """Returns (objective J, diagnosis, feasible-by-defence mask, extras) for candidates X."""
    w = ctx.cfg["mass_weight"]
    if defence == "raw" or defence == "fingerprint":
        S = ctx.shap(X); M = ctx.topk(S)
        clf = D["raw"]; pr = clf.predict_proba(M)
        J = pr[:, fam_index(clf, fam_c)] + w * raw_mass(S, ctx, fam_c)
        diag = clf.classes_[pr.argmax(1)]
        ok = np.ones(len(X), bool)
        if defence == "fingerprint":
            fp = D["fingerprint"]
            F = S / (np.abs(S).sum(1, keepdims=True) + 1e-12)
            ok = fp["clf"].predict_proba(F)[:, 1] < fp["thr"]
        return J, diag, ok, {"mass": raw_mass(S, ctx, fam_c)}
    if defence == "consensus":
        M = consensus_membership(ctx, X, _ref_median(ctx))
        clf = D["consensus"]; pr = clf.predict_proba(M)
        J = pr[:, fam_index(clf, fam_c)] + w * decoy_mass_from_members(M, ctx, fam_c)
        return J, clf.classes_[pr.argmax(1)], np.ones(len(X), bool), {"mass": decoy_mass_from_members(M, ctx, fam_c)}
    if defence == "unsmoothed":
        M = state["smoother"].unsmoothed(X)
        clf = D["unsmoothed"]; pr = clf.predict_proba(M)
        J = pr[:, fam_index(clf, fam_c)] + w * decoy_mass_from_members(M, ctx, fam_c)
        return J, clf.classes_[pr.argmax(1)], np.ones(len(X), bool), {"mass": decoy_mass_from_members(M, ctx, fam_c)}
    if defence == "assuredx":
        p, _ = state["smoother"].frequencies(X, ctx.cfg["n_attack"], rng)
        M = ctx.topk(p); clf = D["assuredx"]
        pr = clf.predict_proba(M)
        mass = decoy_mass_from_members(p, ctx, fam_c)
        J = pr[:, fam_index(clf, fam_c)] + w * mass
        return J, clf.classes_[pr.argmax(1)], np.ones(len(X), bool), {"mass": mass}
    if defence == "assuredx_vote":
        clf = D["raw"]
        V = state["smoother"].votes(X, ctx.cfg["n_attack"], rng, clf)
        ci = fam_index(clf, fam_c)
        J = V[:, ci] - V.max(1) + 1.0                  # 1 when the decoy is the plurality
        return J, clf.classes_[V.argmax(1)], np.ones(len(X), bool), {"mass": V[:, ci]}
    raise ValueError(defence)


def attack_one(ctx, x0, y, c, eps, defence, D, rng, state=None, objective="diag"):
    """Finite-budget random search with restarts inside the d_W ball (Section 4.2).
    Feasible = numerically valid, detection preserved, accepted by the defence."""
    cfg = ctx.cfg
    m = len(ctx.mut)
    lo, hi = ctx.bounds_for(x0)
    state = state or {}
    per_restart = cfg["budget"] // cfg["restarts"]
    iters = max(1, per_restart // cfg["batch"])
    best = {"J": -np.inf, "x": None, "diag": None}
    hit = None
    evals = feasible_n = 0
    app = ctx.app_mask(x0).astype(float)
    if app.sum() == 0:                      # nothing the attacker may edit in this stratum
        return {"x_adv": None, "x_hit": None, "J": -np.inf, "diag_best": None,
                "evals": 0, "feasible": 0, "no_editable_fields": True}
    u_best = np.zeros(m)

    def ball(u):
        nrm = np.linalg.norm(u, axis=1, keepdims=True)
        return u * np.minimum(1.0, eps / np.maximum(nrm, 1e-12))

    for r in range(cfg["restarts"]):
        if r == 0:
            u_cur = np.zeros(m); J_cur = -np.inf
        else:
            d = rng.standard_normal(m) * app; d /= np.linalg.norm(d)
            u_cur = d * eps * rng.random() ** (1 / m); J_cur = -np.inf
        for it in range(iters):
            B = cfg["batch"]
            local = rng.random(B) < cfg["p_local"]
            U = np.empty((B, m))
            steps = rng.standard_normal((B, m)) * app * cfg["step_frac"] * eps / math.sqrt(max(app.sum(), 1))
            U[local] = u_cur + steps[local]
            nl = (~local).sum()
            if nl:
                dd = rng.standard_normal((nl, m)) * app; dd /= np.linalg.norm(dd, axis=1, keepdims=True)
                U[~local] = dd * eps * rng.random((nl, 1)) ** (1 / max(app.sum(), 1))
            U = ball(U)
            Xc = np.repeat(x0[None], B, axis=0)
            Xc[:, ctx.mut] = x0[ctx.mut] + U / ctx.W
            Xc = ctx.project(Xc, x0, lo, hi)
            evals += B
            ok = ctx.dW(Xc, x0) <= eps * (1 + 1e-9)
            ok &= ctx.score(Xc) >= ctx.thr
            if not ok.any(): continue
            J, diag, acc, ex = evaluate(ctx, defence, Xc[ok], c, D, state, rng)
            idx_ok = np.where(ok)[0]
            feas = idx_ok[acc]
            if len(feas) == 0: continue
            feasible_n += len(feas)
            Jf = J[acc]; dg = diag[acc]
            if hit is None and (dg == c).any():
                hit = Xc[feas[np.argmax(dg == c)]].copy()
            j = int(np.argmax(Jf))
            if Jf[j] > J_cur:
                J_cur = Jf[j]; u_cur = (Xc[feas[j], ctx.mut] - x0[ctx.mut]) * ctx.W
            if Jf[j] > best["J"]:
                best = {"J": float(Jf[j]), "x": Xc[feas[j]].copy(), "diag": dg[j]}
    return {"x_adv": best["x"], "x_hit": hit, "J": best["J"], "diag_best": best["diag"],
            "evals": evals, "feasible": feasible_n}


# ==========================================================================
# STAGE 6 - clean evaluation, certificates, naive-smoothing ablation
# ==========================================================================
def stage6_clean(ctx):
    cfg = ctx.cfg
    D = load_defences(ctx); bank = _ctx_bank(ctx); ref = _ref_median(ctx)
    alerts = stage4_alerts(ctx)
    te = ctx.split("test")
    out = ctx.p("stage6", "clean.jsonl")
    done = jl_done(out, "alert_id")
    t0 = time.time(); n_new = 0
    for _, a in alerts.iterrows():
        if a.alert_id in done: continue
        x0 = te[ctx.feats].values[a.row].astype("float64"); y = a.family
        rec = {"alert_id": int(a.alert_id), "family": y, "decoy": a.decoy, "row": int(a.row)}
        S = ctx.shap(x0[None]); Mraw = ctx.topk(S)
        rec["score"] = float(ctx.score(x0[None])[0])
        rec["raw_diag"] = D["raw"].predict(Mraw)[0]
        rec["raw_mass"] = float(raw_mass(S, ctx, a.decoy)[0])
        F = S / (np.abs(S).sum(1, keepdims=True) + 1e-12)
        rec["fp_accept"] = bool(D["fingerprint"]["clf"].predict_proba(F)[:, 1][0] < D["fingerprint"]["thr"])
        Mc = consensus_membership(ctx, x0[None], ref)
        rec["consensus_diag"] = D["consensus"].predict(Mc)[0]
        rec["consensus_overlap_raw"] = float((Mc & Mraw).sum() / ctx.k)
        sm0 = Smoother(ctx, bank, x0, 0.0); Mu = sm0.unsmoothed(x0[None])
        rec["unsmoothed_diag"] = D["unsmoothed"].predict(Mu)[0]
        rec["unsmoothed_overlap_raw"] = float((Mu & Mraw).sum() / ctx.k)
        rec["decoder_dist"] = float(bank.nn[sm0.s].kneighbors((x0[ctx.mut] * ctx.W)[None])[0][0, 0])
        for s in cfg["sigmas"]:
            r = np.random.default_rng(cfg["seed"] * 7919 + int(a.alert_id) * 31 + int(1000 * s))
            sm = Smoother(ctx, bank, x0, s)
            ts = time.time()
            p, uq = sm.frequencies(x0[None], cfg["n_cert"], r)
            M, gap, R = certify(p, cfg["n_cert"], ctx.k, s, cfg["alpha"], ctx.d)
            key = f"s{s}"
            rec[f"{key}_diag"] = D[f"assuredx_s{s}"].predict(M)[0]
            rec[f"{key}_radius"] = float(R[0]); rec[f"{key}_gap"] = float(gap[0])
            rec[f"{key}_overlap_raw"] = float((M & Mraw).sum() / ctx.k)
            rec[f"{key}_unique_neighbours"] = int(uq[0]); rec[f"{key}_shap_rows"] = sm.shap_rows
            rec[f"{key}_sec"] = time.time() - ts
            rec[f"{key}_pmin_sel"] = float(np.sort(p[0])[::-1][ctx.k - 1])
            rec[f"{key}_pmax_exc"] = float(np.sort(p[0])[::-1][ctx.k])
        jl_append(out, rec); n_new += 1
        if n_new % 50 == 0:
            L.log(f"  clean: {n_new} new alerts ({(time.time()-t0)/n_new:.2f}s each)")
    L.log(f"stage 6 clean evaluation: {len(alerts)} alerts")

    # sampling-budget sweep on a subset (selected sigma)
    sw = ctx.p("stage6", "n_sweep.jsonl"); done = jl_done(sw, "key")
    subset = alerts.groupby("family").head(max(1, cfg["n_sweep_alerts"] // len(ctx.families)))
    for _, a in subset.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64")
        sm = Smoother(ctx, bank, x0, ctx.sigma)
        for n in cfg["n_sweep"]:
            key = f"{a.alert_id}_{n}"
            if key in done: continue
            r = np.random.default_rng(cfg["seed"] * 104729 + int(a.alert_id) * 17 + n)
            ts = time.time()
            p, uq = sm.frequencies(x0[None], n, r)
            M, gap, R = certify(p, n, ctx.k, ctx.sigma, cfg["alpha"], ctx.d)
            jl_append(sw, {"key": key, "alert_id": int(a.alert_id), "family": a.family, "n": n,
                           "radius": float(R[0]), "gap": float(gap[0]), "sec": time.time() - ts,
                           "diag": D["assuredx"].predict(M)[0]})
    L.log("stage 6 n-sweep done")

    # naive feature-space Gaussian smoothing (no decoder): validity of the samples
    nv = ctx.p("stage6", "naive.jsonl"); done = jl_done(nv, "key")
    sub = alerts.groupby("family").head(cfg["naive_alerts_per_family"])
    m = len(ctx.mut)
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64")
        for s in cfg["sigmas"]:
            key = f"{a.alert_id}_{s}"
            if key in done: continue
            r = np.random.default_rng(cfg["seed"] * 15485863 + int(a.alert_id) * 13 + int(1000 * s))
            X = np.repeat(x0[None], cfg["naive_n"], axis=0)
            X[:, ctx.mut] = x0[ctx.mut] + s * r.standard_normal((cfg["naive_n"], m)) / ctx.W
            rb, ob, ib = ctx.invalid_mask(X, x0, parts=True); bad = rb | ob | ib
            Sn = ctx.shap(X); p = ctx.topk(Sn).mean(0, keepdims=True)
            M, gap, R = certify(p, cfg["naive_n"], ctx.k, s, cfg["alpha"], ctx.d)
            Sraw = ctx.topk(ctx.shap(x0[None]))
            detect_flip = float((ctx.score(X) < ctx.thr).mean())
            jl_append(nv, {"key": key, "alert_id": int(a.alert_id), "family": a.family, "sigma": s,
                           "invalid_frac": float(bad.mean()), "range_violation_frac": float(rb.mean()),
                           "order_violation_frac": float(ob.mean()), "identity_violation_frac": float(ib.mean()),
                           "range_or_order_frac": float((rb | ob).mean()), "radius": float(R[0]),
                           "overlap_raw": float((M & Sraw).sum() / ctx.k),
                           "detector_flip_frac": detect_flip})
    L.log("stage 6 naive-smoothing ablation done")


# ==========================================================================
# STAGE 7 - attacks
# ==========================================================================
def stage7_attacks(ctx, defences=("raw", "consensus", "fingerprint", "unsmoothed", "assuredx", "random")):
    cfg = ctx.cfg
    D = load_defences(ctx); bank = _ctx_bank(ctx)
    alerts = stage4_alerts(ctx)
    clean = jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    te = ctx.split("test")
    for defence in defences:
        out = ctx.p("stage7", f"attack_{defence}.jsonl")
        done = jl_done(out, "key")
        todo = alerts[alerts.adaptive_subset] if defence == "assuredx" else alerts
        t0 = time.time(); n_new = 0
        for _, a in todo.iterrows():
            x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
            cl = clean.loc[a.alert_id]
            for eps in cfg["eps"]:
                key = f"{a.alert_id}_{eps}"
                if key in done: continue
                rng = np.random.default_rng(cfg["seed"] * 2654435761 % 2**31 + int(a.alert_id) * 97
                                            + int(eps * 1000) + zlib.crc32(defence.encode()) % 1000)
                rec = {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                       "defence": defence, "source_file": a.source_file}
                ts = time.time()
                if defence == "random":
                    rec.update(random_edits(ctx, x0, y, c, eps, D, rng)); rec["eligible"] = cl["raw_diag"] == y
                elif defence == "assuredx":
                    sm = Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
                    res = attack_one(ctx, x0, y, c, eps, "assuredx", D, rng, state={"smoother": sm})
                    rec.update(validate_assuredx(ctx, sm, res, x0, c, eps, D, a.alert_id))
                    rec["eligible"] = cl[f"s{ctx.sigma}_diag"] == y
                    rec["clean_radius"] = float(cl[f"s{ctx.sigma}_radius"])
                    rec["certified_at_eps"] = rec["clean_radius"] >= eps
                    rec["shap_rows"] = sm.shap_rows
                else:
                    state = {"smoother": Smoother(ctx, bank, x0, 0.0)} if defence == "unsmoothed" else {}
                    res = attack_one(ctx, x0, y, c, eps, defence, D, rng, state=state)
                    xs = res["x_hit"] if res["x_hit"] is not None else res["x_adv"]
                    rec["found"] = res["x_adv"] is not None
                    rec["success"] = res["x_hit"] is not None
                    rec["evals"] = res["evals"]; rec["feasible"] = res["feasible"]
                    if xs is not None:
                        rec["score_drift"] = float(ctx.score(xs[None])[0] - cl["score"])
                        rec["dW"] = float(ctx.dW(xs[None], x0)[0])
                        if defence in ("raw", "fingerprint"):
                            S = ctx.shap(xs[None])
                            rec["mass_after"] = float(raw_mass(S, ctx, c)[0])
                            rec["Dk"] = float(1 - (ctx.topk(S) & ctx.topk(ctx.shap(x0[None]))).sum() / ctx.k)
                    key_diag = {"raw": "raw_diag", "consensus": "consensus_diag", "fingerprint": "raw_diag",
                                "unsmoothed": "unsmoothed_diag"}[defence]
                    rec["eligible"] = cl[key_diag] == y and (defence != "fingerprint" or bool(cl["fp_accept"]))
                rec["sec"] = time.time() - ts
                jl_append(out, rec)
            n_new += 1
            if n_new % 20 == 0:
                L.log(f"  {defence}: {n_new}/{len(todo)} alerts ({(time.time()-t0)/n_new:.1f}s per alert)")
        L.log(f"stage 7 {defence} done")


def random_edits(ctx, x0, y, c, eps, D, rng):
    """Random feasible edits with the same budget (no optimisation), against raw SHAP."""
    cfg = ctx.cfg; m = len(ctx.mut); lo, hi = ctx.bounds_for(x0)
    B = cfg["budget"]
    app = ctx.app_mask(x0).astype(float)
    if app.sum() == 0: return {"found": False, "success": False, "evals": 0, "feasible": 0}
    dd = rng.standard_normal((B, m)) * app; dd /= np.linalg.norm(dd, axis=1, keepdims=True)
    U = dd * eps * rng.random((B, 1)) ** (1 / max(app.sum(), 1))
    Xc = np.repeat(x0[None], B, axis=0); Xc[:, ctx.mut] = x0[ctx.mut] + U / ctx.W
    Xc = ctx.project(Xc, x0, lo, hi)
    ok = (ctx.dW(Xc, x0) <= eps * (1 + 1e-9)) & (ctx.score(Xc) >= ctx.thr)
    if not ok.any(): return {"found": False, "success": False, "evals": B, "feasible": 0}
    diag = D["raw"].predict(ctx.topk(ctx.shap(Xc[ok])))
    return {"found": True, "success": bool((diag == c).any()), "evals": B, "feasible": int(ok.sum()),
            "untargeted": bool((diag != y).any())}


def validate_assuredx(ctx, sm, res, x0, c, eps, D, alert_id):
    """Defender-side validation with independent samples (Algorithm 1 at x')."""
    cfg = ctx.cfg
    out = {"found": res["x_adv"] is not None, "evals": res["evals"], "feasible": res["feasible"]}
    cands = [x for x in (res["x_adv"], res["x_hit"]) if x is not None]
    succ_any = succ_cert = False; radius_adv = None
    for j, x in enumerate(cands):
        r = np.random.default_rng(cfg["seed"] * 999331 + int(alert_id) * 7 + int(eps * 1000) + j)
        p, _ = sm.frequencies(x[None], cfg["n_cert"], r)
        M, gap, R = certify(p, cfg["n_cert"], ctx.k, sm.sigma, cfg["alpha"], ctx.d)
        diag = D["assuredx"].predict(M)[0]
        if diag == c:
            succ_any = True
            if gap[0] > 0: succ_cert = True
        if j == 0: radius_adv = float(R[0]); out["mass_after"] = float(decoy_mass_from_members(p, ctx, c)[0])
    out.update({"success": succ_any, "success_certified_output": succ_cert, "radius_at_adv": radius_adv})
    if cands: out["dW"] = float(ctx.dW(cands[0][None], x0)[0])
    return out


# ==========================================================================
# STAGE 8 - summary
# ==========================================================================
def md(df, index=True):
    """Plain markdown table (avoids the optional 'tabulate' dependency)."""
    d = df.copy()
    if index: d = d.reset_index()
    fmt = lambda v: (f"{v:.4f}" if isinstance(v, (float, np.floating)) and not np.isnan(v) else
                     ("" if isinstance(v, (float, np.floating)) else str(v)))
    head = "| " + " | ".join(map(str, d.columns)) + " |"
    sep = "|" + "---|" * len(d.columns)
    body = ["| " + " | ".join(fmt(v) for v in r) + " |" for r in d.itertuples(index=False)]
    return "\n".join([head, sep] + body)

def cluster_boot(df, col, groups, B, seed):
    """Capture-level bootstrap of a mean (files are resampled with replacement)."""
    if len(df) == 0: return (np.nan, np.nan, np.nan)
    rng = np.random.default_rng(seed)
    g = df[groups].values; u = np.unique(g)
    sums = df.groupby(groups)[col].sum().reindex(u).values
    cnts = df.groupby(groups)[col].count().reindex(u).values
    est = sums.sum() / cnts.sum()
    bs = []
    for _ in range(B):
        pick = rng.integers(0, len(u), len(u))
        bs.append(sums[pick].sum() / max(cnts[pick].sum(), 1))
    return est, np.quantile(bs, 0.025), np.quantile(bs, 0.975)

def stage8_summary(ctx):
    cfg = ctx.cfg; B = cfg["bootstrap"]
    D = load_defences(ctx)
    clean = jl_read(ctx.p("stage6", "clean.jsonl"))
    alerts = stage4_alerts(ctx)
    clean = clean.merge(alerts[["alert_id", "source_file"]], on="alert_id")
    s = f"s{ctx.sigma}"
    lines = [f"# AssureDx results ({time.strftime('%Y-%m-%d %H:%M')})", "",
             f"k = {ctx.k}, sigma (selected on validation) = {ctx.sigma}, n_cert = {cfg['n_cert']}, "
             f"alpha = {cfg['alpha']}, budget = {cfg['budget']} candidates", ""]

    # clean diagnostic accuracy per defence
    rows = []
    for name, col in (("Raw SHAP", "raw_diag"), ("Consensus", "consensus_diag"),
                      ("Unsmoothed decoder", "unsmoothed_diag")) + tuple(
                     (f"AssureDx sigma={x}", f"s{x}_diag") for x in cfg["sigmas"]):
        acc = (clean[col] == clean["family"]).mean()
        from sklearn.metrics import f1_score
        rows.append({"explanation": name, "clean_diag_accuracy": acc,
                     "clean_diag_macro_f1": f1_score(clean["family"], clean[col], average="macro")})
    rows.append({"explanation": "Fingerprint (clean acceptance)", "clean_diag_accuracy": clean["fp_accept"].mean(),
                 "clean_diag_macro_f1": np.nan})
    t1 = pd.DataFrame(rows); t1.to_csv(ctx.p("stage8", "clean_diagnosis.csv"), index=False)
    lines += ["## Clean diagnosis on the attacked alert set", "", md(t1, index=False), ""]

    # certification: coverage and useful certified coverage
    cov = []
    for x in cfg["sigmas"]:
        R = clean[f"s{x}_radius"]; correct = clean[f"s{x}_diag"] == clean["family"]
        for r in cfg["eps"]:
            cov.append({"sigma": x, "radius": r, "certified_coverage": (R >= r).mean(),
                        "useful_certified_coverage": ((R >= r) & correct).mean()})
        cov.append({"sigma": x, "radius": "any>0", "certified_coverage": (R > 0).mean(),
                    "useful_certified_coverage": ((R > 0) & correct).mean()})
    t2 = pd.DataFrame(cov); t2.to_csv(ctx.p("stage8", "certified_coverage.csv"), index=False)
    lines += ["## Certified coverage (clean alerts)", "", md(t2, index=False), ""]
    fid = {f"sigma={x}": {"overlap_with_raw_topk": clean[f"s{x}_overlap_raw"].mean(),
                          "unique_neighbours_median": clean[f"s{x}_unique_neighbours"].median(),
                          "sec_per_certificate_median": clean[f"s{x}_sec"].median(),
                          "median_radius": clean[f"s{x}_radius"].median()} for x in cfg["sigmas"]}
    fid["unsmoothed"] = {"overlap_with_raw_topk": clean["unsmoothed_overlap_raw"].mean(),
                         "decoder_distance_median": clean["decoder_dist"].median()}
    fid["consensus"] = {"overlap_with_raw_topk": clean["consensus_overlap_raw"].mean()}
    t3 = pd.DataFrame(fid).T; t3.to_csv(ctx.p("stage8", "fidelity.csv"))
    lines += ["## Neighbourhood fidelity and cost", "", md(t3), ""]

    sw = jl_read(ctx.p("stage6", "n_sweep.jsonl"))
    if len(sw):
        t4 = sw.groupby("n").agg(certified=("radius", lambda v: (v > 0).mean()),
                                 median_radius=("radius", "median"), sec=("sec", "median"))
        t4.to_csv(ctx.p("stage8", "n_sweep.csv"))
        lines += ["## Sampling budget (selected sigma)", "", md(t4), ""]
    nv = jl_read(ctx.p("stage6", "naive.jsonl"))
    if len(nv):
        t5 = nv.groupby("sigma").agg(invalid_sample_fraction=("invalid_frac", "mean"),
                                     range_violation=("range_violation_frac", "mean"),
                                     order_violation=("order_violation_frac", "mean"),
                                     identity_violation=("identity_violation_frac", "mean"),
                                     detector_flip_fraction=("detector_flip_frac", "mean"),
                                     certified=("radius", lambda v: (v > 0).mean()),
                                     overlap_with_raw=("overlap_raw", "mean"))
        t5.to_csv(ctx.p("stage8", "naive_smoothing.csv"))
        lines += ["## Naive feature-space smoothing (no decoder)", "", md(t5), ""]

    # attacks: TMR on each defence's own eligible set, with capture-level bootstrap
    res = []
    for defence in ("random", "raw", "consensus", "fingerprint", "unsmoothed", "assuredx"):
        A = jl_read(ctx.p("stage7", f"attack_{defence}.jsonl"))
        if not len(A): continue
        A["eligible"] = A["eligible"].astype(bool)
        for eps, g in A.groupby("eps"):
            E = g[g.eligible].copy(); E["succ"] = E["success"].astype(float)
            est, lo_, hi_ = cluster_boot(E, "succ", "source_file", B, cfg["seed"])
            row = {"defence": defence, "eps": eps, "eligible": len(E), "attacked": len(g),
                   "TMR": est, "TMR_lo": lo_, "TMR_hi": hi_,
                   "feasible_found": g["found"].mean() if "found" in g else np.nan}
            if defence == "assuredx":
                E["sc"] = E["success_certified_output"].astype(float)
                row["TMR_certified_output"] = E["sc"].mean() if len(E) else np.nan
                row["provably_immune"] = E["certified_at_eps"].mean() if len(E) else np.nan
            res.append(row)
    Araw = jl_read(ctx.p("stage7", "attack_raw.jsonl")); Arnd = jl_read(ctx.p("stage7", "attack_random.jsonl"))
    if len(Araw) and len(Arnd):
        Mg = Araw.merge(Arnd[["key", "success"]].rename(columns={"success": "succ_rnd"}), on="key")
        Mg["eligible"] = Mg["eligible"].astype(bool)
        for eps, g in Mg.groupby("eps"):
            E = g[g.eligible].copy(); E["succ"] = (E["success"].astype(bool) | E["succ_rnd"].astype(bool)).astype(float)
            est, lo_, hi_ = cluster_boot(E, "succ", "source_file", B, cfg["seed"])
            res.append({"defence": "raw_strongest", "eps": eps, "eligible": len(E), "attacked": len(g),
                        "TMR": est, "TMR_lo": lo_, "TMR_hi": hi_, "feasible_found": g["found"].mean()})
    if res:
        t6 = pd.DataFrame(res); t6.to_csv(ctx.p("stage8", "tmr.csv"), index=False)
        piv = t6.pivot(index="eps", columns="defence", values="TMR")
        lines += ["## Targeted misattribution rate (own eligible set)", "", md(t6, index=False), "",
                  "### TMR by defence", "", md(piv), ""]
    open(ctx.p("stage8", "results.md"), "w", encoding="utf-8").write("\n".join(lines))
    L.log("stage 8 done: " + ctx.p("stage8", "results.md"))
    print("\n".join(lines))


# ==========================================================================
# STAGE 9 - diagnosis-level certificate (smoothed diagnosis)
# ==========================================================================
def cp_lower(k, n, alpha):
    from scipy.stats import beta
    return float(beta.ppf(alpha, k, n - k + 1)) if k > 0 else 0.0

def diag_certify(ctx, sm, x, clf, n0, n, alpha, seed):
    """CERTIFY for the smoothed diagnosis g(x) = argmax_c P[h(S_k(D(a(x)+sigma Z))) = c]:
    the class is selected on n0 samples, its probability is bounded below on n independent
    samples (Clopper-Pearson, level alpha), and R = sigma * PhiInv(p_lower) when p_lower > 1/2."""
    r0 = np.random.default_rng(seed); r1 = np.random.default_rng(seed + 1)
    v0 = sm.votes(x[None], n0, r0, clf)[0]
    cA = int(v0.argmax())
    v = sm.votes(x[None], n, r1, clf)[0]
    kA = int(round(v[cA] * n))
    pl = cp_lower(kA, n, alpha)
    R = sm.sigma * norm.ppf(pl) if pl > 0.5 else 0.0
    return {"class": clf.classes_[cA], "p_hat": float(v[cA]), "p_lower": pl,
            "radius": float(np.floor(max(R, 0) * 1e6) / 1e6), "mode_full": clf.classes_[int(v.argmax())]}

def stage9_diagnosis_certificates(ctx):
    cfg = ctx.cfg
    D = load_defences(ctx); bank = _ctx_bank(ctx)
    alerts = stage4_alerts(ctx); te = ctx.split("test")
    clf = D["raw"]
    out = ctx.p("stage9", "diag_cert.jsonl"); done = jl_done(out, "key")
    t0 = time.time(); n_new = 0
    sweep_ids = set(alerts.groupby("family").head(max(1, cfg["n_sweep_alerts"] // len(ctx.families))).alert_id)
    for _, a in alerts.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64")
        for s in cfg["sigmas"]:
            sm = Smoother(ctx, bank, x0, s)
            for n in ([cfg["n_cert"]] + ([10000] if (a.alert_id in sweep_ids and s == ctx.sigma) else [])):
                key = f"{a.alert_id}_{s}_{n}"
                if key in done: continue
                ts = time.time()
                r = diag_certify(ctx, sm, x0, clf, 100, n, cfg["alpha"],
                                 cfg["seed"] * 7777 + int(a.alert_id) * 101 + int(1000 * s) + n)
                r.update({"key": key, "alert_id": int(a.alert_id), "family": a.family, "sigma": s, "n": n,
                          "correct": r["class"] == a.family, "sec": time.time() - ts})
                jl_append(out, r)
        n_new += 1
        if n_new % 100 == 0:
            L.log(f"  diagnosis certificates: {n_new}/{len(alerts)} alerts ({(time.time()-t0)/n_new:.2f}s each)")
    L.log("stage 9 certificates done")

    # adaptive attack on the smoothed diagnosis (subset)
    vout = ctx.p("stage9", "attack_vote.jsonl"); vdone = jl_done(vout, "key")
    cert = jl_read(out); cert = cert[(cert.n == cfg["n_cert"]) & (cert.sigma == ctx.sigma)].set_index("alert_id")
    sub = alerts.groupby("family").head(cfg["vote_alerts_per_family"])
    t0 = time.time(); n_new = 0
    for _, a in sub.iterrows():
        x0 = te[ctx.feats].values[a.row].astype("float64"); y, c = a.family, a.decoy
        for eps in cfg["vote_eps"]:
            key = f"{a.alert_id}_{eps}"
            if key in vdone: continue
            rng = np.random.default_rng(cfg["seed"] * 31337 + int(a.alert_id) * 97 + int(eps * 1000))
            sm = Smoother(ctx, bank, x0, ctx.sigma); sm.localise(eps)
            ts = time.time()
            res = attack_one(ctx, x0, y, c, eps, "assuredx_vote", D, rng, state={"smoother": sm})
            succ = succ_cert = False
            for j, x in enumerate([v for v in (res["x_adv"], res["x_hit"]) if v is not None]):
                rv = diag_certify(ctx, sm, x, clf, 100, cfg["n_cert"], cfg["alpha"],
                                  cfg["seed"] * 424243 + int(a.alert_id) * 7 + int(eps * 1000) + 10 * j)
                if rv["class"] == c:
                    succ = True
                    if rv["p_lower"] > 0.5: succ_cert = True
            cl = cert.loc[a.alert_id]
            jl_append(vout, {"key": key, "alert_id": int(a.alert_id), "family": y, "decoy": c, "eps": eps,
                             "source_file": a.source_file, "eligible": bool(cl["correct"]),
                             "clean_radius": float(cl["radius"]), "certified_at_eps": float(cl["radius"]) >= eps,
                             "success": succ, "success_certified_output": succ_cert,
                             "found": res["x_adv"] is not None, "evals": res["evals"], "sec": time.time() - ts})
        n_new += 1
        if n_new % 20 == 0:
            L.log(f"  vote attack: {n_new}/{len(sub)} alerts ({(time.time()-t0)/n_new:.1f}s per alert)")
    L.log("stage 9 vote attack done")


def stage10_diag_summary(ctx):
    cfg = ctx.cfg
    alerts = stage4_alerts(ctx)
    cert = jl_read(ctx.p("stage9", "diag_cert.jsonl"))
    clean = jl_read(ctx.p("stage6", "clean.jsonl")).set_index("alert_id")
    lines = [f"# Diagnosis-level certificate ({time.strftime('%Y-%m-%d %H:%M')})", "",
             f"Smoothed diagnosis = plurality of the frozen raw diagnoser over decoded valid flows; "
             f"n0 = 100 selection samples, Clopper-Pearson lower bound at alpha = {cfg['alpha']}.", ""]
    rows = []
    for s in cfg["sigmas"]:
        C = cert[(cert.sigma == s) & (cert.n == cfg["n_cert"])].set_index("alert_id")
        setR = clean.loc[C.index, f"s{s}_radius"]; setok = clean.loc[C.index, f"s{s}_diag"] == C["family"]
        r = {"sigma": s, "clean_accuracy": C["correct"].mean(), "certified_any": (C.radius > 0).mean(),
             "median_radius_certified": C.radius[C.radius > 0].median()}
        for e in cfg["eps"]:
            r[f"useful@{e}"] = ((C.radius >= e) & C.correct).mean()
            r[f"set_useful@{e}"] = ((setR >= e) & setok).mean()
        rows.append(r)
    t = pd.DataFrame(rows); t.to_csv(ctx.p("stage10", "diag_certificate.csv"), index=False)
    lines += ["## Useful certified coverage: diagnosis certificate vs set certificate (n = 1000)", "",
              md(t, index=False), ""]
    S = cert[cert.n == 10000]
    if len(S):
        C1 = cert[(cert.n == cfg["n_cert"]) & (cert.sigma == ctx.sigma) & cert.alert_id.isin(S.alert_id)]
        t2 = pd.DataFrame({"n": [cfg["n_cert"], 10000],
                           "certified": [(C1.radius > 0).mean(), (S.radius > 0).mean()],
                           "median_radius": [C1.radius.median(), S.radius.median()],
                           "sec": [C1.sec.median(), S.sec.median()]})
        lines += ["## Sampling budget (selected sigma, subset)", "", md(t2, index=False), ""]
    V = jl_read(ctx.p("stage9", "attack_vote.jsonl"))
    if len(V):
        V["eligible"] = V["eligible"].astype(bool)
        res = []
        for eps, g in V.groupby("eps"):
            E = g[g.eligible].copy(); E["succ"] = E.success.astype(float)
            est, lo_, hi_ = cluster_boot(E, "succ", "source_file", cfg["bootstrap"], cfg["seed"])
            res.append({"eps": eps, "eligible": len(E), "TMR": est, "TMR_lo": lo_, "TMR_hi": hi_,
                        "TMR_certified_output": E.success_certified_output.mean(),
                        "provably_immune": E.certified_at_eps.mean()})
        t3 = pd.DataFrame(res); t3.to_csv(ctx.p("stage10", "tmr_vote.csv"), index=False)
        lines += ["## Adaptive attack on the smoothed diagnosis", "", md(t3, index=False), ""]
    open(ctx.p("stage10", "diag_results.md"), "w", encoding="utf-8").write("\n".join(lines))
    print("\n".join(lines))


STAGES = {4: stage4_alerts, 5: stage5_defences, 6: stage6_clean, 7: stage7_attacks, 8: stage8_summary,
          9: stage9_diagnosis_certificates, 10: stage10_diag_summary}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", type=int, nargs="+")
    ap.add_argument("--base", required=True, help="finished stage 0-3 results folder")
    ap.add_argument("--out", required=True, help="results folder for stages 4-8")
    ap.add_argument("--k", type=int, default=None)
    ap.add_argument("--quick", action="store_true", help="tiny settings for a smoke test")
    ap.add_argument("--stratum-mask", action="store_true",
                    help="restrict edits to mutable fields that vary within the alert's protocol stratum")
    a = ap.parse_args()
    over = {"k": a.k}
    if a.stratum_mask: over["stratum_mutable_mask"] = True
    if a.quick:
        over.update(alerts_per_family=4, adaptive_alerts_per_family=2, budget=100, restarts=2, batch=10,
                    n_cert=200, n_sweep=[100, 300], n_sweep_alerts=7, n_train_expl=64,
                    diag_train_per_family=60, fp_train_attacks=40, naive_alerts_per_family=2,
                    naive_n=64, bootstrap=200, bank_per_stratum=5000, eps=[0.1, 1.0])
    ctx = Ctx(a.base, a.out, **over)
    L.log(f"assuredx_attack {ATTACK_VERSION}: base {a.base}")
    for s in a.stage:
        STAGES[s](ctx)
