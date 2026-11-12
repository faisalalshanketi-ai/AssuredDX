"""Builds the Supplementary Materials (Tables S1-S17) from the released results.

usage: python make_supplementary.py <results_dir> <out.md>
then:  pandoc <out.md> -o Supplementary.docx
"""
import json, os, sys
import numpy as np
import pandas as pd

AUTHOR_LINE = os.environ.get("AUTHOR_LINE", "")  # optional author line for the supplement header

RES = sys.argv[1]; OUT = sys.argv[2]
DET = os.path.join(RES, "detection_and_explanations")
RUNS = {"CICIoT2023": os.path.join(RES, "ciciot2023_k5"), "Edge-IIoTset": os.path.join(RES, "edgeiiot_k5")}
BASES = {"CICIoT2023": os.path.join(DET, "ciciot2023_clean"), "Edge-IIoTset": os.path.join(DET, "edgeiiot_noport")}
EPS = [0.01, 0.03, 0.1, 0.3, 1.0]
L = []

def jl(p): return pd.read_json(p, lines=True).assign(eps=lambda d: d.eps.round(4))

def md(df):
    cols = list(df.columns)
    out = ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
    for r in df.itertuples(index=False):
        out.append("| " + " | ".join("" if (isinstance(v, float) and np.isnan(v)) else str(v) for v in r) + " |")
    return "\n".join(out)

def boot(succ, groups, B=2000, seed=7):
    """Capture-level bootstrap of a mean (same scheme as assuredx_attack.cluster_boot)."""
    d = pd.DataFrame({"s": succ.astype(float).values, "g": groups.values})
    if not len(d): return np.nan, np.nan, np.nan
    sums = d.groupby("g").s.sum(); cnts = d.groupby("g").s.count(); u = len(sums)
    rng = np.random.default_rng(seed); bs = []
    for _ in range(B):
        pick = rng.integers(0, u, u); bs.append(sums.values[pick].sum() / max(cnts.values[pick].sum(), 1))
    return sums.sum() / cnts.sum(), np.quantile(bs, .025), np.quantile(bs, .975)

def cell(est, lo, hi, n=None):
    if np.isnan(est): return "–"
    return f"{est:.3f} [{lo:.3f}, {hi:.3f}]"

L += ["# Supplementary Materials", "",
      "**Certified Attack Diagnosis for Explainable Intrusion Detection in IoT Security Operations**", "",
      AUTHOR_LINE, "",
      "All tables are generated from the released per-alert results by `analysis/make_supplementary.py`. "
      "TMR denotes the targeted misattribution rate (Equation (9) of the main text); intervals are 95% capture-level bootstrap intervals with 2,000 replicates.", ""]

# ---------------- S1 feature roles ----------------
L += ["## Table S1. Feature roles, ranges and scales used by the threat model and the decoder.", ""]
for name, base in BASES.items():
    tax = json.load(open(os.path.join(base, "taxonomy.json")))
    rows = []
    for f in tax["features"]:
        role = tax["roles"][f]
        w = tax["W"].get(f)
        rows.append({"Feature": f, "Role": role, "Range (0.1%–99.9% quantile)": f"{tax['lo'][f]:.4g} – {tax['hi'][f]:.4g}",
                     "Scale W": f"{w:.4g}" if w is not None else "–"})
    L += [f"**{name}** ({len(tax['features'])} features; protocol strata: " +
          ", ".join(f"{k} {v:,}" for k, v in tax.get("strata_counts", {}).items()) + " training rows).", "", md(pd.DataFrame(rows)), ""]
    ids = {k: v for k, v in tax.get("identities", {}).items() if v.get("used")}
    if ids or tax.get("order_constraints"):
        txt = []
        if ids: txt.append("derived identities " + ", ".join(ids))
        oc = [f"{c['lo']} ≤ {c['hi']}" for c in tax.get("order_constraints", []) if c.get("used")]
        if oc: txt.append("order constraints " + "; ".join(oc))
        L += ["Enforced after every edit: " + "; ".join(txt) + ".", ""]

# ---------------- S2 decoy groups ----------------
L += ["## Table S2. Decoy feature groups per attack family (five mutable features with the highest family-contrast attribution on training data).", ""]
for name, base in BASES.items():
    g = json.load(open(os.path.join(base, "decoy_groups.json")))
    L += [f"**{name}**", "", md(pd.DataFrame([{"Family": k, "Decoy group G_c": ", ".join(v)} for k, v in g.items()])), ""]

# ---------------- S3 TMR all defences, own eligible, strongest attack ----------------
L += ["## Table S3. Targeted misattribution rate of every defence at every budget, each on its own eligible set, under the strongest available attack (k = 5).", ""]
for name, run in RUNS.items():
    al = pd.read_csv(os.path.join(run, "stage4", "alerts.csv")).set_index("alert_id")
    R = {d: jl(os.path.join(run, "stage7", f"attack_{d}.jsonl")) for d in ["raw", "random", "fingerprint", "consensus", "unsmoothed", "assuredx"]}
    R["fp_ae"] = jl(os.path.join(run, "stage12", "attack_fingerprint_ae.jsonl"))
    R["mus"] = jl(os.path.join(run, "stage12", "attack_mus.jsonl"))
    R["vor_u"] = jl(os.path.join(run, "stage11", "voronoi_unsmoothed.jsonl"))
    R["vote"] = jl(os.path.join(run, "stage9", "attack_vote.jsonl"))
    R["vor_c"] = jl(os.path.join(run, "stage11", "voronoi_assuredx.jsonl"))
    R["gate"] = jl(os.path.join(run, "stage14", "attack_gate.jsonl"))
    for v in R.values(): v["eligible"] = v.eligible.astype(bool); v["success"] = v.success.astype(bool)
    rows = []
    def add(label, df, succ_col="success", other=None, other_col="success"):
        r = {"Defence": label}
        for e in EPS:
            g = df[df.eps == e].set_index("alert_id")
            if not len(g): r[f"ε = {e}"] = "–"; continue
            s = g[succ_col].astype(bool)
            if other is not None:
                o = other[other.eps == e].set_index("alert_id").reindex(g.index)
                s = s | o[other_col].fillna(False).astype(bool)
            el = g.eligible
            est, lo, hi = boot(s[el], al.loc[s[el].index, "source_file"])
            r[f"ε = {e}"] = cell(est, lo, hi)
        r["n"] = int(df[df.eps == df.eps.max()].eligible.sum())
        rows.append(r)
    add("No defence (targeted or random edits)", R["raw"], other=R["random"])
    add("Random feasible edits only", R["random"])
    add("Fingerprint, Sharma et al. (autoencoder)", R["fp_ae"])
    add("Fingerprint, supervised variant", R["fingerprint"])
    add("Consensus (TreeSHAP, Saabas, occlusion)", R["consensus"])
    add("Multiplicative smoothing, adapted from Xue et al.", R["mus"])
    add("Unsmoothed decoder (strongest attack)", R["unsmoothed"], other=R["vor_u"])
    add("AssureDx set, reference search", R["assuredx"])
    add("AssureDx diagnosis, always output (strongest attack)", R["vote"], other=R["vor_c"])
    add("AssureDx diagnosis, certified outputs only", R["vote"], "success_certified_output", R["vor_c"], "success_certified_output")
    add("AssureDx behind fingerprint gate, certified outputs", R["gate"], "success_certified_output")
    L += [f"**{name}**", "", md(pd.DataFrame(rows)), ""]
L += ["n is the eligible count, which depends only on the clean alert and is therefore the same at every budget (Table S8); the multiplicative smoother and the diagnosis attacks run on the subsets described in Section 9.4 of the main text. An interval of [0, 0] reflects zero observed successes among n eligible alerts; the exact one-sided 95% upper bound on the underlying rate is then 3/n approximately.", ""]

# ---------------- S4 per family ----------------
L += ["## Table S4. Per-family targeted misattribution rate on the common eligible set under the reference search (k = 5).", ""]
for name, run in RUNS.items():
    txt = open(os.path.join(run, "paper_numbers.md")).read()
    for e in ("0.1", "0.3"):
        key = f"## Per-family TMR, common set, eps = {e}"
        if key not in txt: continue
        block = txt.split(key)[1].split("##")[0].split("Raw successful")[0].strip().splitlines()
        hdr = ["Family"] + block[0].split(); data = [ln.split() for ln in block[2:] if ln.strip()]
        df = pd.DataFrame(data, columns=hdr).rename(columns={"raw": "No defence", "fingerprint": "Fingerprint (supervised)",
                                                             "unsmoothed": "Unsmoothed decoder", "assuredx": "AssureDx set",
                                                             "assuredx_diag": "AssureDx diagnosis"})
        L += [f"**{name}, ε = {e}**", "", md(df), ""]

# ---------------- S5 k = 10 ----------------
k10 = os.path.join(RES, "ciciot2023_k10")
if os.path.exists(k10):
    L += ["## Table S5. Sensitivity analysis with k = 10 on CICIoT2023 (σ = 0.1 selected on validation; reference search).", ""]
    t = pd.read_csv(os.path.join(k10, "stage8", "tmr.csv"))
    piv = t.assign(v=[cell(a, b, c) for a, b, c in zip(t.TMR, t.TMR_lo, t.TMR_hi)]).pivot(index="defence", columns="eps", values="v")
    piv.columns = [f"ε = {c}" for c in piv.columns]
    names = {"raw_strongest": "No defence (targeted or random edits)", "raw": "No defence, targeted search only", "random": "Random feasible edits only",
             "fingerprint": "Fingerprint, supervised variant", "consensus": "Consensus", "unsmoothed": "Unsmoothed decoder (reference search)",
             "assuredx": "AssureDx set (reference search)"}
    piv = piv.reset_index(); piv["defence"] = piv.defence.map(names).fillna(piv.defence)
    L += ["**Own eligible sets**", "", md(piv.rename(columns={"defence": "Defence"})), ""]
    v = pd.read_csv(os.path.join(k10, "stage10", "tmr_vote.csv"))
    v = v.assign(TMR=[cell(a, b, c) for a, b, c in zip(v.TMR, v.TMR_lo, v.TMR_hi)])[["eps", "eligible", "TMR", "TMR_certified_output", "provably_immune"]]
    v.columns = ["ε", "Eligible", "AssureDx diagnosis TMR", "Certified outputs only", "Provably immune"]
    L += ["**Attack on the smoothed diagnosis**", "", md(v.round(3)), ""]
    d = pd.read_csv(os.path.join(k10, "stage10", "diag_certificate.csv")).round(3)
    d = d[["sigma", "clean_accuracy", "certified_any", "median_radius_certified", "useful@0.01", "useful@0.03", "useful@0.1", "useful@0.3"]]
    d.columns = ["σ", "Clean accuracy", "Certified (any radius)", "Median radius", "Useful r = 0.01", "Useful r = 0.03", "Useful r = 0.1", "Useful r = 0.3"]
    L += ["**Diagnosis-certificate coverage**", "", md(d), ""]

# ---------------- S6 detection ----------------
L += ["## Table S6. Detector performance per seed (binary task, natural test distribution) and multiclass results.", ""]
for name, base in BASES.items():
    b = pd.read_csv(os.path.join(base, "binary_metrics.csv"))
    b = b[b.view == "natural"][["model", "seed", "accuracy", "precision", "attack_recall", "fpr", "macro_f1", "auc"]].round(4)
    L += [f"**{name}, main run (binary)**", "", md(b), ""]
    m = pd.read_csv(os.path.join(base, "multiclass_metrics.csv")).round(4)
    L += [f"**{name}, main run (multiclass; '8class' denotes the family level, '34class' the attack level)**", "", md(m), ""]
for run, label in (("ciciot2023", "CICIoT2023, all 39 features (with the Number artefact), file-level split"),
                   ("ciciot2023_rowsplit", "CICIoT2023 per-class files, random row split"),
                   ("ciciot2023_merged", "CICIoT2023 merged release, random row split")):
    p = os.path.join(DET, run, "multiclass_metrics.csv")
    if os.path.exists(p):
        L += [f"**{label}**", "", md(pd.read_csv(p).round(4)), ""]

# ---------------- S7 decoder ----------------
L += ["## Table S7. Decoder and certificate statistics (k = 5).", ""]
BANK = {"CICIoT2023": "icmp 19,849; other 46,928; tcp 49,160; udp 48,854",
        "Edge-IIoTset": "icmp 1; other 1; tcp 869; udp 6"}
for name, run in RUNS.items():
    L += [f"**{name}.** Distinct flows in the decoder bank per protocol stratum (after deduplication of up to 50,000 sampled training flows): {BANK[name]}.", ""]
    f = pd.read_csv(os.path.join(run, "stage8", "fidelity.csv")).rename(columns={"Unnamed: 0": "Representation"}).round(4)
    L += [md(f), ""]
    s = pd.read_csv(os.path.join(run, "stage8", "n_sweep.csv")).round(4)
    L += ["Sampling-budget sweep of the set certificate (selected σ):", "", md(s), ""]
    nv = pd.read_csv(os.path.join(run, "stage8", "naive_smoothing.csv")).round(4)
    L += ["Naive feature-space Gaussian smoothing (ablation):", "", md(nv), ""]

# ---------------- S8-S11 (CSVs written by analysis/supplement_tables.py) ----------------
def rv(name, f): return pd.read_csv(os.path.join(RUNS[name], "extended", f))
L += ["## Table S8. Sample-flow accounting (k = 5).", "",
      "Alerts sampled at stage 4, the subsets on which the adaptive and diagnosis attacks run, and the eligible set of each defence. Eligibility depends only on the clean alert, so each count is the same at every budget.", ""]
for name in RUNS:
    d = rv(name, "sample_flow.csv"); d["Alerts"] = [f"{v:.3f}" if v < 1 else f"{int(v)}" for v in d.Alerts]
    L += [f"**{name}**", "", md(d), ""]
L += ["## Table S9. Results per protocol stratum (k = 5).", "",
      "Clean accuracy of the smoothed and raw diagnoses, share certified, share certified and correct with radius at least 0.03, and targeted misattribution of the smoothed diagnosis under the strongest attack (always output, with eligible n; certified outputs only). On Edge-IIoTset the ICMP and 'other' banks hold one mutable vector and the alerts have no editable field, so their certificates are trivial.", ""]
for name in RUNS:
    d = rv(name, "strata.csv").rename(columns={"stratum": "Stratum", "alerts": "Alerts", "clean_acc_smoothed": "Accuracy, smoothed", "clean_acc_raw": "Accuracy, raw",
        "certified": "Certified", "useful@0.03": "Certified, correct, R ≥ 0.03", "TMR@0.1 (n)": "TMR ε = 0.1 (n)", "certTMR@0.1": "Certified TMR ε = 0.1",
        "TMR@0.3 (n)": "TMR ε = 0.3 (n)", "certTMR@0.3": "Certified TMR ε = 0.3"})
    L += [f"**{name}**", "", md(d), ""]
L += ["## Table S10. Audit of decoded smoothing samples.", "",
      "120 alerts per dataset, 1,000 decoded samples each, at the selected σ. Every decoded sample satisfies the ordering and derived-identity constraints and keeps the alert's immutable attributes. Values outside the 0.1% to 99.9% training quantile range are extreme values that occur in training flows.", ""]
for name in RUNS:
    L += [f"**{name}**", "", md(rv(name, "decoder_audit.csv")), ""]
L += ["## Table S11. Clean diagnostic accuracy, equivalence and certification.", "",
      "Paired difference between the smoothed and the raw SHAP diagnosis on all clean alerts with capture-level bootstrap intervals; equivalence by two one-sided tests at a ±5-percentage-point margin (α = 0.05, 90% interval); accuracy of certified diagnoses and of abstentions.", ""]
for name in RUNS:
    d = rv(name, "accuracy.csv").dropna(); L += [f"**{name}**", "", md(d), ""]

# ---------------- S12-S17 (extended experiments, stages 15-20; CSVs written by compile_extended.py and independence.py) ----------------
def rvo(name, f):
    q = os.path.join(RUNS[name], "extended", f)
    return pd.read_csv(q) if os.path.exists(q) else None
def block(title, intro, files):
    global L
    L += [title, "", intro, ""]
    for name in RUNS:
        for f, sub in files:
            d = rvo(name, f)
            if d is not None:
                L += [f"**{name}{(', ' + sub) if sub else ''}**", "", md(d.fillna("–")), ""]
block("## Table S12. Attack convergence and deployed outcomes.",
      "Smoothed-diagnosis attack at four search configurations on a subset of the diagnosis-attack set (eligible alerts only), combined with the decoder-aware attack. Outcomes of the deployed (certified-only) pipeline at the attacker's chosen points: certified decoy, abstention, certified correct, certified other family; R is the clean certified radius.",
      [("convergence.csv", "")])
block("## Table S13. Availability (abstention) attack on AssureDx.",
      "The attacker minimises the vote margin of the smoothed diagnosis within the budget (1,000 candidates) on clean-certified correct alerts; outcome of a fresh certification run at the attacker's points.",
      [("abstention_attack.csv", "")])
block("## Table S14. Projected Gaussian smoothing (constraint-aware, input-dependent repair).",
      "Gaussian noise on the scaled mutable features, each sample projected onto the constraints of its own centre; σ selected on validation. Certificates are nominal (Proposition 2). Clean evaluation on all alerts; attack on a subset of the diagnosis-attack set, paired with AssureDx.",
      [("projected_clean.csv", "clean"), ("projected.csv", "attack")])
block("## Table S15. Configuration-matched decoder.",
      "Bank restricted to training flows with the alert's exact immutable configuration ('matched': fallback to the protocol stratum below 50 distinct flows; 'exact': no minimum). Clean certificates and decoded-sample audit; strongest attack on the diagnosis-attack set, paired with the stratum decoder.",
      [("matched_decoder_clean.csv", "clean"), ("matched_decoder_attack.csv", "attack")])
block("## Table S16. Split independence (CICIoT2023 main comparison on independent subsets).",
      "Alerts from labels split at file level, alerts without a near-duplicate training row (standardised distance below 0.001), and both; TMR under the strongest attack on the common eligible set, with paired capture-level intervals.",
      [("independence_tmr.csv", "")])
block("## Table S17. Refusal attack on the fingerprint detector with integer-valued fields.",
      "Edge-IIoTset, 80 randomly drawn clean-accepted alerts, published threshold: share refused by the original refusal attack and by a rerun that rounds every byte and count field to an integer after projection.",
      [("refusal_integer_check_summary.csv", "")])

open(OUT, "w").write("\n".join(L))
print("written", OUT)
