"""Split-independence audit: split mode per label, exact and near duplicates
of training rows among attacked alerts, and the main paired comparison restricted to alerts
from file-level-split labels and to alerts without a (near-)duplicate in training.

usage: python independence.py <results_dir> <runs_dir>
<runs_dir>/{ciciot2023,edgeiiot}/stage0 hold the stage-0 splits and manifest.json.
Writes <results_dir>/<run>/extended/independence_alerts.csv and independence_tmr.csv.
"""
import os, sys, json
import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile_results import boot_diff
from compile_extra import load

RES, RUNS = sys.argv[1], sys.argv[2]
DS = {"ciciot2023_k5": ("ciciot2023", "ciciot2023_clean"), "edgeiiot_k5": ("edgeiiot", "edgeiiot_noport")}
NEAR = 1e-3            # near duplicate: standardized Euclidean distance below this value

for run, (s0, base) in DS.items():
    rdir = os.path.join(RES, run); st0 = os.path.join(RUNS, s0, "stage0")
    man = json.load(open(os.path.join(st0, "manifest.json")))
    feats = json.load(open(os.path.join(RES, "detection_and_explanations", base, "taxonomy.json")))["features"]
    tr = pd.read_parquet(os.path.join(st0, "train.parquet")); te = pd.read_parquet(os.path.join(st0, "test.parquet"))
    al = pd.read_csv(os.path.join(rdir, "stage4", "alerts.csv")).set_index("alert_id")
    mode = man["split_mode_per_label"]
    lab = te["label"].values[al.row.values]
    al["label"] = lab
    al["split_mode"] = ["row-level" if mode.get(l, "").startswith("row") else
                        ("file-level" if mode.get(l, "").startswith("file") else "temporal") for l in lab]
    Xtr = tr[feats].values.astype("float64"); Xa = te[feats].values[al.row.values].astype("float64")
    mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-12
    nn = NearestNeighbors(n_neighbors=1).fit((Xtr - mu) / sd)
    d = nn.kneighbors((Xa - mu) / sd)[0][:, 0]
    al["nn_dist"] = d; al["exact_dup"] = d < 1e-9; al["near_dup"] = d < NEAR
    os.makedirs(os.path.join(rdir, "extended"), exist_ok=True)
    al[["family", "label", "source_file", "split_mode", "nn_dist", "exact_dup", "near_dup"]].to_csv(
        os.path.join(rdir, "extended", "independence_alerts.csv"))
    print(f"== {run}: alerts by split mode", al.split_mode.value_counts().to_dict(),
          "| exact dup", round(al.exact_dup.mean(), 4), "| near dup", round(al.near_dup.mean(), 4))
    print("   row-level labels:", sorted({l for l, m in mode.items() if m.startswith("row")}))

    R = load(rdir); rows = []
    subsets = {"all": al.index, "file-level or temporal split": al.index[al.split_mode != "row-level"],
               "no near duplicate": al.index[~al.near_dup],
               "both": al.index[(al.split_mode != "row-level") & ~al.near_dup]}
    for e in sorted(R["vote"].eps.unique()):
        g = {k: v[v.eps == e].set_index("alert_id") for k, v in R.items()}
        common = set(g["vote"].index)
        for k in ["raw", "fingerprint", "fp_ae", "consensus", "unsmoothed", "vote"]:
            common &= set(g[k][g[k].eligible].index)
        for name, ids in subsets.items():
            c = sorted(common & set(ids))
            if len(c) < 5: rows.append({"eps": e, "subset": name, "n": len(c)}); continue
            files = al.loc[c, "source_file"]
            nd = g["raw"].success.reindex(c) | g["random"].success.reindex(c).fillna(False)
            sh = g["fp_ae"].success.reindex(c)
            cx = g["vote"].success.reindex(c) | g["vor_c"].success.reindex(c)
            cc = g["vote"].success_certified_output.astype(bool).reindex(c) | g["vor_c"].success_certified_output.astype(bool).reindex(c)
            r = {"eps": e, "subset": name, "n": len(c), "captures": files.nunique(), "no defence": round(nd.mean(), 3),
                 "Sharma et al.": round(sh.mean(), 3), "AssureDx always output": round(cx.mean(), 3),
                 "AssureDx certified only": round(cc.mean(), 3)}
            for a, b, lbl in [(cx, nd, "AssureDx - no defence"), (cx, sh, "AssureDx - Sharma et al.")]:
                dm, lo, hi = boot_diff(a, b, files); r[lbl] = f"{dm:.3f} [{lo:.3f}, {hi:.3f}]"
            rows.append(r)
    T = pd.DataFrame(rows); T.to_csv(os.path.join(rdir, "extended", "independence_tmr.csv"), index=False)
    print(T.to_string(index=False))
