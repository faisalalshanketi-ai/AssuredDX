"""Figure 1 of the paper: targeted misattribution rate versus attack budget.

usage: python make_figure.py <ciciot2023_run_dir> <edgeiiot_run_dir> [out.png]
"""
import sys
import pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

def jl(p): return pd.read_json(p, lines=True).assign(eps=lambda d: d.eps.round(4))

def panel(ax, run, title):
    t = pd.read_csv(f"{run}/stage8/tmr.csv")
    line = lambda e, v, lab, c, m, ls, lw=1.5, ms=5: ax.plot(e, v, marker=m, color=c, ls=ls, label=lab, lw=lw, ms=ms)
    for k, (lab, c, m, ls) in {"raw_strongest": ("No defence", "#444444", "o", "-"),
                               "fingerprint": ("Fingerprint, supervised", "#d62728", "s", "--"),
                               "consensus": ("Consensus", "#ff7f0e", "^", ":")}.items():
        s = t[t.defence == k].sort_values("eps"); line(s.eps, s.TMR, lab, c, m, ls)
    F = jl(f"{run}/stage12/attack_fingerprint_ae.jsonl"); F = F[F.eligible.astype(bool)]
    s = F.groupby("eps").success.mean(); line(s.index, s.values, "Fingerprint, Sharma et al.", "#8c564b", "P", "--")
    U = jl(f"{run}/stage11/voronoi_unsmoothed.jsonl"); S = jl(f"{run}/stage7/attack_unsmoothed.jsonl")
    m = U.merge(S[["alert_id", "eps", "success"]], on=["alert_id", "eps"], suffixes=("", "_r")); m = m[m.eligible.astype(bool)]
    s = (m.success.astype(bool) | m.success_r.astype(bool)).groupby(m.eps).mean(); line(s.index, s.values, "Unsmoothed decoder", "#9467bd", "v", "-.")
    V = jl(f"{run}/stage9/attack_vote.jsonl"); C = jl(f"{run}/stage11/voronoi_assuredx.jsonl")
    m = V.merge(C[["alert_id", "eps", "success_certified_output"]], on=["alert_id", "eps"], suffixes=("", "_v")); m = m[m.eligible.astype(bool)]
    s = (m.success_certified_output.astype(bool) | m.success_certified_output_v.astype(bool)).groupby(m.eps).mean()
    line(s.index, s.values, "AssureDx (deployed)", "#2ca02c", "*", "-", 2, 9)
    ax.set_xscale("log"); ax.set_title(title); ax.set_xlabel("Attack budget ε (scaled L2)"); ax.grid(alpha=.3)

if __name__ == "__main__":
    fig, axs = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    panel(axs[0], sys.argv[1], "CICIoT2023"); panel(axs[1], sys.argv[2], "Edge-IIoTset")
    axs[0].set_ylabel("Targeted misattribution rate")
    h, l = axs[0].get_legend_handles_labels(); fig.legend(h, l, loc="lower center", ncol=6, fontsize=7.2, frameon=False)
    fig.tight_layout(rect=(0, 0.08, 1, 1)); fig.savefig(sys.argv[3] if len(sys.argv) > 3 else "fig_tmr.png", dpi=220)
