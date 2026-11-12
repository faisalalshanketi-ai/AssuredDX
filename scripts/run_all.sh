#!/usr/bin/env bash
# Reproduces every experiment in the paper. All stages resume after an interruption.
# Usage: DATA=/path/to/data RUNS=/path/to/runs bash scripts/run_all.sh
set -euo pipefail
DATA=${DATA:-./data}; RUNS=${RUNS:-./runs}
SRC="$(cd "$(dirname "$0")/../src" && pwd)"; AN="$(cd "$(dirname "$0")/../analysis" && pwd)"
EDGE="$DATA/Edge-IIoTset dataset"

# ---- CICIoT2023: detectors, taxonomy and explanations (stages 0-3) ----
python "$SRC/assuredx_lib.py" 0 1 2 3 --data "$DATA/CICIoT2023" --out "$RUNS/ciciot2023"
python "$SRC/assuredx_lib.py" 0 1 2 3 --data "$DATA/CICIoT2023" --out "$RUNS/ciciot2023_clean" \
       --reuse-stage0 "$RUNS/ciciot2023" --drop Number "Tot sum"
python "$SRC/assuredx_lib.py" 0 1 --data "$DATA/CICIoT2023" --out "$RUNS/ciciot2023_rowsplit" \
       --cache-from "$RUNS/ciciot2023" --split row
python "$SRC/assuredx_lib.py" 0 1 --data "$DATA/CICIoT2023_merged/MERGED_CSV" --out "$RUNS/ciciot2023_merged" --split row

# ---- CICIoT2023: attacks, defences and certificates (stages 4-14) ----
python "$SRC/assuredx_attack.py" 4 5 6 7 8 9 10 --base "$RUNS/ciciot2023_clean" --out "$RUNS/ciciot2023_k5" --k 5
python "$SRC/assuredx_extra.py" 11 12 13 14 --base "$RUNS/ciciot2023_clean" --out "$RUNS/ciciot2023_k5"
python "$SRC/assuredx_extended.py" 15 16 17 18 19 20 --base "$RUNS/ciciot2023_clean" --out "$RUNS/ciciot2023_k5"
python "$SRC/assuredx_attack.py" 4 5 6 7 8 9 10 --base "$RUNS/ciciot2023_clean" --out "$RUNS/ciciot2023_k10" --k 10

# ---- Edge-IIoTset: stage 0 (with ports, for the audit), then the port-free model ----
python "$SRC/assuredx_lib.py" 0 1 2 3 --data "$EDGE" --out "$RUNS/edgeiiot" --dataset EdgeIIoTset
python "$SRC/assuredx_lib.py" 0 1 2 3 --data "$EDGE" --out "$RUNS/edgeiiot_noport" --dataset EdgeIIoTset \
       --reuse-stage0 "$RUNS/edgeiiot" --drop tcp.dstport udp.port
python "$SRC/assuredx_attack.py" 4 --base "$RUNS/edgeiiot_noport" --out "$RUNS/edgeiiot_k5" --k 5 --stratum-mask
python - "$RUNS/edgeiiot_k5/attack_config.json" <<'PY'
import json, sys; p = sys.argv[1]; c = json.load(open(p)); c["vote_alerts_per_family"] = 120; json.dump(c, open(p, "w"), indent=1)
PY
python "$SRC/assuredx_attack.py" 5 6 7 8 9 10 --base "$RUNS/edgeiiot_noport" --out "$RUNS/edgeiiot_k5"
python "$SRC/assuredx_extra.py" 11 12 13 14 --base "$RUNS/edgeiiot_noport" --out "$RUNS/edgeiiot_k5"
python "$SRC/assuredx_extended.py" 15 16 17 18 19 20 --base "$RUNS/edgeiiot_noport" --out "$RUNS/edgeiiot_k5"
python "$AN/spelling_audit.py" "$EDGE/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv"

# ---- Paper tables and figure ----
for r in ciciot2023_k5 edgeiiot_k5; do
  python "$AN/compile_results.py" "$RUNS/$r" x "$r"
  python "$AN/compile_extra.py" "$RUNS/$r"
  python "$AN/compile_gate.py" "$RUNS/$r"
done
python "$AN/compile_results.py" "$RUNS/ciciot2023_k10" x ciciot2023_k10
python "$AN/make_figure.py" "$RUNS/ciciot2023_k5" "$RUNS/edgeiiot_k5" "$RUNS/fig_tmr.png"
