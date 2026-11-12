# Certified Attack Diagnosis for Explainable Intrusion Detection in IoT Security Operations

Code, per-alert results and analysis scripts for the paper

> F. Alshanketi, "Certified Attack Diagnosis for Explainable Intrusion Detection in IoT Security Operations," *Systems* (MDPI), under review, 2026.

An intrusion alert and its explanation drive different decisions: the alert flags traffic, and the explanation tells the analyst which attack family to investigate. An adversary can keep the alert intact while steering the explanation, and the diagnosis built on it, toward a decoy family. AssureDx smooths top-k SHAP feature membership and the resulting attack-family diagnosis over a fixed decoder that maps Gaussian noise onto constraint-satisfying flows: each decoded sample keeps the alert's immutable attributes and takes its mutable values from one deduplicated training flow of the same protocol stratum (nearest neighbour in scaled space, ties broken by smallest bank index). It issues finite-sample certificates for the displayed feature set and for the diagnosed family, and abstains otherwise.

This repository reproduces every experiment in the paper on **CICIoT2023** and **Edge-IIoTset**: detectors, explanations, targeted explanation-manipulation attacks (including a decoder-aware attack), six defences (no defence, two attribution-fingerprint detectors, consensus, the unsmoothed decoder, multiplicative smoothing, and AssureDx alone or behind a fingerprint gate), set and diagnosis certificates, and the paper's tables and figure.

## Repository layout

```
src/
  assuredx_lib.py       stages 0-3: data preparation, detectors, feature taxonomy, SHAP explanations
  assuredx_attack.py    stages 4-10: alerts, defences, clean evaluation, attacks, certificates, summaries
  assuredx_extra.py     stages 11-14: decoder-aware attack, published baselines, combined pipeline
  assuredx_extended.py    stages 15-20: attack convergence and adversarial outcomes, abstention attack,
                      fingerprint at matched coverage, projected Gaussian smoothing, matched decoder
analysis/
  compile_results.py  per-run paper numbers (common eligible set, McNemar, coverage, runtime)
  compile_extra.py    paired comparison of all defences under the strongest attack (Tables 4, 5, 7)
  compile_gate.py     deployed pipelines and analyst-routing rates (Table 6)
  make_figure.py      Figure 1
  spelling_audit.py   Edge-IIoTset placeholder-spelling artefact (Section 9.1)
  make_supplementary.py  Supplementary Tables S1-S17 (python make_supplementary.py results supp.md; pandoc supp.md -o supp.docx)
  compile_extended.py   tables of stages 15-20 (python compile_extended.py <run>)
  independence.py     split mode, near duplicates and the main comparison on independent subsets
  supplement_tables.py    Tables S8-S11: sample flow, per-stratum results, decoded-sample audit, accuracy equivalence (needs local runs)
scripts/
  run_all.sh          full reproduction on Linux/macOS
  run_all.bat         full reproduction on Windows
results/              released outputs of the runs reported in the paper (see results/README.md)
```

## Installation

```bash
conda env create -f environment.yml      # or: pip install -r requirements.txt
conda activate assuredx
```

The paper's runs used Python 3.11.16, NumPy 2.4.6, pandas 3.0.6, XGBoost 3.2.0 and scikit-learn 1.9.1 on an Intel Core i7-11700 (8 cores, 2.5 GHz) with 32 GB of RAM under Windows 11. No GPU is needed.

## Data

The datasets are not redistributed here. Download them from the providers and arrange them as follows.

| Dataset | Source | Expected location |
|---|---|---|
| CICIoT2023, per-class CSV files | Canadian Institute for Cybersecurity, <https://www.unb.ca/cic/datasets/iotdataset-2023.html> | `data/CICIoT2023/CSV/<ClassFolder>/*.csv` |
| CICIoT2023, merged CSV release (detection comparison only) | same | `data/CICIoT2023_merged/MERGED_CSV/*.csv` |
| Edge-IIoTset | Ferrag et al., IEEE DataPort, <https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications> | `data/Edge-IIoTset dataset/{Attack traffic, Normal traffic, Selected dataset for ML and DL}` |

Keep the providers' folder and file names. The exact CICIoT2023 files used in the paper (309 files) and the Edge-IIoTset files with their row counts are listed in `results/detection_and_explanations/*/manifest_stage0.json`; stage 0 records the same manifest for your copy.

## Running

```bash
DATA=./data RUNS=./runs bash scripts/run_all.sh
```

On Windows, edit `DATA` and `RUNS` at the top of `scripts\run_all.bat` and run it from Anaconda Prompt. Every stage appends per-alert results and skips finished work, so after a power cut or interruption, run the same command again.

Individual stages can be run on their own, for example:

```bash
python src/assuredx_lib.py 0 1 2 3 --data data/CICIoT2023 --out runs/ciciot2023
python src/assuredx_attack.py 4 5 6 7 8 9 10 --base runs/ciciot2023_clean --out runs/ciciot2023_k5 --k 5
python src/assuredx_extra.py 11 12 13 14 --base runs/ciciot2023_clean --out runs/ciciot2023_k5
```

Add `--quick` to `assuredx_attack.py` or `assuredx_extra.py` for a few-minute smoke test on a handful of alerts.

### Stages

| Stage | Script | What it does |
|---|---|---|
| 0 | assuredx_lib | Reads the provider files; file-level split (CICIoT2023) or temporal split within captures (Edge-IIoTset); artefact handling |
| 1 | assuredx_lib | XGBoost detectors (5 seeds), random-forest reference, family- and attack-level models |
| 2 | assuredx_lib | Feature roles (mutable, immutable, derived), ranges, identities and order constraints, scales W |
| 3 | assuredx_lib | Exact path-dependent TreeSHAP, set-only and rich diagnosers for k = 3, 5, 10, decoy groups |
| 4 | assuredx_attack | 120 detected test alerts per family, balanced across captures; decoy families |
| 5 | assuredx_attack | Bank decoder per protocol stratum, σ chosen on validation, frozen diagnosers, fingerprint detector |
| 6 | assuredx_attack | Clean explanations of every defence, set certificates, sampling-budget sweep, naive-smoothing ablation |
| 7 | assuredx_attack | Matched-budget targeted attacks (1,000 candidates) on every defence at ε ∈ {0.01, 0.03, 0.1, 0.3, 1.0} |
| 8 | assuredx_attack | TMR with capture-level bootstrap intervals, coverage and fidelity tables |
| 9 | assuredx_attack | Diagnosis-level certificates (Clopper-Pearson) and the adaptive attack on the smoothed diagnosis |
| 10 | assuredx_attack | Diagnosis-certificate summary |
| 11 | assuredx_extra | Decoder-aware (Voronoi) attack on the unsmoothed decoder and on AssureDx |
| 12 | assuredx_extra | Sharma et al. autoencoder fingerprint detector; Xue et al. multiplicative smoothing |
| 13 | assuredx_extra | Summary of stages 11-12 |
| 14 | assuredx_extra | AssureDx behind the fingerprint gate, attacked with both attacks |
| 15 | assuredx_extended | Attack convergence (1,000 / 4,000 / 16,000 candidates; 128 or 512 attacker samples) with the decoder-aware attack; deployed outcome of every attacked alert |
| 16 | assuredx_extended | Abstention attack: the attacker minimises the vote margin to force abstention |
| 17 | assuredx_extended | Sharma et al. fingerprint with its clean acceptance matched to AssureDx's certified share |
| 18 | assuredx_extended | Projected Gaussian smoothing (constraint-aware, input-dependent repair) with nominal certificates |
| 19 | assuredx_extended | Decoder restricted to the alert's exact immutable configuration (with and without stratum fallback) |
| 20 | assuredx_extended | Refusal attack on the fingerprint gate (published and matched thresholds); AssureDx behind the gate at the matched threshold |

Approximate run time on the paper's hardware: stages 0-3 about 2 h per dataset; stages 4-10 about 12 h for CICIoT2023 and 3 h for Edge-IIoTset; stages 11-14 about 7 h and 2 h.

## Reproducing the paper's tables

| Paper item | File (after running, or in `results/`) |
|---|---|
| Section 9.1, CICIoT2023 counter artefact (Number, 52.3% of SHAP mass) | `detection_and_explanations/ciciot2023/global_importance.csv` |
| Section 9.1, Edge-IIoTset ports (21.4% of SHAP mass) | `detection_and_explanations/edgeiiot/global_importance.csv` |
| Section 9.1, placeholder-spelling artefact (86.2%) | `analysis/spelling_audit.py` |
| Table 3 | `detection_and_explanations/*/manifest_stage0.json`, `*/taxonomy.json` |
| Table 4 | `ciciot2023_k5/summary/paired_all.csv` |
| Table 5 | `edgeiiot_k5/stage8/tmr.csv`, `edgeiiot_k5/summary/paired_all.csv`, `edgeiiot_k5/stage10/tmr_vote.csv` |
| Table 6 | `*/summary/deployed_pipelines.csv` |
| Table 7 | `*/summary/paired_mus.csv`, `*/stage12/clean_extra.jsonl` |
| Table 8 | `python analysis/compile_extended.py results/<run>` → `*/extended/robust_correct.csv` |
| Table 9 | `*/stage10/diag_certificate.csv`, `*/stage8/certified_coverage.csv` |
| Table 10 | `detection_and_explanations/detection_numbers.md`, `*/binary_summary.csv`, `*/multiclass_metrics.csv` |
| Table 11 | `*/paper_numbers.md` (runtime lines), `*/stage6/clean.jsonl`, `*/stage9/diag_cert.jsonl` |
| Section 10.3 (McNemar) | `*/paper_numbers.md` |
| Section 10.5 ablations | `*/stage8/naive_smoothing.csv`, `fidelity.csv`, `n_sweep.csv`; `*/summary/paired_all.csv` |
| Section 10.6 (k = 10) | `ciciot2023_k10/paper_numbers.md` |
| Figure 2 | `python analysis/make_figure.py results/ciciot2023_k5 results/edgeiiot_k5` |
| Section 10.3 (equivalence, certified vs abstained accuracy) | `*/extended/accuracy.csv` |
| Section 10.5 (strata, decoded-sample audit) | `*/extended/strata.csv`, `*/extended/decoder_audit.csv` |
| Supplementary Tables S1-S17 | `python analysis/make_supplementary.py results supp.md`; S8-S11 read `*/extended/*.csv`, regenerated by `python analysis/supplement_tables.py results runs` |

## Scope

Attacks are evaluated in feature space with exact enforcement of ranges, immutable attributes, ordering constraints and derived identities. Every realizable trace maps into this feature-space domain, so the certificates cover realizable attacks within their radius; empirical attack rates report what the finite search found. Trace-level realizability is outside the released code. All experiments manipulate feature vectors offline and send no traffic to any system.

## Citation

See `CITATION.cff`. Please also cite the dataset papers:

- E. C. P. Neto et al., "CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment," *Sensors*, 23(13):5941, 2023.
- M. A. Ferrag et al., "Edge-IIoTset: A new comprehensive realistic cyber security dataset of IoT and IIoT applications for centralized and federated learning," *IEEE Access*, 10:40281-40306, 2022.

## License

MIT (see `LICENSE`). The datasets remain under their providers' terms.
