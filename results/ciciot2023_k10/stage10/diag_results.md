# Diagnosis-level certificate (2026-10-23 06:37)

Smoothed diagnosis = plurality of the frozen raw diagnoser over decoded valid flows; n0 = 100 selection samples, Clopper-Pearson lower bound at alpha = 0.001.

## Useful certified coverage: diagnosis certificate vs set certificate (n = 1000)

| sigma | clean_accuracy | certified_any | median_radius_certified | useful@0.01 | set_useful@0.01 | useful@0.03 | set_useful@0.03 | useful@0.1 | set_useful@0.1 | useful@0.3 | set_useful@0.3 | useful@1.0 | set_useful@1.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.0300 | 0.6286 | 0.9286 | 0.0533 | 0.5690 | 0.3667 | 0.4536 | 0.1726 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.1000 | 0.6476 | 0.8321 | 0.0949 | 0.5607 | 0.3060 | 0.5000 | 0.1762 | 0.2952 | 0.0238 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.3000 | 0.6321 | 0.6512 | 0.2003 | 0.4667 | 0.1821 | 0.4357 | 0.1381 | 0.3464 | 0.0750 | 0.1952 | 0.0012 | 0.0000 | 0.0000 |

## Sampling budget (selected sigma, subset)

| n | certified | median_radius | sec |
|---|---|---|---|
| 1000 | 0.8357 | 0.0646 | 0.1732 |
| 10000 | 0.8714 | 0.0730 | 1.0360 |

## Adaptive attack on the smoothed diagnosis

| eps | eligible | TMR | TMR_lo | TMR_hi | TMR_certified_output | provably_immune |
|---|---|---|---|---|---|---|
| 0.0300 | 117 | 0.0085 | 0.0000 | 0.0219 | 0.0000 | 0.7949 |
| 0.1000 | 117 | 0.0085 | 0.0000 | 0.0219 | 0.0000 | 0.4872 |
| 0.3000 | 117 | 0.1282 | 0.0763 | 0.1900 | 0.0171 | 0.0000 |
| 1.0000 | 117 | 0.5128 | 0.4237 | 0.6186 | 0.1709 | 0.0000 |
