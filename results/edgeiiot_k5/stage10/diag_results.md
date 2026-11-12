# Diagnosis-level certificate (2026-10-24 03:51)

Smoothed diagnosis = plurality of the frozen raw diagnoser over decoded valid flows; n0 = 100 selection samples, Clopper-Pearson lower bound at alpha = 0.001.

## Useful certified coverage: diagnosis certificate vs set certificate (n = 1000)

| sigma | clean_accuracy | certified_any | median_radius_certified | useful@0.01 | set_useful@0.01 | useful@0.03 | set_useful@0.03 | useful@0.1 | set_useful@0.1 | useful@0.3 | set_useful@0.3 | useful@1.0 | set_useful@1.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.0300 | 0.4833 | 0.9750 | 0.0739 | 0.4646 | 0.4646 | 0.4646 | 0.4646 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.1000 | 0.4854 | 0.9875 | 0.2463 | 0.4813 | 0.4667 | 0.4646 | 0.4646 | 0.4208 | 0.4208 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.3000 | 0.4771 | 0.9646 | 0.3297 | 0.4708 | 0.4479 | 0.4667 | 0.4479 | 0.4000 | 0.3146 | 0.2687 | 0.2188 | 0.0000 | 0.0000 |

## Sampling budget (selected sigma, subset)

| n | certified | median_radius | sec |
|---|---|---|---|
| 1000 | 0.9571 | 0.1351 | 0.0290 |
| 10000 | 0.9643 | 0.1588 | 0.1368 |

## Adaptive attack on the smoothed diagnosis

| eps | eligible | TMR | TMR_lo | TMR_hi | TMR_certified_output | provably_immune |
|---|---|---|---|---|---|---|
| 0.0300 | 50 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.9800 |
| 0.1000 | 50 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.8400 |
| 0.3000 | 50 | 0.0800 | 0.0192 | 0.1556 | 0.0000 | 0.5200 |
| 1.0000 | 50 | 0.1600 | 0.0784 | 0.2558 | 0.0800 | 0.0000 |
