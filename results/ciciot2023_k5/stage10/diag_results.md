# Diagnosis-level certificate (2026-10-24 07:37)

Smoothed diagnosis = plurality of the frozen raw diagnoser over decoded valid flows; n0 = 100 selection samples, Clopper-Pearson lower bound at alpha = 0.001.

## Useful certified coverage: diagnosis certificate vs set certificate (n = 1000)

| sigma | clean_accuracy | certified_any | median_radius_certified | useful@0.01 | set_useful@0.01 | useful@0.03 | set_useful@0.03 | useful@0.1 | set_useful@0.1 | useful@0.3 | set_useful@0.3 | useful@1.0 | set_useful@1.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.0300 | 0.5643 | 0.9571 | 0.0739 | 0.5286 | 0.3774 | 0.4702 | 0.2190 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.1000 | 0.5631 | 0.8952 | 0.1610 | 0.5250 | 0.3286 | 0.4988 | 0.2488 | 0.3881 | 0.0857 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.3000 | 0.5714 | 0.7524 | 0.2647 | 0.4857 | 0.3143 | 0.4750 | 0.2714 | 0.4274 | 0.1429 | 0.2583 | 0.0202 | 0.0000 | 0.0000 |

## Sampling budget (selected sigma, subset)

| n | certified | median_radius | sec |
|---|---|---|---|
| 1000 | 0.9786 | 0.0739 | 0.1819 |
| 10000 | 0.9786 | 0.0913 | 0.9948 |

## Adaptive attack on the smoothed diagnosis

| eps | eligible | TMR | TMR_lo | TMR_hi | TMR_certified_output | provably_immune |
|---|---|---|---|---|---|---|
| 0.0300 | 108 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.8148 |
| 0.1000 | 108 | 0.0278 | 0.0000 | 0.0547 | 0.0093 | 0.0000 |
| 0.3000 | 108 | 0.1389 | 0.0714 | 0.2115 | 0.0833 | 0.0000 |
| 1.0000 | 108 | 0.3611 | 0.2553 | 0.4787 | 0.3241 | 0.0000 |
