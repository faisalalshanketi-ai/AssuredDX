# Paper numbers: edgeiiot_k5

k = 5, sigma = 0.3 (validation {'0.03': 0.4630126441420507, '0.1': 0.4630126441420507, '0.3': 0.5303343031898485}), alerts = 480 {'DDoS': 120, 'Injection': 120, 'Malware': 120, 'Scanning': 120}

Alerts with no feasible candidate under raw SHAP (any eps): 0.154

## Common eligible set (n = 53, 20 capture clusters)

 eps  raw_strongest  fingerprint  consensus  unsmoothed  assuredx          set_minus_raw  assuredx_diag  assuredx_diag_certified_output  provably_immune_diag         diag_minus_raw          diag_minus_fp
0.01         0.0189       0.0189     0.1321      0.0000  0.0000 -0.019 [-0.064, 0.000]          NaN                           NaN                   NaN                    NaN                    NaN
0.03         0.0189       0.0189     0.1321      0.0000  0.0000 -0.019 [-0.064, 0.000]       0.0000                        0.0000                1.0000 -0.019 [-0.064, 0.000] -0.019 [-0.064, 0.000]
0.10         0.0755       0.0566     0.1321      0.0000  0.0000 -0.075 [-0.173, 0.000]       0.0000                        0.0000                0.9434 -0.075 [-0.173, 0.000] -0.057 [-0.149, 0.000]
0.30         0.1321       0.1321     0.1887      0.0943  0.0943 -0.038 [-0.096, 0.000]       0.0755                        0.0189                0.7547 -0.057 [-0.127, 0.000] -0.057 [-0.127, 0.000]
1.00         0.1321       0.1321     0.2075      0.1132  0.1509  0.019 [-0.061, 0.114]       0.0943                        0.0566                0.0000 -0.038 [-0.113, 0.037] -0.038 [-0.113, 0.037]

## Own-eligible TMR (stage 8)

      defence  eps  eligible  attacked    TMR  TMR_lo  TMR_hi  feasible_found  TMR_certified_output  provably_immune
       random 0.01       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
       random 0.03       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
       random 0.10       233       480 0.0730  0.0326  0.1275          0.8458                   NaN              NaN
       random 0.30       233       480 0.1931  0.1162  0.2734          0.8458                   NaN              NaN
       random 1.00       233       480 0.2318  0.1547  0.3104          0.8458                   NaN              NaN
          raw 0.01       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
          raw 0.03       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
          raw 0.10       233       480 0.0644  0.0237  0.1198          0.8458                   NaN              NaN
          raw 0.30       233       480 0.1931  0.1162  0.2734          0.8458                   NaN              NaN
          raw 1.00       233       480 0.2361  0.1616  0.3130          0.8458                   NaN              NaN
    consensus 0.01       246       480 0.2927  0.1973  0.3957          0.8458                   NaN              NaN
    consensus 0.03       246       480 0.3171  0.2120  0.4322          0.8458                   NaN              NaN
    consensus 0.10       246       480 0.3171  0.2120  0.4322          0.8458                   NaN              NaN
    consensus 0.30       246       480 0.3293  0.2271  0.4410          0.8458                   NaN              NaN
    consensus 1.00       246       480 0.3496  0.2548  0.4531          0.8458                   NaN              NaN
  fingerprint 0.01       230       480 0.0435  0.0084  0.0982          0.8458                   NaN              NaN
  fingerprint 0.03       230       480 0.0435  0.0084  0.0982          0.8458                   NaN              NaN
  fingerprint 0.10       230       480 0.0609  0.0180  0.1176          0.8458                   NaN              NaN
  fingerprint 0.30       230       480 0.1957  0.1212  0.2780          0.8458                   NaN              NaN
  fingerprint 1.00       230       480 0.2391  0.1666  0.3167          0.8458                   NaN              NaN
   unsmoothed 0.01       233       480 0.0258  0.0000  0.0606          0.8458                   NaN              NaN
   unsmoothed 0.03       233       480 0.0258  0.0000  0.0606          0.8458                   NaN              NaN
   unsmoothed 0.10       233       480 0.0258  0.0000  0.0606          0.8458                   NaN              NaN
   unsmoothed 0.30       233       480 0.1674  0.1004  0.2383          0.8458                   NaN              NaN
   unsmoothed 1.00       233       480 0.2318  0.1558  0.3088          0.8458                   NaN              NaN
       assuredx 0.01        97       200 0.0000  0.0000  0.0000          0.8400                0.0000           0.8763
       assuredx 0.03        97       200 0.0000  0.0000  0.0000          0.8400                0.0000           0.8763
       assuredx 0.10        97       200 0.0000  0.0000  0.0000          0.8400                0.0000           0.6186
       assuredx 0.30        97       200 0.0515  0.0099  0.1087          0.8400                0.0309           0.4536
       assuredx 1.00        97       200 0.2062  0.1188  0.3053          0.8400                0.0928           0.0000
raw_strongest 0.01       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
raw_strongest 0.03       233       480 0.0429  0.0079  0.0945          0.8458                   NaN              NaN
raw_strongest 0.10       233       480 0.0730  0.0326  0.1275          0.8458                   NaN              NaN
raw_strongest 0.30       233       480 0.1931  0.1162  0.2734          0.8458                   NaN              NaN
raw_strongest 1.00       233       480 0.2361  0.1616  0.3130          0.8458                   NaN              NaN

## Vote attack own-eligible (stage 10)

 eps  eligible    TMR  TMR_lo  TMR_hi  TMR_certified_output  provably_immune
0.03       229 0.0044  0.0000  0.0149                0.0000           0.9782
0.10       229 0.0131  0.0000  0.0352                0.0044           0.8384
0.30       229 0.1004  0.0569  0.1506                0.0262           0.5633
1.00       229 0.2576  0.1653  0.3565                0.1485           0.0000

Clean diagnosis accuracy: smoothed 0.4771 vs raw 0.4854 (+5/-9, exact McNemar p = 0.4240); certified output issued for 0.965

## Diagnosis certificate coverage

 sigma  clean_accuracy  certified_any  median_radius_certified  useful@0.01  set_useful@0.01  useful@0.03  set_useful@0.03  useful@0.1  set_useful@0.1  useful@0.3  set_useful@0.3  useful@1.0  set_useful@1.0
  0.03          0.4833         0.9750                   0.0739       0.4646           0.4646       0.4646           0.4646      0.0000          0.0000      0.0000          0.0000         0.0             0.0
  0.10          0.4854         0.9875                   0.2463       0.4812           0.4667       0.4646           0.4646      0.4208          0.4208      0.0000          0.0000         0.0             0.0
  0.30          0.4771         0.9646                   0.3297       0.4708           0.4479       0.4667           0.4479      0.4000          0.3146      0.2688          0.2188         0.0             0.0

## certified_coverage

 sigma radius  certified_coverage  useful_certified_coverage
  0.03   0.01              0.8771                     0.4646
  0.03   0.03              0.8646                     0.4646
  0.03    0.1              0.0000                     0.0000
  0.03    0.3              0.0000                     0.0000
  0.03    1.0              0.0000                     0.0000
  0.03  any>0              0.9208                     0.4729
  0.10   0.01              0.8792                     0.4667
  0.10   0.03              0.8625                     0.4646
  0.10    0.1              0.8083                     0.4208
  0.10    0.3              0.0000                     0.0000
  0.10    1.0              0.0000                     0.0000
  0.10  any>0              0.9729                     0.4833
  0.30   0.01              0.8625                     0.4479
  0.30   0.03              0.8542                     0.4479
  0.30    0.1              0.6000                     0.3146
  0.30    0.3              0.4542                     0.2188
  0.30    1.0              0.0000                     0.0000
  0.30  any>0              0.8792                     0.4542

## clean_diagnosis

                   explanation  clean_diag_accuracy  clean_diag_macro_f1
                      Raw SHAP               0.4854               0.4291
                     Consensus               0.5125               0.5033
            Unsmoothed decoder               0.4854               0.4291
             AssureDx sigma=0.03               0.4854               0.4291
              AssureDx sigma=0.1               0.4854               0.4291
              AssureDx sigma=0.3               0.5042               0.4974
Fingerprint (clean acceptance)               0.9896                  NaN

## fidelity

Unnamed: 0  overlap_with_raw_topk  unique_neighbours_median  sec_per_certificate_median  median_radius  decoder_distance_median
sigma=0.03                 1.0000                       7.0                      0.0205         0.0432                      NaN
 sigma=0.1                 1.0000                      12.0                      0.0228         0.1440                      NaN
 sigma=0.3                 0.9767                      24.0                      0.0243         0.2677                      NaN
unsmoothed                 1.0000                       NaN                         NaN            NaN                      0.0
 consensus                 0.7988                       NaN                         NaN            NaN                      NaN

## n_sweep

    n  certified  median_radius    sec
  100     0.5643         0.0402 0.0091
 1000     0.8500         0.1103 0.0227
10000     0.9786         0.1413 0.1348

## naive_smoothing

 sigma  invalid_sample_fraction  range_violation  order_violation  identity_violation  detector_flip_fraction  certified  overlap_with_raw
  0.03                      1.0              1.0              0.0                 0.0                  0.3085     0.2500            0.9142
  0.10                      1.0              1.0              0.0                 0.0                  0.3063     0.3792            0.9133
  0.30                      1.0              1.0              0.0                 0.0                  0.3050     0.2042            0.8767

## Per-family TMR, common set, eps = 0.1

             raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                            
DDoS       0.000        0.000         0.0     0.0          0.0  16
Injection  0.062        0.062         0.0     0.0          0.0  16
Scanning   0.095        0.095         0.0     0.0          0.0  21

## Per-family TMR, common set, eps = 0.3

             raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                            
DDoS       0.000        0.000       0.000   0.000        0.000  16
Injection  0.312        0.312       0.188   0.188        0.188  16
Scanning   0.095        0.095       0.095   0.095        0.048  21

Raw successful attacks: median dW {0.01: 0.0067, 0.03: 0.0085, 0.1: 0.0684, 0.3: 0.2059, 1.0: 0.3676}; median score drift {0.01: -2e-05, 0.03: -2e-05, 0.1: 2e-05, 0.3: 3e-05, 1.0: 2e-05}

Median attack seconds per alert-eps: {'raw': 0.38, 'random': 0.03, 'consensus': 0.54, 'fingerprint': 0.31, 'unsmoothed': 0.16, 'assuredx': 1.77}
