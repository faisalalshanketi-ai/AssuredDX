# Paper numbers: ciciot2023_k5

k = 5, sigma = 0.03 (validation {'0.03': 0.6073581619111293, '0.1': 0.6002005275160608, '0.3': 0.577341075987834}), alerts = 840 {'BruteForce': 120, 'DDoS': 120, 'DoS': 120, 'Mirai': 120, 'Recon': 120, 'Spoofing': 120, 'Web': 120}

Alerts with no feasible candidate under raw SHAP (any eps): 0.000

## Common eligible set (n = 85, 42 capture clusters)

 eps  raw_strongest  fingerprint  consensus  unsmoothed  assuredx           set_minus_raw  assuredx_diag  assuredx_diag_certified_output  provably_immune_diag          diag_minus_raw           diag_minus_fp
0.01         0.1647       0.1765     0.2118      0.0000  0.0000 -0.165 [-0.270, -0.080]          NaN                           NaN                   NaN                     NaN                     NaN
0.03         0.1529       0.1412     0.2471      0.0000  0.0118 -0.141 [-0.239, -0.058]       0.0000                        0.0000                0.9059 -0.153 [-0.244, -0.078] -0.141 [-0.238, -0.061]
0.10         0.2824       0.2706     0.3529      0.0471  0.0824 -0.200 [-0.295, -0.103]       0.0235                        0.0118                0.0000 -0.259 [-0.365, -0.170] -0.247 [-0.361, -0.149]
0.30         0.4824       0.5059     0.6588      0.1529  0.1882 -0.294 [-0.409, -0.157]       0.1294                        0.0588                0.0000 -0.353 [-0.460, -0.253] -0.376 [-0.474, -0.277]
1.00         0.8000       0.7882     0.8588      0.4000  0.4353 -0.365 [-0.483, -0.232]       0.3647                        0.3176                0.0000 -0.435 [-0.544, -0.319] -0.424 [-0.520, -0.319]

## Own-eligible TMR (stage 8)

      defence  eps  eligible  attacked    TMR  TMR_lo  TMR_hi  feasible_found  TMR_certified_output  provably_immune
       random 0.01       484       840 0.1756  0.1372  0.2292             1.0                   NaN              NaN
       random 0.03       484       840 0.1921  0.1522  0.2455             1.0                   NaN              NaN
       random 0.10       484       840 0.3017  0.2483  0.3495             1.0                   NaN              NaN
       random 0.30       484       840 0.5186  0.4409  0.5814             1.0                   NaN              NaN
       random 1.00       484       840 0.7851  0.7332  0.8248             1.0                   NaN              NaN
          raw 0.01       484       840 0.1777  0.1391  0.2292             1.0                   NaN              NaN
          raw 0.03       484       840 0.1880  0.1508  0.2364             1.0                   NaN              NaN
          raw 0.10       484       840 0.3079  0.2537  0.3513             1.0                   NaN              NaN
          raw 0.30       484       840 0.5496  0.4817  0.6053             1.0                   NaN              NaN
          raw 1.00       484       840 0.7831  0.7365  0.8268             1.0                   NaN              NaN
    consensus 0.01       538       840 0.2881  0.2183  0.3807             1.0                   NaN              NaN
    consensus 0.03       538       840 0.3271  0.2566  0.4200             1.0                   NaN              NaN
    consensus 0.10       538       840 0.4498  0.3794  0.5386             1.0                   NaN              NaN
    consensus 0.30       538       840 0.7249  0.6720  0.7883             1.0                   NaN              NaN
    consensus 1.00       538       840 0.8625  0.8278  0.8998             1.0                   NaN              NaN
  fingerprint 0.01       479       840 0.1795  0.1414  0.2334             1.0                   NaN              NaN
  fingerprint 0.03       479       840 0.1858  0.1481  0.2353             1.0                   NaN              NaN
  fingerprint 0.10       479       840 0.3090  0.2585  0.3564             1.0                   NaN              NaN
  fingerprint 0.30       479       840 0.5365  0.4754  0.5829             1.0                   NaN              NaN
  fingerprint 1.00       479       840 0.7683  0.7160  0.8146             1.0                   NaN              NaN
   unsmoothed 0.01       472       840 0.0064  0.0000  0.0144             1.0                   NaN              NaN
   unsmoothed 0.03       472       840 0.0148  0.0056  0.0275             1.0                   NaN              NaN
   unsmoothed 0.10       472       840 0.0593  0.0388  0.0854             1.0                   NaN              NaN
   unsmoothed 0.30       472       840 0.1441  0.1090  0.1835             1.0                   NaN              NaN
   unsmoothed 1.00       472       840 0.4131  0.3467  0.4910             1.0                   NaN              NaN
       assuredx 0.01       211       350 0.0000  0.0000  0.0000             1.0                0.0000           0.6872
       assuredx 0.03       211       350 0.0142  0.0000  0.0287             1.0                0.0000           0.4076
       assuredx 0.10       211       350 0.0711  0.0435  0.1050             1.0                0.0427           0.0000
       assuredx 0.30       211       350 0.1659  0.1141  0.2367             1.0                0.1280           0.0000
       assuredx 1.00       211       350 0.4218  0.3320  0.5334             1.0                0.3697           0.0000
raw_strongest 0.01       484       840 0.1818  0.1420  0.2350             1.0                   NaN              NaN
raw_strongest 0.03       484       840 0.2004  0.1621  0.2500             1.0                   NaN              NaN
raw_strongest 0.10       484       840 0.3285  0.2694  0.3762             1.0                   NaN              NaN
raw_strongest 0.30       484       840 0.5661  0.4984  0.6258             1.0                   NaN              NaN
raw_strongest 1.00       484       840 0.7996  0.7495  0.8414             1.0                   NaN              NaN

## Vote attack own-eligible (stage 10)

 eps  eligible    TMR  TMR_lo  TMR_hi  TMR_certified_output  provably_immune
0.03       108 0.0000  0.0000  0.0000                0.0000           0.8148
0.10       108 0.0278  0.0000  0.0547                0.0093           0.0000
0.30       108 0.1389  0.0714  0.2115                0.0833           0.0000
1.00       108 0.3611  0.2553  0.4787                0.3241           0.0000

Clean diagnosis accuracy: smoothed 0.5643 vs raw 0.5762 (+30/-40, exact McNemar p = 0.2820); certified output issued for 0.957

## Diagnosis certificate coverage

 sigma  clean_accuracy  certified_any  median_radius_certified  useful@0.01  set_useful@0.01  useful@0.03  set_useful@0.03  useful@0.1  set_useful@0.1  useful@0.3  set_useful@0.3  useful@1.0  set_useful@1.0
  0.03          0.5643         0.9571                   0.0739       0.5286           0.3774       0.4702           0.2190      0.0000          0.0000      0.0000          0.0000         0.0             0.0
  0.10          0.5631         0.8952                   0.1610       0.5250           0.3286       0.4988           0.2488      0.3881          0.0857      0.0000          0.0000         0.0             0.0
  0.30          0.5714         0.7524                   0.2647       0.4857           0.3143       0.4750           0.2714      0.4274          0.1429      0.2583          0.0202         0.0             0.0

## certified_coverage

 sigma radius  certified_coverage  useful_certified_coverage
  0.03   0.01              0.6917                     0.3774
  0.03   0.03              0.3988                     0.2190
  0.03    0.1              0.0000                     0.0000
  0.03    0.3              0.0000                     0.0000
  0.03    1.0              0.0000                     0.0000
  0.03  any>0              0.8631                     0.4881
  0.10   0.01              0.6083                     0.3286
  0.10   0.03              0.4619                     0.2488
  0.10    0.1              0.2083                     0.0857
  0.10    0.3              0.0000                     0.0000
  0.10    1.0              0.0000                     0.0000
  0.10  any>0              0.7214                     0.3976
  0.30   0.01              0.5667                     0.3143
  0.30   0.03              0.5048                     0.2714
  0.30    0.1              0.2929                     0.1429
  0.30    0.3              0.0417                     0.0202
  0.30    1.0              0.0000                     0.0000
  0.30  any>0              0.6119                     0.3440

## clean_diagnosis

                   explanation  clean_diag_accuracy  clean_diag_macro_f1
                      Raw SHAP               0.5762               0.5581
                     Consensus               0.6405               0.6350
            Unsmoothed decoder               0.5619               0.5510
             AssureDx sigma=0.03               0.5643               0.5537
              AssureDx sigma=0.1               0.5679               0.5562
              AssureDx sigma=0.3               0.5738               0.5630
Fingerprint (clean acceptance)               0.9929                  NaN

## fidelity

Unnamed: 0  overlap_with_raw_topk  unique_neighbours_median  sec_per_certificate_median  median_radius  decoder_distance_median
sigma=0.03                 0.9255                      38.0                      0.1019         0.0212                      NaN
 sigma=0.1                 0.9205                     209.0                      0.1696         0.0237                      NaN
 sigma=0.3                 0.9052                     371.5                      0.2885         0.0309                      NaN
unsmoothed                 0.9181                       NaN                         NaN            NaN                   0.0324
 consensus                 0.7698                       NaN                         NaN            NaN                      NaN

## n_sweep

    n  certified  median_radius    sec
  100       0.65         0.0065 0.0448
 1000       0.90         0.0201 0.1131
10000       0.95         0.0250 0.7684

## naive_smoothing

 sigma  invalid_sample_fraction  range_violation  order_violation  identity_violation  detector_flip_fraction  certified  overlap_with_raw
  0.03                      1.0           0.9885           0.3384                 1.0                  0.0482     0.2190            0.8500
  0.10                      1.0           0.9985           0.4552                 1.0                  0.0353     0.1619            0.8224
  0.30                      1.0           0.9997           0.5716                 1.0                  0.0253     0.0095            0.7538

## Per-family TMR, common set, eps = 0.1

              raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                             
BruteForce  0.100        0.100       0.000   0.000        0.000  10
DDoS        0.400        0.600       0.100   0.100        0.000  10
DoS         0.111        0.111       0.000   0.000        0.000   9
Mirai       0.100        0.100       0.000   0.150        0.000  20
Recon       0.462        0.462       0.154   0.154        0.077  13
Spoofing    0.375        0.438       0.062   0.062        0.062  16
Web         0.143        0.000       0.000   0.000        0.000   7

## Per-family TMR, common set, eps = 0.3

              raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                             
BruteForce  0.300        0.400       0.200   0.000        0.000  10
DDoS        0.700        0.700       0.200   0.300        0.300  10
DoS         0.111        0.111       0.000   0.000        0.000   9
Mirai       0.300        0.400       0.150   0.300        0.050  20
Recon       0.769        0.769       0.308   0.385        0.308  13
Spoofing    0.625        0.562       0.125   0.125        0.188  16
Web         0.429        0.571       0.000   0.000        0.000   7

Raw successful attacks: median dW {0.01: 0.0032, 0.03: 0.0122, 0.1: 0.0738, 0.3: 0.2253, 1.0: 0.6505}; median score drift {0.01: -2e-05, 0.03: 0.0, 0.1: 0.00028, 0.3: 8e-05, 1.0: 0.00018}

Median attack seconds per alert-eps: {'raw': 0.39, 'random': 0.32, 'consensus': 0.5, 'fingerprint': 0.61, 'unsmoothed': 0.47, 'assuredx': 5.11}
