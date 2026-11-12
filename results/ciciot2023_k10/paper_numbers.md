# Paper numbers: CICIoT2023 k=10

k = 10, sigma = 0.1 (validation {'0.03': 0.5741318918654933, '0.1': 0.5829057471184615, '0.3': 0.5751903509734488}), alerts = 840 {'BruteForce': 120, 'DDoS': 120, 'DoS': 120, 'Mirai': 120, 'Recon': 120, 'Spoofing': 120, 'Web': 120}

Alerts with no feasible candidate under raw SHAP (any eps): 0.000

## Common eligible set (n = 80, 49 capture clusters)

 eps  raw_strongest  fingerprint  consensus  unsmoothed  assuredx           set_minus_raw  assuredx_diag  assuredx_diag_certified_output  provably_immune_diag          diag_minus_raw           diag_minus_fp
0.01         0.3125       0.3125     0.4125      0.0125  0.0000 -0.312 [-0.443, -0.212]          NaN                           NaN                   NaN                     NaN                     NaN
0.03         0.3250       0.3125     0.4500      0.0625  0.0000 -0.325 [-0.460, -0.222]       0.0000                        0.0000                0.8875 -0.325 [-0.460, -0.222] -0.312 [-0.439, -0.215]
0.10         0.4750       0.4625     0.6125      0.1000  0.0500 -0.425 [-0.544, -0.316]       0.0000                        0.0000                0.6000 -0.475 [-0.592, -0.373] -0.463 [-0.592, -0.366]
0.30         0.7625       0.7250     0.8625      0.2000  0.1875 -0.575 [-0.730, -0.436]       0.1125                        0.0250                0.0000 -0.650 [-0.789, -0.537] -0.613 [-0.761, -0.492]
1.00         0.8625       0.8875     0.9875      0.4750  0.5375 -0.325 [-0.463, -0.211]       0.4625                        0.1625                0.0000 -0.400 [-0.544, -0.279] -0.425 [-0.549, -0.306]

## Own-eligible TMR (stage 8)

      defence  eps  eligible  attacked    TMR  TMR_lo  TMR_hi  feasible_found  TMR_certified_output  provably_immune
       random 0.01       521       840 0.3090  0.2469  0.3874             1.0                   NaN              NaN
       random 0.03       521       840 0.3493  0.2852  0.4252             1.0                   NaN              NaN
       random 0.10       521       840 0.4798  0.3945  0.5628             1.0                   NaN              NaN
       random 0.30       521       840 0.7121  0.5784  0.8238             1.0                   NaN              NaN
       random 1.00       521       840 0.8503  0.7741  0.9170             1.0                   NaN              NaN
          raw 0.01       521       840 0.3090  0.2400  0.3933             1.0                   NaN              NaN
          raw 0.03       521       840 0.3628  0.2912  0.4442             1.0                   NaN              NaN
          raw 0.10       521       840 0.5067  0.4152  0.5996             1.0                   NaN              NaN
          raw 0.30       521       840 0.7294  0.6130  0.8338             1.0                   NaN              NaN
          raw 1.00       521       840 0.8829  0.8142  0.9431             1.0                   NaN              NaN
    consensus 0.01       471       840 0.4161  0.3339  0.5188             1.0                   NaN              NaN
    consensus 0.03       471       840 0.4565  0.3756  0.5518             1.0                   NaN              NaN
    consensus 0.10       471       840 0.6093  0.5288  0.6965             1.0                   NaN              NaN
    consensus 0.30       471       840 0.8641  0.7997  0.9249             1.0                   NaN              NaN
    consensus 1.00       471       840 0.9618  0.9391  0.9852             1.0                   NaN              NaN
  fingerprint 0.01       516       840 0.3101  0.2469  0.3867             1.0                   NaN              NaN
  fingerprint 0.03       516       840 0.3566  0.2859  0.4381             1.0                   NaN              NaN
  fingerprint 0.10       516       840 0.4942  0.4028  0.5912             1.0                   NaN              NaN
  fingerprint 0.30       516       840 0.7209  0.5875  0.8363             1.0                   NaN              NaN
  fingerprint 1.00       516       840 0.8721  0.8121  0.9300             1.0                   NaN              NaN
   unsmoothed 0.01       515       840 0.0155  0.0025  0.0336             1.0                   NaN              NaN
   unsmoothed 0.03       515       840 0.0524  0.0323  0.0763             1.0                   NaN              NaN
   unsmoothed 0.10       515       840 0.1243  0.0998  0.1530             1.0                   NaN              NaN
   unsmoothed 0.30       515       840 0.2660  0.2208  0.3222             1.0                   NaN              NaN
   unsmoothed 1.00       515       840 0.5689  0.4877  0.6554             1.0                   NaN              NaN
       assuredx 0.01       229       350 0.0087  0.0000  0.0244             1.0                0.0000           0.4803
       assuredx 0.03       229       350 0.0087  0.0000  0.0244             1.0                0.0000           0.3057
       assuredx 0.10       229       350 0.0524  0.0276  0.0852             1.0                0.0131           0.0393
       assuredx 0.30       229       350 0.1834  0.1358  0.2348             1.0                0.0830           0.0000
       assuredx 1.00       229       350 0.5633  0.4840  0.6257             1.0                0.3537           0.0000
raw_strongest 0.01       521       840 0.3244  0.2585  0.4061             1.0                   NaN              NaN
raw_strongest 0.03       521       840 0.3820  0.3068  0.4671             1.0                   NaN              NaN
raw_strongest 0.10       521       840 0.5413  0.4487  0.6360             1.0                   NaN              NaN
raw_strongest 0.30       521       840 0.7620  0.6423  0.8651             1.0                   NaN              NaN
raw_strongest 1.00       521       840 0.8944  0.8328  0.9488             1.0                   NaN              NaN

## Vote attack own-eligible (stage 10)

 eps  eligible    TMR  TMR_lo  TMR_hi  TMR_certified_output  provably_immune
0.03       117 0.0085  0.0000  0.0219                0.0000           0.7949
0.10       117 0.0085  0.0000  0.0219                0.0000           0.4872
0.30       117 0.1282  0.0763  0.1900                0.0171           0.0000
1.00       117 0.5128  0.4237  0.6186                0.1709           0.0000

Clean diagnosis accuracy: smoothed 0.6476 vs raw 0.6202 (+64/-41, exact McNemar p = 0.0313); certified output issued for 0.832

## Diagnosis certificate coverage

 sigma  clean_accuracy  certified_any  median_radius_certified  useful@0.01  set_useful@0.01  useful@0.03  set_useful@0.03  useful@0.1  set_useful@0.1  useful@0.3  set_useful@0.3  useful@1.0  set_useful@1.0
  0.03          0.6286         0.9286                   0.0533       0.5690           0.3667       0.4536           0.1726      0.0000          0.0000      0.0000          0.0000         0.0             0.0
  0.10          0.6476         0.8321                   0.0949       0.5607           0.3060       0.5000           0.1762      0.2952          0.0238      0.0000          0.0000         0.0             0.0
  0.30          0.6321         0.6512                   0.2003       0.4667           0.1821       0.4357           0.1381      0.3464          0.0750      0.1952          0.0012         0.0             0.0

## Per-family TMR, common set, eps = 0.1

              raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                             
BruteForce  0.308        0.308       0.154   0.077          0.0  13
DDoS        0.571        0.571       0.071   0.071          0.0  14
DoS         0.615        0.692       0.077   0.077          0.0  13
Mirai       0.263        0.263       0.105   0.053          0.0  19
Recon       0.667        0.500       0.000   0.000          0.0   6
Spoofing    0.286        0.571       0.143   0.000          0.0   7
Web         0.625        0.500       0.125   0.000          0.0   8

## Per-family TMR, common set, eps = 0.3

              raw  fingerprint  unsmoothed  assuredx  assuredx_diag   n
family                                                             
BruteForce  0.385        0.308       0.154   0.154        0.000  13
DDoS        0.643        0.714       0.143   0.357        0.143  14
DoS         0.923        0.769       0.154   0.154        0.000  13
Mirai       0.737        0.737       0.263   0.158        0.158  19
Recon       0.833        0.833       0.167   0.167        0.333   6
Spoofing    1.000        1.000       0.143   0.143        0.143   7
Web         1.000        1.000       0.375   0.125        0.125   8

Raw successful attacks: median dW {0.01: 0.0041, 0.03: 0.0168, 0.1: 0.0678, 0.3: 0.2105, 1.0: 0.5408}; median score drift {0.01: -7e-05, 0.03: -0.00022, 0.1: -0.00018, 0.3: -0.00029, 1.0: -0.00012}

Median attack seconds per alert-eps: {'raw': 0.67, 'random': 0.25, 'consensus': 0.72, 'fingerprint': 0.6, 'unsmoothed': 0.41, 'assuredx': 7.85}
