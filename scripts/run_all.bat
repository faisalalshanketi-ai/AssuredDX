@echo off
REM Reproduces every experiment in the paper on Windows (Anaconda Prompt, after: conda activate assuredx).
REM Edit DATA and RUNS below. All stages resume after an interruption: re-run this file.
set DATA=C:\AssureDx\data
set RUNS=C:\AssureDx\runs
set SRC=%~dp0..\src
set AN=%~dp0..\analysis
set EDGE=%DATA%\Edge-IIoTset dataset

python "%SRC%\assuredx_lib.py" 0 1 2 3 --data "%DATA%\CICIoT2023" --out "%RUNS%\ciciot2023" || goto :err
python "%SRC%\assuredx_lib.py" 0 1 2 3 --data "%DATA%\CICIoT2023" --out "%RUNS%\ciciot2023_clean" --reuse-stage0 "%RUNS%\ciciot2023" --drop Number "Tot sum" || goto :err
python "%SRC%\assuredx_lib.py" 0 1 --data "%DATA%\CICIoT2023" --out "%RUNS%\ciciot2023_rowsplit" --cache-from "%RUNS%\ciciot2023" --split row || goto :err
python "%SRC%\assuredx_lib.py" 0 1 --data "%DATA%\CICIoT2023_merged\MERGED_CSV" --out "%RUNS%\ciciot2023_merged" --split row || goto :err

python "%SRC%\assuredx_attack.py" 4 5 6 7 8 9 10 --base "%RUNS%\ciciot2023_clean" --out "%RUNS%\ciciot2023_k5" --k 5 || goto :err
python "%SRC%\assuredx_extra.py" 11 12 13 14 --base "%RUNS%\ciciot2023_clean" --out "%RUNS%\ciciot2023_k5" || goto :err
python "%SRC%\assuredx_extended.py" 15 16 17 18 19 20 --base "%RUNS%\ciciot2023_clean" --out "%RUNS%\ciciot2023_k5" || goto :err
python "%SRC%\assuredx_attack.py" 4 5 6 7 8 9 10 --base "%RUNS%\ciciot2023_clean" --out "%RUNS%\ciciot2023_k10" --k 10 || goto :err

python "%SRC%\assuredx_lib.py" 0 1 2 3 --data "%EDGE%" --out "%RUNS%\edgeiiot" --dataset EdgeIIoTset || goto :err
python "%SRC%\assuredx_lib.py" 0 1 2 3 --data "%EDGE%" --out "%RUNS%\edgeiiot_noport" --dataset EdgeIIoTset --reuse-stage0 "%RUNS%\edgeiiot" --drop tcp.dstport udp.port || goto :err
python "%SRC%\assuredx_attack.py" 4 --base "%RUNS%\edgeiiot_noport" --out "%RUNS%\edgeiiot_k5" --k 5 --stratum-mask || goto :err
python -c "import json,sys;p=sys.argv[1];c=json.load(open(p));c['vote_alerts_per_family']=120;json.dump(c,open(p,'w'),indent=1)" "%RUNS%\edgeiiot_k5\attack_config.json" || goto :err
python "%SRC%\assuredx_attack.py" 5 6 7 8 9 10 --base "%RUNS%\edgeiiot_noport" --out "%RUNS%\edgeiiot_k5" || goto :err
python "%SRC%\assuredx_extra.py" 11 12 13 14 --base "%RUNS%\edgeiiot_noport" --out "%RUNS%\edgeiiot_k5" || goto :err
python "%SRC%\assuredx_extended.py" 15 16 17 18 19 20 --base "%RUNS%\edgeiiot_noport" --out "%RUNS%\edgeiiot_k5" || goto :err
python "%AN%\spelling_audit.py" "%EDGE%\Selected dataset for ML and DL\ML-EdgeIIoT-dataset.csv" || goto :err

for %%r in (ciciot2023_k5 edgeiiot_k5) do (
  python "%AN%\compile_results.py" "%RUNS%\%%r" x %%r
  python "%AN%\compile_extra.py" "%RUNS%\%%r"
  python "%AN%\compile_gate.py" "%RUNS%\%%r"
)
python "%AN%\compile_results.py" "%RUNS%\ciciot2023_k10" x ciciot2023_k10
python "%AN%\make_figure.py" "%RUNS%\ciciot2023_k5" "%RUNS%\edgeiiot_k5" "%RUNS%\fig_tmr.png"
echo Finished.
pause
exit /b 0
:err
echo A step failed. Fix the error above and re-run this file; finished work is kept.
pause
exit /b 1
