@echo off
cd /d "%~dp0"

echo ========================================
echo  Monolith - Reset All
echo ========================================

REM ---- Step 1: Kill running processes ----
echo [1/8] Stopping scanner and backend processes...
taskkill /f /im scanner.exe >nul 2>&1
taskkill /f /im monolith-backend.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo [1/8] OK

REM ---- Step 2: Delete stale log files ----
echo [2/8] Removing stale log files...
if exist backend*.log del /f /q backend*.log >nul 2>&1
if exist scanner*.log del /f /q scanner*.log >nul 2>&1
if exist scanner*.err del /f /q scanner*.err >nul 2>&1
echo [2/8] OK

REM ---- Step 3: Empty logs directory ----
echo [3/8] Emptying logs/ directory...
if exist logs\ (
    del /f /q /s logs\ >nul 2>&1
)
echo [3/8] OK

REM ---- Step 4: Delete scan reports ----
echo [4/8] Deleting scan reports...
if exist reports\ (
    del /f /q reports\ 2>nul
    for /d %%d in (reports\*) do rd /s /q "%%d" 2>nul
)
echo [4/8] OK

REM ---- Step 5: Reset database ----
echo [5/8] Resetting database (deleting edr.db)...
if exist data\edr.db del /f /q data\edr.db >nul 2>&1
if exist data\edr.db-shm del /f /q data\edr.db-shm >nul 2>&1
if exist data\edr.db-wal del /f /q data\edr.db-wal >nul 2>&1
echo [5/8] OK

REM ---- Step 6: Clear quarantine ----
echo [6/8] Clearing quarantine...
if exist "%ProgramData%\EDR\Quarantine" (
    del /f /q /s "%ProgramData%\EDR\Quarantine\*" >nul 2>&1
    for /d %%d in ("%ProgramData%\EDR\Quarantine\*") do rd /s /q "%%d" 2>nul
    echo [6/8] OK
) else (
    echo [6/8] (no quarantine dir)
)

REM ---- Step 7: Clear YARA compile cache ----
echo [7/8] Clearing YARA compile cache...
if exist scanner\yara\cache (
    del /f /q scanner\yara\cache\* >nul 2>&1
    echo [7/8] OK
) else (
    echo [7/8] (no cache dir)
)

echo.
echo ========================================
echo  Reset complete.
echo  All logs, reports, database, and
echo  quarantine cleared.
echo.
echo  Run run-all.bat to start fresh.
echo ========================================
