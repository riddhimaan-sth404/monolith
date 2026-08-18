@echo off
setlocal enabledelayedexpansion
title Monolith EDR - Launch All
cd /d "%~dp0"

>nul 2>&1 net session
if %errorlevel% neq 0 (
    if "%*"=="" (
        powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    ) else (
        powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
    )
    exit /b 0
)

set "QUICK_MODE=0"
set "RELEASE_MODE=0"
for %%a in (%*) do (
    if /i "%%a"=="--quick" set "QUICK_MODE=1"
    if /i "%%a"=="--release" set "RELEASE_MODE=1"
)

set "RUSTLS_CRYPTO_PROVIDER=ring"
set "GO111MODULE=on"

set "PATH=%~dp0.tools\protoc\bin;%PATH%"

set "BUILD_FLAG="
set "TARGET_DIR=target\debug"
if "%RELEASE_MODE%"=="1" (
    set "BUILD_FLAG=--release"
    set "TARGET_DIR=target\release"
)

set "SKIP_SCANNER="

if "%QUICK_MODE%"=="1" (
    echo [QUICK MODE] Skipping setup, certs, build, and nuget restore.
    echo.
) else if "%RELEASE_MODE%"=="1" (
    echo Monolith EDR - Release Build
    echo.
) else (
    echo Monolith EDR - Debug Build
    echo.
)

net stop winnat > nul
net start winnat > nul

if "%QUICK_MODE%"=="0" goto full_setup
goto after_setup

:full_setup
echo [0/9] Checking prerequisites...

REM Check Rust
where rustc >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Rust not found. Run scripts\setup.ps1 as Admin or install from rustup.rs
    pause
    exit /b 1
)

for /f "tokens=1-3" %%a in ('rustc --version 2^>nul') do echo       rustc %%b
where cargo >nul 2>&1 && for /f "tokens=2" %%a in ('cargo --version 2^>nul') do echo       cargo %%a

REM Check Go
where go >nul 2>&1
if errorlevel 1 (
    echo [WARN] Go not found - scanner will be skipped.
    echo       Install from https://go.dev
    set "SKIP_SCANNER=1"
) else (
    for /f "tokens=2" %%a in ('go version 2^>nul') do echo       go %%a
)

REM Check protoc
where protoc >nul 2>&1
if errorlevel 1 (
    echo       protoc: not found ^(codegen may fail^)
) else (
    for /f "tokens=2" %%a in ('protoc --version 2^>nul') do echo       protoc %%a
)

REM Check MSBuild
set "MSBUILD="
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
) else if exist "C:\Program Files\Microsoft Visual Studio\17\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=C:\Program Files\Microsoft Visual Studio\17\Community\MSBuild\Current\Bin\MSBuild.exe"
) else if exist "C:\Program Files\Microsoft Visual Studio\16\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=C:\Program Files\Microsoft Visual Studio\16\Community\MSBuild\Current\Bin\MSBuild.exe"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) else (
    echo       MSBuild: not found ^(GUI will use cached binary if available^)
)
if defined MSBUILD echo       MSBuild: found

echo [OK] Prerequisites checked.
echo.

:after_setup

REM Clean stale processes
echo [..] Cleaning stale processes...
taskkill /f /im scanner.exe            >nul 2>&1
taskkill /f /im monolith-matcher.exe   >nul 2>&1
taskkill /f /im monolith-backend.exe   >nul 2>&1
REM Agent is protected by the kernel driver — taskkill may fail silently.
REM This is expected. The driver will respawn if the agent was killed manually.
taskkill /f /im monolith-agent.exe     >nul 2>&1
taskkill /f /im MonolithGui.exe        >nul 2>&1
ping -n 2 127.0.0.1 >nul
echo [OK] Stale processes cleaned
echo.

REM Phase 1 - Certificates
if "%QUICK_MODE%"=="0" (
    if not exist "certs\ca.pem" (
        echo [1/9] Generating mTLS certificates...
        powershell -ExecutionPolicy Bypass -File scripts\gen-certs.ps1
        if errorlevel 1 (
            echo [WARN] Certificate generation failed
        ) else (
            echo [OK] Certificates generated in certs/
        )
    ) else (
        echo [1/9] Certs already exist
    )
) else (
    if not exist "certs\ca.pem" (
        echo [1/9] No certs found - service TLS may fail
    )
)

if not exist "build" mkdir build

REM Phase 2 - YARA Matcher :50054
if "%QUICK_MODE%"=="0" (
    echo [2/9] Building YARA matcher...
    cargo build %BUILD_FLAG% -p monolith-matcher
    if errorlevel 1 (
        echo [WARN] Matcher build failed
    ) else (
        echo [OK] Starting YARA matcher on :50054...
        start "Monolith Matcher" /B cmd /c "%TARGET_DIR%\monolith-matcher.exe --rules scanner\yara\rules --listen 127.0.0.1:50054"
    )
) else (
    if exist "%TARGET_DIR%\monolith-matcher.exe" (
        echo [2/9] Starting YARA matcher ^(cached^)...
        start "Monolith Matcher" /B cmd /c "%TARGET_DIR%\monolith-matcher.exe --rules scanner\yara\rules --listen 127.0.0.1:50054"
    ) else (
        echo [2/9] No cached matcher binary, skipping
    )
)

REM Wait for YARA matcher to be ready before starting scanner
echo [..] Waiting for YARA matcher :50054...
for /l %%i in (1,1,20) do (
    >nul 2>&1 curl.exe -s http://127.0.0.1:50054/health
    if not errorlevel 1 (
        echo [OK] YARA matcher is responding
        goto matcher_ready
    )
    ping -n 2 127.0.0.1 >nul
)
echo [WARN] YARA matcher not responding within ~40s
:matcher_ready

REM Phase 3 - Go Scanner :50053 / :50052
set "SCANNER_BUILT="
if not defined SKIP_SCANNER (
    if "%QUICK_MODE%"=="0" (
        echo [3/9] Building Go scanner...
        pushd scanner
        go mod tidy >nul 2>&1
        go build -o ..\build\scanner.exe .\cmd\scanner\
        if errorlevel 1 (
            popd
            echo [WARN] Scanner build failed
        ) else (
            popd
            set "SCANNER_BUILT=1"
            echo [OK] Scanner built
        )
    ) else (
        if exist "build\scanner.exe" (
            set "SCANNER_BUILT=1"
            echo [3/9] Using cached scanner binary
        ) else (
            echo [3/9] No cached scanner binary
        )
    )
) else (
    echo [3/9] Skipping scanner
)

if defined SCANNER_BUILT (
    start "Monolith Scanner" /B cmd /c "build\scanner.exe --config configs\scanner.yaml"
    echo [OK] Scanner starting...

    echo [..] Waiting for scanner API :50053...
    for /l %%i in (1,1,10) do (
        >nul 2>&1 curl.exe -s http://127.0.0.1:50053/api/scan/status
        if not errorlevel 1 (
            echo [OK] Scanner is responding
            goto scanner_ready
        )
        ping -n 2 127.0.0.1 >nul
    )
    echo [WARN] Scanner API not responding within 10s
)
:scanner_ready

REM Phase 4 - Backend :8443 / :9443 / :7443
if "%QUICK_MODE%"=="0" (
    echo [4/9] Building Backend...
    cargo build %BUILD_FLAG% -p monolith-backend
    if errorlevel 1 (
        echo [FAIL] Backend build failed
        pause
        exit /b 1
    )
) else (
    echo [4/9] Using cached backend binary
)

REM Persist JWT secret to a file so tokens survive server restarts
if not defined EDR_JWT_SECRET (
    if exist "data\jwt_secret.txt" (
        set /p EDR_JWT_SECRET=<"data\jwt_secret.txt"
    ) else (
        if not exist "data" mkdir data
        for /f %%i in ('powershell -Command "[System.Convert]::ToBase64String((1..64|%%{[byte](Get-Random -Min 0 -Max 256)}))"') do set "EDR_JWT_SECRET=%%i"
        >"data\jwt_secret.txt" echo !EDR_JWT_SECRET!
    )
)
echo [OK] Starting Backend...
start "Monolith Backend" /B cmd /c "set EDR_JWT_SECRET=%EDR_JWT_SECRET% && %TARGET_DIR%\monolith-backend.exe --config configs\backend.toml"

echo [..] Waiting for backend REST :8443...
for /l %%i in (1,1,20) do (
    >nul 2>&1 curl.exe -sk https://127.0.0.1:8443/api/v1/dashboard
    if not errorlevel 1 (
        echo [OK] Backend is responding
        goto backend_ready
    )
    ping -n 2 127.0.0.1 >nul
)
echo [WARN] Backend did not respond within 20s
:backend_ready

echo [..] Waiting for backend gRPC :9443...
for /l %%i in (1,1,15) do (
    >nul 2>&1 powershell -Command "try {$c=New-Object System.Net.Sockets.TcpClient; $c.Connect('127.0.0.1',9443); $c.Close(); exit 0} catch {exit 1}"
    if not errorlevel 1 (
        echo [OK] gRPC port is open
        goto grpc_ready
    )
    ping -n 2 127.0.0.1 >nul
)
echo [WARN] gRPC port did not open within 15s
:grpc_ready

REM Phase 5 - Agent
echo [5/9] Building Agent...
cargo build %BUILD_FLAG% -p monolith-agent
if errorlevel 1 (
    echo [WARN] Agent build failed
) else (
    REM Remove stale signatures so agent re-signs on launch
    if exist "%TARGET_DIR%\monolith-agent.exe.sig" del "%TARGET_DIR%\monolith-agent.exe.sig"
    if exist "configs\agent.toml.sig" del "configs\agent.toml.sig"
    echo [OK] Starting Agent...
    start "Monolith Agent" /B cmd /c "%TARGET_DIR%\monolith-agent.exe"
)

REM Phase 6 - C# GUI
if defined MSBUILD (
    echo [6/9] Restoring NuGet packages for C# GUI...
    "%MSBUILD%" /t:restore gui-csharp\MonolithGui.csproj /nologo /v:q
    
    echo [7/9] Building C# GUI...
    "%MSBUILD%" /p:Configuration=Release gui-csharp\MonolithGui.csproj /nologo /v:q
    if errorlevel 1 (
        echo [WARN] GUI build failed
    ) else (
REM Verify all required cert files exist
set "CERT_OK=1"
for %%f in (ca.pem ca.key server.pem server.key agent.pem agent.key scanner.pem) do (
    if not exist "certs\%%f" (
        echo [FAIL] Missing certs\%%f
        set "CERT_OK=0"
    )
)
if "%CERT_OK%"=="0" (
    echo.
    echo [FATAL] TLS certificates are incomplete. Run scripts\gen-certs.ps1 manually or install OpenSSL.
    pause
    exit /b 1
) else if "%QUICK_MODE%"=="1" (
    echo [OK] Certs validated
)

if not exist "build" mkdir build
        xcopy /y /q "gui-csharp\bin\Release\*.*" "build\" >nul 2>&1
        echo [OK] GUI built successfully
    )
) else (
    echo [6/9] MSBuild not found — skipping C# GUI build
)

echo [8/9] Launching C# GUI...
if exist "%~dp0build\MonolithGui.exe" (
    start "" "%~dp0build\MonolithGui.exe"
    echo [OK] GUI launched
) else if exist "%~dp0gui-csharp\bin\Release\MonolithGui.exe" (
    start "" "%~dp0gui-csharp\bin\Release\MonolithGui.exe"
    echo [OK] GUI launched
) else (
    echo [WARN] No C# GUI binary found
)

echo [9/9] Shared library built ^(as dependency of backend + agent^)

echo.
echo ======================================================
echo   All services launched
echo.
echo   YARA Matcher    127.0.0.1:50054
echo   Go Scanner      127.0.0.1:50052 ^(gRPC^)
echo   Go Scanner      127.0.0.1:50053 ^(HTTP API^)
echo   Backend REST    127.0.0.1:8443
echo   Backend gRPC    127.0.0.1:9443
echo   Backend WS      127.0.0.1:7443
echo   Agent           ^(persistent via kernel driver^)
echo   C# GUI          ^(desktop window^)
echo.
echo   Press Ctrl+C or close GUI to stop services.
echo ======================================================
echo.

set MONITOR_TICK=0

:monitor
ping -n 6 127.0.0.1 >nul
set /a MONITOR_TICK+=1

REM Check Backend
tasklist /fi "ImageName eq monolith-backend.exe" 2>nul | find /i "monolith-backend.exe" >nul
if errorlevel 1 goto shutdown

set /a MOD_VAL=MONITOR_TICK %% 6
if "!MOD_VAL!"=="0" (
    >nul 2>&1 curl.exe -sk https://127.0.0.1:8443/api/v1/health/ready
    if errorlevel 1 (
        title Monolith EDR - WARNING - Backend unreachable
    ) else (
        title Monolith EDR - All services running
    )
)

goto monitor

:shutdown
echo.
echo Shutting down Monolith EDR services...
taskkill /f /im MonolithGui.exe        >nul 2>&1
echo   GUI terminated

REM Agent is guarded by OB callback — taskkill is expected to fail.
REM If the agent was started in this console, Ctrl+C already sent it
REM CTL_CLOSE_EVENT, so it will exit on its own. If not, it survives.
taskkill /f /im monolith-agent.exe     >nul 2>&1
if errorlevel 1 (
    echo   Agent protected by driver — will survive until console close
) else (
    echo   Agent terminated
)
taskkill /f /im monolith-backend.exe   >nul 2>&1
echo   Backend terminated
taskkill /f /im scanner.exe            >nul 2>&1
echo   Scanner terminated
taskkill /f /im monolith-matcher.exe   >nul 2>&1
echo   YARA matcher terminated
ping -n 2 127.0.0.1 >nul
echo All services stopped.
pause
exit /b 0
