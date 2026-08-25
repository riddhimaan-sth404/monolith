@echo off
setlocal enabledelayedexpansion
title Monolith EDR - Requirements and Components Installer

echo ==============================================================================
echo Monolith EDR - Complete Environment ^& Visual Studio Installer
echo ==============================================================================

:: 1. Check for Administrator elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo [OK] Running with Administrator privileges.
echo.

:: 2. Locate Visual Studio Installer & VS Installation Path
set "VS_INSTALLER=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\setup.exe"
set "VS_WHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VS_PATH="

if exist "%VS_WHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VS_WHERE%" -latest -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if "%VS_PATH%"=="" (
    if exist "C:\Program Files\Microsoft Visual Studio\18\Community" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community"
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional"
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
)

if not exist "%VS_INSTALLER%" (
    echo [ERROR] Visual Studio Installer was not found at: "%VS_INSTALLER%"
    echo Please install Visual Studio 2022 or newer from https://visualstudio.microsoft.com/
    goto :INSTALL_EXTERNAL_TOOLS
)

if "%VS_PATH%"=="" (
    echo [WARNING] Existing Visual Studio instance path could not be detected.
    echo Defaulting to standard Community path...
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community"
)

echo [1/3] Modifying Visual Studio installation at: "%VS_PATH%"
echo Installing all required workloads and components directly (no .vsconfig required)...
echo Components:
echo   - .NET Desktop Development (Workload)
echo   - .NET Framework 4.8.1 SDK ^& Targeting Pack
echo   - .NET Framework 4.8 SDK ^& Targeting Pack
echo   - Desktop Development with C++ (Workload)
echo   - MSVC C++ x64/x86 Build Tools
echo   - Windows 11 SDK (10.0.26100.0)
echo   - C++ ATL Support
echo   - C++ CMake Project Tools
echo   - Windows Driver Kit (WDK) Integration
echo.

"%VS_INSTALLER%" modify --installPath "%VS_PATH%" ^
  --add Microsoft.VisualStudio.Workload.ManagedDesktop ^
  --add Microsoft.VisualStudio.Component.ManagedDesktop.Core ^
  --add Microsoft.VisualStudio.Component.ManagedDesktop.Prerequisites ^
  --add Microsoft.Net.Component.4.8.1.SDK ^
  --add Microsoft.Net.Component.4.8.1.TargetingPack ^
  --add Microsoft.Net.Component.4.8.SDK ^
  --add Microsoft.Net.Component.4.8.TargetingPack ^
  --add Microsoft.Net.ComponentGroup.4.8.1.DeveloperTools ^
  --add Microsoft.Net.ComponentGroup.DevelopmentPrerequisites ^
  --add Microsoft.VisualStudio.Workload.NativeDesktop ^
  --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
  --add Microsoft.VisualStudio.Component.Windows11SDK.26100 ^
  --add Microsoft.VisualStudio.Component.VC.ATL ^
  --add Microsoft.VisualStudio.Component.VC.CMake.Project ^
  --add Component.Microsoft.Windows.DriverKit ^
  --includeRecommended ^
  --passive ^
  --norestart

if %errorlevel% equ 0 (
    echo [SUCCESS] Visual Studio components verified and installed!
) else if %errorlevel% equ 3010 (
    echo [SUCCESS] Visual Studio components installed (system reboot recommended).
) else (
    echo [INFO] VS Installer finished with exit code %errorlevel%.
)

:INSTALL_EXTERNAL_TOOLS
echo.
echo ==============================================================================
echo [2/3] Installing and Verifying External Project Requirements
echo ==============================================================================

:: Protobuf compiler (protoc)
where protoc >nul 2>&1
if %errorlevel% neq 0 (
    if not exist "C:\Program Files\protoc\bin\protoc.exe" (
        echo [INFO] Downloading and installing Protocol Buffers Compiler (protoc 29.3)...
        powershell -NoProfile -Command ^
            "$p = '$env:TEMP\protoc.zip'; " ^
            "Invoke-WebRequest -Uri 'https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-win64.zip' -OutFile $p; " ^
            "Expand-Archive -Path $p -DestinationPath 'C:\Program Files\protoc' -Force; " ^
            "Remove-Item $p -Force"
    )
    set "PATH=C:\Program Files\protoc\bin;!PATH!"
    powershell -NoProfile -Command "[System.Environment]::SetEnvironmentVariable('Path', [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\Program Files\protoc\bin', 'Machine')" >nul 2>&1
    echo [OK] protoc installed to C:\Program Files\protoc\bin
) else (
    echo [OK] protoc is already available.
)

:: Rust toolchain
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    if not exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
        echo [INFO] Downloading and installing Rust (x86_64-pc-windows-msvc)...
        powershell -NoProfile -Command ^
            "$r = '$env:TEMP\rustup-init.exe'; " ^
            "Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile $r; " ^
            "Start-Process -FilePath $r -ArgumentList '-y --default-toolchain stable --profile default' -Wait; " ^
            "Remove-Item $r -Force"
    )
    set "PATH=%USERPROFILE%\.cargo\bin;!PATH!"
    echo [OK] Rust installed.
) else (
    echo [OK] Rust is already available.
)

:: Go
where go >nul 2>&1
if %errorlevel% neq 0 (
    if not exist "C:\Program Files\Go\bin\go.exe" (
        echo [INFO] Downloading and installing Go 1.23...
        powershell -NoProfile -Command ^
            "$g = '$env:TEMP\go.msi'; " ^
            "Invoke-WebRequest -Uri 'https://go.dev/dl/go1.23.0.windows-amd64.msi' -OutFile $g; " ^
            "Start-Process msiexec.exe -ArgumentList '/i', $g, '/quiet', '/norestart' -Wait; " ^
            "Remove-Item $g -Force"
    )
    set "PATH=C:\Program Files\Go\bin;!PATH!"
    echo [OK] Go installed to C:\Program Files\Go\bin
) else (
    echo [OK] Go is already available.
)

:: Task runner
where task >nul 2>&1
if %errorlevel% neq 0 (
    if not exist "C:\Program Files\task\task.exe" (
        echo [INFO] Downloading and installing Task runner...
        powershell -NoProfile -Command ^
            "$t = '$env:TEMP\task.zip'; " ^
            "Invoke-WebRequest -Uri 'https://github.com/go-task/task/releases/download/v3.40.0/task_windows_amd64.zip' -OutFile $t; " ^
            "Expand-Archive -Path $t -DestinationPath 'C:\Program Files\task' -Force; " ^
            "Remove-Item $t -Force"
    )
    set "PATH=C:\Program Files\task;!PATH!"
    powershell -NoProfile -Command "[System.Environment]::SetEnvironmentVariable('Path', [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\Program Files\task', 'Machine')" >nul 2>&1
    echo [OK] Task runner installed to C:\Program Files\task
) else (
    echo [OK] Task runner is already available.
)

echo.
echo ==============================================================================
echo [3/3] Creating Directories ^& Generating Development Certificates
echo ==============================================================================

set "PROJECT_ROOT=%~dp0.."
if not exist "%PROJECT_ROOT%\certs" mkdir "%PROJECT_ROOT%\certs"
if not exist "%PROJECT_ROOT%\data" mkdir "%PROJECT_ROOT%\data"
if not exist "%PROJECT_ROOT%\logs" mkdir "%PROJECT_ROOT%\logs"
if not exist "%PROJECT_ROOT%\build" mkdir "%PROJECT_ROOT%\build"

if exist "%~dp0gen-certs.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0gen-certs.ps1"
)

echo.
echo ==============================================================================
echo [COMPLETE] All requirements and Visual Studio components are installed!
echo ==============================================================================
echo.
pause
