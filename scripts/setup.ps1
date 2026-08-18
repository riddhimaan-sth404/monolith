<#
.SYNOPSIS
    EDR Platform Setup Script
.DESCRIPTION
    Installs all prerequisites for the EDR platform development environment.
.NOTES
    Run as Administrator. Some steps require Visual Studio Build Tools.
#>

$ErrorActionPreference = "Stop"

Write-Host "=== EDR Platform Setup ===`n" -ForegroundColor Cyan

function Test-Command {
    param([string]$Name, [string]$VersionArg = "--version")
    try {
        $v = & $Name $VersionArg 2>&1
        Write-Host "  [OK] $Name: $v" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  [MISSING] $Name" -ForegroundColor Yellow
        return $false
    }
}

# 1. Check existing tools
Write-Host "Checking prerequisites..." -ForegroundColor White
$hasRust = Test-Command rustc
Test-Command cargo
Test-Command go
Test-Command python
Test-Command protoc
Test-Command cmake
Test-Command git

# 2. Install Rust if missing
if (-not $hasRust) {
    Write-Host "`nInstalling Rust..." -ForegroundColor White
    # rustup-init.exe downloaded and run
    $rustup = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustup
    Start-Process -FilePath $rustup -ArgumentList "-y --default-toolchain stable --profile default" -Wait
    # Add to PATH for current session
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    rustc --version
    cargo --version
    # Install useful cargo tools
    cargo install cargo-audit cargo-deny cargo-tarpaulin cargo-expand cargo-udeps
}

# 3. Install Go if missing
$hasGo = Test-Command go
if (-not $hasGo) {
    Write-Host "`nInstalling Go..." -ForegroundColor White
    $goUrl = "https://go.dev/dl/go1.23.0.windows-amd64.msi"
    $goInstaller = "$env:TEMP\go.msi"
    Invoke-WebRequest -Uri $goUrl -OutFile $goInstaller
    Start-Process msiexec -ArgumentList "/i $goInstaller /quiet" -Wait
    $env:Path = "C:\Program Files\Go\bin;$env:Path"
    go version
}

# 4. Install protoc if missing
$hasProtoc = Test-Command protoc
if (-not $hasProtoc) {
    Write-Host "`nInstalling protoc..." -ForegroundColor White
    $protocUrl = "https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-win64.zip"
    $protocZip = "$env:TEMP\protoc.zip"
    Invoke-WebRequest -Uri $protocUrl -OutFile $protocZip
    Expand-Archive -Path $protocZip -DestinationPath "C:\Program Files\protoc" -Force
    $env:Path = "C:\Program Files\protoc\bin;$env:Path"
    protoc --version
}

# 5. Install Task runner
if (-not (Test-Command task)) {
    Write-Host "`nInstalling Task runner..." -ForegroundColor White
    # scoop install task or download manually
    $taskUrl = "https://github.com/go-task/task/releases/download/v3.40.0/task_windows_amd64.zip"
    $taskZip = "$env:TEMP\task.zip"
    Invoke-WebRequest -Uri $taskUrl -OutFile $taskZip
    Expand-Archive -Path $taskZip -DestinationPath "C:\Program Files\task" -Force
    $env:Path = "C:\Program Files\task;$env:Path"
}

# 6. Create required directories
Write-Host "`nCreating project directories..." -ForegroundColor White
@("certs", "data", "logs", "build") | ForEach-Object {
    $p = Join-Path $PWD $_
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

# 7. Generate development certificates
Write-Host "`nGenerating development certificates..." -ForegroundColor White
& "$PSScriptRoot\gen-certs.ps1"

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
Write-Host "Restart your terminal or run: `$env:Path = [System.Environment]::GetEnvironmentVariable('Path','User')" -ForegroundColor Yellow
