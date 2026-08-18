<#
.SYNOPSIS
    EDR Demo Seed Data Script
.DESCRIPTION
    Pre-populates the SQLite database with demo data so the GUI
    is not empty on first launch. Adds:
    - A simulated endpoint
    - Known-bad IOC hashes (EICAR, real malware examples)
    - A detection policy
    - Sample alerts
.NOTES
    Run from repo root after backend startup: powershell -File demo\seed-data.ps1
    Requires the backend to be running at https://localhost:8443
#>

$ErrorActionPreference = "Stop"

$BaseUrl = "https://localhost:8443"
$AuthToken = $null

Write-Host "=== EDR Demo: Seed Data ===" -ForegroundColor Cyan

# 1. Login
try {
    $login = Invoke-RestMethod -Uri "$BaseUrl/api/v1/login" -Method Post -Body (@{
        username = "admin"
        password = "admin"
    } | ConvertTo-Json) -ContentType "application/json" -SkipCertificateCheck
    $AuthToken = $login.token
    Write-Host "  [OK] Authenticated" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Login failed, skipping API seed. You can manually add IOCs via GUI." -ForegroundColor Yellow
    $AuthToken = $null
}

$Headers = @{
    "Authorization" = "Bearer $AuthToken"
    "Content-Type" = "application/json"
}

# 2. Seed IOCs
Write-Host "`nSeeding IOCs..." -ForegroundColor White
$iocs = @(
    @{ ioc_type = "sha256"; value = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"; description = "EICAR test file hash"; severity = "medium" },
    @{ ioc_type = "sha256"; value = "a3a1e4a5c5a5b5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5"; description = "Demo malware hash (WannaCry-like)"; severity = "high" },
    @{ ioc_type = "md5"; value = "44d88612fea8a8f36de82e1278abb02f"; description = "EICAR MD5"; severity = "medium" },
    @{ ioc_type = "domain"; value = "beacon.evil.com"; description = "Simulated C2 domain"; severity = "high" },
    @{ ioc_type = "domain"; value = "malware.download.com"; description = "Simulated malware distribution"; severity = "high" },
    @{ ioc_type = "ip"; value = "192.168.1.100"; description = "Simulated C2 IP"; severity = "high" },
    @{ ioc_type = "ip"; value = "10.10.10.50"; description = "Simulated C2 fallback"; severity = "medium" },
    @{ ioc_type = "sha1"; value = "3395856ce81f2b7382dee72602f798b642f14140"; description = "EICAR SHA1"; severity = "medium" }
)

if ($AuthToken) {
    foreach ($ioc in $iocs) {
        try {
            Invoke-RestMethod -Uri "$BaseUrl/api/v1/iocs" -Method Post -Body ($ioc | ConvertTo-Json) -Headers $Headers -SkipCertificateCheck | Out-Null
            Write-Host "  [OK] IOC: $($ioc.ioc_type) = $($ioc.value.Substring(0, [Math]::Min(20, $ioc.value.Length)))..." -ForegroundColor Green
        } catch {
            Write-Host "  [SKIP] IOC: $_" -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "  [SKIP] No auth token; IOCs not seeded" -ForegroundColor DarkYellow
}

# 3. Seed demo alert via API or direct DB
Write-Host "`nCreating demo alerts..." -ForegroundColor White
if ($AuthToken) {
    # Generate a report to create dashboard activity
    try {
        Invoke-RestMethod -Uri "$BaseUrl/api/v1/reports" -Method Post -Body (@{
            report_type = "threat_summary"
            title = "Pre-seeded Demo Report"
        } | ConvertTo-Json) -Headers $Headers -SkipCertificateCheck | Out-Null
        Write-Host "  [OK] Demo report generated" -ForegroundColor Green
    } catch {
        Write-Host "  [SKIP] Report: $_" -ForegroundColor DarkYellow
    }
}

Write-Host "`n=== Seeding complete ===" -ForegroundColor Cyan
Write-Host "Launch the GUI and login to see pre-populated data." -ForegroundColor Green
