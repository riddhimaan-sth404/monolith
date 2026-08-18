# Monolith — Demo Walkthrough

## Prerequisites

- All components built (`task build:all`)
- TLS certs generated (`task certs`)
- Backend running (`cargo run -p monolith-backend -- --config configs/backend.toml`)

## Demo Flow: "Attack → Detect → Respond"

### Step 1: Seed Data

Pre-populate IOCs and demo data so the GUI isn't empty:

```powershell
powershell -File demo\seed-data.ps1
```

### Step 2: Simulate Attack

Run the attack simulation to generate telemetry events:

```powershell
powershell -File demo\simulate-attack.ps1
```

This triggers:
| Phase | Tactic | What it does |
|-------|--------|-------------|
| 1 | **LOLBin Chain (T1218)** | rundll32.exe + regsvr32.exe with suspicious args |
| 2 | **Obfuscated PowerShell (T1027)** | Base64-encoded command + download cradle |
| 3 | **Registry Persistence (T1547.001)** | Run key added to HKCU |
| 4 | **Beaconing (T1071)** | Outbound TCP connects to C2 IPs |
| 5 | **Discovery (T1082/T1016)** | systeminfo, netstat, whoami |
| 6 | **Test files** | EICAR + malicious scripts for YARA scanner |
| 7 | **Masquerading (T1036)** | notepad.exe renamed to svchost.exe |

### Step 3: Observe Detection

1. **GUI**: Open `python gui/app/main.py` → Alerts page shows detected events
2. **API**: Check `GET /api/v1/alerts/summary` for alert counts
3. **Events**: Check `GET /api/v1/events` for ingested telemetry
4. **Metrics**: Check `GET /api/v1/metrics` for event/alert counters

### Step 4: Respond

1. **Isolate endpoint**: `POST /api/v1/endpoints/{id}/isolate`
2. **Trigger scan**: `POST /api/v1/scans` with endpoint target
3. **Generate report**: `POST /api/v1/reports` for PDF/CSV/JSON

### Step 5: Verify Scanner (YARA + PE)

With the Go scanner running (`cd scanner && go run ./cmd/scanner/`):

1. Scanner picks up EICAR test file in `%TEMP%\EDR_Demo_Scan\`
2. YARA rules from `yara/yara-rules-full.yar` (11,728 rules) match malware patterns
3. Malicious files are quarantined

## Expected Results

| Detection Engine | Triggered By | Alert Output |
|-----------------|-------------|-------------|
| IOC Matcher | EICAR hash match | `IOC match: sha256/eicar` |
| Correlation: LOLBin | rundll32.exe / regsvr32.exe | `LOLBin chain detected` |
| Correlation: Obfuscated | Base64 PowerShell | `Obfuscated command detected` |
| Correlation: Persistence | Registry Run key | `Persistence mechanism detected` |
| Correlation: Discovery | systeminfo/netstat/whoami | `Discovery commands detected` |
| Correlation: Masquerading | svchost.exe from temp | `Masquerading detected` |
| YARA Scanner | EICAR + suspicious scripts | `YARA rule match: EICAR/PS1` |
