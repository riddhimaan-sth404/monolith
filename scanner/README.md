# Monolith File Scanner Engine

The Monolith Scanner is a high-throughput, multi-engine file inspection service written in Go. It performs static binary analysis, signature verification, YARA pattern matching, and machine learning inference using LightGBM EMBER models.

## Inspection Pipeline & Detection Stages

When a file path or buffer is enqueued for scanning, it passes through 7 sequential analysis stages:

1. **Hash Calculation & Deduplication**: Computes SHA256, SHA1, and MD5 file hashes while calculating Shannon entropy for packed binary detection.
2. **Authenticode Verification**: Uses WinTrust APIs to verify digital signatures. Validly signed executables from trusted certificate authorities skip heavy ML scoring.
3. **YARA Pattern Matching**: Dispatches file paths to the YARA matcher service (`:50074`) to evaluate rules against malware families, webshells, and exploit payloads.
4. **PE Metadata Parsing**: Extracts headers, section characteristics, import/export tables, TLS callbacks, and compile timestamps.
5. **EMBER LightGBM ML Inference**: Features are extracted (2,568 dimensions) and evaluated against specialized LightGBM models:
   - **PE Model**: Evaluates general malware probability.
   - **Exploit Model**: Detects exploit payload structures.
   - **Packer Model**: Identifies executable compression/packing.
   - **.NET & PDF Models**: Evaluates document and managed assembly structures.
6. **Verdict Fusion Engine**: Merges scores into final verdicts (`clean`, `suspicious`, `malicious`).
7. **AES-256-GCM Quarantine**: Malicious files are safely encrypted with AES-256-GCM and stored in `%ProgramData%\EDR\Quarantine`.

## API Interfaces

- **HTTP Control API (`:50053`)**:
  - `POST /api/scan/start`: Triggers quick, full, or custom directory scans.
  - `GET /api/scan/status`: Returns current progress, active worker jobs, and scanned file paths.
  - `GET /api/scan/results`: Returns full `[]ScanResult` array with verdicts and matched rules.
  - `POST /api/scan/cancel`: Cancels running directory walks and drains worker queues.
- **gRPC Transactional API (`:50072`)**: Single-file scanning interface for real-time endpoint events.

## Directory Structure

```
scanner/
├── cmd/scanner/          # Main entrypoint and CLI flag parsing
├── internal/
│   ├── config/           # YAML/TOML configuration parser (scanner.yaml)
│   ├── ember/            # Feature extraction and LightGBM tree inference engine
│   ├── hasher/           # Hash computation and Shannon entropy calculator
│   ├── monitor/          # Recursive file system watcher (fsnotify)
│   ├── parser/           # PE and PDF static parsing routines
│   ├── quarantine/       # AES-256-GCM file quarantine manager
│   ├── scanner/          # Core worker pool, queue dispatch, and verdict fusion
│   ├── throttle/         # Resource throttling and CPU usage controls
│   └── yara/             # YARA matcher client integration
```

## Running the Scanner

```powershell
cd scanner
go run ./cmd/scanner/ --config ../configs/scanner.yaml
```
