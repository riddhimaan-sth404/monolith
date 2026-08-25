# Monolith Endpoint Detection and Response (EDR)

Monolith is an enterprise-grade Endpoint Detection and Response platform designed for Microsoft Windows environments. It provides real-time kernel-level telemetry collection, multi-stage threat scanning (combining static signature analysis, YARA rules, and EMBER LightGBM machine learning models), automated threat isolation and quarantine, and a centralized management architecture.

## System Architecture

Monolith is built using a multi-component architecture leveraging Rust, Go, C (KMDF), and C# WPF.

### Core Subsystems

| Component | Technology | Role & Description |
| :--- | :--- | :--- |
| **Backend** | Rust (Axum 0.8) | Management server handling REST API endpoints, gRPC control pipelines, WebSocket live event streaming, detection correlation engine, and policy enforcement. |
| **Agent** | Rust (Windows Service) | Endpoint monitoring daemon running as a Windows Service. Collects event telemetry from the kernel driver ring buffer, executes local detection logic, and synchronizes status with the backend. |
| **Kernel Driver** | C (KMDF Driver) | Kernel-mode driver providing process creation, thread creation, image loading, registry modification, and file I/O monitoring callbacks with tamper-resistance controls. |
| **File Scanner** | Go | Distributed file scanning engine integrating static PE parsing, YARA rule matching, EMBER LightGBM machine learning classification, and AES-256-GCM encrypted file quarantine. |
| **YARA Matcher** | Rust | High-performance YARA sidecar service providing real-time pattern matching over dedicated HTTP interfaces. |
| **Management Console** | C# (WPF) | Desktop management console providing live threat dashboards, system telemetry views, scan controls, policy configuration, allowlist management, and PDF/CSV reporting. |

---

## Technical Specifications

### Network Ports & Communication Protocols

All external and inter-service network traffic is strictly secured using TLS and mutual TLS (mTLS):

| Port | Protocol | Usage | Security |
| :--- | :--- | :--- | :--- |
| **8443** | HTTPS / REST | Backend REST API for administration and GUI management | TLS 1.3 / JWT Authentication |
| **9443** | gRPC | Agent-to-Backend telemetry and command sync | mTLS (Certificate Pinning) |
| **7443** | WebSocket | Live event push streaming to management consoles | WSS / JWT |
| **50053** | HTTP | Scanner control API (Backend trigger & polling) | Loopback (127.0.0.1) |
| **50072** | gRPC | Scanner single-file transactional scanning service | Loopback (127.0.0.1) |
| **50074** | HTTP | YARA Matcher sidecar rule engine | Loopback (127.0.0.1) |

---

## Detection & Machine Learning Pipeline

Monolith implements a multi-stage threat evaluation pipeline to balance high detection efficacy with low false-positive rates:

1. **Authenticode Verification**: Validates digital signatures using the Windows WinTrust API. Validly signed executables from trusted certificate authorities skip heavy ML scoring.
2. **YARA Pattern Matching**: Evaluates file contents against specialized YARA rule packs targeting malware families, webshells, packers, and exploit payloads.
3. **PE Metadata Heuristics**: Analyzes PE header anomalies, section entropy, import table characteristics, TLS callbacks, and compiler timestamps.
4. **EMBER LightGBM ML Inference**: Extracts 2,568 feature vectors across byte histograms, entropy distributions, section attributes, import/export tables, and string patterns. Evaluates separate models for general PE classification, exploit payloads, packer detection, and .NET assemblies.
5. **Verdict Fusion Engine**: Merges multi-dimensional scores into final verdicts (`clean`, `suspicious`, `malicious`) with automated sandbox routing for borderline probabilities.

---

## Prerequisites & Dependencies

Before building Monolith, ensure the following software tools are installed on your Windows system:

- **Operating System**: Windows 10 / Windows 11 x64 or Windows Server 2019+
- **Visual Studio 2022+ / Build Tools**:
  - Desktop development with C++ (MSVC x64/x86 tools, Windows 11 SDK, ATL, CMake)
  - .NET desktop development (.NET Framework 4.8.1 SDK & Targeting Pack)
  - Windows Driver Kit (WDK) Visual Studio Integration
- **Rust Compiler**: 1.80+ (`rustup default stable-x86_64-pc-windows-msvc`)
- **Go**: 1.22+
- **Protocol Buffers Compiler**: `protoc` 29.3+
- **Task Runner**: `task` (optional but recommended)

---

## Build & Execution Instructions

### Initial Setup & Prerequisites Installation

Run the automated installer script to install all Visual Studio components, compilers, tools, directories, and certificates:

```cmd
:: Run automated full environment & Visual Studio components setup
.\scripts\install-vs-components.bat
```

Or execute setup steps individually via PowerShell:

```powershell
# 1. Install prerequisites and setup directory structure
.\scripts\setup.ps1

# 2. Generate mTLS self-signed CA and service certificates
.\scripts\gen-certs.ps1
```

### Quick Start Launcher (Recommended)

To compile, verify, and launch all backend services, file scanners, YARA matchers, agents, and the C# WPF console in a unified environment:

```cmd
:: Launch all components in Debug mode
run-all.bat

:: Launch in Release mode
run-all.bat --release

:: Launch in Quick mode (skip rebuilds and cert checks)
run-all.bat --quick
```

### Manual Service Execution

Services can also be launched individually via `task` or raw binaries:

```powershell
# Build all components
task build:all

# Run Backend Server (REST :8443, gRPC :9443, WS :7443)
cargo run -p monolith-backend -- --config configs/backend.toml

# Run File Scanner Engine (HTTP :50053, gRPC :50072)
cd scanner; go run ./cmd/scanner/ --config ../configs/scanner.yaml

# Run YARA Matcher Sidecar (:50074)
cargo run -p monolith-matcher -- --rules scanner/yara/rules --listen 127.0.0.1:50074

# Build & Run C# Management Console
msbuild gui-csharp/MonolithGui.csproj /t:Restore,Build /p:Configuration=Release
.\gui-csharp\bin\Release\MonolithGui.exe
```

### Environment Variables

- `EDR_JWT_SECRET`: Overrides the default JWT signing key for backend authentication. Required for production deployments.
- `RUSTLS_CRYPTO_PROVIDER`: Pinned to `ring` for standardized cryptographic operations.

---

## Reset & Cleanup

To stop running processes, flush database tables, clear quarantine repositories, and remove log files:

```cmd
reset-all.bat
```

---

## Verification & Testing

Monolith contains automated test suites covering unit logic, gRPC communication, API endpoints, and detection correlation:

```powershell
# Run all test suites across Rust and Go
task test:all

# Run Rust unit and integration tests (single-threaded required for DB isolation)
cargo test --workspace -- --test-threads=1

# Run Go scanner tests
cd scanner; go test ./... -v -count=1
```

---

## Directory Layout

```
monolith/
├── agent/            # Rust Windows Service agent daemon
├── backend/          # Rust Axum management server & detection engine
├── certs/            # Auto-generated mTLS certificates
├── configs/          # TOML and YAML configuration files
├── driver/           # C KMDF Kernel-mode driver
├── gui-csharp/       # C# WPF desktop management console
├── matcher/          # Rust YARA matcher sidecar service
├── protobuf/         # Protobuf definitions and codegen rules
├── scanner/          # Go multi-engine file scanner & EMBER ML models
├── shared/           # Rust shared types, DB migrations, crypto, and models
├── scripts/          # Setup and certificate generation PowerShell scripts
├── reset-all.bat     # Database and log reset utility
├── run-all.bat       # Master system launcher
└── Taskfile.yml      # Task runner configuration
```

---

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
