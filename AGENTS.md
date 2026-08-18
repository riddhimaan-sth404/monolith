# Monolith — Agent Guide

## Build & Run

Use `task` (Taskfile.yml) for all multi-component commands — not raw cargo.

```powershell
# Prerequisites
.\scripts\setup.ps1            # Install Rust, Go, protoc, Task runner, create dirs
.\scripts\gen-certs.ps1        # Generate mTLS certs (required before running)

# Build individual components
task build:shared   # cargo build --release in shared/
task build:backend  # depends on build:shared
task build:agent    # depends on build:shared
task build:scanner  # go build -o ../build/scanner.exe ./cmd/scanner/
# (GUI stripped, to be rewritten from scratch in C#)

# Build all
task build:all
```

### Run (dev)
```powershell
# Backend: REST :8443, gRPC :9443, WS :7443
# JWT secret overridable via EDR_JWT_SECRET env var (REQUIRED: do not use the default)
cargo run -p monolith-backend -- --config configs/backend.toml

# Scanner: local gRPC :50052 (config: configs/scanner.yaml)
cd scanner && go run ./cmd/scanner/

# Agent: Windows service (requires admin)
cargo run -p monolith-agent

# (GUI stripped, to be rewritten from scratch in C#)
```

### Lint, Test, Audit (order matters: lint → test)
```powershell
task lint:rust    # cargo clippy --workspace -- -D warnings + cargo fmt --all --check
task lint:go      # go vet + staticcheck
task lint:py      # ruff check + ruff format --check (deprecated, no GUI)

task test:rust    # cargo test --workspace
task test:go      # go test ./... -v -count=1
task test:py      # pytest tests/ -v (deprecated, no GUI)
task test:all     # all three

task test:integration   # cargo test --test integration -- --test-threads=1 (serial only)
task test:api           # cargo test --test api
task test:bench         # cargo bench
task coverage           # cargo tarpaulin --workspace --out html
task audit              # cargo audit + cargo deny check
task docs               # mdbook build docs
task docs:serve         # mdbook serve docs --open
```

## Architecture

| Component | Language | Entrypoint | Description |
|-----------|----------|------------|-------------|
| `backend/` | Rust (axum 0.8) | `src/main.rs` | Management server: REST API, gRPC, WS, detection engine |
| `agent/` | Rust (Windows Service) | `src/main.rs` | Endpoint agent: collector, sync, driver comm |
| `shared/` | Rust | `src/lib.rs` | Shared: config, crypto, auth, DB traits, types, migrations |
| `protobuf/` | Rust (build.rs) | `build.rs` | Proto → Rust/Go codegen (tonic + prost) |
| `scanner/` | Go | `cmd/scanner/main.go` | File scanner: YARA, PE parser, quarantine (AES-256-GCM), fsnotify |
| `driver/` | C (KMDF) | `edr.vcxproj` | Kernel driver: callbacks, ring buffer |
| *(GUI stripped)* | *(to be rewritten)* | *(from scratch in C#)* | *(desktop management console)* |

### Workspace (Rust)
Crates: `monolith-backend`, `monolith-agent`, `monolith-shared`, `monolith-protobuf`. Edition 2024, resolver 2.

## Key Constraints

- **Windows-only**: CI runs on `windows-latest`. All targets are Windows. Agent runs as a Windows service (`windows-service` crate).
- **Cargo.lock is .gitignore'd** (deliberate — workspace but lockfile not tracked).
- **`unsafe_code = "deny"`** in workspace lints. `missing_docs = "warn"` — add doc comments.
- **All network communication is TLS/mTLS**: REST :8443 (JWT), Agent-Backend gRPC :9443 (mTLS), WS :7443 (JWT), Agent-Scanner gRPC :50052 (loopback, no TLS).
- **Database**: SQLite via `rusqlite` (bundled). Migrations in `shared/migrations/`, embedded via `include_str!` in code, applied at startup by both backend and agent.
- **Protobuf**: Generated automatically in `protobuf/build.rs`. Requires `protoc` installed. Rebuilds on `.proto` changes.
- **Config**: TOML files in `configs/`. Agent config uses `%ProgramData%` paths. Backend reads `--config` CLI arg. Scanner config reads `configs/scanner.yaml` (fallback to `scanner.toml`).
- **Config overrides**: `configs/*.local.toml` in .gitignore — use for local overrides.
- **JWT secret**: Can be overridden via `EDR_JWT_SECRET` env var (takes precedence over config file).
- **Metrics**: Available at `GET /api/v1/metrics` (counters for events, alerts, requests, errors).

## Key API Endpoints (besides standard CRUD)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/events/ingest` | POST | Ingest events, runs detection engine, publishes to WS |
| `/api/v1/metrics` | GET | Prometheus-style counters |
| `/api/v1/ws/events` | WS | Push-based live events via `LiveEventBus` |
| `/api/v1/health/ready` | GET | Readiness check (includes DB connectivity) |

## Scanner HTTP API (Go scanner, port 50053)

Used by the backend to trigger on-demand scans via HTTP (bypasses broken gRPC stubs).

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/scan/start` | POST | Start scan. Body: `{"scan_type": "quick"\|"full"\|"custom", "paths": [...]}` |
| `/api/scan/status` | GET | Returns `{"active_jobs": N, "status": "running"\|"completed", "current_path": "..."}` |
| `/api/scan/results` | GET | Returns full `[]ScanResult` array with verdicts, scores, rules |

The Go scanner tracks the currently-scanned file path via `ScannerEngine.currentPath` (atomic.Value), set by each worker goroutine at the start of every `scanFile` call. The scan API exposes it in the status response.

Backend `trigger()` handler (`handlers/scans.rs`) calls the scanner HTTP API in a background task: start → poll every 2s (updates `details.current_path` in DB each cycle for the GUI progress bar) → fetch results on completion → store verdict breakdown + full `[]ScanResult` JSON in `scan_results` table (`details` column). The old file-walking-in-process approach is replaced. This avoids the gRPC bridge altogether.

Dashboard `/api/v1/dashboard` endpoint reads `current_path` from the running scan's `details` JSON field and returns it for the GUI progress bar. The `last_completed_scan` now includes `all_results` (full pipeline data per file) and `threat_details` (filtered non-clean results).

## Testing Gotchas

- Integration tests **must run single-threaded**: `--test-threads=1`
- Rust tests use `tempfile` for DB test isolation (in-memory + temp dirs)
- `testcontainers` is a workspace dependency (for future container-based tests)
- Go tests use `-count=1` to disable caching
- Python tests require `pytest-qt` (needs display server; skip in non-interactive CI)

## Protobuf Codegen

Proto files in `protobuf/edr/proto/v1/`. `protobuf/build.rs` generates both:
1. **tonic** gRPC server/client code (`build_server(true)`, `build_client(true)`)
2. **prost** pure types for shared use

Go code is regenerated separately — `go_package` option points to `scanner/internal/grpc/pb`.

## Certificates

Development certs generated by `scripts/gen-certs.ps1` into `certs/`. Creates self-signed CA + per-component certs. Production should use a proper PKI.

## Enterprise Fixes Applied

| Area | Changes |
|------|---------|
| **Security** | Brute-force lockout (10 attempts → 30min lock), JWT secret via env var, security headers (X-Content-Type-Options), restricted CORS, IOCTL caller integrity checks (`IoValidateDeviceIoControlAccess`) |
| **Detection** | DetectionEngine wired into event pipeline, alerts created on match, LiveEventBus broadcasts events |
| **gRPC** | Backend EndpointService/ScannerService/ManagementService implemented, Scanner gRPC methods wired to engine |
| **Scans** | Quarantine triggered on malicious verdict, Results channel consumed for logging |
| **Metrics** | /api/v1/metrics endpoint with counters |
| **CI** | Integration tests, API tests, Python tests, lint:py format check all added |
| **Bug fixes** | Ring buffer SequenceNumber corruption (driver), secureWipe never writing (Go), EDR_REGISTRATION_TAG missing (driver), scanner config TOML/YAML mismatch, ringbuf.c payload/header write ordering (driver) |
| **Python GUI** | ApiClient switched from aiohttp+asyncio to requests (deadlock fix), config path uses `__file__`-relative resolution, orphaned `QLabel`→`QMessageBox`, `QFrame`→`QDialog` with proper layout |
| **CI/CD** | Python version pinned to 3.12, test target names fixed (`integration`→`api_integration`, removed dead `test-api`), Python test step uses `|| echo`, release.yml now builds driver (`msbuild`) and creates `build/` dir |
| **Config** | `agent.toml` now has `[logging]` table and `kind`/`max_connections` in `[database]`, `scanner.toml` marked deprecated |
| **Bench fixes** | Custom `impl Debug` for benchmark `EventProcessor` (removed `#[derive(Debug)]` on raw pointer), unused import removed in `engine.rs`, `detection.rs`, `ioc_matcher.rs`, `iocs.rs`, `reporting/mod.rs`, `grpc/mod.rs` |
| **Config** | Scanner now reads configs/scanner.yaml (was silently failing on TOML parse) |
| **YARA CGo** | `MatchFile()` implemented with real CGo YARA via `github.com/hillar/yara` — compiler + `ScanFile` + rule metadata extraction |
| **File monitoring** | Recursive directory watching via `filepath.Walk`, glob expansion, subdirectory auto-discovery, 8000 dir limit |
| **PostgreSQL** | `shared/src/db/postgres.rs` — full `DatabaseConnection` impl via `sqlx::PgPool` with parameterized queries, transactions |
| **Rate limiting** | `backend/src/middleware/redis_rate_limit.rs` — Redis-backed sliding window via `redis` crate with connection manager, auto-expiry |
| **PDF reporting** | `backend/src/reporting/mod.rs` — `printpdf`-based generator with title, summary, alerts table, endpoints table, CSV/JSON export |

## Remaining Gaps (not yet addressed)

- **go.sum missing** — must be generated with `go mod tidy` (requires network; CI without git/network may need vendoring)
- **YARA CGo pseudo-version** `v0.0.0-20241201000000-000000000000` is unresolvable — must be vendored or replaced with a real release
- **Protobuf Go stubs** in `scanner/internal/grpc/pb/` are hand-written — will diverge from `.proto` files when protos change; needs `protoc --go_out=... --go-grpc_out=...` regeneration
- **Ring buffer concurrency**: CAS-based slot claim in `ringbuf.c` writes payload then header with a `MemoryBarrier()` gap — on non-x64 architectures this is not formally correct; acceptable for telemetry on x64
- **PostgreSQL transactions** return `EdrError::NotImplemented` due to sqlx `Transaction<'_, Postgres>` lifetime constraints with `Box<dyn Transaction>` trait object
- **Scanner HTTP API is minimal**: `/api/scan/status` returns only `active_jobs` not per-file progress; `/api/scan/start` for `custom` type walks directories in a goroutine but doesn't exclude configured excluded paths. Enhance when needed.

## Snapshot / Release

On `v*` tag push: builds all binaries, creates `edr.sys` (driver), and uploads artifacts. Uses `cargo build --release -p monolith-backend` and `-p monolith-agent` (not workspace-wide).
