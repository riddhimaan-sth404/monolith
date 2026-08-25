# Monolith Backend Server

The Monolith Backend is an enterprise management server built in Rust using Axum 0.8. It serves as the primary control plane for endpoint agents, file scanners, threat detection correlation, policy administration, and desktop management consoles.

## Core Capabilities

- **REST Administrative API (`:8443`)**: Handles authentication, user management, endpoint registration, scan triggers, alert queries, allowlists, IOC management, and reporting. Secured via TLS 1.3 and JWT tokens.
- **Agent gRPC Service (`:9443`)**: High-throughput gRPC endpoint (`EndpointService`, `ManagementService`) utilizing mTLS for secure telemetry ingest and agent command dispatch.
- **Live Event Push (`:7443`)**: Real-time WebSocket event streaming pipeline (`LiveEventBus`) broadcasting endpoint events, threat alerts, and scan status updates to connected management consoles.
- **Correlation & Detection Engine**: Multi-stage detection system processing events through IOC hash/IP matching, behavioral correlation rules, and automated response playbooks.
- **Multi-Database Support**: High-performance embedded SQLite storage with migration tracking, plus modular PostgreSQL database pooling via `sqlx`.

## Architecture & Module Structure

```
backend/src/
├── config.rs         # Application configuration parsing and validation
├── engine/           # Detection engine, rule cache, IOC matcher, behavioral correlation
├── db/               # Repository abstractions and database queries
├── grpc/             # Tonic gRPC services for agent and scanner integration
├── handlers/         # Axum REST endpoint handlers (scans, alerts, endpoints, iocs, auth)
├── middleware/       # JWT auth verification, Redis sliding-window rate limiting, request tracing
├── reporting/        # PDF (printpdf) and CSV report generation engines
├── router.rs         # HTTP router composition and security headers
└── server.rs         # Server initialization, TLS setup, database connection pool, graceful shutdown
```

## REST API Specification

| Endpoint Path | HTTP Method | Description | Required Role |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth/login` | POST | Authenticates users and returns JWT tokens | Public |
| `/api/v1/dashboard` | GET | Returns global telemetry metrics, active alerts, and scan status | Viewer / Analyst / Admin |
| `/api/v1/events/ingest` | POST | Ingests endpoint telemetry, runs detection engine, broadcasts WS events | Agent / Automation |
| `/api/v1/scans` | POST | Initiates quick, full, or custom file system scans | Analyst / Admin |
| `/api/v1/alerts` | GET | Queries active and resolved threat alerts with pagination | Viewer / Analyst / Admin |
| `/api/v1/quarantine` | GET | Lists quarantined malware samples across endpoints | Analyst / Admin |
| `/api/v1/reports/pdf` | GET | Generates downloadable executive PDF threat reports | Analyst / Admin |

## Running the Backend

```powershell
# Run with default config
cargo run -p monolith-backend -- --config configs/backend.toml

# Override JWT signing secret (Required for Production)
$env:EDR_JWT_SECRET="your-production-256bit-secret-here"
cargo run --release -p monolith-backend -- --config configs/backend.toml
```
