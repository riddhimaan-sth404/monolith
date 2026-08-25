# Monolith Shared Library

`monolith-shared` is the foundational Rust crate shared across `monolith-backend`, `monolith-agent`, and `monolith-matcher`. It provides core data structures, database abstractions, cryptographic utilities, logging initializers, and embedded migrations.

## Key Modules

- **`types`**: Core domain models, telemetry event schemas, alert structures, scan results, and enum definitions.
- **`db`**: Generic database connection traits (`DatabaseConnection`, `Transaction`), embedded SQLite migration manager (`include_str!`), and PostgreSQL connection pooling (`sqlx::PgPool`).
- **`crypto`**: JWT token generation and verification routines, Argon2id password hashing, base64 payload handling, and configuration signature verification.
- **`auth`**: Role-Based Access Control (RBAC) permission matrices (`Administrator`, `Analyst`, `Viewer`).
- **`license`**: Ed25519 digital license verification and expiration checking.
- **`logging`**: Dual-output JSON/Text tracing initializer using `tracing-subscriber` and `tracing-appender`.
- **`error`**: Centralized `EdrError` enum mapping database, network, authentication, and validation errors to HTTP status codes.

## Running Tests

```powershell
cargo test -p monolith-shared
```
