# Monolith Architecture

## Overview

```mermaid
graph TB
    subgraph "Endpoint"
        KMDF["KMDF Kernel Driver"]
        AGENT["Monolith Agent"]
        SCANNER["Monolith Scanner"]
        GUI["Monolith GUI"]
        KMDF -->|IOCTL| AGENT
        AGENT -->|gRPC :50052| SCANNER
    end
    subgraph "Management Server"
        BACKEND["Monolith Backend"]
        DB[("SQLite")]
        DETECT["Detection Engine"]
    end
    AGENT -->|mTLS :9443| BACKEND
    GUI -->|REST :8443| BACKEND
```

## Component Architecture

```mermaid
graph LR
    subgraph "Shared Layer"
        PROTO["Protocol Buffers"]
        SHARED["monolith-shared crate"]
    end
    subgraph "Backend"
        ROUTER["Axum Router"]
        MIDDLEWARE["Middleware Stack"]
        HANDLERS["Handlers (14 modules)"]
        SERVICES["Services (13 modules)"]
        MIDDLEWARE --> HANDLERS
        HANDLERS --> SERVICES
        SERVICES --> SHARED
    end
    subgraph "Agent"
        COLLECTORS["Event Collectors"]
        DRIVERCOMM["Driver Comm"]
        SYNC["Sync Module"]
        COLLECTORS --> DRIVERCOMM
        SYNC --> PROTO
    end
    subgraph "Scanner"
        WORKERS["Worker Pool"]
        HASHER["Hasher"]
        PARSER["PE Parser"]
        YARA["YARA Engine"]
        QUARANTINE["Quarantine"]
        HASHER --> WORKERS
        PARSER --> WORKERS
        YARA --> WORKERS
    end
    subgraph "Driver"
        CALLBACKS["Kernel Callbacks"]
        RINGBUF["Ring Buffer"]
        CALLBACKS --> RINGBUF
    end
    PROTO --> SHARED
    PROTO --> SYNC
```

## Data Flow: File Scan

```mermaid
sequenceDiagram
    participant KMDF as Kernel Driver
    participant Agent as Monolith Agent
    participant Scanner as Monolith Scanner
    participant Backend as Monolith Backend

    KMDF->>Agent: IOCTL_MONOLITH_GET_EVENTS
    Agent->>Agent: Evaluate event
    Agent->>Scanner: ScanFile(path)
    Scanner->>Scanner: Compute hashes
    Scanner->>Scanner: Parse PE
    Scanner->>Scanner: Check signature
    Scanner-->>Agent: ScanResult
    alt Malicious
        Agent->>Backend: Send Alert
        Backend-->>Agent: Response Action
        Agent->>Scanner: QuarantineFile(path)
    else Clean
        Agent->>Backend: Send Event
    end
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant Client as GUI / REST Client
    participant Backend as Monolith Backend
    participant DB as Database

    Client->>Backend: POST /api/v1/login
    Backend->>DB: SELECT user WHERE username = ?
    DB-->>Backend: User { password_hash, role }
    Backend->>Backend: Argon2id verify(password, hash)
    alt Valid
        Backend-->>Client: { access_token, refresh_token }
    else Invalid
        Backend-->>Client: 401
    end

    Note over Client,Backend: Subsequent requests
    Client->>Backend: GET /api/v1/endpoints (Bearer jwt)
    Backend->>Backend: Auth Middleware: Validate JWT
    Backend->>Backend: RBAC: Check Permission
    alt Valid & Authorized
        Backend-->>Client: 200 OK
    else Expired
        Backend-->>Client: 401
        Client->>Backend: POST /api/v1/refresh
        Backend-->>Client: New access_token
    else Forbidden
        Backend-->>Client: 403
    end
```

## Database Schema

```mermaid
erDiagram
    users {
        uuid id PK
        string username
        string role
        string password_hash
        boolean enabled
    }
    endpoints {
        uuid id PK
        string hostname
        string status
        string policy_id FK
    }
    events {
        uuid id PK
        uuid endpoint_id FK
        string event_type
    }
    alerts {
        uuid id PK
        string severity
        string status
        uuid endpoint_id FK
    }
    iocs {
        string id PK
        string ioc_type
        string value
    }
    users ||--o{ audit_logs : ""
    endpoints ||--o{ events : ""
    endpoints ||--o{ alerts : ""
    events ||--o{ alerts : ""
```

## Communication Ports

| Channel | Transport | Auth | Purpose | Port |
|---------|-----------|------|---------|------|
| REST | HTTPS TLS 1.3 | JWT | Client Backend | 8443 |
| gRPC | HTTP/2 mTLS | Client Cert | Agent Backend | 9443 |
| WebSocket | WSS TLS 1.3 | JWT | Live Events | 7443 |
| Local gRPC | HTTP/2 none | Loopback | Agent Scanner | 50052 |
| IOCTL | Kernel | Process Token | Driver Agent | N/A |

## Directory Layout

```
edr/
  protobuf/       # Cross-component contracts
  shared/         # Shared Rust crate
  backend/        # Management server (Rust/Axum)
  agent/          # Endpoint agent (Rust Windows Service)
  scanner/        # File scanner (Go)
  driver/         # KMDF kernel driver (C)
  # (GUI stripped, to be rewritten from scratch in C#)
  configs/        # TOML config files
  scripts/        # Setup scripts
  docs/           # Documentation
```
