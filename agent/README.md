# Monolith Endpoint Agent

The Monolith Agent is a lightweight Windows Service daemon written in Rust (`windows-service` crate). It operates at SYSTEM privileges to collect real-time system telemetry, interface with the kernel-mode driver, execute local behavioral detection rules, and maintain secure mTLS communications with the management backend.

## Subsystem Architecture

- **Driver Interop & Ring Buffer Reader**: Communicates with `edr.sys` via Device I/O Control (`DeviceIoControl`). Continuously claims slots from the kernel shared memory ring buffer to process process creation, thread injection, DLL image load, registry key modification, and file I/O events.
- **Event Tracing for Windows (ETW)**: Supplemental user-mode ETW session manager capturing network connections, DNS queries, and process token manipulation events.
- **Local Detection Engine**: Evaluates incoming telemetry against local heuristics and signature patterns before forwarding events to the backend, enabling offline endpoint protection.
- **mTLS Sync Client**: Maintains a persistent gRPC stream with the backend over port `:9443` for heartbeat status reporting, policy updates, and telemetry batching.
- **Self-Protection & Anti-Tampering**: Integrates process protection mechanisms, token integrity verification, and watchdog monitoring to prevent process termination by unauthorized callers.

## Directory Layout

```
agent/src/
├── collector/        # System state and process telemetry collectors
├── config.rs         # Agent configuration parser (%ProgramData%\EDR\agent.toml)
├── db/               # Local SQLite database for offline event queuing
├── detection/        # Heuristic engine, alert generation, and alert chaining
├── driver/           # Kernel driver IOCTL interface and ring buffer consumer
├── etw_manager/      # ETW session handlers (file, process, registry, network)
├── grpc/             # gRPC client for backend synchronization
├── memory_scanner.rs # Live process RAM scanner and YARA pattern matcher
├── response/         # Local remediation actions (process termination, network isolation)
├── service.rs        # Windows Service Control Manager (SCM) lifecycle handlers
├── system_state.rs   # Process tree tracking and active network connections
└── main.rs           # Service entrypoint and initialization logic
```

## Running & Testing the Agent

The agent requires administrative privileges to interact with the kernel driver and SCM:

```powershell
# Run directly from console (Requires Administrator PowerShell)
cargo run -p monolith-agent

# Build release binary
cargo build --release -p monolith-agent
```
