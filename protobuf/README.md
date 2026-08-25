# Monolith Protobuf & Codegen Crate

`monolith-protobuf` contains the Protocol Buffers (`.proto`) schemas for gRPC communication between agent, backend, and scanner components, along with automatic Rust build codegen (`build.rs`).

## Proto Definitions (`edr/proto/v1/`)

- `common.proto`: Shared primitive types and timestamp structures.
- `endpoint.proto`: Agent registration and system metadata schemas.
- `event.proto`: Telemetry event payload definitions (process, file, registry, network).
- `alert.proto`: Alert structures and severity levels.
- `scan.proto`: Scan request and result message formats.
- `service.proto`: gRPC service definitions (`EndpointService`, `ScannerService`, `ManagementService`).

## Codegen Execution

`protobuf/build.rs` uses `tonic-build` and `prost-build` to compile `.proto` files at build time. Requires `protoc` installed in system PATH.
