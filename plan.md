# Kernel-Level RAM Monitoring Integration Plan

## Problem

The agent only scans memory **reactively** — triggered when a `ModuleLoad` event arrives from the driver. Memory-only attacks (shellcode injection, process hollowing, reflective DLLs) that don't trigger image loads are invisible unless a YARA file scan happens to catch them.

The driver already has these definitions but no implementation:

| Artifact | Location | Status |
|----------|----------|--------|
| `EDR_MEMORY_SUSPICIOUS_DATA` struct | `driver/edr.h:138-146` | Defined |
| `EventMemorySuspicious = 13` | `driver/edr.h:54` | Defined, enum value reserved |
| `IOCTL_EDR_SCAN_PROCESS_MEMORY` (0x809) | `driver/edr.h:35-36` | Code defined, no IOCTL handler |
| Agent `IOCTL_EDR_SCAN_PROCESS_MEMORY` constant | `agent/src/driver/ioctl.rs:11` | Defined |
| Agent `EDR_EVENT_MEMORY_SUSPICIOUS = 13` | `agent/src/driver/ioctl.rs:27` | Defined |

---

## Phase 1: On-Demand Kernel Memory Scan via IOCTL

Implement `IOCTL_EDR_SCAN_PROCESS_MEMORY` so the agent requests the driver to scan a specific process from kernel mode (immune to user-mode tampering by a compromised process).

### Driver (C) — 3 files

| File | Change |
|------|--------|
| `driver/edr.h` | Declare `NTSTATUS EdrIoctlScanProcessMemory(PEDR_DEVICE_CONTEXT, PIRP, PIO_STACK_LOCATION)` |
| `driver/edr.c` | Add `case IOCTL_EDR_SCAN_PROCESS_MEMORY:` in IOCTL dispatch → calls `EdrIoctlScanProcessMemory` |
| `driver/ioctl_scanmem.c` (new) | Implement `EdrIoctlScanProcessMemory`: attach to target via `KeStackAttachProcess`, enumerate regions with `ZwQueryVirtualMemory`, check commit state + protection flags + type, emit `EventMemorySuspicious` to ring buffer for each suspicious region. Returns count to agent. |

### Protobuf — 3 files

| File | Change |
|------|--------|
| `protobuf/edr/proto/v1/driver.proto` | Add `DRIVER_EVENT_MEMORY_SUSPICIOUS = 13` to `DriverEventType` enum. Add `DriverMemorySuspicious` message with fields: `process_id`, `process_name`, `base_address`, `region_size`, `protect`, `memory_type`, `suspicion_flags` |
| `protobuf/edr/proto/v1/event.proto` | Add `MemorySuspiciousEvent memory_suspicious = 29` to `Event` oneof. Add corresponding message `MemorySuspiciousEvent { DriverMemorySuspicious suspicious = 1; }` |
| `protobuf/edr/proto/v1/common.proto` | Add `EVENT_TYPE_MEMORY_SUSPICIOUS = 25` to `EventType` enum |

### Agent (Rust) — 3 files

| File | Change |
|------|--------|
| `agent/src/tlv_parser.rs` | Add `parse_memory_suspicious()` reading 552-byte payload into `DriverMemorySuspicious`. Add match arm for `ioctl::EDR_EVENT_MEMORY_SUSPICIOUS` (13) |
| `agent/src/driver/mod.rs` | Add `scan_process_memory(pid: u32) -> Result<Vec<MemoryRegion>, String>` — sends `IOCTL_EDR_SCAN_PROCESS_MEMORY` with PID, receives suspicious region results from driver output buffer |
| `agent/src/main.rs` | In Worker 2a detection loop, handle `Payload::MemorySuspicious(ms)` — add metadata, push to upload buffer, trigger alert if `suspicion_flags` indicate high severity |

---

## Phase 2: Proactive Driver Memory Sweep

Add a kernel DPC timer that periodically scans critical processes without agent intervention.

### Driver (C) — 1 new file, 2 edits

| File | Change |
|------|--------|
| `driver/timer.c` (new) | `EdrTimerDpc` — walks all processes via `PsGetProcessNext`, calls `ZwQueryVirtualMemory` per process, emits `EventMemorySuspicious` for RWX/private-exec/unbacked-exec pages in critical processes (System, lsass, winlogon, svchost, agent). 30s interval, max 50 events per tick |
| `driver/edr.h` | Declare timer fields in device context + `EdrInitializeMemoryTimer` / `EdrStopMemoryTimer` |
| `driver/edr.c` | Call `EdrInitializeMemoryTimer` in `EdrEvtDeviceAdd`, `EdrStopMemoryTimer` in `EdrEvtDriverContextCleanup` |

No agent-side changes needed — events flow through existing ring buffer → driver reader → TLV parser → detection pipeline.

---

## Phase 3: Consolidation (Optional)

Once Phase 1 is proven, deprecate the agent's user-mode `memory_scanner.rs` (`VirtualQueryEx` + `ReadProcessMemory`) in favor of the kernel IOCTL path, which is more tamper-resistant (can't be intercepted by user-mode hooks).

| File | Change |
|------|--------|
| `agent/src/memory_scanner.rs` | Remove or gate behind `legacy_scanner` config flag |
| `agent/src/main.rs` | Change module-load trigger to call `driver.scan_process_memory()` instead of `memory_scanner::scan_process()` |

---

## Summary

| Phase | Component | Files | Net Change |
|-------|-----------|-------|------------|
| 1 | Driver C | `edr.h`, `edr.c`, `ioctl_scanmem.c` (new) | ~120 lines |
| 1 | Protobuf | `driver.proto`, `event.proto`, `common.proto` | ~30 lines |
| 1 | Agent Rust | `tlv_parser.rs`, `driver/mod.rs`, `main.rs` | ~80 lines |
| 2 | Driver C | `timer.c` (new), `edr.h`, `edr.c` | ~100 lines |
| 3 | Agent Rust | `memory_scanner.rs`, `main.rs` | ~30 lines |

Total: ~360 lines across 10 files (3 new, 7 edited).
