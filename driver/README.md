# Monolith Kernel Driver Framework (KMDF)

`edr.sys` is a Windows Kernel-Mode Driver Framework (KMDF) driver designed to provide tamper-resistant system event collection and process protection for the Monolith EDR platform.

## Features & Kernel Callbacks

- **Process Creation & Termination**: Registered via `PsSetCreateProcessNotifyRoutineEx` to capture process IDs, parent process IDs, image paths, command line arguments, and access tokens.
- **Thread Creation & Injection**: Registered via `PsSetCreateThreadNotifyRoutine` to monitor thread creation across process boundaries.
- **Image Load Notifications**: Registered via `PsSetLoadImageNotifyRoutine` to track DLL and driver loads with base addresses and image sizes.
- **Registry Modification Tracking**: Registered via `CmRegisterCallbackEx` to monitor key creation, modification, and value data writes.
- **Object Access Callbacks (`ObRegisterCallbacks`)**: Intercepts handle creation and duplication requests targeting the `monolith-agent.exe` process, stripping `PROCESS_TERMINATE` and `PROCESS_VM_WRITE` rights from unauthorized callers.
- **Lock-Free Ring Buffer**: Maintains a high-speed shared memory ring buffer (`ringbuf.c`) transferring telemetry directly from kernel space to the user-mode agent without thread blocking.

## Driver Build Instructions

Building `edr.sys` requires Visual Studio 2022 and the Windows Driver Kit (WDK):

```cmd
:: Build Release x64 driver binary
msbuild driver/edr.vcxproj /p:Configuration=Release /p:Platform=x64
```
