/*++
Copyright (c) 2026 EDR Contributors

Module Name:
    edr.c

Abstract:
    Main driver entry point and dispatch for the EDR kernel driver.
    Uses KMDF (Kernel-Mode Driver Framework) with documented Windows APIs only.

--*/

#include "edr.h"
#include "restore.h"
#include "ringbuf.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EdrEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EdrEvtIoDeviceControl;
EVT_WDF_DEVICE_CONTEXT_CLEANUP EdrEvtDeviceContextCleanup;

// Forward declarations
VOID EdrDriverUnload(_In_ WDFDRIVER Driver);

// Global driver state
PEDR_DEVICE_CONTEXT g_DeviceContext = NULL;

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EdrEvtDeviceAdd)
#pragma alloc_text(PAGE, EdrEvtDeviceContextCleanup)

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    KdPrint(("[EDR] DriverEntry: Version 1.0.0\n"));

    // Initialize WDF driver config
    WDF_DRIVER_CONFIG_INIT(&config, EdrEvtDeviceAdd);
    config.EvtDriverUnload = EdrDriverUnload;
    config.DriverPoolTag = 'RDE ';

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.Size = sizeof(WDF_OBJECT_ATTRIBUTES);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        WDF_NO_HANDLE
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    // NOTE: DriverObject->DriverShutdown field is not available in modern WDK.
    // Shutdown cleanup is handled by the WDF framework through EvtDeviceContextCleanup.
    KdPrint(("[EDR] Driver initialized successfully\n"));
    return status;
}

NTSTATUS
EdrEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    PAGED_CODE();

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    WDFQUEUE queue;
    PEDR_DEVICE_CONTEXT deviceContext;
    NTSTATUS status;
    UNICODE_STRING symbolicLink;

    KdPrint(("[EDR] EdrEvtDeviceAdd: Creating device\n"));

    // Initialize device context
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
        &deviceAttributes,
        EDR_DEVICE_CONTEXT
    );

    // Create the device
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfDeviceCreate failed: 0x%08X\n", status));
        return status;
    }

    // Get device context
    deviceContext = GetDeviceContext(device);
    if (deviceContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_DeviceContext = deviceContext;

    // Initialize device context
    RtlZeroMemory(deviceContext, sizeof(EDR_DEVICE_CONTEXT));
    deviceContext->LogLevel = LogLevelInfo;
    ExInitializeFastMutex(&deviceContext->StatsLock);
    ExInitializeFastMutex(&deviceContext->ProtectedKeysLock);

    // Create symbolic link
    RtlInitUnicodeString(&symbolicLink, EDR_SYMBOLIC_LINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfDeviceCreateSymbolicLink failed: 0x%08X\n", status));
        return status;
    }

    // Configure IO queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &ioQueueConfig,
        WdfIoQueueDispatchSequential
    );
    ioQueueConfig.EvtIoDeviceControl = EdrEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &ioQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
    );
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfIoQueueCreate failed: 0x%08X\n", status));
        return status;
    }

    // Initialize ring buffer
    status = EdrRingBufferInitialize(&deviceContext->RingBuffer);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] EdrRingBufferInitialize failed: 0x%08X\n", status));
        return status;
    }
    deviceContext->Stats.BufferSize = deviceContext->RingBuffer->Size;

    // Register telemetry callbacks
    EdrRegisterCallbacks();

    // Initialize proactive memory sweep timer
    status = EdrInitializeMemoryTimer(deviceContext, device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] EdrInitializeMemoryTimer failed: 0x%08X\n", status));
        // Non-fatal — driver continues without proactive sweep
    }

    // Initialize restore subsystem
    deviceContext->RestoreActivated = FALSE;
    RtlZeroMemory(deviceContext->RestorePayloadHash, 32);
    deviceContext->RestorePartitionPath.Buffer = NULL;
    deviceContext->RestorePartitionPath.Length = 0;
    deviceContext->RestorePartitionPath.MaximumLength = 0;
    deviceContext->RestorePartitionSize = 0;

    // Create respawn work item for process resurrection
    {
            WDF_WORKITEM_CONFIG workItemConfig;
            WDF_WORKITEM_CONFIG_INIT(&workItemConfig, EdrRespawnWorker);
        status = WdfWorkItemCreate(&workItemConfig, WDF_NO_OBJECT_ATTRIBUTES, &deviceContext->RespawnWorkItem);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[EDR] WdfWorkItemCreate for respawn failed: 0x%08X\n", status));
        }
    }

    KdPrint(("[EDR] Device created successfully\n"));
    return status;
}

VOID
EdrEvtDeviceContextCleanup(
    _In_ WDFOBJECT DeviceObject
)
{
    PAGED_CODE();

    PEDR_DEVICE_CONTEXT context = GetDeviceContext(DeviceObject);
    if (context != NULL) {
        // Stop proactive memory sweep
        EdrStopMemoryTimer(context);

        // Delete respawn work item
        if (context->RespawnWorkItem != NULL) {
            WdfObjectDelete(context->RespawnWorkItem);
            context->RespawnWorkItem = NULL;
        }

        // Free respawn path buffers
        if (context->AgentImagePath.Buffer != NULL) {
            ExFreePoolWithTag(context->AgentImagePath.Buffer, 'RDE ');
            context->AgentImagePath.Buffer = NULL;
        }
        if (context->AgentCmdLine.Buffer != NULL) {
            ExFreePoolWithTag(context->AgentCmdLine.Buffer, 'RDE ');
            context->AgentCmdLine.Buffer = NULL;
        }

        if (context->AgentProcess != NULL) {
            ObDereferenceObject(context->AgentProcess);
            context->AgentProcess = NULL;
        }
        // Free restore partition path
        if (context->RestorePartitionPath.Buffer != NULL) {
            ExFreePoolWithTag(context->RestorePartitionPath.Buffer, 'RDE ');
            context->RestorePartitionPath.Buffer = NULL;
        }

        // Clean up ring buffer
        if (context->RingBuffer != NULL) {
            ExFreePoolWithTag(context->RingBuffer, 'RDE ');
            context->RingBuffer = NULL;
        }
    }
}

VOID
EdrEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    PEDR_DEVICE_CONTEXT context = GetDeviceContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesReturned = 0;

    switch (IoControlCode) {
    case IOCTL_EDR_GET_EVENTS:
        status = EdrIoctlGetEvents(Request, context, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_GET_STATS:
        status = EdrIoctlGetStats(Request, context, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_GET_DRIVER_INFO:
        status = EdrIoctlGetDriverInfo(Request, context, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_SET_LOG_LEVEL:
        // Only allow from elevated callers (admin/SYSTEM)
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlSetLogLevel(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_QUERY_OPERATIONS:
        status = EdrIoctlQueryOperations(Request, context, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_CLEAR_BUFFER:
        // Only allow from elevated callers (admin/SYSTEM)
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlClearBuffer(Request, context);
        break;

    case IOCTL_EDR_QUARANTINE_FILE:
        // Requires admin; quarantines a file by path
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        KdPrint(("[EDR] IOCTL_EDR_QUARANTINE_FILE received (stub)\n"));
        status = STATUS_SUCCESS;
        break;

    case IOCTL_EDR_TERMINATE_PROCESS:
        // Requires admin; terminates a process by PID
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        KdPrint(("[EDR] IOCTL_EDR_TERMINATE_PROCESS received (stub)\n"));
        status = STATUS_SUCCESS;
        break;

    case IOCTL_EDR_REGISTER_AGENT:
        // Requires admin/SYSTEM write access
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlRegisterAgent(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_UPDATE_PROTECTED_KEYS:
        // Requires admin/SYSTEM write access
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlUpdateProtectedKeys(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_SCAN_PROCESS_MEMORY:
        // Requires admin/SYSTEM write access
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlScanProcessMemory(Request, context, InputBufferLength, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_SET_RESPAWN_PATH:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlSetRespawnPath(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_PREPARE_SHUTDOWN:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        {
            PEPROCESS caller = PsGetCurrentProcess();
            if (caller != context->AgentProcess) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            context->AgentCleanShutdown = TRUE;
            context->AgentShutdownExpiry = KeQueryInterruptTime() + 10000000; // 10 seconds
            KdPrint(("[EDR] Agent preparing for clean shutdown\n"));
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_EDR_RESTORE_ACTIVATE:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlRestoreActivate(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_RESTORE_DEACTIVATE:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlRestoreDeactivate(Request, context);
        break;

    case IOCTL_EDR_RESTORE_STATUS:
        status = EdrIoctlRestoreStatus(Request, context, OutputBufferLength, &bytesReturned);
        break;

    case IOCTL_EDR_RESTORE_CLAIM_PARTITION:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = EdrIoctlRestoreClaimPartition(Request, context, InputBufferLength);
        break;

    case IOCTL_EDR_ALLOW_UNLOAD:
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(WdfRequestWdmGetIrp(Request), FILE_WRITE_DATA))) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        {
            PEPROCESS caller = PsGetCurrentProcess();
            if (caller != context->AgentProcess) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            context->AllowUnload = TRUE;
            KdPrint(("[EDR] Agent allowed driver unload\n"));
            status = STATUS_SUCCESS;
        }
        break;

    default:
        KdPrint(("[EDR] Unknown IOCTL: 0x%08X\n", IoControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

//
// IOCTL handlers
//

NTSTATUS
EdrIoctlGetEvents(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PVOID outputBuffer;

    if (Context->AgentProcess != NULL) {
        PEPROCESS caller = IoGetRequestorProcess(WdfRequestWdmGetIrp(Request));
        if (caller != Context->AgentProcess) {
            return STATUS_ACCESS_DENIED;
        }
    }

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *BytesReturned = EdrRingBufferRead(Context->RingBuffer, outputBuffer, OutputBufferLength);

    InterlockedIncrement64((PLONG64)&Context->Stats.EventsCollected);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlGetStats(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PEDR_DRIVER_STATS statsBuffer;

    if (Context->AgentProcess != NULL) {
        PEPROCESS caller = IoGetRequestorProcess(WdfRequestWdmGetIrp(Request));
        if (caller != Context->AgentProcess) {
            return STATUS_ACCESS_DENIED;
        }
    }

    if (OutputBufferLength < sizeof(EDR_DRIVER_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, (PVOID*)&statsBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquireFastMutex(&Context->StatsLock);
    RtlCopyMemory(statsBuffer, &Context->Stats, sizeof(EDR_DRIVER_STATS));
    ExReleaseFastMutex(&Context->StatsLock);

    *BytesReturned = sizeof(EDR_DRIVER_STATS);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlGetDriverInfo(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PEDR_DRIVER_INFO infoBuffer;

    if (OutputBufferLength < sizeof(EDR_DRIVER_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, (PVOID*)&infoBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(infoBuffer, sizeof(EDR_DRIVER_INFO));
    infoBuffer->VersionMajor = 1;
    infoBuffer->VersionMinor = 0;
    infoBuffer->VersionPatch = 0;
    infoBuffer->BuildNumber = 1;
    infoBuffer->CallbackStatus = Context->RegisteredCallbacks;
    RtlStringCbCopyW(infoBuffer->BuildDate, sizeof(infoBuffer->BuildDate), L"2026-06-29");
    RtlStringCbCopyW(infoBuffer->BuildTime, sizeof(infoBuffer->BuildTime), L"00:00:00");

    *BytesReturned = sizeof(EDR_DRIVER_INFO);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlSetLogLevel(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    PEDR_LOG_LEVEL logLevel;

    if (InputBufferLength < sizeof(EDR_LOG_LEVEL)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, (PVOID*)&logLevel, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Context->LogLevel = *logLevel;
    KdPrint(("[EDR] Log level set to: %d\n", *logLevel));

    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlQueryOperations(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PULONG operations;

    if (OutputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, (PVOID*)&operations, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *operations = Context->RegisteredCallbacks;
    *BytesReturned = sizeof(ULONG);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlClearBuffer(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context
)
{
    EdrRingBufferClear(Context->RingBuffer);
    KdPrint(("[EDR] Ring buffer cleared\n"));
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlRegisterAgent(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    PULONG agentPid;

    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, (PVOID*)&agentPid, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HANDLE pid = (HANDLE)(ULONG_PTR)*agentPid;
    PEPROCESS process = NULL;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Verify caller is registering itself
    PEPROCESS caller = IoGetRequestorProcess(WdfRequestWdmGetIrp(Request));
    if (caller != process) {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }

    // If agent is already registered, only that same process can re-register
    if (Context->AgentProcess != NULL && Context->AgentProcess != caller) {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }

    if (Context->AgentProcess != NULL) {
        ObDereferenceObject(Context->AgentProcess);
        Context->AgentProcess = NULL;
    }

    Context->AgentProcess = process; // Keeps reference from PsLookupProcessByProcessId
    Context->AgentPid = pid;

    KdPrint(("[EDR] Agent registered: PID=%p, PEPROCESS=%p\n", pid, process));
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlUpdateProtectedKeys(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    PVOID inputBuffer;

    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG count = *(PULONG)inputBuffer;
    if (count > 64) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T expectedSize = sizeof(ULONG) + count * 260 * sizeof(WCHAR);
    if (InputBufferLength < expectedSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PWCHAR keyArray = (PWCHAR)((PUCHAR)inputBuffer + sizeof(ULONG));

    ExAcquireFastMutex(&Context->ProtectedKeysLock);

    Context->ProtectedKeyCount = count;
    for (ULONG i = 0; i < count; i++) {
        RtlCopyMemory(
            Context->ProtectedKeys[i],
            &keyArray[i * 260],
            260 * sizeof(WCHAR)
        );
        Context->ProtectedKeys[i][259] = L'\0';
    }

    ExReleaseFastMutex(&Context->ProtectedKeysLock);

    KdPrint(("[EDR] Protected keys updated: %lu entries\n", count));
    return STATUS_SUCCESS;
}

NTSTATUS
EdrIoctlSetRespawnPath(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t InputBufferLength
)
{
    // PEPROCESS-gate: only the registered agent can set the respawn path
    PEPROCESS caller = PsGetCurrentProcess();
    if (caller != Context->AgentProcess) {
        return STATUS_ACCESS_DENIED;
    }

    if (InputBufferLength < sizeof(EDR_RESPAWN_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEDR_RESPAWN_INFO info;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, (PVOID*)&info, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Free previous allocations
    if (Context->AgentImagePath.Buffer != NULL) {
        ExFreePoolWithTag(Context->AgentImagePath.Buffer, 'RDE ');
        Context->AgentImagePath.Buffer = NULL;
    }
    if (Context->AgentCmdLine.Buffer != NULL) {
        ExFreePoolWithTag(Context->AgentCmdLine.Buffer, 'RDE ');
        Context->AgentCmdLine.Buffer = NULL;
    }

    // Allocate and copy image path
    size_t pathLen = (wcslen(info->ImagePath) + 1) * sizeof(WCHAR);
    Context->AgentImagePath.Buffer = ExAllocatePool2(POOL_FLAG_PAGED, pathLen, 'RDE ');
    if (Context->AgentImagePath.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Context->AgentImagePath.Buffer, info->ImagePath, pathLen);
    Context->AgentImagePath.Length = (USHORT)(pathLen - sizeof(WCHAR));
    Context->AgentImagePath.MaximumLength = (USHORT)pathLen;

    // Allocate and copy command line
    size_t cmdLen = (wcslen(info->CommandLine) + 1) * sizeof(WCHAR);
    Context->AgentCmdLine.Buffer = ExAllocatePool2(POOL_FLAG_PAGED, cmdLen, 'RDE ');
    if (Context->AgentCmdLine.Buffer == NULL) {
        ExFreePoolWithTag(Context->AgentImagePath.Buffer, 'RDE ');
        Context->AgentImagePath.Buffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Context->AgentCmdLine.Buffer, info->CommandLine, cmdLen);
    Context->AgentCmdLine.Length = (USHORT)(cmdLen - sizeof(WCHAR));
    Context->AgentCmdLine.MaximumLength = (USHORT)cmdLen;

    KdPrint(("[EDR] Agent respawn path registered\n"));
    return STATUS_SUCCESS;
}

//
// Respawn work item — called when agent exits unexpectedly
//
VOID
EdrRespawnWorker(
    _In_ WDFWORKITEM WorkItem
)
{
    PEDR_DEVICE_CONTEXT ctx = GetDeviceContext(WdfWorkItemGetParentObject(WorkItem));

    if (ctx->AgentImagePath.Buffer == NULL || ctx->AgentImagePath.Length == 0) {
        return;
    }

    // NOTE: Kernel-mode process creation (ZwCreateUserProcess/NtCreateUserProcess) is not
    // available in the current WDK headers. Process resurrection is delegated to a
    // user-mode watchdog service. This is a stub.
    UNREFERENCED_PARAMETER(ctx);
    KdPrint(("[EDR] Agent respawn would be triggered here — delegated to watchdog\n"));
}

//
// Unload routine
//

VOID
EdrDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    PEDR_DEVICE_CONTEXT ctx = g_DeviceContext;

    if (ctx != NULL && !ctx->AllowUnload) {
        KdPrint(("[EDR] Warning: Driver unload requested without explicit agent AllowUnload signal.\n"));
    }

    KdPrint(("[EDR] Driver unloading cleanly\n"));

    // Unregister callbacks
    EdrUnregisterCallbacks();

    KdPrint(("[EDR] Driver unloaded successfully\n"));
}
