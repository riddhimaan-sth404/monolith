/*++
Copyright (c) 2026 EDR Contributors

Module Name:
    timer.c

Abstract:
    Proactive memory sweep — a periodic WDF timer fires every 30 seconds
    and queues a work item that walks critical system processes, scans
    their virtual address space for suspicious memory regions, and emits
    EventMemorySuspicious telemetry to the ring buffer.

    This catches memory-only attacks (shellcode injection, reflective
    DLLs) that may not trigger image-load callbacks.

--*/

#include "edr.h"
#include "ringbuf.h"

#define MEMORY_SWEEP_INTERVAL_SEC 30
#define MAX_SUSPICIOUS_PER_SWEEP  50

static const PCHAR CriticalProcessNames[] = {
    "system",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "monolithagent.exe",
    "monolithwatchdog.exe",
};

static
BOOLEAN
IsCriticalProcess(
    _In_ PEPROCESS Process
)
{
    PCHAR name = PsGetProcessImageFileName(Process);
    if (name == NULL) {
        return FALSE;
    }

    // Fold to lowercase for case-insensitive comparison
    CHAR lower[64];
    size_t len = 0;
    while (name[len] != '\0' && len < sizeof(lower) - 1) {
        if (name[len] >= 'A' && name[len] <= 'Z') {
            lower[len] = name[len] - 'A' + 'a';
        } else {
            lower[len] = name[len];
        }
        len++;
    }
    lower[len] = '\0';

    for (ULONG i = 0; i < sizeof(CriticalProcessNames) / sizeof(CriticalProcessNames[0]); i++) {
        size_t j;
        for (j = 0; j < len && CriticalProcessNames[i][j] != '\0'; j++) {
            if (lower[j] != CriticalProcessNames[i][j]) {
                break;
            }
        }
        if (lower[j] == '\0' && CriticalProcessNames[i][j] == '\0') {
            return TRUE;
        }
    }
    return FALSE;
}

static
VOID
ScanProcessMemoryRegions(
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ PEPROCESS Process,
    _Inout_ PULONG SuspiciousCount
)
{
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;
    ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
    PCHAR procNameAnsi = PsGetProcessImageFileName(Process);
    WCHAR procName[260];
    procName[0] = L'\0';
    if (procNameAnsi != NULL) {
        RtlStringCbPrintfW(procName, sizeof(procName), L"%S", procNameAnsi);
    }

    KeStackAttachProcess(Process, &apcState);

    while (*SuspiciousCount < MAX_SUSPICIOUS_PER_SWEEP) {
        SIZE_T returnSize;
        NTSTATUS status = ZwQueryVirtualMemory(
            NtCurrentProcess(),
            address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnSize
        );
        if (!NT_SUCCESS(status)) {
            break;
        }

        ULONG suspicionFlags = 0;

        if (mbi.State == MEM_COMMIT) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                suspicionFlags |= 1;
            }
            if (mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                suspicionFlags |= 2;
            }
            if (mbi.Type == MEM_MAPPED &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                suspicionFlags |= 4;
            }
        }

        if (suspicionFlags != 0) {
            EDR_MEMORY_SUSPICIOUS_DATA data;
            RtlZeroMemory(&data, sizeof(data));
            data.ProcessId = pid;
            data.BaseAddress = (ULONGLONG)(ULONG_PTR)address;
            data.RegionSize = mbi.RegionSize;
            data.Protect = mbi.Protect;
            data.Type = mbi.Type;
            data.SuspicionFlags = suspicionFlags;
            RtlCopyMemory(data.ProcessName, procName, sizeof(data.ProcessName));
            data.ProcessName[259] = L'\0';

            EdrRingBufferWrite(Context->RingBuffer, EventMemorySuspicious, (PUCHAR)&data, sizeof(data));
            (*SuspiciousCount)++;
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    KeUnstackDetachProcess(&apcState);
}

//
// Work item callback — runs at PASSIVE_LEVEL
//
VOID
EdrMemoryScanWorkItem(
    _In_ WDFWORKITEM WorkItem
)
{
    WDFDEVICE device = WdfWorkItemGetParentObject(WorkItem);
    PEDR_DEVICE_CONTEXT context = GetDeviceContext(device);
    if (context == NULL) {
        return;
    }

    // Guard against re-entrancy if previous sweep is still running
    if (InterlockedExchange(&context->MemorySweepActive, TRUE)) {
        return;
    }

    ULONG suspiciousCount = 0;
    PEPROCESS process = NULL;

    // Walk process list using ZwQuerySystemInformation
    ULONG bufferSize = 256 * 1024; // 256 KB initial buffer
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, TAG_EDR);
    if (buffer == NULL) {
        KdPrint(("[EDR] Memory sweep: failed to allocate process info buffer\n"));
        return;
    }

    NTSTATUS enumStatus = ZwQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        NULL
    );
    if (!NT_SUCCESS(enumStatus)) {
        ExFreePoolWithTag(buffer, TAG_EDR);
        KdPrint(("[EDR] Memory sweep: ZwQuerySystemInformation failed 0x%08X\n", enumStatus));
        return;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE) {
        if (spi->UniqueProcessId != NULL) {
            PEPROCESS process;
            NTSTATUS lookupStatus = PsLookupProcessByProcessId(spi->UniqueProcessId, &process);
            if (NT_SUCCESS(lookupStatus)) {
                if (IsCriticalProcess(process)) {
                    ScanProcessMemoryRegions(context, process, &suspiciousCount);
                }
                ObDereferenceObject(process);
            }
        }

        if (spi->NextEntryOffset == 0) {
            break;
        }
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, TAG_EDR);

    if (suspiciousCount > 0) {
        KdPrint(("[EDR] Memory sweep: %lu suspicious regions found in critical processes\n", suspiciousCount));
    }

    context->MemorySweepActive = FALSE;
}

//
// Timer DPC — runs at DISPATCH_LEVEL, queues the scan work item
//
VOID
EdrMemoryTimerDpc(
    _In_ WDFTIMER Timer
)
{
    WDFDEVICE device = WdfTimerGetParentObject(Timer);
    PEDR_DEVICE_CONTEXT context = GetDeviceContext(device);
    if (context == NULL || context->MemoryWorkItem == NULL) {
        return;
    }

    WdfWorkItemEnqueue(context->MemoryWorkItem);
}

//
// PsGetProcessNext — process enumeration API available since Windows 10 20H1.
// Not declared in WDK headers for all versions.
//
EXTERN_C __drv_maxIRQL(APC_LEVEL)
PEPROCESS NTAPI PsGetProcessNext(_In_opt_ PEPROCESS Process);

//
// Initialize the proactive memory sweep timer + work item
//
NTSTATUS
EdrInitializeMemoryTimer(
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ WDFDEVICE Device
)
{
    NTSTATUS status;
    WDF_TIMER_CONFIG timerConfig;
    WDF_OBJECT_ATTRIBUTES timerAttributes;
    WDF_WORKITEM_CONFIG workItemConfig;
    WDF_OBJECT_ATTRIBUTES workItemAttributes;

    // Create the work item first (parent = device)
    WDF_WORKITEM_CONFIG_INIT(&workItemConfig, EdrMemoryScanWorkItem);
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
    workItemAttributes.ParentObject = Device;

    status = WdfWorkItemCreate(&workItemConfig, &workItemAttributes, &Context->MemoryWorkItem);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfWorkItemCreate failed: 0x%08X\n", status));
        return status;
    }

    // Create periodic timer (parent = device)
    WDF_TIMER_CONFIG_INIT_PERIODIC(
        &timerConfig,
        EdrMemoryTimerDpc,
        (LONG)WDF_REL_TIMEOUT_IN_SEC(MEMORY_SWEEP_INTERVAL_SEC)
    );
    WDF_OBJECT_ATTRIBUTES_INIT(&timerAttributes);
    timerAttributes.ParentObject = Device;

    status = WdfTimerCreate(&timerConfig, &timerAttributes, &Context->MemoryTimer);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[EDR] WdfTimerCreate failed: 0x%08X\n", status));
        // Clean up the work item (WDF will clean it when device is removed)
        Context->MemoryWorkItem = NULL;
        return status;
    }

    Context->MemorySweepActive = FALSE;

    // Start the timer — first fire after MEMORY_SWEEP_INTERVAL_SEC seconds
    WdfTimerStart(Context->MemoryTimer, WDF_REL_TIMEOUT_IN_SEC(MEMORY_SWEEP_INTERVAL_SEC));

    KdPrint(("[EDR] Memory sweep timer initialized (%u s interval)\n", MEMORY_SWEEP_INTERVAL_SEC));
    return STATUS_SUCCESS;
}

//
// Stop the proactive memory sweep timer
//
VOID
EdrStopMemoryTimer(
    _In_ PEDR_DEVICE_CONTEXT Context
)
{
    if (Context->MemoryTimer != NULL) {
        WdfTimerStop(Context->MemoryTimer, TRUE);
        Context->MemoryTimer = NULL;
    }
}
