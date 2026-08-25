/*++
Copyright (c) 2026 EDR Contributors

Module Name:
    ioctl_scanmem.c

Abstract:
    Implements IOCTL_EDR_SCAN_PROCESS_MEMORY — on-demand kernel-mode
    memory region scan.  Attaches to the target process, walks its virtual
    address space with ZwQueryVirtualMemory, and writes suspicious regions
    to the ring buffer as EventMemorySuspicious telemetry.

    Suspicion criteria (bitmask in SuspicionFlags):
      1  — PAGE_EXECUTE_READWRITE (RWX)
      2  — MEM_PRIVATE + executable
      4  — MEM_MAPPED + executable (unbacked mapping)

--*/

#include "edr.h"
#include "ringbuf.h"

// Limit on suspicious regions reported per IOCTL to avoid flooding the ring buffer
#define MAX_SUSPICIOUS_REGIONS_PER_SCAN 100

NTSTATUS
EdrIoctlScanProcessMemory(
    _In_ WDFREQUEST Request,
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PULONG inputPid;
    PULONG outputCount;
    PEPROCESS targetProcess;
    KAPC_STATE apcState;
    ULONG suspiciousCount = 0;

    if (InputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, (PVOID*)&inputPid, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (OutputBufferLength < sizeof(ULONG)) {
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, (PVOID*)&outputCount, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HANDLE pid = (HANDLE)(ULONG_PTR)*inputPid;
    status = PsLookupProcessByProcessId(pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    // Get process image name
    PCHAR procNameAnsi = PsGetProcessImageFileName(targetProcess);
    WCHAR procName[260];
    procName[0] = L'\0';
    if (procNameAnsi != NULL) {
        RtlStringCbPrintfW(procName, sizeof(procName), L"%hs", procNameAnsi);
    }

    // Attach to target process's address space
    KeStackAttachProcess(targetProcess, &apcState);

    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;

    while (suspiciousCount < MAX_SUSPICIOUS_REGIONS_PER_SCAN) {
        SIZE_T returnSize;
        status = ZwQueryVirtualMemory(NtCurrentProcess(), address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnSize);
        if (!NT_SUCCESS(status)) {
            break;
        }

        ULONG suspicionFlags = 0;

        // RWX detection
        if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
            suspicionFlags |= 1;
        }

        // Private executable memory (potential shellcode / injected code)
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            suspicionFlags |= 2;
        }

        // Unbacked executable mapping
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            suspicionFlags |= 4;
        }

        if (suspicionFlags != 0) {
            EDR_MEMORY_SUSPICIOUS_DATA data;
            RtlZeroMemory(&data, sizeof(data));
            data.ProcessId = *inputPid;
            data.BaseAddress = (ULONGLONG)(ULONG_PTR)address;
            data.RegionSize = mbi.RegionSize;
            data.Protect = mbi.Protect;
            data.Type = mbi.Type;
            data.SuspicionFlags = suspicionFlags;
            RtlCopyMemory(data.ProcessName, procName, sizeof(data.ProcessName));
            data.ProcessName[259] = L'\0';

            EdrRingBufferWrite(Context->RingBuffer, EventMemorySuspicious, (PUCHAR)&data, sizeof(data));
            suspiciousCount++;
        }

        // Advance to next region
        ULONG_PTR nextAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= (ULONG_PTR)address || nextAddr >= (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
            break;
        }
        address = (PVOID)nextAddr;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    *outputCount = suspiciousCount;
    *BytesReturned = sizeof(ULONG);

    KdPrint(("[EDR] IOCTL_EDR_SCAN_PROCESS_MEMORY: PID=%lu, suspicious=%lu\n", *inputPid, suspiciousCount));

    return STATUS_SUCCESS;
}
