#pragma once

//
// Restore subsystem IOCTL definitions and data structures.
// All restore IOCTLs are gated behind RestoreActivated.
//

#include "edr.h"

// IOCTL codes for restore feature (0x80E - 0x814)
#define IOCTL_EDR_RESTORE_ACTIVATE \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80E, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_RESTORE_DEACTIVATE \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80F, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_RESTORE_STATUS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_EDR_RESTORE_CLAIM_PARTITION \
    CTL_CODE(EDR_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_WRITE_DATA)

// Maximum payload size for restore activation (4KB)
#define EDR_RESTORE_MAX_PAYLOAD_SIZE 4096

// Output for IOCTL_EDR_RESTORE_STATUS
typedef struct _EDR_RESTORE_STATUS {
    BOOLEAN Activated;
    UCHAR PayloadHash[32];       // SHA-256 of activated payload (zero if inactive)
    WCHAR ClaimedPartitionPath[64]; // Partition device path
    ULONGLONG PartitionSize;     // Size in bytes (0 if not claimed)
} EDR_RESTORE_STATUS, *PEDR_RESTORE_STATUS;

// Input for IOCTL_EDR_RESTORE_CLAIM_PARTITION
typedef struct _EDR_RESTORE_CLAIM_INPUT {
    ULONG PhysicalDriveNumber;   // e.g. 0 for \\.\PhysicalDrive0
    ULONG PartitionNumber;       // e.g. 3 for Partition3
} EDR_RESTORE_CLAIM_INPUT, *PEDR_RESTORE_CLAIM_INPUT;

// Restore subsystem function declarations (implemented in restore.c)
NTSTATUS EdrIoctlRestoreActivate(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlRestoreDeactivate(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context);
NTSTATUS EdrIoctlRestoreStatus(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlRestoreClaimPartition(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
