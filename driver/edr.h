#pragma once

//
// EDR Kernel Driver - Shared Definitions
//

#include <ntifs.h>     // ntddk.h + ZwQueryVirtualMemory, MEMORY_BASIC_INFORMATION, KAPC_STATE
#include <wdf.h>
#include <ntstrsafe.h>

// Pool tag for EDR allocations
#define TAG_EDR 'rdE'   // "Edr" (little-endian)

// PsGetProcessImageFileName — not declared in WDK 10.0.28000.0 headers but exported by ntoskrnl.
EXTERN_C __drv_maxIRQL(APC_LEVEL)
PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

// Process enumeration via ZwQuerySystemInformation (deprecated but still exported).
// This is the only reliable way to enumerate processes from kernel mode in modern Windows.
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

EXTERN_C
NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// CRITICAL_PROCESS_DIED bugcheck code (0xEF) — defined in bugcodes.h via ntddk.h
// but some build environments may not export it cleanly.

#ifndef CRITICAL_PROCESS_DIED
#define CRITICAL_PROCESS_DIED 0x000000EF
#endif

// Device names
#define EDR_DEVICE_NAME          L"\\Device\\EDR"
#define EDR_SYMBOLIC_LINK_NAME   L"\\DosDevices\\EDR"
#define EDR_DEVICE_TYPE          0x8000

// IOCTL codes
// METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA
#define IOCTL_EDR_GET_EVENTS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_EDR_GET_STATS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_EDR_GET_DRIVER_INFO \
    CTL_CODE(EDR_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_EDR_SET_LOG_LEVEL \
    CTL_CODE(EDR_DEVICE_TYPE, 0x803, METHOD_NEITHER, FILE_WRITE_DATA)
#define IOCTL_EDR_QUERY_OPERATIONS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_EDR_CLEAR_BUFFER \
    CTL_CODE(EDR_DEVICE_TYPE, 0x805, METHOD_NEITHER, FILE_WRITE_DATA)
#define IOCTL_EDR_QUARANTINE_FILE \
    CTL_CODE(EDR_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_TERMINATE_PROCESS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_REGISTER_AGENT \
    CTL_CODE(EDR_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_SCAN_PROCESS_MEMORY \
    CTL_CODE(EDR_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_EDR_UPDATE_PROTECTED_KEYS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_SET_RESPAWN_PATH \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80B, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_PREPARE_SHUTDOWN \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80C, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_ALLOW_UNLOAD \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80D, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_RESTORE_ACTIVATE \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80E, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_RESTORE_DEACTIVATE \
    CTL_CODE(EDR_DEVICE_TYPE, 0x80F, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_EDR_RESTORE_STATUS \
    CTL_CODE(EDR_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_EDR_RESTORE_CLAIM_PARTITION \
    CTL_CODE(EDR_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_WRITE_DATA)

// Telemetry event types
typedef enum _EDR_EVENT_TYPE {
    EventProcessCreate = 1,
    EventProcessTerminate = 2,
    EventThreadCreate = 3,
    EventThreadTerminate = 4,
    EventImageLoad = 5,
    EventRegistryCreateKey = 6,
    EventRegistryDeleteKey = 7,
    EventRegistrySetValue = 8,
    EventRegistryDeleteValue = 9,
    EventRegistryRenameKey = 10,
    EventObjectHandleCreate = 11,
    EventObjectHandleDuplicate = 12,
    EventMemorySuspicious = 13,
} EDR_EVENT_TYPE;

// TLV header for ring buffer entries
typedef struct _EDR_TLV_HEADER {
    ULONG EventType;
    ULONG DataLength;
    ULONGLONG SequenceNumber;
    ULONGLONG Timestamp;
} EDR_TLV_HEADER, *PEDR_TLV_HEADER;

#define EDR_TLV_HEADER_SIZE sizeof(EDR_TLV_HEADER)

// Process create event payload
typedef struct _EDR_PROCESS_CREATE_DATA {
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG SessionId;
    ULONG CreatorProcessId;
    ULONG ThreadId;
    WCHAR ImagePath[260];
    WCHAR CommandLine[1024];
    WCHAR UserSid[256];
    WCHAR IntegrityLevel[32];
    ULONGLONG CreateTime;
} EDR_PROCESS_CREATE_DATA, *PEDR_PROCESS_CREATE_DATA;

// Process terminate event payload
typedef struct _EDR_PROCESS_TERMINATE_DATA {
    ULONG ProcessId;
    LONG ExitCode;
    ULONGLONG RunTimeNanos;
} EDR_PROCESS_TERMINATE_DATA, *PEDR_PROCESS_TERMINATE_DATA;

// Thread create event payload
typedef struct _EDR_THREAD_CREATE_DATA {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG CreatorProcessId;
    ULONG CreatorThreadId;
} EDR_THREAD_CREATE_DATA, *PEDR_THREAD_CREATE_DATA;

// Thread terminate event payload
typedef struct _EDR_THREAD_TERMINATE_DATA {
    ULONG ProcessId;
    ULONG ThreadId;
    LONG ExitCode;
} EDR_THREAD_TERMINATE_DATA, *PEDR_THREAD_TERMINATE_DATA;

// Image load event payload
typedef struct _EDR_IMAGE_LOAD_DATA {
    ULONG ProcessId;
    WCHAR ImagePath[260];
    ULONGLONG BaseAddress;
    ULONGLONG ImageSize;
    ULONG LoadFlags;
    WCHAR ProcessName[260];
} EDR_IMAGE_LOAD_DATA, *PEDR_IMAGE_LOAD_DATA;

// Registry operation payload
typedef struct _EDR_REGISTRY_DATA {
    WCHAR KeyPath[512];
    WCHAR ValueName[256];
    ULONG ProcessId;
    WCHAR ProcessName[260];
    ULONG OperationType; // 1=CreateKey, 2=DeleteKey, 3=SetValue, 4=DeleteValue, 5=RenameKey
    ULONG OldValueType;
    ULONG NewValueType;
    ULONG OldValueDataSize;
    ULONG NewValueDataSize;
    UCHAR OldValueData[256];
    UCHAR NewValueData[256];
} EDR_REGISTRY_DATA, *PEDR_REGISTRY_DATA;

// Object callback data
typedef struct _EDR_OBJECT_DATA {
    ULONG ProcessId;
    ULONGLONG ObjectAddress;
    ULONG HandleValue;
    ULONG ObjectType;   // 1=Process, 2=Thread, 3=Token
    ULONG GrantedAccess;
} EDR_OBJECT_DATA, *PEDR_OBJECT_DATA;

// Suspicious memory event payload
typedef struct _EDR_MEMORY_SUSPICIOUS_DATA {
    ULONG ProcessId;
    WCHAR ProcessName[260];
    ULONGLONG BaseAddress;    // Address of suspicious page
    ULONGLONG RegionSize;     // Size of suspicious region
    ULONG Protect;           // Memory protection flags (e.g. PAGE_EXECUTE_READWRITE)
    ULONG Type;              // MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE
    ULONG SuspicionFlags;    // Bitmask: 1=RWX, 2=shellcode_header, 4=unbacked
} EDR_MEMORY_SUSPICIOUS_DATA, *PEDR_MEMORY_SUSPICIOUS_DATA;

// Driver statistics
typedef struct _EDR_DRIVER_STATS {
    ULONGLONG EventsCollected;
    ULONGLONG EventsDropped;
    ULONGLONG BufferSize;
    ULONGLONG BufferUsed;
    ULONGLONG ReadIndex;
    ULONGLONG WriteIndex;
    ULONG CallbacksRegistered;
    ULONG PidCount;
    ULONG ImageLoadCount;
    ULONG RegistryOpCount;
    ULONG ObjectOpCount;
    ULONGLONG DriverStartTime;
    USHORT DriverVersionMajor;
    USHORT DriverVersionMinor;
    USHORT DriverVersionPatch;
} EDR_DRIVER_STATS, *PEDR_DRIVER_STATS;

// Driver information
typedef struct _EDR_DRIVER_INFO {
    USHORT VersionMajor;
    USHORT VersionMinor;
    USHORT VersionPatch;
    ULONG BuildNumber;
    WCHAR BuildDate[32];
    WCHAR BuildTime[32];
    ULONG CallbackStatus; // Bitmask of registered callbacks
} EDR_DRIVER_INFO, *PEDR_DRIVER_INFO;

// Ring buffer configuration
#define EDR_RING_BUFFER_SIZE (64 * 1024)        // 64K entries
#define EDR_RING_BUFFER_MEMORY_SIZE (64 * 1024 * 1024) // 64MB total buffer

// Callback registration bitmask
#define EDR_CB_PROCESS     0x0001
#define EDR_CB_THREAD      0x0002
#define EDR_CB_IMAGE       0x0004
#define EDR_CB_REGISTRY    0x0008
#define EDR_CB_OBJECT      0x0010

// Log levels
typedef enum _EDR_LOG_LEVEL {
    LogLevelError = 0,
    LogLevelWarning = 1,
    LogLevelInfo = 2,
    LogLevelVerbose = 3,
} EDR_LOG_LEVEL;
typedef EDR_LOG_LEVEL *PEDR_LOG_LEVEL;

// Respawn info input for IOCTL_EDR_SET_RESPAWN_PATH
typedef struct _EDR_RESPAWN_INFO {
    WCHAR ImagePath[260];
    WCHAR CommandLine[1024];
} EDR_RESPAWN_INFO, *PEDR_RESPAWN_INFO;

// Forward declaration — ring buffer struct is defined at the end of this header.
typedef struct _EDR_RING_BUFFER EDR_RING_BUFFER, *PEDR_RING_BUFFER;

// Device context
typedef struct _EDR_DEVICE_CONTEXT {
    PEDR_RING_BUFFER RingBuffer;
    EDR_DRIVER_STATS Stats;
    EDR_LOG_LEVEL LogLevel;
    ULONG RegisteredCallbacks;
    BOOLEAN CallbacksActive;
    FAST_MUTEX StatsLock;
    LARGE_INTEGER RegistrationHandle;  // Cm callback registration
    PVOID ObRegistrationHandle;        // Ob callback registration
    PEPROCESS AgentProcess;            // Registered agent process object pointer
    HANDLE AgentPid;                   // Registered agent PID
    WCHAR ProtectedKeys[64][260];      // Up to 64 protected registry key paths
    ULONG ProtectedKeyCount;           // Number of active protected key entries
    FAST_MUTEX ProtectedKeysLock;      // Lock for protected key updates
    WDFTIMER MemoryTimer;              // Periodic proactive memory sweep timer
    WDFWORKITEM MemoryWorkItem;        // Work item for memory sweep (runs at PASSIVE_LEVEL)
    LONG MemorySweepActive;            // Guard against concurrent sweeps (InterlockedExchange needs LONG)
    // Process resurrection
    WDFWORKITEM RespawnWorkItem;       // Work item to relaunch agent on unexpected exit
    UNICODE_STRING AgentImagePath;     // Full exe path for respawn (kernel pool)
    UNICODE_STRING AgentCmdLine;       // Command-line for respawn (kernel pool)
    BOOLEAN AgentCleanShutdown;        // TRUE if agent signaled intentional exit
    ULONGLONG AgentShutdownExpiry;     // Interrupt-time expiry for clean-shutdown window (10s)
    // Driver unload guard
    BOOLEAN AllowUnload;               // TRUE only on clean agent shutdown or system shutdown
    // Restore subsystem
    BOOLEAN RestoreActivated;          // TRUE after successful HMAC activation
    UCHAR RestorePayloadHash[32];      // SHA-256 of activated license payload
    UNICODE_STRING RestorePartitionPath; // Device path to claimed hidden partition
    ULONGLONG RestorePartitionSize;    // Size of claimed partition in bytes
} EDR_DEVICE_CONTEXT, *PEDR_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(EDR_DEVICE_CONTEXT, GetDeviceContext)

//
// IOCTL handler declarations (defined in edr.c)
// Restore handlers (defined in restore.c)
NTSTATUS EdrIoctlRestoreActivate(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlRestoreDeactivate(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context);
NTSTATUS EdrIoctlRestoreStatus(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlRestoreClaimPartition(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
//
NTSTATUS EdrIoctlGetEvents(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlGetStats(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlGetDriverInfo(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlSetLogLevel(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlQueryOperations(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS EdrIoctlClearBuffer(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context);
NTSTATUS EdrIoctlRegisterAgent(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlUpdateProtectedKeys(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlSetRespawnPath(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength);
NTSTATUS EdrIoctlScanProcessMemory(_In_ WDFREQUEST Request, _In_ PEDR_DEVICE_CONTEXT Context, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
VOID EdrRespawnWorker(_In_ WDFWORKITEM WorkItem);

// Callback registration (defined in callbacks.c)
NTSTATUS EdrRegisterCallbacks(VOID);
VOID EdrUnregisterCallbacks(VOID);

// Proactive memory sweep (defined in timer.c)
NTSTATUS EdrInitializeMemoryTimer(_In_ PEDR_DEVICE_CONTEXT Context, _In_ WDFDEVICE Device);
VOID EdrStopMemoryTimer(_In_ PEDR_DEVICE_CONTEXT Context);

// Ring buffer structure (full definition of forward-declared type)
struct _EDR_RING_BUFFER {
    ULONG Size;
    volatile LONG ReadIndex;
    volatile LONG WriteIndex;
    volatile LONGLONG SequenceNumber;
    UCHAR Buffer[1]; // Variable-length
};
