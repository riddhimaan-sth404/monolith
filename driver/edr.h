#pragma once

//
// EDR Kernel Driver - Shared Definitions
//

// WDK pool tags use the multi-character constant idiom ('XxXx').
// Suppress Clang's -Wmultichar warning for the entire driver;
// MSVC accepts these without complaint.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmultichar"
#endif

#if defined(__has_include) && __has_include(<ntifs.h>)
#include <ntifs.h>     // ntddk.h + ZwQueryVirtualMemory, MEMORY_BASIC_INFORMATION, KAPC_STATE
#include <wdf.h>
#include <ntstrsafe.h>
#else
// Fallback definitions for Clang / IntelliSense when WDK is not in include path
#include <windows.h>
#include <winternl.h>
#include <sal.h>
#include <stdio.h>
#include <wchar.h>

#ifndef EXTERN_C
#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C extern
#endif
#endif

typedef void *PVOID;
typedef unsigned char UCHAR, *PUCHAR;
typedef unsigned short USHORT, *PUSHORT;
typedef unsigned long ULONG, *PULONG;
typedef unsigned long long ULONGLONG, *PULONGLONG;
typedef long LONG, *PLONG;
typedef long long LONG64, *PLONG64;
typedef void *HANDLE;
typedef char CHAR, *PCHAR;
typedef const char *PCSTR;
typedef wchar_t WCHAR, *PWCHAR, *PWCH;
typedef const wchar_t *PCWSTR;
typedef LONG NTSTATUS;
#ifndef VOID
#define VOID void
#endif
typedef unsigned char BOOLEAN;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef _In_
#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#endif

typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode  : 8;
            ULONG SystemModeImage      : 1;
            ULONG ImageMappedToAllPids : 1;
            ULONG ExtendedInfoPresent  : 1;
            ULONG Reserved             : 21;
        };
    };
    PVOID ImageBase;
    ULONG ImageSelector;
    SIZE_T ImageSize;
    ULONG ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PVOID Process;
    BOOLEAN InProgressFlags;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPendingAll;
} KAPC_STATE, *PKAPC_STATE;

typedef struct _FAST_MUTEX {
    LONG Count;
    PVOID Owner;
    ULONG Contention;
    PVOID Event;
    ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

typedef PVOID PEPROCESS;
typedef PVOID PETHREAD;
typedef PVOID WDFDRIVER;
typedef PVOID WDFDEVICE;
typedef PVOID WDFQUEUE;
typedef PVOID WDFREQUEST;
typedef PVOID WDFWORKITEM;
typedef PVOID WDFTIMER;
typedef PVOID WDFOBJECT;

typedef enum _REG_NOTIFY_CLASS {
    RegNtPreCreateKeyEx = 1,
    RegNtPreDeleteKey = 2,
    RegNtPreSetValueKey = 3,
    RegNtPreDeleteValueKey = 4,
    RegNtPreRenameKey = 5,
} REG_NOTIFY_CLASS;

typedef enum _OB_PREOP_CALLBACK_STATUS {
    OB_PREOP_SUCCESS = 0
} OB_PREOP_CALLBACK_STATUS;

typedef struct _OB_PRE_OPERATION_INFORMATION {
    PVOID Object;
    PVOID ObjectType;
    ULONG Operation;
    BOOLEAN KernelHandle;
    struct {
        struct {
            ULONG DesiredAccess;
            ULONG OriginalDesiredAccess;
        } CreateHandleInformation;
        struct {
            ULONG DesiredAccess;
            ULONG OriginalDesiredAccess;
        } DuplicateHandleInformation;
    } *Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

#define OB_OPERATION_HANDLE_CREATE     0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE  0x00000002
#define OB_FLT_REGISTRATION_VERSION    0x0100

typedef struct _OB_OPERATION_REGISTRATION {
    PVOID *ObjectType;
    ULONG Operations;
    PVOID PreOperation;
    PVOID PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT Version;
    USHORT OperationRegistrationCount;
    UNICODE_STRING Altitude;
    PVOID RegistrationContext;
    OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif
#define RtlStringCbPrintfW(dst, dstSize, fmt, ...) _snwprintf_s(dst, (dstSize)/sizeof(WCHAR), _TRUNCATE, fmt, __VA_ARGS__)
#define RtlStringCbCopyW(dst, dstSize, src) wcsncpy_s(dst, (dstSize)/sizeof(WCHAR), src, _TRUNCATE)
#define KdPrint(x)
#define ExAcquireFastMutex(m)
#define ExReleaseFastMutex(m)
#define ExInitializeFastMutex(m)
#define KeQueryPerformanceCounter(x) (*(LARGE_INTEGER*)&(ULONGLONG){0})
#define KeQueryInterruptTime() 0
#ifndef MemoryBarrier
#define MemoryBarrier()
#endif
#ifndef HandleToULong
#define HandleToULong(h) ((ULONG)(ULONG_PTR)(h))
#endif
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x00000040ULL
#endif
#ifndef POOL_FLAG_PAGED
#define POOL_FLAG_PAGED     0x00000100ULL
#endif
#ifndef POOL_FLAG_UNINITIALIZED
#define POOL_FLAG_UNINITIALIZED 0x00000002ULL
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif
#ifndef PAGE_EXECUTE
#define PAGE_EXECUTE 0x10
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ 0x20
#endif
#ifndef PAGE_EXECUTE_WRITECOPY
#define PAGE_EXECUTE_WRITECOPY 0x80
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_PRIVATE
#define MEM_PRIVATE 0x20000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED 0x40000
#endif
extern PVOID *PsProcessType;
extern PVOID *PsThreadType;
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
VOID ObDereferenceObject(PVOID Object);
PEPROCESS PsGetCurrentProcess(VOID);
HANDLE PsGetCurrentProcessId(VOID);
HANDLE PsGetProcessId(PEPROCESS Process);
VOID KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
PVOID ExAllocatePool2(ULONGLONG Flags, SIZE_T NumberOfBytes, ULONG Tag);
VOID ExFreePoolWithTag(PVOID P, ULONG Tag);
WCHAR RtlUpcaseUnicodeChar(WCHAR SourceCharacter);
NTSTATUS PsSetCreateProcessNotifyRoutine(PVOID NotifyRoutine, BOOLEAN Remove);
NTSTATUS PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsRemoveCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS PsRemoveLoadImageNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS CmRegisterCallbackEx(PVOID Function, PCUNICODE_STRING Altitude, PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved);
NTSTATUS CmUnRegisterCallback(LARGE_INTEGER Cookie);
NTSTATUS ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID *RegistrationHandle);
VOID ObUnRegisterCallbacks(PVOID RegistrationHandle);
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct _WDFDEVICE_INIT WDFDEVICE_INIT, *PWDFDEVICE_INIT;

#ifndef DRIVER_INITIALIZE
typedef NTSTATUS (DRIVER_INITIALIZE)(
    _In_ struct _DRIVER_OBJECT *DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);
typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;
#endif

typedef NTSTATUS (EVT_WDF_DRIVER_DEVICE_ADD)(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
);
typedef EVT_WDF_DRIVER_DEVICE_ADD *PFN_WDF_DRIVER_DEVICE_ADD;

typedef VOID (EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL)(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
);
typedef EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL *PFN_WDF_IO_QUEUE_IO_DEVICE_CONTROL;

typedef VOID (EVT_WDF_DEVICE_CONTEXT_CLEANUP)(
    _In_ WDFOBJECT Object
);
typedef EVT_WDF_DEVICE_CONTEXT_CLEANUP *PFN_WDF_DEVICE_CONTEXT_CLEANUP;

typedef VOID (EVT_WDF_DRIVER_UNLOAD)(
    _In_ WDFDRIVER Driver
);
typedef EVT_WDF_DRIVER_UNLOAD *PFN_WDF_DRIVER_UNLOAD;

typedef VOID (EVT_WDF_TIMER)(
    _In_ WDFTIMER Timer
);
typedef EVT_WDF_TIMER *PFN_WDF_TIMER;

typedef VOID (EVT_WDF_WORKITEM)(
    _In_ WDFWORKITEM WorkItem
);
typedef EVT_WDF_WORKITEM *PFN_WDF_WORKITEM;

typedef enum _WDF_IO_QUEUE_DISPATCH_TYPE {
    WdfIoQueueDispatchInvalid = 0,
    WdfIoQueueDispatchSequential,
    WdfIoQueueDispatchParallel,
    WdfIoQueueDispatchManual,
    WdfIoQueueDispatchMaximum
} WDF_IO_QUEUE_DISPATCH_TYPE;

typedef struct _WDF_DRIVER_CONFIG {
    ULONG Size;
    PFN_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;
    PFN_WDF_DRIVER_UNLOAD EvtDriverUnload;
    ULONG DriverInitFlags;
    ULONG DriverPoolTag;
} WDF_DRIVER_CONFIG, *PWDF_DRIVER_CONFIG;

typedef struct _WDF_OBJECT_ATTRIBUTES {
    ULONG Size;
    PFN_WDF_DEVICE_CONTEXT_CLEANUP EvtCleanupCallback;
    PVOID EvtDestroyCallback;
    ULONG ExecutionLevel;
    ULONG SynchronizationScope;
    WDFOBJECT ParentObject;
    size_t ContextSizeOverride;
    PVOID ContextTypeInfo;
} WDF_OBJECT_ATTRIBUTES, *PWDF_OBJECT_ATTRIBUTES;

typedef struct _WDF_IO_QUEUE_CONFIG {
    ULONG Size;
    WDF_IO_QUEUE_DISPATCH_TYPE DispatchType;
    ULONG PowerManaged;
    BOOLEAN AllowZeroLengthRequests;
    BOOLEAN DefaultQueue;
    PFN_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
    PVOID EvtIoDefault;
    PVOID EvtIoRead;
    PVOID EvtIoWrite;
    PVOID EvtIoStop;
    PVOID EvtIoResume;
    PVOID EvtIoCanceledOnQueue;
    ULONG DriverPoolTag;
} WDF_IO_QUEUE_CONFIG, *PWDF_IO_QUEUE_CONFIG;

typedef struct _WDF_TIMER_CONFIG {
    ULONG Size;
    PFN_WDF_TIMER EvtTimerFunc;
    LONGLONG Period;
    BOOLEAN AutomaticSerialization;
    ULONG TolerableDelay;
    BOOLEAN UseHighResolutionTimer;
} WDF_TIMER_CONFIG, *PWDF_TIMER_CONFIG;

typedef struct _WDF_WORKITEM_CONFIG {
    ULONG Size;
    PFN_WDF_WORKITEM EvtWorkItemFunc;
    BOOLEAN AutomaticSerialization;
} WDF_WORKITEM_CONFIG, *PWDF_WORKITEM_CONFIG;

#ifndef WDF_NO_HANDLE
#define WDF_NO_HANDLE NULL
#endif

#ifndef WDF_NO_OBJECT_ATTRIBUTES
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#endif

#ifndef PAGED_CODE
#define PAGED_CODE() ((void)0)
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#endif

#ifndef WDF_REL_TIMEOUT_IN_SEC
#define WDF_REL_TIMEOUT_IN_SEC(s) ((LONGLONG)(s) * -10000000LL)
#endif

#ifndef WDF_DRIVER_CONFIG_INIT
#define WDF_DRIVER_CONFIG_INIT(Config, EvtDeviceAdd) \
    do { \
        RtlZeroMemory((Config), sizeof(WDF_DRIVER_CONFIG)); \
        (Config)->Size = sizeof(WDF_DRIVER_CONFIG); \
        (Config)->EvtDriverDeviceAdd = (EvtDeviceAdd); \
    } while (0)
#endif

#ifndef WDF_OBJECT_ATTRIBUTES_INIT
#define WDF_OBJECT_ATTRIBUTES_INIT(Attributes) \
    do { \
        RtlZeroMemory((Attributes), sizeof(WDF_OBJECT_ATTRIBUTES)); \
        (Attributes)->Size = sizeof(WDF_OBJECT_ATTRIBUTES); \
    } while (0)
#endif

#ifndef WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(Attributes, Type) \
    do { \
        WDF_OBJECT_ATTRIBUTES_INIT(Attributes); \
    } while (0)
#endif

#ifndef WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(Config, _DispatchType) \
    do { \
        RtlZeroMemory((Config), sizeof(WDF_IO_QUEUE_CONFIG)); \
        (Config)->Size = sizeof(WDF_IO_QUEUE_CONFIG); \
        (Config)->DispatchType = (_DispatchType); \
        (Config)->DefaultQueue = TRUE; \
    } while (0)
#endif

#ifndef WDF_TIMER_CONFIG_INIT_PERIODIC
#define WDF_TIMER_CONFIG_INIT_PERIODIC(Config, _EvtTimerFunc, _Period) \
    do { \
        RtlZeroMemory((Config), sizeof(WDF_TIMER_CONFIG)); \
        (Config)->Size = sizeof(WDF_TIMER_CONFIG); \
        (Config)->EvtTimerFunc = (_EvtTimerFunc); \
        (Config)->Period = (LONGLONG)(_Period); \
    } while (0)
#endif

#ifndef WDF_WORKITEM_CONFIG_INIT
#define WDF_WORKITEM_CONFIG_INIT(Config, _EvtWorkItemFunc) \
    do { \
        RtlZeroMemory((Config), sizeof(WDF_WORKITEM_CONFIG)); \
        (Config)->Size = sizeof(WDF_WORKITEM_CONFIG); \
        (Config)->EvtWorkItemFunc = (_EvtWorkItemFunc); \
    } while (0)
#endif

NTSTATUS WdfDriverCreate(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _In_opt_ PWDF_OBJECT_ATTRIBUTES DriverAttributes,
    _In_ PWDF_DRIVER_CONFIG DriverConfig,
    _Out_opt_ WDFDRIVER *Driver
);
NTSTATUS WdfDeviceCreate(
    _Inout_ PWDFDEVICE_INIT *DeviceInit,
    _In_opt_ PWDF_OBJECT_ATTRIBUTES DeviceAttributes,
    _Out_ WDFDEVICE *Device
);
NTSTATUS WdfDeviceCreateSymbolicLink(
    _In_ WDFDEVICE Device,
    _In_ PCUNICODE_STRING SymbolicLinkName
);
NTSTATUS WdfIoQueueCreate(
    _In_ WDFDEVICE Device,
    _In_ PWDF_IO_QUEUE_CONFIG Config,
    _In_opt_ PWDF_OBJECT_ATTRIBUTES QueueAttributes,
    _Out_opt_ WDFQUEUE *Queue
);
VOID WdfObjectDelete(
    _In_ WDFOBJECT Object
);
NTSTATUS WdfTimerCreate(
    _In_ PWDF_TIMER_CONFIG Config,
    _In_opt_ PWDF_OBJECT_ATTRIBUTES Attributes,
    _Out_ WDFTIMER *Timer
);
BOOLEAN WdfTimerStart(
    _In_ WDFTIMER Timer,
    _In_ LONGLONG DueTime
);
BOOLEAN WdfTimerStop(
    _In_ WDFTIMER Timer,
    _In_ BOOLEAN Wait
);
NTSTATUS WdfWorkItemCreate(
    _In_ PWDF_WORKITEM_CONFIG Config,
    _In_opt_ PWDF_OBJECT_ATTRIBUTES Attributes,
    _Out_ WDFWORKITEM *WorkItem
);
VOID WdfWorkItemEnqueue(
    _In_ WDFWORKITEM WorkItem
);
WDFOBJECT WdfWorkItemGetParentObject(
    _In_ WDFWORKITEM WorkItem
);
WDFDEVICE WdfTimerGetParentObject(
    _In_ WDFTIMER Timer
);
WDFDEVICE WdfIoQueueGetDevice(
    _In_ WDFQUEUE Queue
);
PEPROCESS IoGetRequestorProcess(
    _In_ PVOID Irp
);
PVOID WdfRequestWdmGetIrp(
    _In_ WDFREQUEST Request
);
NTSTATUS IoValidateDeviceIoControlAccess(
    _In_ PVOID Irp,
    _In_ ULONG RequiredAccess
);
NTSTATUS WdfRequestRetrieveOutputBuffer(
    _In_ WDFREQUEST Request,
    _In_ size_t MinimumRequiredLength,
    _Out_ PVOID *Buffer,
    _Out_opt_ size_t *Length
);
NTSTATUS WdfRequestRetrieveInputBuffer(
    _In_ WDFREQUEST Request,
    _In_ size_t MinimumRequiredLength,
    _Out_ PVOID *Buffer,
    _Out_opt_ size_t *Length
);
VOID WdfRequestCompleteWithInformation(
    _In_ WDFREQUEST Request,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
);

#ifndef WDF_DECLARE_CONTEXT_TYPE_WITH_NAME
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(_struct, _name) \
    static __inline _struct* _name(WDFOBJECT Handle) { (VOID)Handle; return (_struct*)0; }
#endif

#endif

// Pool tag for EDR allocations — 'rdE' is the conventional WDK multi-char pool tag.
#define TAG_EDR 'rdE'   // "Edr" (little-endian)

#ifndef __drv_maxIRQL
#define __drv_maxIRQL(x)
#endif

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef MM_HIGHEST_USER_ADDRESS
#define MM_HIGHEST_USER_ADDRESS ((PVOID)(ULONG_PTR)0x7FFFFFFF0000ULL)
#endif

// PsGetProcessImageFileName — not declared in WDK 10.0.28000.0 headers but exported by ntoskrnl.
EXTERN_C __drv_maxIRQL(APC_LEVEL)
PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

// Virtual memory query declarations
#ifndef _MEMORY_INFORMATION_CLASS_DEFINED
#define _MEMORY_INFORMATION_CLASS_DEFINED
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;
#endif

EXTERN_C
NTSTATUS NTAPI ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

// Process enumeration via ZwQuerySystemInformation (deprecated but still exported).
// This is the only reliable way to enumerate processes from kernel mode in modern Windows.
#ifndef _WINTERNL_
#ifndef _SYSTEM_INFORMATION_CLASS_DEFINED
#define _SYSTEM_INFORMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;
#endif

#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
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
#endif

EXTERN_C
NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
#else
#ifndef ZwQuerySystemInformation
#define ZwQuerySystemInformation(Class, Info, Length, RetLen) NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)(Class), Info, Length, RetLen)
#endif
#endif

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
