/*++
Module Name:
    callbacks.c

Abstract:
    Kernel callbacks for process, thread, image load, registry, and object events.
    Uses only documented Windows kernel APIs.

--*/

#include "edr.h"
#include "ringbuf.h"

// External device context reference
extern PEDR_DEVICE_CONTEXT g_DeviceContext;

// Process access rights (not defined in kernel headers for this WDK)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE            (0x0001)
#define PROCESS_SUSPEND_RESUME       (0x0800)
#define PROCESS_VM_WRITE             (0x0020)
#define PROCESS_VM_OPERATION         (0x0008)
#endif

// Registration tag for kernel callbacks
DEFINE_GUID(EDR_REGISTRATION_TAG, 0xe6b3c9a1, 0x4d5f, 0x4a2e, 0x8b, 0x7c, 0x9f, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e);

//
// Process notification callback
//
VOID
EdrProcessCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL || !context->CallbacksActive) {
        return;
    }

    if (Create) {
        EDR_PROCESS_CREATE_DATA data;
        RtlZeroMemory(&data, sizeof(data));

        data.ProcessId = HandleToULong(ProcessId);
        data.ParentProcessId = HandleToULong(ParentId);

        // Get process information
        PEPROCESS process;
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status)) {
            // Process image name is available via PsGetProcessImageFileName
            // (can't call it here at DISPATCH_LEVEL in some cases, but okay for telemetry)
            ObDereferenceObject(process);
        }

        // Write to ring buffer
        EdrRingBufferWrite(
            context->RingBuffer,
            EventProcessCreate,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);
    } else {
        // Process terminate event
        EDR_PROCESS_TERMINATE_DATA data;
        RtlZeroMemory(&data, sizeof(data));
        data.ProcessId = HandleToULong(ProcessId);

        EdrRingBufferWrite(
            context->RingBuffer,
            EventProcessTerminate,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);

        // Check if this is the registered agent terminating
        if (context->AgentPid != NULL && HandleToULong(ProcessId) == HandleToULong(context->AgentPid)) {
            // Clear stale EPROCESS reference immediately (before it's freed)
            if (context->AgentProcess != NULL) {
                ObDereferenceObject(context->AgentProcess);
                context->AgentProcess = NULL;
            }

            // Determine if this exit was expected (clean shutdown) or unexpected
            BOOLEAN expectedShutdown = context->AgentCleanShutdown &&
                (KeQueryInterruptTime() <= context->AgentShutdownExpiry);

            // Reset the flag — one-shot
            context->AgentCleanShutdown = FALSE;

            if (!expectedShutdown && context->AgentImagePath.Buffer != NULL) {
                // Unexpected termination — queue respawn work item
                if (context->RespawnWorkItem != NULL) {
                    WdfWorkItemEnqueue(context->RespawnWorkItem);
                    KdPrint(("[EDR] Agent terminated unexpectedly — queued respawn\n"));
                }
            } else {
                KdPrint(("[EDR] Agent terminated cleanly — no respawn\n"));
            }
        }
    }
}

//
// Thread notification callback
//
VOID
EdrThreadCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL || !context->CallbacksActive) {
        return;
    }

    if (Create) {
        EDR_THREAD_CREATE_DATA data;
        RtlZeroMemory(&data, sizeof(data));

        data.ProcessId = HandleToULong(ProcessId);
        data.ThreadId = HandleToULong(ThreadId);

        EdrRingBufferWrite(
            context->RingBuffer,
            EventThreadCreate,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);
    } else {
        // Thread terminate event
        EDR_THREAD_TERMINATE_DATA data;
        RtlZeroMemory(&data, sizeof(data));
        data.ProcessId = HandleToULong(ProcessId);
        data.ThreadId = HandleToULong(ThreadId);

        EdrRingBufferWrite(
            context->RingBuffer,
            EventThreadTerminate,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);
    }
}

//
// Image load notification callback
//
VOID
EdrImageLoadCallback(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL || !context->CallbacksActive || FullImageName == NULL) {
        return;
    }

    EDR_IMAGE_LOAD_DATA data;
    RtlZeroMemory(&data, sizeof(data));

    data.ProcessId = HandleToULong(ProcessId);
    if (ImageInfo != NULL) {
        data.BaseAddress = (ULONGLONG)ImageInfo->ImageBase;
        data.ImageSize = ImageInfo->ImageSize;
    }

    // Copy image path
    if (FullImageName->Buffer != NULL && FullImageName->Length > 0) {
        USHORT copyBytes = min(FullImageName->Length, (USHORT)(sizeof(data.ImagePath) - sizeof(WCHAR)));
        RtlCopyMemory(data.ImagePath, FullImageName->Buffer, copyBytes);
        data.ImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    EdrRingBufferWrite(
        context->RingBuffer,
        EventImageLoad,
        (PUCHAR)&data,
        sizeof(data)
    );

    InterlockedIncrement64(&context->Stats.EventsCollected);
}

//
// Helper: extract the ObjectName from registry notification Argument2.
// Each notification class uses a different structure layout.
//
static
PUNICODE_STRING
EdrGetRegObjectName(
    REG_NOTIFY_CLASS NotifyClass,
    PVOID Argument2
)
{
    if (Argument2 == NULL) return NULL;

    switch (NotifyClass) {
    case RegNtPreCreateKeyEx: {
        //
        // REG_CREATE_KEY_INFORMATION_V1 layout:
        //   offset 0: PUNICODE_STRING CompleteName
        //   offset sizeof(PUNICODE_STRING): PUNICODE_STRING ObjectName
        //
        typedef struct {
            PUNICODE_STRING CompleteName;
            PUNICODE_STRING ObjectName;
        } _REG_CREATE_V1, *_P_REG_CREATE_V1;
        return ((_P_REG_CREATE_V1)Argument2)->ObjectName;
    }
    case RegNtPreDeleteKey:
    case RegNtPreSetValueKey:
    case RegNtPreDeleteValueKey:
    case RegNtPreRenameKey: {
        //
        // These structures all start with ObjectName as the first field.
        //
        typedef struct {
            PUNICODE_STRING ObjectName;
        } _REG_COMMON, *_P_REG_COMMON;
        return ((_P_REG_COMMON)Argument2)->ObjectName;
    }
    default:
        return NULL;
    }
}

//
// Helper: check if a registry key path falls under any protected key
//
BOOLEAN
EdrIsKeyProtected(
    _In_ PEDR_DEVICE_CONTEXT Context,
    _In_ PCUNICODE_STRING KeyPath
)
{
    if (KeyPath == NULL || KeyPath->Buffer == NULL || Context->ProtectedKeyCount == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&Context->ProtectedKeysLock);
    BOOLEAN protected = FALSE;

    for (ULONG i = 0; i < Context->ProtectedKeyCount && !protected; i++) {
        SIZE_T protectedLen = wcslen(Context->ProtectedKeys[i]);
        if (protectedLen == 0) continue;

        // Convert protected key to uppercase for case-insensitive comparison
        WCHAR upperProtected[260];
        ULONG j;
        for (j = 0; j < protectedLen && j < 259; j++) {
            upperProtected[j] = RtlUpcaseUnicodeChar(Context->ProtectedKeys[i][j]);
        }
        upperProtected[j] = L'\0';
        protectedLen = j;

        // Also convert the operation key path
        SIZE_T keyLen = KeyPath->Length / sizeof(WCHAR);
        if (keyLen > 259) keyLen = 259;

        // Only check if operation key starts with protected key
        if (keyLen >= protectedLen) {
            BOOLEAN match = TRUE;
            for (j = 0; j < protectedLen; j++) {
                WCHAR upOp = RtlUpcaseUnicodeChar(KeyPath->Buffer[j]);
                if (upOp != upperProtected[j]) {
                    match = FALSE;
                    break;
                }
            }
            if (match) {
                protected = TRUE;
            }
        }
    }

    ExReleaseFastMutex(&Context->ProtectedKeysLock);
    return protected;
}

//
// Registry notification callback
//
NTSTATUS
EdrRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL || !context->CallbacksActive) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PUNICODE_STRING objectName = EdrGetRegObjectName(notifyClass, Argument2);

    // Check if this operation targets a protected key
    // Block unauthorized writes to protected keys
    if (notifyClass == RegNtPreCreateKeyEx ||
        notifyClass == RegNtPreDeleteKey ||
        notifyClass == RegNtPreSetValueKey ||
        notifyClass == RegNtPreDeleteValueKey ||
        notifyClass == RegNtPreRenameKey)
    {
        if (objectName != NULL && EdrIsKeyProtected(context, objectName)) {
            HANDLE callerPid = PsGetCurrentProcessId();
            if (callerPid != context->AgentPid) {
                // Block access — emit tamper event first
                EDR_REGISTRY_DATA data;
                RtlZeroMemory(&data, sizeof(data));
                data.ProcessId = HandleToULong(callerPid);
                data.OperationType = notifyClass;

                if (objectName != NULL && objectName->Buffer != NULL && objectName->Length > 0) {
                    USHORT copyBytes = min(objectName->Length, (USHORT)(sizeof(data.KeyPath) - sizeof(WCHAR)));
                    RtlCopyMemory(data.KeyPath, objectName->Buffer, copyBytes);
                    data.KeyPath[copyBytes / sizeof(WCHAR)] = L'\0';
                }

                EdrRingBufferWrite(
                    context->RingBuffer,
                    EventRegistrySetValue,
                    (PUCHAR)&data,
                    sizeof(data)
                );

                InterlockedIncrement64(&context->Stats.EventsCollected);
                KdPrint(("[EDR] Blocked registry write to protected key: PID=%lu\n",
                    HandleToULong(callerPid)));

                return STATUS_ACCESS_DENIED;
            }
        }
    }

    // Process registry notifications
    // We capture create/delete key and set/delete value operations
    switch (notifyClass) {
    case RegNtPreCreateKeyEx:
    case RegNtPreDeleteKey:
    case RegNtPreSetValueKey:
    case RegNtPreDeleteValueKey:
    case RegNtPreRenameKey:
    {
        EDR_REGISTRY_DATA data;
        RtlZeroMemory(&data, sizeof(data));

        data.ProcessId = HandleToULong(PsGetCurrentProcessId());

        // Get the key path
        if (objectName != NULL && objectName->Buffer != NULL && objectName->Length > 0) {
            USHORT copyBytes = min(objectName->Length, (USHORT)(sizeof(data.KeyPath) - sizeof(WCHAR)));
            RtlCopyMemory(data.KeyPath, objectName->Buffer, copyBytes);
            data.KeyPath[copyBytes / sizeof(WCHAR)] = L'\0';
        }

        data.OperationType = notifyClass;

        EDR_EVENT_TYPE evType;
        switch (notifyClass) {
        case RegNtPreCreateKeyEx:    evType = EventRegistryCreateKey;   break;
        case RegNtPreDeleteKey:      evType = EventRegistryDeleteKey;   break;
        case RegNtPreSetValueKey:    evType = EventRegistrySetValue;    break;
        case RegNtPreDeleteValueKey: evType = EventRegistryDeleteValue; break;
        case RegNtPreRenameKey:      evType = EventRegistryRenameKey;   break;
        default: return STATUS_SUCCESS;
        }

        EdrRingBufferWrite(
            context->RingBuffer,
            evType,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);
        break;
    }
    default:
        break;
    }

    return STATUS_SUCCESS;
}

//
// Object callback notification
//
OB_PREOP_CALLBACK_STATUS
EdrObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL || !context->CallbacksActive) {
        return OB_PREOP_SUCCESS;
    }

    // Only monitor process, thread, and token handle operations
    if (OperationInformation->ObjectType != NULL) {
        EDR_OBJECT_DATA data;
        RtlZeroMemory(&data, sizeof(data));

        data.ProcessId = HandleToULong(PsGetCurrentProcessId());
        data.ObjectAddress = (ULONGLONG)OperationInformation->Object;
        data.HandleValue = 0; // Handle field removed in modern WDK
        data.GrantedAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

        // Determine object type
        if (OperationInformation->ObjectType == *PsProcessType) {
            data.ObjectType = 1;
            BOOLEAN isUserMode = !OperationInformation->KernelHandle;
            if (context->AgentProcess != NULL && OperationInformation->Object == context->AgentProcess) {
                if (isUserMode) {
                    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                            ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
                    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                            ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
                    }
                }
            }
        } else if (OperationInformation->ObjectType == *PsThreadType) {
            data.ObjectType = 2;
        }

        EdrRingBufferWrite(
            context->RingBuffer,
            EventObjectHandleCreate,
            (PUCHAR)&data,
            sizeof(data)
        );

        InterlockedIncrement64(&context->Stats.EventsCollected);
    }

    return OB_PREOP_SUCCESS;
}

//
// Register all callbacks
//
NTSTATUS
EdrRegisterCallbacks(VOID)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status;

    // Process notification
    status = PsSetCreateProcessNotifyRoutine(EdrProcessCallback, FALSE);
    if (NT_SUCCESS(status)) {
        context->RegisteredCallbacks |= EDR_CB_PROCESS;
    } else {
        KdPrint(("[EDR] PsSetCreateProcessNotifyRoutine failed: 0x%08X\n", status));
    }

    // Thread notification
    status = PsSetCreateThreadNotifyRoutine(EdrThreadCallback);
    if (NT_SUCCESS(status)) {
        context->RegisteredCallbacks |= EDR_CB_THREAD;
    } else {
        KdPrint(("[EDR] PsSetCreateThreadNotifyRoutine failed: 0x%08X\n", status));
    }

    // Image load notification
    status = PsSetLoadImageNotifyRoutine(EdrImageLoadCallback);
    if (NT_SUCCESS(status)) {
        context->RegisteredCallbacks |= EDR_CB_IMAGE;
    } else {
        KdPrint(("[EDR] PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status));
    }

    // Registry notification
    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"12345.6789");
        status = CmRegisterCallbackEx(
            EdrRegistryCallback,
            &altitude,
            NULL,    // Driver
            context, // Context
            &context->RegistrationHandle,
            NULL     // Reserved (must be NULL per WDK)
        );
    }
    if (NT_SUCCESS(status)) {
        context->RegisteredCallbacks |= EDR_CB_REGISTRY;
    } else {
        KdPrint(("[EDR] CmRegisterCallbackEx failed: 0x%08X\n", status));
    }

    // Object callbacks
    OB_OPERATION_REGISTRATION operationRegistration = {
        PsProcessType,
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        EdrObjectPreCallback,
        NULL
    };

    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"12345.6789");
        OB_CALLBACK_REGISTRATION callbackRegistration = {
            OB_FLT_REGISTRATION_VERSION,
            1, // One operation registration
            altitude,
            NULL, // RegistrationContext
            &operationRegistration
        };

        status = ObRegisterCallbacks(&callbackRegistration, &context->ObRegistrationHandle);
    }
    if (NT_SUCCESS(status)) {
        context->RegisteredCallbacks |= EDR_CB_OBJECT;
    } else {
        KdPrint(("[EDR] ObRegisterCallbacks failed: 0x%08X\n", status));
    }

    context->CallbacksActive = TRUE;

    KdPrint(("[EDR] Callbacks registered: 0x%04X\n", context->RegisteredCallbacks));
    return STATUS_SUCCESS;
}

//
// Unregister all callbacks
//
VOID
EdrUnregisterCallbacks(VOID)
{
    PEDR_DEVICE_CONTEXT context = g_DeviceContext;
    if (context == NULL) {
        return;
    }

    context->CallbacksActive = FALSE;

    if (context->RegisteredCallbacks & EDR_CB_PROCESS) {
        PsSetCreateProcessNotifyRoutine(EdrProcessCallback, TRUE);
    }
    if (context->RegisteredCallbacks & EDR_CB_THREAD) {
        PsRemoveCreateThreadNotifyRoutine(EdrThreadCallback);
    }
    if (context->RegisteredCallbacks & EDR_CB_IMAGE) {
        PsRemoveLoadImageNotifyRoutine(EdrImageLoadCallback);
    }
    if (context->RegisteredCallbacks & EDR_CB_REGISTRY) {
        CmUnRegisterCallback(context->RegistrationHandle);
    }
    if (context->RegisteredCallbacks & EDR_CB_OBJECT) {
        ObUnRegisterCallbacks(context->ObRegistrationHandle);
    }

    RtlZeroMemory(&context->RegisteredCallbacks, sizeof(context->RegisteredCallbacks));

    KdPrint(("[EDR] All callbacks unregistered\n"));
}
