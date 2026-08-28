#pragma once

//
// Ring buffer public interface
//

#include "edr.h"

NTSTATUS
EdrRingBufferInitialize(
    _Out_ PEDR_RING_BUFFER* RingBuffer
);

ULONG
EdrRingBufferWrite(
    _Inout_ PEDR_RING_BUFFER Buffer,
    _In_ EDR_EVENT_TYPE EventType,
    _In_ const UCHAR* Data,
    _In_ ULONG DataLength
);

ULONG
EdrRingBufferRead(
    _Inout_ PEDR_RING_BUFFER Buffer,
    _Out_ PUCHAR OutputBuffer,
    _In_ ULONG OutputBufferSize
);

VOID
EdrRingBufferClear(
    _Inout_ PEDR_RING_BUFFER Buffer
);

ULONG
EdrRingBufferGetUsed(
    _In_ PEDR_RING_BUFFER Buffer
);

BOOLEAN
EdrRingBufferIsEmpty(
    _In_ PEDR_RING_BUFFER Buffer
);
