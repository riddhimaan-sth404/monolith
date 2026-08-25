/*++
Module Name:
    ringbuf.c

Abstract:
    Lock-free ring buffer implementation for driver telemetry.
    Uses Interlocked operations for thread-safe read/write without locks.

--*/

#include "edr.h"
#include "ringbuf.h"

NTSTATUS
EdrRingBufferInitialize(
    _Out_ PEDR_RING_BUFFER* RingBuffer
)
{
    ULONG bufferSize = sizeof(EDR_RING_BUFFER) + EDR_RING_BUFFER_MEMORY_SIZE;
    PEDR_RING_BUFFER buffer;

    // Allocate from non-paged pool
    buffer = (PEDR_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
        bufferSize,
        'RDE '
    );

    if (buffer == NULL) {
        KdPrint(("[EDR] Failed to allocate ring buffer memory\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);
    buffer->Size = EDR_RING_BUFFER_MEMORY_SIZE;
    buffer->ReadIndex = 0;
    buffer->WriteIndex = 0;
    buffer->SequenceNumber = 0;

    *RingBuffer = buffer;

    KdPrint(("[EDR] Ring buffer initialized: %lu bytes\n", bufferSize));
    return STATUS_SUCCESS;
}

ULONG
EdrRingBufferWrite(
    _Inout_ PEDR_RING_BUFFER Buffer,
    _In_ EDR_EVENT_TYPE EventType,
    _In_ const UCHAR* Data,
    _In_ ULONG DataLength
)
{
    LONG currentWrite;
    LONG currentRead;
    LONG nextWrite;
    ULONG totalSize = DataLength + EDR_TLV_HEADER_SIZE;

    // Check if the entry fits in the buffer
    if (totalSize > Buffer->Size) {
        return 0;
    }

    BOOLEAN wrapped = FALSE;
    do {
        currentWrite = Buffer->WriteIndex;
        currentRead = Buffer->ReadIndex;

        // Calculate next write position
        nextWrite = currentWrite + totalSize;

        // Wrap around if at end of buffer
        if (nextWrite > (LONG)Buffer->Size) {
            // Not enough space at end, wrap to beginning
            if (totalSize > (ULONG)currentRead) {
                // Buffer is full, drop the event
                return 0;
            }
            wrapped = TRUE;
            nextWrite = totalSize;
        } else {
            // Check if we'd overwrite unread data
            if (currentRead > currentWrite) {
                if (nextWrite >= currentRead) {
                    // Buffer is full, drop the event
                    return 0;
                }
            }
            wrapped = FALSE;
        }

        // Try to atomically claim the write position
    } while (InterlockedCompareExchange(
        &Buffer->WriteIndex,
        nextWrite,
        currentWrite
    ) != currentWrite);

    // Zero-fill the dead tail after claiming the range
    if (wrapped) {
        RtlZeroMemory(&Buffer->Buffer[currentWrite], Buffer->Size - currentWrite);
    }

    ULONG writeOffset = wrapped ? 0 : (ULONG)currentWrite;

    // Write the payload first (so reader never sees partial header with wrong data)
    RtlCopyMemory(
        &Buffer->Buffer[writeOffset + EDR_TLV_HEADER_SIZE],
        Data,
        DataLength
    );

    // Memory barrier ensures payload is visible before header
    MemoryBarrier();

    // Write the TLV header last
    PEDR_TLV_HEADER header = (PEDR_TLV_HEADER)(&Buffer->Buffer[writeOffset]);
    header->EventType = (ULONG)EventType;
    header->DataLength = DataLength;
    header->SequenceNumber = InterlockedIncrement64((PLONG64)&Buffer->SequenceNumber);
    header->Timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

    return totalSize;
}

ULONG
EdrRingBufferRead(
    _Inout_ PEDR_RING_BUFFER Buffer,
    _Out_ PUCHAR OutputBuffer,
    _In_ ULONG OutputBufferSize
)
{
    LONG currentRead;
    LONG currentWrite;
    ULONG totalBytesRead = 0;
    ULONG bytesRemaining = OutputBufferSize;

    while (bytesRemaining > EDR_TLV_HEADER_SIZE) {
        currentRead = Buffer->ReadIndex;
        currentWrite = Buffer->WriteIndex;

        if (currentRead == currentWrite) {
            // Buffer is empty
            break;
        }

        // Read the header at current position
        PEDR_TLV_HEADER header = (PEDR_TLV_HEADER)(&Buffer->Buffer[currentRead]);
        
        // Skip zeroed tail if encountered
        if (header->EventType == 0 && header->DataLength == 0) {
            InterlockedExchange(&Buffer->ReadIndex, 0);
            continue;
        }

        ULONG entrySize = EDR_TLV_HEADER_SIZE + header->DataLength;

        if (entrySize > bytesRemaining) {
            // Output buffer full
            break;
        }

        // Copy entry to output buffer
        RtlCopyMemory(OutputBuffer + totalBytesRead, header, entrySize);
        totalBytesRead += entrySize;
        bytesRemaining -= entrySize;

        // Advance read index
        LONG nextRead = currentRead + entrySize;
        if (nextRead >= (LONG)Buffer->Size) {
            nextRead = 0;
        }

        InterlockedExchange(&Buffer->ReadIndex, nextRead);
    }

    return totalBytesRead;
}

VOID
EdrRingBufferClear(
    _Inout_ PEDR_RING_BUFFER Buffer
)
{
    InterlockedExchange(&Buffer->ReadIndex, 0);
    InterlockedExchange(&Buffer->WriteIndex, 0);
    RtlZeroMemory(Buffer->Buffer, Buffer->Size);
}

ULONG
EdrRingBufferGetUsed(
    _In_ PEDR_RING_BUFFER Buffer
)
{
    LONG readIndex = Buffer->ReadIndex;
    LONG writeIndex = Buffer->WriteIndex;

    if (writeIndex >= readIndex) {
        return (ULONG)(writeIndex - readIndex);
    }

    return (ULONG)(Buffer->Size - readIndex + writeIndex);
}

BOOLEAN
EdrRingBufferIsEmpty(
    _In_ PEDR_RING_BUFFER Buffer
)
{
    return (Buffer->ReadIndex == Buffer->WriteIndex);
}
