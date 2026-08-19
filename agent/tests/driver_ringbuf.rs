//! Tests for the driver ring buffer protocol — validates the lock-free ring buffer
//! algorithm from driver/ringbuf.c using safe Rust.
//!
//! # Test signatures
//!
//! Several tests use golden byte vectors to verify the ring buffer produces
//! byte-for-byte identical output to the expected C driver layout.
//! The TLV header is 24 bytes: EventType(4) + DataLength(4) + SequenceNumber(8) + Timestamp(8).

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// --- Constants matching driver/edr.h ---

// sizeof(EDR_TLV_HEADER) on MSVC x64: 4+4+8+8 = 24 bytes (no trailing padding)
const EDR_TLV_HEADER_SIZE: usize = 24;

const DRIVER_PROCESS_CREATE_SIZE: usize = 3176;
const DRIVER_PROCESS_TERMINATE_SIZE: usize = 16; // ULONG+LONG+ULONGLONG = 4+4+8
const DRIVER_REGISTRY_DATA_SIZE: usize = 2560; // 512*2 + 256*2 + 4 + 260*2 + 4*6 + 256*2
const DRIVER_THREAD_CREATE_SIZE: usize = 16; // ULONG*4

// --- TLV primitives ---

fn write_tlv_header(buf: &mut [u8], event_type: u32, data_length: u32, seq: u64, ts: u64) {
    buf[0..4].copy_from_slice(&event_type.to_le_bytes());
    buf[4..8].copy_from_slice(&data_length.to_le_bytes());
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
    buf[16..24].copy_from_slice(&ts.to_le_bytes());
}

fn read_tlv_header(buf: &[u8]) -> Option<(u32, u32, u64, u64)> {
    if buf.len() < EDR_TLV_HEADER_SIZE {
        return None;
    }
    let event_type = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let data_length = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let seq = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let ts = u64::from_le_bytes(buf[16..24].try_into().ok()?);
    Some((event_type, data_length, seq, ts))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdrEventType {
    ProcessCreate = 1,
    ProcessTerminate = 2,
    ThreadCreate = 3,
    ThreadTerminate = 4,
    ImageLoad = 5,
    RegistryCreateKey = 6,
    RegistryDeleteKey = 7,
    RegistrySetValue = 8,
    RegistryDeleteValue = 9,
    RegistryRenameKey = 10,
    ObjectHandleCreate = 11,
    ObjectHandleDuplicate = 12,
}

// --- Ring buffer implementation (mirrors driver/ringbuf.c) ---

struct EdrRingBuffer {
    size: u32,
    read_index: AtomicI32,
    write_index: AtomicI32,
    sequence_number: AtomicI64,
    last_read_seq: AtomicU64,
    buffer: Vec<u8>,
}

impl EdrRingBuffer {
    fn new(size: usize) -> Self {
        Self {
            size: size as u32,
            read_index: AtomicI32::new(0),
            write_index: AtomicI32::new(0),
            sequence_number: AtomicI64::new(0),
            last_read_seq: AtomicU64::new(0),
            buffer: vec![0u8; size],
        }
    }

    /// Write with live timestamp.
    fn write(&mut self, event_type: EdrEventType, data: &[u8]) -> Option<u32> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.write_with_ts(event_type, data, ts)
    }

    /// Write with deterministic timestamp (used for golden-signature tests).
    fn write_with_ts(&mut self, event_type: EdrEventType, data: &[u8], ts: u64) -> Option<u32> {
        let total_size = data.len() + EDR_TLV_HEADER_SIZE;
        if total_size > self.size as usize {
            return None;
        }

        let mut wrapped = false;
        let mut old_write = 0;
        let next_write = loop {
            let current_write = self.write_index.load(Ordering::Acquire);
            let current_read = self.read_index.load(Ordering::Acquire);
            let next = current_write + total_size as i32;

            let next = if next > self.size as i32 {
                if total_size as i32 > current_read {
                    return None;
                }
                wrapped = true;
                old_write = current_write;
                total_size as i32
            } else {
                if current_read > current_write && next >= current_read {
                    return None;
                }
                next
            };

            if self
                .write_index
                .compare_exchange_weak(current_write, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break next;
            }
        };

        let current_write = if wrapped {
            let cw = next_write - total_size as i32;
            self.buffer[old_write as usize..self.size as usize].fill(0);
            cw
        } else {
            next_write - total_size as i32
        };

        // Write payload first (reader never sees partial header with wrong data)
        if !data.is_empty() {
            let payload_offset = current_write as usize + EDR_TLV_HEADER_SIZE;
            self.buffer[payload_offset..payload_offset + data.len()].copy_from_slice(data);
        }

        std::sync::atomic::compiler_fence(Ordering::Release);

        // Write header last (makes entry visible atomically)
        let seq = self.sequence_number.fetch_add(1, Ordering::Relaxed) + 1;
        write_tlv_header(
            &mut self.buffer[current_write as usize..],
            event_type as u32,
            data.len() as u32,
            seq as u64,
            ts,
        );

        Some(total_size as u32)
    }

    fn read(&mut self, output: &mut Vec<u8>, max_size: usize) -> usize {
        let mut total_read = 0;
        let mut remaining = max_size;

        while remaining > EDR_TLV_HEADER_SIZE {
            let current_read = self.read_index.load(Ordering::Acquire);
            let current_write = self.write_index.load(Ordering::Acquire);

            if current_read == current_write {
                // If they are equal, we check if the entry at current_read is a new unread entry.
                let mut check_read = current_read;
                if self.size as i32 - check_read < EDR_TLV_HEADER_SIZE as i32 {
                    check_read = 0;
                }

                let header_buf = &self.buffer[check_read as usize..];
                if let Some((event_type, _, seq, _)) = read_tlv_header(header_buf) {
                    let last_seq = self.last_read_seq.load(Ordering::Acquire);
                    if event_type == 0 || seq <= last_seq {
                        break;
                    }
                } else {
                    break;
                }
            }

            if self.size as i32 - current_read < EDR_TLV_HEADER_SIZE as i32 {
                self.read_index.store(0, Ordering::Release);
                continue;
            }

            let header_buf = &self.buffer[current_read as usize..];
            let Some((event_type, data_length, seq, _)) = read_tlv_header(header_buf) else {
                break;
            };

            // Skip zeroed tail (occurs after wrap)
            if event_type == 0 && data_length == 0 {
                self.read_index.store(0, Ordering::Release);
                continue;
            }

            let entry_size = EDR_TLV_HEADER_SIZE + data_length as usize;
            if entry_size > remaining {
                break;
            }

            output.extend_from_slice(
                &self.buffer[current_read as usize..current_read as usize + entry_size],
            );
            total_read += entry_size;
            remaining -= entry_size;
            self.last_read_seq.store(seq, Ordering::Release);

            let mut next_read = current_read + entry_size as i32;
            if next_read >= self.size as i32 {
                next_read = 0;
            }
            self.read_index.store(next_read, Ordering::Release);
        }

        total_read
    }

    fn clear(&mut self) {
        self.read_index.store(0, Ordering::Release);
        self.write_index.store(0, Ordering::Release);
        self.last_read_seq.store(0, Ordering::Release);
        self.buffer.fill(0);
    }

    fn is_empty(&self) -> bool {
        self.read_index.load(Ordering::Acquire) == self.write_index.load(Ordering::Acquire)
    }

    fn used(&self) -> u32 {
        let ri = self.read_index.load(Ordering::Acquire);
        let wi = self.write_index.load(Ordering::Acquire);
        if wi >= ri {
            (wi - ri) as u32
        } else {
            (self.size as i32 - ri + wi) as u32
        }
    }

    fn parse_entry(data: &[u8]) -> Option<(u32, u32, u64, u64, &[u8])> {
        if data.len() < EDR_TLV_HEADER_SIZE {
            return None;
        }
        let (event_type, data_length, seq, ts) = read_tlv_header(data)?;
        let payload_start = EDR_TLV_HEADER_SIZE;
        let payload_end = payload_start + data_length as usize;
        if payload_end > data.len() {
            return None;
        }
        Some((
            event_type,
            data_length,
            seq,
            ts,
            &data[payload_start..payload_end],
        ))
    }
}

// =====================================================================
//  GOLDEN BYTE-VECTOR SIGNATURES
//  Each test constructs an expected byte buffer and asserts the ring
//  buffer produces byte-for-byte identical output for known inputs.
// =====================================================================

mod signatures {
    use super::*;

    /// Helper: construct the expected bytes for a single ring-buffer entry.
    fn entry_bytes(event_type: u32, data: &[u8], seq: u64, ts: u64) -> Vec<u8> {
        let mut buf = vec![0u8; EDR_TLV_HEADER_SIZE + data.len()];
        write_tlv_header(&mut buf[..], event_type, data.len() as u32, seq, ts);
        buf[EDR_TLV_HEADER_SIZE..].copy_from_slice(data);
        buf
    }

    // ---------------------------------------------------------------
    //  Signature 1 — Empty buffer
    //  A freshly initialised 64-byte buffer is all zeros.
    // ---------------------------------------------------------------
    #[test]
    fn sig1_empty_buffer_is_zeros() {
        let rb = EdrRingBuffer::new(64);
        let expected = vec![0u8; 64];
        assert_eq!(rb.buffer, expected);
    }

    // ---------------------------------------------------------------
    //  Signature 2 — Single ProcessCreate entry
    //  event_type=1, payload = { pid=1234, ppid=5678, image="C:\calc.exe" }
    //  seq=1, ts=0xDEADBEEFCAFEBABE
    //  Verifies: TLV header bytes, payload immediately after header,
    //  ring buffer indices advance correctly.
    // ---------------------------------------------------------------
    #[test]
    fn sig2_process_create_entry() {
        let payload: Vec<u8> = {
            let mut p = vec![0u8; DRIVER_PROCESS_CREATE_SIZE];
            // PID at offset 0
            p[0..4].copy_from_slice(&1234u32.to_le_bytes());
            // PPID at offset 4
            p[4..8].copy_from_slice(&5678u32.to_le_bytes());
            // ImagePath "C:\calc.exe" as null-terminated UTF-16 at offset 20
            let wpath: Vec<u16> = "C:\\calc.exe\0".encode_utf16().collect();
            for (i, &cp) in wpath.iter().enumerate() {
                p[20 + i * 2..20 + i * 2 + 2].copy_from_slice(&cp.to_le_bytes());
            }
            p
        };

        let mut rb = EdrRingBuffer::new(4096);
        rb.write_with_ts(EdrEventType::ProcessCreate, &payload, 0xDEAD_BEEF_CAFE_BABE)
            .unwrap();

        // ReadIndex=0, WriteIndex=24+3176=3200
        assert_eq!(rb.read_index.load(Ordering::Relaxed), 0);
        assert_eq!(rb.write_index.load(Ordering::Relaxed), 3200);

        // First 24 bytes = TLV header
        let header_bytes = &rb.buffer[0..EDR_TLV_HEADER_SIZE];
        let (ty, dl, seq, ts) = read_tlv_header(header_bytes).unwrap();
        assert_eq!(ty, 1); // ProcessCreate
        assert_eq!(dl, DRIVER_PROCESS_CREATE_SIZE as u32);
        assert_eq!(seq, 1);
        assert_eq!(ts, 0xDEAD_BEEF_CAFE_BABE);

        // Bytes 24..3200 = payload (verbatim)
        assert_eq!(&rb.buffer[EDR_TLV_HEADER_SIZE..3200], payload.as_slice());

        // Rest of buffer untouched
        assert!(rb.buffer[3200..].iter().all(|&b| b == 0));
    }

    // ---------------------------------------------------------------
    //  Signature 3 — ProcessTerminate
    //  event_type=2, payload = { pid=999, exit_code=-1, run_time=0 }
    //  seq=1, ts=0x1111222233334444
    // ---------------------------------------------------------------
    #[test]
    fn sig3_process_terminate_entry() {
        let payload: Vec<u8> = {
            let mut p = vec![0u8; DRIVER_PROCESS_TERMINATE_SIZE];
            p[0..4].copy_from_slice(&999u32.to_le_bytes()); // PID
            p[4..8].copy_from_slice(&(-1i32).to_le_bytes()); // ExitCode = -1
            p[8..16].copy_from_slice(&0u64.to_le_bytes()); // RunTimeNanos
            p
        };

        let mut rb = EdrRingBuffer::new(256);
        rb.write_with_ts(
            EdrEventType::ProcessTerminate,
            &payload,
            0x1111_2222_3333_4444,
        )
        .unwrap();

        assert_eq!(
            rb.write_index.load(Ordering::Relaxed),
            (EDR_TLV_HEADER_SIZE + DRIVER_PROCESS_TERMINATE_SIZE) as i32
        );

        let (ty, dl, seq, ts) = read_tlv_header(&rb.buffer[..EDR_TLV_HEADER_SIZE]).unwrap();
        assert_eq!(ty, 2);
        assert_eq!(dl, DRIVER_PROCESS_TERMINATE_SIZE as u32);
        assert_eq!(seq, 1);
        assert_eq!(ts, 0x1111_2222_3333_4444);

        let total = EDR_TLV_HEADER_SIZE + DRIVER_PROCESS_TERMINATE_SIZE;
        assert_eq!(&rb.buffer[EDR_TLV_HEADER_SIZE..total], payload);
    }

    // ---------------------------------------------------------------
    //  Signature 4 — RegistrySetValue
    //  event_type=8, payload = EDR_REGISTRY_DATA with key "HKLM\Software\Test"
    //  seq=1, ts=0xAAAABBBBCCCCDDDD
    // ---------------------------------------------------------------
    #[test]
    fn sig4_registry_set_value_entry() {
        let payload: Vec<u8> = {
            let mut p = vec![0u8; DRIVER_REGISTRY_DATA_SIZE];
            // KeyPath at offset 0 (512 WCHARs = 1024 bytes UTF-16)
            let wkey: Vec<u16> = "HKLM\\Software\\Test\0".encode_utf16().collect();
            for (i, &cp) in wkey.iter().enumerate() {
                p[i * 2..i * 2 + 2].copy_from_slice(&cp.to_le_bytes());
            }
            // ProcessId at offset 1024+512 = 1536
            // Actually, layout: KeyPath[512] + ValueName[256] + ProcessId(4) + ProcessName[260] + ...
            // KeyPath = 512 WCHAR = 1024 bytes, offset 0
            // ValueName = 256 WCHAR = 512 bytes, offset 1024
            // ProcessId = ULONG = 4 bytes, offset 1536
            p[1536..1540].copy_from_slice(&4444u32.to_le_bytes()); // PID
            p
        };

        let mut rb = EdrRingBuffer::new(4096);
        rb.write_with_ts(
            EdrEventType::RegistrySetValue,
            &payload,
            0xAAAA_BBBB_CCCC_DDDD,
        )
        .unwrap();

        let (ty, dl, seq, ts) = read_tlv_header(&rb.buffer[..EDR_TLV_HEADER_SIZE]).unwrap();
        assert_eq!(ty, 8);
        assert_eq!(dl, DRIVER_REGISTRY_DATA_SIZE as u32);
        assert_eq!(seq, 1);
        assert_eq!(ts, 0xAAAA_BBBB_CCCC_DDDD);

        let total = EDR_TLV_HEADER_SIZE + DRIVER_REGISTRY_DATA_SIZE;
        assert_eq!(&rb.buffer[EDR_TLV_HEADER_SIZE..total], payload);
    }

    // ---------------------------------------------------------------
    //  Signature 5 — Two entries back-to-back
    //  Entry 1: ProcessCreate at offset 0, 24+3176 = 3200 bytes
    //  Entry 2: ThreadCreate at offset 3200, 24+16 = 40 bytes
    //  Verifies sequential layout with no gaps.
    // ---------------------------------------------------------------
    #[test]
    fn sig5_two_entries_back_to_back() {
        let pc_payload = vec![0xABu8; DRIVER_PROCESS_CREATE_SIZE];
        let tc_payload: Vec<u8> = {
            let mut p = vec![0u8; DRIVER_THREAD_CREATE_SIZE];
            p[0..4].copy_from_slice(&777u32.to_le_bytes()); // PID
            p[4..8].copy_from_slice(&888u32.to_le_bytes()); // TID
            p[8..12].copy_from_slice(&999u32.to_le_bytes()); // CreatorPID
            p[12..16].copy_from_slice(&111u32.to_le_bytes()); // CreatorTID
            p
        };

        let mut rb = EdrRingBuffer::new(6400);
        rb.write_with_ts(EdrEventType::ProcessCreate, &pc_payload, 1000)
            .unwrap();

        let e1_total = EDR_TLV_HEADER_SIZE + DRIVER_PROCESS_CREATE_SIZE; // 3200
        assert_eq!(rb.write_index.load(Ordering::Relaxed), e1_total as i32);

        rb.write_with_ts(EdrEventType::ThreadCreate, &tc_payload, 2000)
            .unwrap();

        // Read both entries back
        let mut out = Vec::new();
        rb.read(&mut out, 6400);
        assert_eq!(
            out.len(),
            e1_total + EDR_TLV_HEADER_SIZE + DRIVER_THREAD_CREATE_SIZE
        );

        // Parse entry 1
        let (ty1, dl1, seq1, ts1, data1) = EdrRingBuffer::parse_entry(&out).unwrap();
        assert_eq!(ty1, 1);
        assert_eq!(dl1, DRIVER_PROCESS_CREATE_SIZE as u32);
        assert_eq!(seq1, 1);
        assert_eq!(ts1, 1000);
        assert_eq!(data1, pc_payload);

        // Parse entry 2
        let off2 = e1_total;
        let (ty2, dl2, seq2, ts2, data2) = EdrRingBuffer::parse_entry(&out[off2..]).unwrap();
        assert_eq!(ty2, 3); // ThreadCreate
        assert_eq!(dl2, DRIVER_THREAD_CREATE_SIZE as u32);
        assert_eq!(seq2, 2);
        assert_eq!(ts2, 2000);
        assert_eq!(data2, tc_payload);

        assert!(rb.is_empty());
    }

    // ---------------------------------------------------------------
    //  Signature 6 — Wrap-around
    //  Buffer = 100 bytes. Entry 1 (30 bytes) at offset 0.
    //  Entry 2 (30 bytes) at offset 30. Entry 3 (30 bytes) — doesn't
    //  fit at offset 60 (only 40 bytes left), so wraps to offset 0.
    //  Verifies: dead tail zeroed, entry 3 header at offset 0,
    //  Read can traverse wrap.
    // ---------------------------------------------------------------
    #[test]
    fn sig6_wrap_around_zeroes_tail() {
        let entry_sz = EDR_TLV_HEADER_SIZE + 6; // 30
        let buf_sz = 100;
        let payload5 = b"ABCDEF";
        let payload6 = b"UVWXYZ";

        let mut rb = EdrRingBuffer::new(buf_sz);

        // Entry 1 at offset 0 (30 bytes) → WriteIndex=30
        rb.write_with_ts(EdrEventType::ProcessCreate, payload5, 10)
            .unwrap();
        assert_eq!(rb.write_index.load(Ordering::Relaxed), 30);
        assert_eq!(rb.read_index.load(Ordering::Relaxed), 0);

        // Entry 2 at offset 30 (30 bytes) → WriteIndex=60
        rb.write_with_ts(EdrEventType::ThreadCreate, payload6, 20)
            .unwrap();
        assert_eq!(rb.write_index.load(Ordering::Relaxed), 60);

        // Entry 3 at offset 60 — only 40 bytes left, needs 30, fits
        rb.write_with_ts(EdrEventType::ImageLoad, b"GHIJKL", 30)
            .unwrap();
        assert_eq!(rb.write_index.load(Ordering::Relaxed), 90);

        // Entry 4 at offset 90 — only 10 bytes left, needs 30 → doesn't fit
        // Wrap check: total_size=30, buf_sz=100. current_read=0.
        // In non-wrap path: current_read(0) > current_write(90)? No, 0 < 90.
        // Non-wrap: next=90+30=120, 120 > 100? Yes → try wrap path.
        // Wrap: total_size(30) > current_read(0)? Yes → buffer full → drop
        let result = rb.write_with_ts(EdrEventType::ProcessTerminate, b"MNOPQR", 40);
        assert!(result.is_none());

        // Read entry 1 and entry 2 to free space
        let mut out = Vec::new();
        let n1 = rb.read(&mut out, entry_sz * 2);
        assert_eq!(n1, entry_sz * 2); // read 2 entries
        // ReadIndex should now be at 60
        assert_eq!(rb.read_index.load(Ordering::Relaxed), 60);

        // Now entry 4 should fit: total_size=30, current_read=60, non-wrap:
        // next=90+30=120, 120 > 100 → wrap path
        // total_size(30) > current_read(60)? No (30 < 60) → wrap allowed
        // → wrapped=true, next_write=30
        // CAS claims WriteIndex=90→30
        // Dead tail: zero buffer[90..100] (10 bytes)
        // Write at offset 0 (next_write - total_size = 0)
        let result = rb.write_with_ts(EdrEventType::ProcessTerminate, b"MNOPQR", 40);
        assert!(result.is_some());
        assert_eq!(rb.write_index.load(Ordering::Relaxed), 30);

        // Assert dead tail [90..100] was zeroed
        assert!(rb.buffer[90..100].iter().all(|&b| b == 0));

        // Read remaining entries (3 and 4) — traverses the wrap
        let mut out2 = Vec::new();
        let n2 = rb.read(&mut out2, buf_sz);

        // Should read entry 3 (at offset 60) and entry 4 (at offset 0)
        // Total = 2 * 30 = 60 bytes
        // But entry 4 was written at offset 0, and entry 3 is still at 60
        // Read starts at ReadIndex=60, reads entry 3 (30 bytes), advances to 90
        // At 90, check if current_read(90) == current_write(30) → no
        // Read header at 90: found zeroed tail → ReadIndex resets to 0
        // Read header at 0: entry 4 → reads it, advances to 30
        // At 30: current_read(30) == current_write(30) → empty → break
        assert!(n2 > 0);
        assert_eq!(out2.len(), entry_sz * 2);
        assert!(rb.is_empty());
    }

    // ---------------------------------------------------------------
    //  Signature 7 — Exact buffer fill
    //  Buffer = exactly 2 entries. Buffer fills, 3rd write fails.
    //  ReadIndex advances, wrap and write again.
    // ---------------------------------------------------------------
    #[test]
    fn sig7_exact_fill_then_wrap() {
        let entry_sz = EDR_TLV_HEADER_SIZE + 8; // 32
        let buf_sz = entry_sz * 2; // 64

        let mut rb = EdrRingBuffer::new(buf_sz);

        // Write 2 entries: WriteIndex=32, then 64
        rb.write_with_ts(EdrEventType::ProcessCreate, b"payload1", 100)
            .unwrap();
        rb.write_with_ts(EdrEventType::ThreadCreate, b"payload2", 200)
            .unwrap();
        assert_eq!(rb.write_index.load(Ordering::Relaxed), buf_sz as i32);

        // 3rd write should fail (buffer full: current_read=0, non-wrap: next=96, >64)
        // Wrap: total_size(32) > current_read(0)? Yes → drop
        assert!(
            rb.write_with_ts(EdrEventType::ImageLoad, b"payload3", 300)
                .is_none()
        );

        // Read 1 entry: ReadIndex advances to 32
        let mut out = Vec::new();
        rb.read(&mut out, entry_sz);
        assert_eq!(rb.read_index.load(Ordering::Relaxed), entry_sz as i32);

        // Now write entry 3 again: current_read=32, current_write=64
        // next=64+32=96, 96>64 → wrap path
        // total_size(32) > current_read(32)? No (32 > 32? No, equal) → 32 > 32 is false
        // So wrap is allowed (total_size <= current_read)
        // next_write = 32, wrapped=true
        // CAS: WriteIndex 64→32
        rb.write_with_ts(EdrEventType::ImageLoad, b"payload3", 300)
            .unwrap();
        assert_eq!(rb.write_index.load(Ordering::Relaxed), entry_sz as i32);

        // Dead tail at offset 64 should be zeroed (but buffer is 64, so offset 64 is beyond end? No, write was at 64 initially)
        // Actually: current_write=64, next_write=32 (wrapped), dead tail = buffer[64..], but buffer size = 64, so nothing to zero
        // The dead tail zeroing covers buffer[current_write..] where current_write=64, but that's past end

        // Read all: starts at 32 (entry 2), then hits 64 (treat as 0 after reset)
        // Actually ReadIndex is at 32. Reads entry 2 at offset 32.
        // Advances to 64. 64 >= buf_sz(64) → nextRead=0.
        // current_read=0, current_write=32 → header at 0 = entry 3
        let mut out2 = Vec::new();
        let n = rb.read(&mut out2, buf_sz);
        // Should read entry 2 (at 32) and entry 3 (at 0) = 2 * 32 = 64
        assert_eq!(n, entry_sz * 2);
        assert!(rb.is_empty());
    }

    // ---------------------------------------------------------------
    //  Signature 8 — TLV write_tlv_header byte layout
    //  Verify the exact byte pattern the C driver would produce.
    // ---------------------------------------------------------------
    #[test]
    fn sig8_tlv_header_byte_layout() {
        let mut buf = [0u8; EDR_TLV_HEADER_SIZE];
        write_tlv_header(
            &mut buf,
            0x01020304,
            0x05060708,
            0x090A0B0C0D0E0F10,
            0x1112131415161718,
        );

        // EventType (LE): 0x04030201
        assert_eq!(buf[0..4], [0x04, 0x03, 0x02, 0x01]);
        // DataLength (LE): 0x08070605
        assert_eq!(buf[4..8], [0x08, 0x07, 0x06, 0x05]);
        // SequenceNumber (LE): 0x100F0E0D0C0B0A09
        assert_eq!(buf[8..16], [0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09]);
        // Timestamp (LE): 0x1817161514131211
        assert_eq!(
            buf[16..24],
            [0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
    }

    // ---------------------------------------------------------------
    //  Signature 9 — Entry read yields exact bytes written
    //  Write → read → compare byte-for-byte (including TLV header)
    // ---------------------------------------------------------------
    #[test]
    fn sig9_read_exact_bytes() {
        let mut rb = EdrRingBuffer::new(1024);
        let payload = b"golden-payload-0123456789";

        // Construct expected bytes
        let expected = entry_bytes(5, payload, 1, 0xFEDCBA9876543210);

        rb.write_with_ts(EdrEventType::ImageLoad, payload, 0xFEDCBA9876543210)
            .unwrap();

        let mut out = Vec::new();
        let n = rb.read(&mut out, 1024);
        assert_eq!(n, expected.len());
        assert_eq!(out, expected);
    }

    // ---------------------------------------------------------------
    //  Signature 10 — Read returns contiguous entries that exactly
    //  match the written bytes, with correct padding between entries.
    // ---------------------------------------------------------------
    #[test]
    fn sig10_two_entries_contiguous_bytes() {
        let mut rb = EdrRingBuffer::new(1024);

        let p1 = b"entry-A";
        let p2 = b"entry-B";

        let e1 = entry_bytes(1, p1, 1, 1111);
        let e2 = entry_bytes(3, p2, 2, 2222);
        let mut expected = Vec::new();
        expected.extend_from_slice(&e1);
        expected.extend_from_slice(&e2);

        rb.write_with_ts(EdrEventType::ProcessCreate, p1, 1111)
            .unwrap();
        rb.write_with_ts(EdrEventType::ThreadCreate, p2, 2222)
            .unwrap();

        let mut out = Vec::new();
        let n = rb.read(&mut out, 1024);
        assert_eq!(n, expected.len());
        assert_eq!(out, expected);
    }

    // ---------------------------------------------------------------
    //  Signature 11 — Wrap produces correct byte layout
    //  Buffer=80, entry=40. Write 2 → full. Read 1. Write 1 (wraps).
    //  Verify byte-layout: [entry2(40)][zeros(40)][entry3(40)]
    //                          ^32          ^72      ^0
    // ---------------------------------------------------------------
    #[test]
    fn sig11_wrap_byte_layout() {
        let entry_sz = EDR_TLV_HEADER_SIZE + 16; // 40
        let buf_sz = entry_sz * 2; // 80
        let mut rb = EdrRingBuffer::new(buf_sz);

        let p1 = b"AAAAAAAAAAAAAAAA"; // 16 bytes
        let p2 = b"BBBBBBBBBBBBBBBB";
        let p3 = b"CCCCCCCCCCCCCCCC";

        // Write 2 entries → buffer full
        rb.write_with_ts(EdrEventType::ProcessCreate, p1, 10)
            .unwrap(); // offset 0, WI=40
        rb.write_with_ts(EdrEventType::ThreadCreate, p2, 20)
            .unwrap(); // offset 40, WI=80

        assert_eq!(rb.write_index.load(Ordering::Relaxed), 80);

        // Verify byte layout: [T1 P1][T2 P2]
        let e1 = entry_bytes(1, p1, 1, 10);
        let e2 = entry_bytes(3, p2, 2, 20);
        assert_eq!(rb.buffer[0..40], e1[..]);
        assert_eq!(rb.buffer[40..80], e2[..]);

        // Read 1 entry → advance ReadIndex to 40
        let mut out = Vec::new();
        rb.read(&mut out, entry_sz);
        assert_eq!(rb.read_index.load(Ordering::Relaxed), 40);

        // Write entry 3 → wraps to offset 0
        // current_write=80, current_read=40
        // next=80+40=120 > 80 → wrap
        // total_size(40) > current_read(40)? No (40 == 40, not >)
        // → wrapped=true, next_write=40
        // CAS 80→40, dead tail = buffer[80..80] = nothing (past end)
        // Write at offset 0
        rb.write_with_ts(EdrEventType::ImageLoad, p3, 30).unwrap();

        assert_eq!(rb.write_index.load(Ordering::Relaxed), 40);

        // Byte layout should be: [T3 P3 at 0][T2 P2 at 40 (still there)][zeros]
        let e3 = entry_bytes(5, p3, 3, 30);
        assert_eq!(rb.buffer[0..40], e3[..]);
        assert_eq!(rb.buffer[40..80], e2[..]);

        // Read 2 entries (wrap traversal): starts at 40 (entry 2), then 80→0 (entry 3)
        let mut out2 = Vec::new();
        rb.read(&mut out2, buf_sz);

        // Should read entry 2 first (at 40), then entry 3 (at 0)
        let mut expected = Vec::new();
        expected.extend_from_slice(&e2);
        expected.extend_from_slice(&e3);
        assert_eq!(out2, expected);
        assert_eq!(out2.len(), entry_sz * 2);
        assert!(rb.is_empty());
    }
}

// =====================================================================
//  BEHAVIOURAL TESTS
// =====================================================================

#[test]
fn test_tlv_header_size() {
    assert_eq!(EDR_TLV_HEADER_SIZE, 24);
}

#[test]
fn test_parse_entry() {
    let mut buf = vec![0u8; EDR_TLV_HEADER_SIZE + 8];
    write_tlv_header(&mut buf[..], 7, 8, 42, 12345);
    buf[EDR_TLV_HEADER_SIZE..].copy_from_slice(b"deadbeef");
    let parsed = EdrRingBuffer::parse_entry(&buf);
    assert!(parsed.is_some());
    let (ev, dl, seq, ts, payload) = parsed.unwrap();
    assert_eq!(ev, 7);
    assert_eq!(dl, 8);
    assert_eq!(seq, 42);
    assert_eq!(ts, 12345);
    assert_eq!(payload, b"deadbeef");
}

#[test]
fn test_parse_entry_too_short() {
    assert!(EdrRingBuffer::parse_entry(&[]).is_none());
    assert!(EdrRingBuffer::parse_entry(&[0u8; 16]).is_none());
}

#[test]
fn test_parse_entry_data_length_exceeds_buf() {
    let mut buf = vec![0u8; EDR_TLV_HEADER_SIZE + 10];
    write_tlv_header(&mut buf[..], 1, 9999, 1, 1);
    assert!(EdrRingBuffer::parse_entry(&buf).is_none());
}

#[test]
fn test_new_is_empty() {
    let rb = EdrRingBuffer::new(1024);
    assert!(rb.is_empty());
    assert_eq!(rb.used(), 0);
}

#[test]
fn test_write_one_entry() {
    let mut rb = EdrRingBuffer::new(4096);
    let result = rb.write(EdrEventType::ProcessCreate, b"hello");
    assert!(result.is_some());
    assert!(!rb.is_empty());
    assert!(rb.used() > 0);
}

#[test]
fn test_write_then_read() {
    let mut rb = EdrRingBuffer::new(4096);
    rb.write(EdrEventType::ImageLoad, b"test payload").unwrap();
    let mut out = Vec::new();
    let n = rb.read(&mut out, 4096);
    assert!(n > 0);
    let (ty, dl, seq, _ts, data) = EdrRingBuffer::parse_entry(&out).unwrap();
    assert_eq!(ty, EdrEventType::ImageLoad as u32);
    assert_eq!(dl as usize, b"test payload".len());
    assert_eq!(data, b"test payload");
    assert!(seq >= 1);
    assert!(rb.is_empty());
}

#[test]
fn test_multiple_entries() {
    let mut rb = EdrRingBuffer::new(8192);
    let payloads: &[&[u8]] = &[b"entry1", b"entry2 longer", b"third"];
    for (i, p) in payloads.iter().enumerate() {
        let ev = match i {
            0 => EdrEventType::ProcessCreate,
            1 => EdrEventType::RegistrySetValue,
            _ => EdrEventType::ObjectHandleCreate,
        };
        rb.write(ev, p).unwrap();
    }
    let mut out = Vec::new();
    let n = rb.read(&mut out, 8192);
    let mut offset = 0;
    for (i, expected) in payloads.iter().enumerate() {
        let (ty, dl, seq, _ts, data) = EdrRingBuffer::parse_entry(&out[offset..]).unwrap();
        assert_eq!(seq, (i + 1) as u64);
        assert_eq!(data, *expected);
        offset += EDR_TLV_HEADER_SIZE + dl as usize;
    }
    assert_eq!(offset, n);
    assert!(rb.is_empty());
}

#[test]
fn test_clear_resets() {
    let mut rb = EdrRingBuffer::new(4096);
    rb.write(EdrEventType::ThreadCreate, b"data").unwrap();
    assert!(!rb.is_empty());
    rb.clear();
    assert!(rb.is_empty());
    assert_eq!(rb.used(), 0);
    let mut out = Vec::new();
    assert_eq!(rb.read(&mut out, 4096), 0);
}

#[test]
fn test_entry_too_large_returns_none() {
    let mut rb = EdrRingBuffer::new(256);
    let result = rb.write(EdrEventType::ProcessCreate, &[0u8; 512]);
    assert!(result.is_none());
}

#[test]
fn test_buffer_full_drops() {
    let mut rb = EdrRingBuffer::new(EDR_TLV_HEADER_SIZE + 8);
    assert!(rb.write(EdrEventType::ProcessCreate, b"1234").is_some());
    assert!(rb.write(EdrEventType::ProcessCreate, b"5678").is_none());
}

#[test]
fn test_clear_resets_but_seq_continues() {
    let mut rb = EdrRingBuffer::new(4096);
    rb.write(EdrEventType::ProcessCreate, b"a").unwrap();
    rb.clear();
    rb.write(EdrEventType::ProcessCreate, b"b").unwrap();
    let mut out = Vec::new();
    rb.read(&mut out, 4096);
    let (_ty, _dl, seq, _ts, _data) = EdrRingBuffer::parse_entry(&out).unwrap();
    assert!(seq >= 2, "seq={}", seq);
}

#[test]
fn test_empty_read_returns_zero() {
    let mut rb = EdrRingBuffer::new(1024);
    let mut out = Vec::new();
    assert_eq!(rb.read(&mut out, 1024), 0);
    assert!(out.is_empty());
}

#[test]
fn test_zero_length_payload() {
    let mut rb = EdrRingBuffer::new(1024);
    rb.write(EdrEventType::ProcessTerminate, b"").unwrap();
    let mut out = Vec::new();
    let n = rb.read(&mut out, 1024);
    assert_eq!(n, EDR_TLV_HEADER_SIZE);
    let (ty, dl, _seq, _ts, data) = EdrRingBuffer::parse_entry(&out).unwrap();
    assert_eq!(ty, EdrEventType::ProcessTerminate as u32);
    assert_eq!(dl, 0);
    assert!(data.is_empty());
}

#[test]
fn test_consecutive_writes_no_gap() {
    let mut rb = EdrRingBuffer::new(4096);
    let payload = b"abc";
    for i in 0..10 {
        let ev = if i % 2 == 0 {
            EdrEventType::ProcessCreate
        } else {
            EdrEventType::RegistrySetValue
        };
        rb.write(ev, payload).unwrap();
    }
    let mut out = Vec::new();
    let n = rb.read(&mut out, 4096);
    let mut offset = 0;
    let mut count = 0;
    while offset + EDR_TLV_HEADER_SIZE <= n {
        let (_ty, dl, _seq, _ts, data) = EdrRingBuffer::parse_entry(&out[offset..]).unwrap();
        assert_eq!(data, payload);
        offset += EDR_TLV_HEADER_SIZE + dl as usize;
        count += 1;
    }
    assert_eq!(count, 10);
}

#[test]
fn test_event_type_all_values() {
    let mut rb = EdrRingBuffer::new(4096);
    let types = [
        EdrEventType::ProcessCreate,
        EdrEventType::ProcessTerminate,
        EdrEventType::ThreadCreate,
        EdrEventType::ThreadTerminate,
        EdrEventType::ImageLoad,
        EdrEventType::RegistryCreateKey,
        EdrEventType::RegistryDeleteKey,
        EdrEventType::RegistrySetValue,
        EdrEventType::RegistryDeleteValue,
        EdrEventType::RegistryRenameKey,
        EdrEventType::ObjectHandleCreate,
        EdrEventType::ObjectHandleDuplicate,
    ];
    for &t in &types {
        rb.write(t, b"data").unwrap();
    }
    let mut out = Vec::new();
    rb.read(&mut out, 4096);
    let mut offset = 0;
    for &expected in &types {
        let (ty, dl, _seq, _ts, _data) = EdrRingBuffer::parse_entry(&out[offset..]).unwrap();
        assert_eq!(ty, expected as u32);
        offset += EDR_TLV_HEADER_SIZE + dl as usize;
    }
}

#[test]
fn test_partial_read_keeps_remaining() {
    let mut rb = EdrRingBuffer::new(4096);
    let small = b"small";
    let large = b"this is a larger payload that won't fit in a small output buffer";
    rb.write(EdrEventType::ProcessCreate, small).unwrap();
    rb.write(EdrEventType::ProcessCreate, large).unwrap();

    let mut out = Vec::new();
    let n = rb.read(&mut out, 40);
    assert!(n > 0);
    assert!(!rb.is_empty());

    let mut out2 = Vec::new();
    let _n2 = rb.read(&mut out2, 4096);
    let (_ty, dl, _seq, _ts, data) = EdrRingBuffer::parse_entry(&out2).unwrap();
    assert_eq!(data, large);
    assert!(rb.is_empty());
}

#[test]
fn test_interleaved_write_read() {
    let mut rb = EdrRingBuffer::new(4096);
    for i in 0..5 {
        let payload = vec![i as u8; 20];
        rb.write(EdrEventType::ProcessCreate, &payload).unwrap();
        let mut out = Vec::new();
        rb.read(&mut out, 4096);
        let (_ty, _dl, seq, _ts, data) = EdrRingBuffer::parse_entry(&out).unwrap();
        assert_eq!(seq, (i + 1) as u64);
        assert_eq!(data, payload.as_slice());
        assert!(rb.is_empty());
    }
}

#[test]
fn test_used_after_partial_read() {
    let mut rb = EdrRingBuffer::new(4096);
    rb.write(EdrEventType::ProcessCreate, b"aaa").unwrap();
    rb.write(EdrEventType::ThreadCreate, b"bbb").unwrap();
    rb.write(EdrEventType::ImageLoad, b"ccc").unwrap();

    let total_used = rb.used();
    assert!(total_used >= 3 * (EDR_TLV_HEADER_SIZE as u32 + 3));

    let mut out = Vec::new();
    rb.read(&mut out, EDR_TLV_HEADER_SIZE + 4);
    let remaining = rb.used();
    assert!(remaining < total_used);
    assert!(remaining > 0);
}
