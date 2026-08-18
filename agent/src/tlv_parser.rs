#![allow(unsafe_code)]
#![allow(missing_docs)]


use crate::driver::ioctl;
use monolith_protobuf::proto::v1::{self as pb};

fn read_struct<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < size_of::<T>() {
        return None;
    }
    unsafe { Some(std::ptr::read_unaligned(data.as_ptr() as *const T)) }
}

pub fn parse_events(data: &[u8]) -> Vec<pb::Event> {
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + ioctl::TLV_HEADER_SIZE <= data.len() {
        let header: ioctl::TlvHeader = unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(offset) as *const ioctl::TlvHeader)
        };
        let data_length = header.data_length as usize;

        if offset + ioctl::TLV_HEADER_SIZE + data_length > data.len() {
            break;
        }

        let payload_start = offset + ioctl::TLV_HEADER_SIZE;
        let payload = &data[payload_start..payload_start + data_length];

        if let Some(event) = tlv_to_event(header.event_type, payload, header.sequence_number, header.timestamp) {
            events.push(event);
        }

        offset = payload_start + data_length;
    }

    events
}

fn tlv_to_event(event_type: u32, payload: &[u8], sequence_number: u64, timestamp_raw: u64) -> Option<pb::Event> {
    let ts = prost_types::Timestamp {
        seconds: (timestamp_raw / 10_000_000) as i64,
        nanos: 0,
    };

    match event_type {
        ioctl::EDR_EVENT_PROCESS_CREATE => {
            parse_process_create(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_PROCESS_TERMINATE => {
            parse_process_terminate(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_THREAD_CREATE => {
            parse_thread_create(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_THREAD_TERMINATE => {
            parse_thread_terminate(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_IMAGE_LOAD => {
            parse_image_load(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_REGISTRY_CREATE_KEY
        | ioctl::EDR_EVENT_REGISTRY_DELETE_KEY
        | ioctl::EDR_EVENT_REGISTRY_SET_VALUE
        | ioctl::EDR_EVENT_REGISTRY_DELETE_VALUE
        | ioctl::EDR_EVENT_REGISTRY_RENAME_KEY => {
            parse_registry(payload, ts, sequence_number, event_type)
        }
        ioctl::EDR_EVENT_OBJECT_HANDLE_CREATE => {
            parse_object_handle(payload, ts, sequence_number)
        }
        ioctl::EDR_EVENT_MEMORY_SUSPICIOUS => {
            parse_memory_suspicious(payload, ts, sequence_number)
        }
        _ => {
            tracing::trace!("unknown event type: {}", event_type);
            None
        }
    }
}

fn parse_process_create(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawProcessCreate {
        process_id: u32,
        parent_process_id: u32,
        session_id: u32,
        creator_process_id: u32,
        thread_id: u32,
        image_path: [u16; 260],
        command_line: [u16; 1024],
        user_sid: [u16; 256],
        integrity_level: [u16; 32],
        create_time: u64,
    }

    let raw: RawProcessCreate = read_struct(payload)?;

    let image_path = copy_widestr(raw.image_path);
    let command_line = copy_widestr(raw.command_line);
    let user_sid = copy_widestr(raw.user_sid);
    let integrity_level = copy_widestr(raw.integrity_level);

    let process_name = std::path::Path::new(&image_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ProcessCreate.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ProcessCreate(pb::ProcessCreateEvent {
            process: Some(pb::ProcessInfo {
                pid: raw.process_id,
                parent_pid: raw.parent_process_id,
                name: process_name,
                path: image_path,
                command_line,
                user_sid,
                integrity_level,
                ..Default::default()
            }),
            ..Default::default()
        })),
        metadata: vec![],
    })
}

fn parse_process_terminate(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawProcessTerminate {
        process_id: u32,
        exit_code: i32,
        run_time_nanos: u64,
    }

    let raw: RawProcessTerminate = read_struct(payload)?;

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ProcessExit.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ProcessExit(pb::ProcessExitEvent {
            pid: raw.process_id,
            exit_code: raw.exit_code as u32,
            run_time_nanos: raw.run_time_nanos,
            exit_time: Some(ts),
        })),
        metadata: vec![],
    })
}

fn parse_thread_create(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawThreadCreate {
        process_id: u32,
        thread_id: u32,
        creator_process_id: u32,
        creator_thread_id: u32,
    }

    let raw: RawThreadCreate = read_struct(payload)?;

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ThreadCreate.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ThreadCreate(pb::ThreadCreateEvent {
            pid: raw.process_id,
            tid: raw.thread_id,
            creator_pid: raw.creator_process_id,
            creator_tid: raw.creator_thread_id,
            create_time: Some(ts),
        })),
        metadata: vec![],
    })
}

fn parse_thread_terminate(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawThreadTerminate {
        process_id: u32,
        thread_id: u32,
        exit_code: i32,
    }

    let raw: RawThreadTerminate = read_struct(payload)?;

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ThreadExit.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ThreadExit(pb::ThreadExitEvent {
            pid: raw.process_id,
            tid: raw.thread_id,
            exit_code: raw.exit_code as u32,
        })),
        metadata: vec![],
    })
}

fn parse_image_load(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawImageLoad {
        process_id: u32,
        image_path: [u16; 260],
        base_address: u64,
        image_size: u64,
        load_flags: u32,
        process_name: [u16; 260],
    }

    let raw: RawImageLoad = read_struct(payload)?;

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ModuleLoad.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ModuleLoad(pb::ModuleLoadEvent {
            pid: raw.process_id,
            module_path: copy_widestr(raw.image_path),
            base_address: raw.base_address,
            module_size: raw.image_size,
            process_name: copy_widestr(raw.process_name),
            ..Default::default()
        })),
        metadata: vec![],
    })
}

fn parse_registry(payload: &[u8], ts: prost_types::Timestamp, seq: u64, event_type: u32) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawRegistry {
        key_path: [u16; 512],
        value_name: [u16; 256],
        process_id: u32,
        process_name: [u16; 260],
        operation_type: u32,
        old_value_type: u32,
        new_value_type: u32,
        old_value_data_size: u32,
        new_value_data_size: u32,
        old_value_data: [u8; 256],
        new_value_data: [u8; 256],
    }

    let raw: RawRegistry = read_struct(payload)?;
    let operation_enum = match event_type {
        ioctl::EDR_EVENT_REGISTRY_CREATE_KEY => pb::registry_change_event::RegistryOperation::RegOpCreateKey,
        ioctl::EDR_EVENT_REGISTRY_DELETE_KEY => pb::registry_change_event::RegistryOperation::RegOpDeleteKey,
        ioctl::EDR_EVENT_REGISTRY_SET_VALUE => pb::registry_change_event::RegistryOperation::RegOpSetValue,
        ioctl::EDR_EVENT_REGISTRY_DELETE_VALUE => pb::registry_change_event::RegistryOperation::RegOpDeleteValue,
        ioctl::EDR_EVENT_REGISTRY_RENAME_KEY => pb::registry_change_event::RegistryOperation::RegOpRenameKey,
        _ => pb::registry_change_event::RegistryOperation::RegOpUnspecified,
    };

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::RegistryChange.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::RegistryChange(pb::RegistryChangeEvent {
            pid: raw.process_id,
            process_name: copy_widestr(raw.process_name),
            key_path: copy_widestr(raw.key_path),
            value_name: copy_widestr(raw.value_name),
            old_value: String::new(),
            new_value: String::new(),
            operation: operation_enum.into(),
        })),
        metadata: vec![],
    })
}

fn parse_object_handle(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    #[derive(Copy, Clone)]
    #[repr(C, packed)]
    struct RawObjectData {
        process_id: u32,
        object_address: u64,
        handle_value: u32,
        object_type: u32,
        granted_access: u32,
    }

    let raw: RawObjectData = read_struct(payload)?;
    let obj_type_val = raw.object_type;
    let obj_type = match obj_type_val {
        1 => "Process",
        2 => "Thread",
        3 => "Token",
        _ => "Unknown",
    };
    let granted_access = raw.granted_access;
    let pid = raw.process_id;

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::ModuleLoad.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::ModuleLoad(pb::ModuleLoadEvent {
            pid,
            module_path: format!("ObjectHandle:{}:0x{:x}", obj_type, granted_access),
            ..Default::default()
        })),
        metadata: vec![],
    })
}

fn parse_memory_suspicious(payload: &[u8], ts: prost_types::Timestamp, seq: u64) -> Option<pb::Event> {
    let raw: ioctl::MemorySuspiciousData = read_struct(payload)?;

    let process_name = copy_widestr(raw.process_name);

    Some(pb::Event {
        id: Some(uuid_to_proto(uuid::Uuid::new_v4())),
        endpoint_id: None,
        event_type: pb::EventType::MemorySuspicious.into(),
        timestamp: Some(ts),
        collected_at: None,
        sequence_number: seq,
        payload: Some(pb::event::Payload::MemorySuspicious(pb::event::MemorySuspiciousEvent {
            suspicious: Some(pb::DriverMemorySuspicious {
                process_id: raw.process_id,
                process_name,
                base_address: raw.base_address,
                region_size: raw.region_size,
                protect: raw.protect,
                memory_type: raw.memory_type,
                suspicion_flags: raw.suspicion_flags,
            }),
        })),
        metadata: vec![],
    })
}

fn copy_widestr<const N: usize>(arr: [u16; N]) -> String {
    let end = arr.iter().position(|&c| c == 0).unwrap_or(N);
    String::from_utf16_lossy(&arr[..end])
}

fn uuid_to_proto(id: uuid::Uuid) -> pb::Uuid {
    pb::Uuid {
        value: id.as_bytes().to_vec(),
    }
}
