// IOCTL codes for driver communication
// These must match the driver's IOCTL definitions exactly

pub const IOCTL_EDR_GET_EVENTS: u32 = 0x80002000;
pub const IOCTL_EDR_GET_STATS: u32 = 0x80002004;
pub const IOCTL_EDR_GET_DRIVER_INFO: u32 = 0x80002008;
pub const IOCTL_EDR_SET_LOG_LEVEL: u32 = 0x8000200C;
pub const IOCTL_EDR_QUERY_OPERATIONS: u32 = 0x80002010;
pub const IOCTL_EDR_CLEAR_BUFFER: u32 = 0x80002014;
pub const IOCTL_EDR_REGISTER_AGENT: u32 = 0x80002020;
pub const IOCTL_EDR_SCAN_PROCESS_MEMORY: u32 = 0x80002024;
pub const IOCTL_EDR_UPDATE_PROTECTED_KEYS: u32 = 0x80002028;
pub const IOCTL_EDR_SET_RESPAWN_PATH: u32 = 0x8000202C;
pub const IOCTL_EDR_PREPARE_SHUTDOWN: u32 = 0x80002030;
pub const IOCTL_EDR_ALLOW_UNLOAD: u32 = 0x80002034;
pub const IOCTL_EDR_RESTORE_ACTIVATE: u32 = 0x80002038;
pub const IOCTL_EDR_RESTORE_DEACTIVATE: u32 = 0x8000203C;
pub const IOCTL_EDR_RESTORE_STATUS: u32 = 0x80002040;
pub const IOCTL_EDR_RESTORE_CLAIM_PARTITION: u32 = 0x80002044;

// Driver telemetry event types
pub const EDR_EVENT_PROCESS_CREATE: u32 = 1;
pub const EDR_EVENT_PROCESS_TERMINATE: u32 = 2;
pub const EDR_EVENT_THREAD_CREATE: u32 = 3;
pub const EDR_EVENT_THREAD_TERMINATE: u32 = 4;
pub const EDR_EVENT_IMAGE_LOAD: u32 = 5;
pub const EDR_EVENT_REGISTRY_CREATE_KEY: u32 = 6;
pub const EDR_EVENT_REGISTRY_DELETE_KEY: u32 = 7;
pub const EDR_EVENT_REGISTRY_SET_VALUE: u32 = 8;
pub const EDR_EVENT_REGISTRY_DELETE_VALUE: u32 = 9;
pub const EDR_EVENT_REGISTRY_RENAME_KEY: u32 = 10;
pub const EDR_EVENT_OBJECT_HANDLE_CREATE: u32 = 11;
pub const EDR_EVENT_OBJECT_HANDLE_DUPLICATE: u32 = 12;
pub const EDR_EVENT_MEMORY_SUSPICIOUS: u32 = 13;

// TLV header size: Type(4) + Length(4) + Sequence(8) + Timestamp(8) = 24 bytes
pub const TLV_HEADER_SIZE: usize = 24;

#[repr(C, packed)]
pub struct TlvHeader {
    pub event_type: u32,
    pub data_length: u32,
    pub sequence_number: u64,
    pub timestamp: u64,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct MemorySuspiciousData {
    pub process_id: u32,
    pub process_name: [u16; 260],
    pub base_address: u64,
    pub region_size: u64,
    pub protect: u32,
    pub memory_type: u32,
    pub suspicion_flags: u32,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct DriverStats {
    pub events_collected: u64,
    pub events_dropped: u64,
    pub buffer_size: u64,
    pub buffer_used: u64,
    pub read_index: u64,
    pub write_index: u64,
    pub callbacks_registered: u32,
    pub pid_count: u32,
    pub image_load_count: u32,
    pub registry_op_count: u32,
    pub object_op_count: u32,
    pub driver_start_time: u64,
    pub driver_version_major: u16,
    pub driver_version_minor: u16,
    pub driver_version_patch: u16,
}
