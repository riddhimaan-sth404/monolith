#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::mem;
use serde_json::{json, Value};

pub struct HeartbeatSender;

impl HeartbeatSender {
    pub fn new() -> Self {
        Self
    }

    pub async fn send(&self) -> monolith_shared::error::Result<bool> {
        let heartbeat = collect_system_status(None);
        tracing::debug!("sending heartbeat: {}", serde_json::to_string(&heartbeat).unwrap_or_default());
        Ok(true)
    }
}

pub fn collect_system_status(driver_stats_raw: Option<&[u8]>) -> Value {
    let cpu_usage = get_cpu_usage();
    let memory_usage = get_memory_usage();
    let disk_free = get_disk_free();
    let driver_loaded = is_driver_loaded();

    let (driver_collected, driver_dropped, driver_version) = if let Some(raw) = driver_stats_raw {
        parse_driver_stats(raw)
    } else {
        (0u64, 0u64, String::new())
    };

    json!({
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "disk_free_bytes": disk_free,
        "driver_loaded": driver_loaded,
        "scanner_connected": false,
        "driver_events_collected": driver_collected,
        "driver_events_dropped": driver_dropped,
        "driver_version": driver_version,
        "event_queue_depth": 0,
    })
}

fn get_cpu_usage() -> f64 {
    #[cfg(windows)]
    {
        // GetSystemTimes requires PROCESSOR_POWER_INFORMATION API set
        // Simplified for now - returns system-wide load estimate
        0.0
    }
    #[cfg(not(windows))]
    0.0
}

fn get_memory_usage() -> f64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::GlobalMemoryStatusEx;
        use windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX;
        let mut mem_info: MEMORYSTATUSEX = unsafe { mem::zeroed() };
        mem_info.dwLength = size_of::<MEMORYSTATUSEX>() as u32;

        unsafe {
            if GlobalMemoryStatusEx(&mut mem_info) != 0 {
                let total = mem_info.ullTotalPhys;
                let available = mem_info.ullAvailPhys;
                if total > 0 {
                    return ((total - available) as f64 / total as f64) * 100.0;
                }
            }
        }
        0.0
    }
    #[cfg(not(windows))]
    0.0
}

fn get_disk_free() -> u64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExA;
        use std::ffi::CString;

        let path = CString::new("C:\\").unwrap();
        let mut free_bytes: u64 = 0;

        unsafe {
            if GetDiskFreeSpaceExA(
                path.as_ptr() as *const u8,
                &mut free_bytes,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != 0
            {
                return free_bytes;
            }
        }
        0
    }
    #[cfg(not(windows))]
    0
}

fn is_driver_loaded() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{CreateFileA, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
        use std::ffi::CString;

        let path = CString::new("\\\\.\\EDR").unwrap();
        let handle = unsafe {
            CreateFileA(
                path.as_ptr() as *const u8,
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return false;
        }

        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
        true
    }
    #[cfg(not(windows))]
    false
}

fn parse_driver_stats(raw: &[u8]) -> (u64, u64, String) {
    #[repr(C, packed)]
    struct DriverStats {
        events_collected: u64,
        events_dropped: u64,
        buffer_size: u64,
        buffer_used: u64,
        read_index: u64,
        write_index: u64,
        callbacks_registered: u32,
        pid_count: u32,
        image_load_count: u32,
        registry_op_count: u32,
        object_op_count: u32,
        driver_start_time: u64,
        driver_version_major: u16,
        driver_version_minor: u16,
        driver_version_patch: u16,
    }

    if raw.len() < size_of::<DriverStats>() {
        return (0, 0, String::new());
    }

    let stats: DriverStats = unsafe {
        std::ptr::read_unaligned(raw.as_ptr() as *const DriverStats)
    };
    let major = stats.driver_version_major;
    let minor = stats.driver_version_minor;
    let patch = stats.driver_version_patch;
    let version = format!("{}.{}.{}", major, minor, patch);
    let collected = stats.events_collected;
    let dropped = stats.events_dropped;

    (collected, dropped, version)
}
