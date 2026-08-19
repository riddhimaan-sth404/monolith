#![allow(unsafe_code)]

use serde_json::{Value, json};
use std::mem;

pub struct SystemCollector;

impl SystemCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self) -> Vec<Value> {
        let mut events = Vec::new();

        #[cfg(windows)]
        {
            // Query system information via GetNativeSystemInfo
            use windows_sys::Win32::System::SystemInformation::{
                GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM,
                PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
            };

            unsafe {
                let mut sys_info: SYSTEM_INFO = mem::zeroed();
                GetNativeSystemInfo(&mut sys_info);
                let arch_val = sys_info.Anonymous.Anonymous.wProcessorArchitecture;
                let arch = match arch_val {
                    PROCESSOR_ARCHITECTURE_INTEL => "x86",
                    PROCESSOR_ARCHITECTURE_AMD64 => "x64",
                    PROCESSOR_ARCHITECTURE_ARM => "arm",
                    PROCESSOR_ARCHITECTURE_ARM64 => "arm64",
                    _ => "unknown",
                };
                events.push(json!({
                    "event_type": "system_info",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "data": {
                        "architecture": arch,
                        "num_processors": sys_info.dwNumberOfProcessors,
                        "page_size": sys_info.dwPageSize,
                    }
                }));
            }

            // Collect logon sessions via WTS APIs from RemoteDesktop module
            use windows_sys::Win32::System::RemoteDesktop::{
                WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory,
            };

            unsafe {
                let mut session_count: u32 = 0;
                let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();

                if WTSEnumerateSessionsW(
                    WTS_CURRENT_SERVER_HANDLE,
                    0,
                    1,
                    &mut sessions,
                    &mut session_count,
                ) != 0
                {
                    let session_slice =
                        std::slice::from_raw_parts(sessions, session_count as usize);
                    for s in session_slice {
                        let state = if s.State == 1 {
                            "active"
                        } else {
                            "disconnected"
                        };
                        events.push(json!({
                            "event_type": "logon_session",
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "data": {
                                "session_id": s.SessionId,
                                "state": state,
                            }
                        }));
                    }
                    WTSFreeMemory(sessions as *mut _);
                }
            }
        }

        events
    }

    pub fn create_usb_insert_event(vendor_id: &str, product_id: &str, serial: &str) -> Value {
        json!({
            "event_type": "usb_insert",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "data": {
                "vendor_id": vendor_id,
                "product_id": product_id,
                "serial": serial,
            }
        })
    }

    pub fn create_logon_event(
        user: &str,
        domain: &str,
        logon_type: &str,
        session_id: u32,
    ) -> Value {
        json!({
            "event_type": "user_logon",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "data": {
                "user": user,
                "domain": domain,
                "logon_type": logon_type,
                "session_id": session_id,
            }
        })
    }

    pub fn create_service_event(name: &str, display_name: &str, action: &str) -> Value {
        json!({
            "event_type": "service_change",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "data": {
                "name": name,
                "display_name": display_name,
                "action": action,
            }
        })
    }
}
