#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

use monolith_protobuf::proto::v1;

use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::core::GUID;

pub(crate) mod file_handler;
pub(crate) mod network_handler;
pub(crate) mod process_handler;
pub(crate) mod registry_handler;

const PROVIDER_FILE: GUID = GUID {
    data1: 0xEDD08927,
    data2: 0x9CC4,
    data3: 0x4E65,
    data4: [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
};
const PROVIDER_PROCESS: GUID = GUID {
    data1: 0x22FB2CD6,
    data2: 0x0E7B,
    data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};
const PROVIDER_REGISTRY: GUID = GUID {
    data1: 0x70EB4F03,
    data2: 0xC1DE,
    data3: 0x4F73,
    data4: [0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD],
};
const PROVIDER_TCPIP: GUID = GUID {
    data1: 0x2F07E2EE,
    data2: 0x15DB,
    data3: 0x40F1,
    data4: [0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A],
};

const SESSION_NAME: &str = "Monolith-ETW";

pub struct EtwManager {
    buffer: Arc<Mutex<VecDeque<v1::Event>>>,
    scan_url: String,
    http_client: reqwest::Client,
    running: Arc<AtomicBool>,
}

impl EtwManager {
    pub fn new(buffer: Arc<Mutex<VecDeque<v1::Event>>>, scan_url: String) -> Self {
        Self {
            buffer,
            scan_url,
            http_client: reqwest::Client::new(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn start(&self) {
        let buffer = self.buffer.clone();
        let scan_url = self.scan_url.clone();
        let client = self.http_client.clone();
        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut retry = 1u64;
            while running.load(Ordering::Relaxed) {
                tracing::info!("starting ETW manager session (attempt {})", retry);
                unsafe {
                    Self::run_session(buffer.clone(), scan_url.clone(), client.clone(), &running);
                }
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                let delay = Duration::from_secs((retry * 30).min(120));
                tracing::warn!("ETW session stopped, retrying in {:?}", delay);
                std::thread::sleep(delay);
                retry = (retry * 2).min(4);
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    unsafe fn run_session(
        buffer: Arc<Mutex<VecDeque<v1::Event>>>,
        scan_url: String,
        http_client: reqwest::Client,
        _running: &AtomicBool,
    ) {
        unsafe {
            let session_name: Vec<u16> =
                OsStrExt::encode_wide(OsString::from(SESSION_NAME).as_os_str())
                    .chain(std::iter::once(0))
                    .collect();

            let props_size = size_of::<EVENT_TRACE_PROPERTIES>() + 256;
            let mut props_mem = vec![0u8; props_size];
            let logger_name_offset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let properties = &mut *(props_mem.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            std::ptr::write_bytes(properties, 0, 1);
            properties.Wnode.BufferSize = props_size as u32;
            properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.Wnode.ClientContext = 1;
            properties.Wnode.Guid = std::mem::zeroed();
            properties.BufferSize = 256;
            properties.MinimumBuffers = 4;
            properties.MaximumBuffers = 64;
            properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            properties.LoggerNameOffset = logger_name_offset;
            properties.EnableFlags = 0;

            let name_dst = props_mem.as_mut_ptr().add(logger_name_offset as usize);
            std::ptr::copy_nonoverlapping(
                session_name.as_ptr(),
                name_dst as *mut u16,
                session_name.len(),
            );

            // Stop any leftover session first to ensure a clean session handle
            stop_session(&CONTROLTRACE_HANDLE { Value: 0 }, &session_name);

            let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(&mut session_handle, session_name.as_ptr(), properties);
            if result != 0 {
                tracing::error!("failed to start ETW session: {}", result);
                return;
            }

            // Enable SystemTraceProviders via EnableTraceEx2.
            // On Win10 1809+ system trace providers require ENABLE_TRACE_PARAMETERS with SourceId.
            let uuid_bytes = uuid::Uuid::new_v4().to_bytes_le();
            let source_id = GUID {
                data1: u32::from_ne_bytes([
                    uuid_bytes[0],
                    uuid_bytes[1],
                    uuid_bytes[2],
                    uuid_bytes[3],
                ]),
                data2: u16::from_ne_bytes([uuid_bytes[4], uuid_bytes[5]]),
                data3: u16::from_ne_bytes([uuid_bytes[6], uuid_bytes[7]]),
                data4: [
                    uuid_bytes[8],
                    uuid_bytes[9],
                    uuid_bytes[10],
                    uuid_bytes[11],
                    uuid_bytes[12],
                    uuid_bytes[13],
                    uuid_bytes[14],
                    uuid_bytes[15],
                ],
            };
            let enable_params = ENABLE_TRACE_PARAMETERS {
                Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
                EnableProperty: 0,
                ControlFlags: 0,
                SourceId: source_id,
                EnableFilterDesc: std::ptr::null_mut(),
                FilterDescCount: 0,
            };

            let providers = [
                (&PROVIDER_FILE, "File"),
                (&PROVIDER_PROCESS, "Process"),
                (&PROVIDER_REGISTRY, "Registry"),
                (&PROVIDER_TCPIP, "TCP/IP"),
            ];
            for (guid, name) in &providers {
                let mut r = EnableTraceEx2(session_handle, *guid, 1, 5, 0, 0, 0, &enable_params);
                if r == 87 {
                    // Fallback for providers (e.g. Microsoft-Windows-TCPIP) that do not support ENABLE_TRACE_PARAMETERS
                    r = EnableTraceEx2(session_handle, *guid, 1, 5, 0, 0, 0, std::ptr::null());
                }
                if r != 0 && r != ERROR_ALREADY_EXISTS {
                    tracing::warn!("failed to enable {} provider: {}", name, r);
                } else {
                    tracing::info!("enabled {} ETW provider", name);
                }
            }

            let ctx = EtwDispatchContext {
                buffer: buffer.clone(),
                scan_url: scan_url.clone(),
                http_client: http_client.clone(),
            };
            let ctx_ptr = Box::into_raw(Box::new(ctx));

            let mut logfile = EVENT_TRACE_LOGFILEW {
                LogFileName: std::ptr::null_mut(),
                LoggerName: session_name.as_ptr() as *mut _,
                CurrentTime: 0,
                BuffersRead: 0,
                Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME
                        | PROCESS_TRACE_MODE_EVENT_RECORD,
                },
                CurrentEvent: std::mem::zeroed(),
                LogfileHeader: std::mem::zeroed(),
                BufferCallback: None,
                BufferSize: 262144,
                Filled: 0,
                EventsLost: 0,
                Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                    EventRecordCallback: Some(Self::dispatch_callback),
                },
                IsKernelTrace: 0,
                Context: ctx_ptr as *mut _,
            };

            let trace_handle = OpenTraceW(std::ptr::addr_of_mut!(logfile));
            if trace_handle.Value == u64::MAX {
                tracing::error!("failed to open ETW trace");
                let _ = Box::from_raw(ctx_ptr);
                stop_session(&CONTROLTRACE_HANDLE { Value: 0 }, &session_name);
                return;
            }

            tracing::info!("ETW manager started, processing events from all providers");
            ProcessTrace(
                std::ptr::addr_of!(trace_handle),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            CloseTrace(trace_handle);
            let _ = unsafe { Box::from_raw(ctx_ptr) };
            stop_session(&CONTROLTRACE_HANDLE { Value: 0 }, &session_name);
            tracing::info!("ETW manager stopped");
        }
    }

    unsafe extern "system" fn dispatch_callback(event_record: *mut EVENT_RECORD) {
        unsafe {
            if event_record.is_null() {
                return;
            }
            let ev = &*event_record;
            if ev.UserDataLength == 0 || ev.UserData.is_null() {
                return;
            }

            let ctx = &*(ev.UserContext as *const EtwDispatchContext);
            let provider = &ev.EventHeader.ProviderId;
            let event_id = ev.EventHeader.EventDescriptor.Id;
            let pid = ev.EventHeader.ProcessId;
            let data =
                std::slice::from_raw_parts(ev.UserData as *const u8, ev.UserDataLength as usize);

            // Dispatch by provider GUID
            if provider.data1 == PROVIDER_FILE.data1
                && provider.data2 == PROVIDER_FILE.data2
                && provider.data3 == PROVIDER_FILE.data3
                && provider.data4 == PROVIDER_FILE.data4
            {
                file_handler::handle_event(event_id, pid, data, ctx);
            } else if provider.data1 == PROVIDER_PROCESS.data1
                && provider.data2 == PROVIDER_PROCESS.data2
                && provider.data3 == PROVIDER_PROCESS.data3
                && provider.data4 == PROVIDER_PROCESS.data4
            {
                process_handler::handle_event(event_id, pid, data, ctx);
            } else if provider.data1 == PROVIDER_REGISTRY.data1
                && provider.data2 == PROVIDER_REGISTRY.data2
                && provider.data3 == PROVIDER_REGISTRY.data3
                && provider.data4 == PROVIDER_REGISTRY.data4
            {
                registry_handler::handle_event(event_id, pid, data, ctx);
            } else if provider.data1 == PROVIDER_TCPIP.data1
                && provider.data2 == PROVIDER_TCPIP.data2
                && provider.data3 == PROVIDER_TCPIP.data3
                && provider.data4 == PROVIDER_TCPIP.data4
            {
                network_handler::handle_event(event_id, pid, data, ctx);
            }
        }
    }
}

unsafe fn stop_session(handle: &CONTROLTRACE_HANDLE, session_name: &[u16]) {
    unsafe {
        let mut props_mem = vec![0u8; 1024];
        let properties = &mut *(props_mem.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        std::ptr::write_bytes(properties, 0, 1);
        properties.Wnode.BufferSize = 1024;
        properties.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let _ = ControlTraceW(
            *handle,
            session_name.as_ptr(),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

pub struct EtwDispatchContext {
    pub buffer: Arc<Mutex<VecDeque<v1::Event>>>,
    pub scan_url: String,
    pub http_client: reqwest::Client,
}

unsafe impl Send for EtwDispatchContext {}
