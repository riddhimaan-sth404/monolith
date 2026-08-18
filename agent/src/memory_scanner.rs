#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::config::AgentConfig;

use std::sync::OnceLock;

fn get_scan_cooldown() -> &'static Mutex<HashMap<u32, Instant>> {
    static SCAN_COOLDOWN: OnceLock<Mutex<HashMap<u32, Instant>>> = OnceLock::new();
    SCAN_COOLDOWN.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryScanRequest {
    pub process_id: u32,
    pub process_name: String,
    pub region_base: u64,
    pub region_size: u64,
    pub protection: u32,
    pub data: String, // base64-encoded raw bytes
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MemoryScanResult {
    pub process_id: u32,
    pub process_name: String,
    pub region_base: u64,
    pub matched_rules: Vec<String>,
    pub yara_matches: usize,
    pub contains_pe: bool,
    pub verdict: String,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub region_size: u64,
    pub protection: u32,
    pub state: u32,
    pub type_: u32,
}

#[cfg(windows)]
pub fn get_process_name(pid: u32) -> String {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    use windows_sys::Win32::Foundation::CloseHandle;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return format!("PID_{}", pid);
    }

    let mut buffer = [0u16; 512];
    let mut size = buffer.len() as u32;
    let success = unsafe {
        QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size)
    };

    unsafe { CloseHandle(handle) };

    if success != 0 {
        let path = String::from_utf16_lossy(&buffer[..size as usize]);
        if let Some(filename) = std::path::Path::new(&path).file_name() {
            return filename.to_string_lossy().to_string();
        }
        path
    } else {
        format!("PID_{}", pid)
    }
}

#[cfg(not(windows))]
pub fn get_process_name(pid: u32) -> String {
    format!("PID_{}", pid)
}

#[cfg(windows)]
pub fn enumerate_suspicious_regions(pid: u32, config: &AgentConfig) -> Result<Vec<MemoryRegion>, String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, MEM_MAPPED};
    use windows_sys::Win32::System::Memory::{PAGE_NOACCESS, PAGE_GUARD};
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE};
    use windows_sys::Win32::Foundation::CloseHandle;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!("Failed to open process {} for query: {}", pid, std::io::Error::last_os_error()));
    }

    let mut regions = Vec::new();
    let mut address = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mbi_size = size_of::<MEMORY_BASIC_INFORMATION>();

    let max_size = config.memory_scanner.max_region_size_mb * 1024 * 1024;

    while unsafe { VirtualQueryEx(handle, address as *const _, &mut mbi, mbi_size) } == mbi_size {
        let size = mbi.RegionSize as u64;
        let protect = mbi.Protect;
        let state = mbi.State;
        let type_ = mbi.Type;

        // Skip non-committed memory and guard pages
        if state == MEM_COMMIT && (protect & PAGE_NOACCESS) == 0 && (protect & PAGE_GUARD) == 0 {
            // Suspicious page characteristics:
            // 1. Executable-Read-Write (PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY)
            // 2. Private executable pages (MEM_PRIVATE + PAGE_EXECUTE_READ / PAGE_EXECUTE) - classic hollowed / injected payload code path
            let is_rwx = (protect & PAGE_EXECUTE_READWRITE) != 0 || (protect & PAGE_EXECUTE_WRITECOPY) != 0;
            let is_private_exec = type_ == MEM_PRIVATE && ((protect & PAGE_EXECUTE_READ) != 0 || (protect & PAGE_EXECUTE) != 0);
            
            // Or unbacked mapped code (MEM_MAPPED executable)
            let is_mapped_exec = type_ == MEM_MAPPED && ((protect & PAGE_EXECUTE_READ) != 0 || (protect & PAGE_EXECUTE_READWRITE) != 0);

            if (is_rwx || is_private_exec || is_mapped_exec) && size <= max_size {
                regions.push(MemoryRegion {
                    base_address: mbi.BaseAddress as u64,
                    region_size: size,
                    protection: protect,
                    state,
                    type_,
                });
            }
        }

        address = (mbi.BaseAddress as usize) + mbi.RegionSize;
    }

    unsafe { CloseHandle(handle) };
    Ok(regions)
}

#[cfg(not(windows))]
pub fn enumerate_suspicious_regions(_pid: u32, _config: &AgentConfig) -> Result<Vec<MemoryRegion>, String> {
    Ok(Vec::new())
}

#[cfg(windows)]
pub fn read_region(pid: u32, region: &MemoryRegion) -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::Foundation::CloseHandle;

    let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u8; region.region_size as usize];
    let mut bytes_read = 0;
    
    let success = unsafe {
        ReadProcessMemory(
            handle,
            region.base_address as *const _,
            buffer.as_mut_ptr() as *mut _,
            region.region_size as usize,
            &mut bytes_read
        )
    };

    unsafe { CloseHandle(handle) };

    if success != 0 && bytes_read > 0 {
        if bytes_read < buffer.len() {
            buffer.truncate(bytes_read);
        }
        Some(buffer)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn read_region(_pid: u32, _region: &MemoryRegion) -> Option<Vec<u8>> {
    None
}

pub async fn scan_process(pid: u32, config: &AgentConfig) -> Vec<MemoryScanResult> {
    if !config.memory_scanner.enabled {
        return Vec::new();
    }

    // Cooldown check
    {
        let mut cooldowns = get_scan_cooldown().lock().unwrap();
        if let Some(&last_scan) = cooldowns.get(&pid) {
            if last_scan.elapsed() < Duration::from_secs(config.memory_scanner.cooldown_secs) {
                debug!("Skip memory scan for PID {} (cooldown)", pid);
                return Vec::new();
            }
        }
        cooldowns.insert(pid, Instant::now());
    }

    let process_name = get_process_name(pid);

    // Skip excluded process names
    if config.memory_scanner.excluded_process_names.iter().any(|name| name.eq_ignore_ascii_case(&process_name)) {
        debug!("Skip memory scan for excluded process: {}", process_name);
        return Vec::new();
    }

    info!("Starting memory scan for process {} (PID {})", process_name, pid);

    let regions = match enumerate_suspicious_regions(pid, config) {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to enumerate memory regions for PID {}: {}", pid, e);
            return Vec::new();
        }
    };

    if regions.is_empty() {
        debug!("No suspicious memory regions found in PID {}", pid);
        return Vec::new();
    }

    debug!("Found {} suspicious memory regions in PID {}", regions.len(), pid);
    let mut results = Vec::new();

    let client = reqwest::Client::new();
    let scan_url = format!("{}/api/scan/memory", config.scanner.api_url);

    for region in regions {
        if let Some(bytes) = read_region(pid, &region) {
            let base64_data = BASE64.encode(&bytes);
            let req_body = MemoryScanRequest {
                process_id: pid,
                process_name: process_name.clone(),
                region_base: region.base_address,
                region_size: region.region_size,
                protection: region.protection,
                data: base64_data,
            };

            match client.post(&scan_url)
                .json(&req_body)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(scan_res) = resp.json::<MemoryScanResult>().await {
                            if scan_res.verdict != "clean" {
                                results.push(scan_res);
                            }
                        }
                    } else {
                        warn!("Scanner returned status {} for memory scan of PID {}", resp.status(), pid);
                    }
                }
                Err(e) => {
                    error!("Failed to send memory scan request to scanner for PID {}: {}", pid, e);
                }
            }
        }
    }

    results
}
