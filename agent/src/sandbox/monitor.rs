#![allow(unsafe_code)]

use monolith_shared::error::{EdrError, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION, WaitForSingleObject,
    PROCESS_TERMINATE, TerminateProcess,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use crate::sandbox::report::SandboxReport;

pub struct SandboxMonitor {
    processes: HashMap<u32, (HANDLE, String)>,
    running: AtomicBool,
    timeout_ms: u64,
    start_time: Instant,
}

impl SandboxMonitor {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            processes: HashMap::new(),
            running: AtomicBool::new(true),
            timeout_ms,
            start_time: Instant::now(),
        }
    }

    pub fn add_process(&mut self, pid: u32, name: String) -> Result<()> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(EdrError::WindowsError(
                format!("OpenProcess failed for pid {}", pid),
            ));
        }
        self.processes.insert(pid, (handle, name));
        Ok(())
    }

    pub fn run(&self) -> SandboxReport {
        let mut report = SandboxReport::new();

        loop {
            if !self.running.load(Ordering::Relaxed) {
                report.terminated_by = "manual".into();
                break;
            }

            if self.start_time.elapsed().as_millis() as u64 >= self.timeout_ms {
                report.timed_out = true;
                self.terminate_all();
                break;
            }

            let mut all_exited = true;
            for (pid, (handle, name)) in &self.processes {
                let result = unsafe { WaitForSingleObject(*handle, 0) };
                if result == WAIT_TIMEOUT {
                    all_exited = false;
                } else {
                    let mut exit_code: u32 = 0;
                    unsafe { GetExitCodeProcess(*handle, &mut exit_code) };
                    report.record_exit(*pid, name.clone(), exit_code as i32);
                }
            }

            if all_exited {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        report.duration_ms = self.start_time.elapsed().as_millis() as u64;
        report
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.terminate_all();
    }

    fn terminate_all(&self) {
        for (_, (handle, _)) in &self.processes {
            unsafe { TerminateProcess(*handle, 1) };
            unsafe { CloseHandle(*handle) };
        }
    }
}

impl Drop for SandboxMonitor {
    fn drop(&mut self) {
        for (_, (handle, _)) in &self.processes {
            unsafe { CloseHandle(*handle) };
        }
    }
}
