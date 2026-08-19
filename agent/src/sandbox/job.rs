#![allow(unsafe_code)]

use monolith_shared::error::{EdrError, Result};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

pub struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    pub fn new(name: Option<&str>) -> Result<Self> {
        let name_wide = name.map(|n| {
            let encoded: Vec<u16> = std::ffi::OsStr::new(n)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            encoded
        });
        let name_ptr = name_wide.as_ref().map(|v| v.as_ptr()).unwrap_or(null());
        let handle = unsafe { CreateJobObjectW(null(), name_ptr) };
        if handle.is_null() {
            return Err(EdrError::WindowsError("CreateJobObjectW failed".into()));
        }
        Ok(Self { handle })
    }

    pub fn set_limits(
        &self,
        memory_limit_mb: u64,
        timeout_ms: u64,
        max_processes: u32,
    ) -> Result<()> {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        {
            let basic = &mut info.BasicLimitInformation;
            basic.PerProcessUserTimeLimit = 0;
            basic.PerJobUserTimeLimit = (timeout_ms * 10000) as i64;
            basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_TIME
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            basic.MinimumWorkingSetSize = 0;
            basic.MaximumWorkingSetSize = 0;
            basic.ActiveProcessLimit = max_processes;
            basic.Affinity = 0;
        }

        info.ProcessMemoryLimit = (memory_limit_mb * 1024 * 1024) as usize;
        info.JobMemoryLimit = (memory_limit_mb * 1024 * 1024 * 2) as usize;

        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info) as *const std::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if result == 0 {
            return Err(EdrError::WindowsError(
                "SetInformationJobObject failed".into(),
            ));
        }
        Ok(())
    }

    pub fn assign_process(&self, process_handle: HANDLE) -> Result<()> {
        let result = unsafe { AssignProcessToJobObject(self.handle, process_handle) };
        if result == 0 {
            return Err(EdrError::WindowsError(
                "AssignProcessToJobObject failed".into(),
            ));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
