#![allow(unsafe_code)]

use monolith_shared::error::{EdrError, Result};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CreateProcessAsUserW, GetCurrentProcess,
    OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
};

pub struct RestrictedToken {
    handle: HANDLE,
}

impl RestrictedToken {
    pub fn new() -> Result<Self> {
        let mut token_handle: HANDLE = null_mut();
        let result = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
                &mut token_handle,
            )
        };
        if result == 0 {
            return Err(EdrError::WindowsError("OpenProcessToken failed".into()));
        }

        let mut restricted: HANDLE = null_mut();
        let result = unsafe {
            CreateRestrictedToken(
                token_handle,
                0,
                0,
                null_mut(),
                0,
                null_mut(),
                0,
                null_mut(),
                &mut restricted,
            )
        };
        unsafe { CloseHandle(token_handle) };
        if result == 0 {
            return Err(EdrError::WindowsError(
                "CreateRestrictedToken failed".into(),
            ));
        }

        Ok(Self { handle: restricted })
    }

    #[allow(dead_code)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn create_process(&self, cmd: &str) -> Result<(HANDLE, u32)> {
        let mut pi = PROCESS_INFORMATION {
            hProcess: null_mut(),
            hThread: null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
        };
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = size_of::<STARTUPINFOW>() as u32;

        let cmd_wide: Vec<u16> = std::ffi::OsStr::new(cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let result = unsafe {
            CreateProcessAsUserW(
                self.handle,
                null_mut(),
                cmd_wide.as_ptr() as *mut u16,
                null_mut(),
                null_mut(),
                FALSE,
                CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                null_mut(),
                null_mut(),
                &si,
                &mut pi,
            )
        };
        if result == 0 {
            return Err(EdrError::WindowsError("CreateProcessAsUserW failed".into()));
        }

        Ok((pi.hProcess, pi.dwProcessId))
    }
}

impl Drop for RestrictedToken {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}
