#![allow(unsafe_code)]
#![allow(missing_docs)]

use monolith_shared::error::{EdrError, Result};

pub struct DriverCommunicator {
    device_path: String,
    buffer_size: u32,
}

impl DriverCommunicator {
    pub fn new(device_path: &str, buffer_size: u32) -> Self {
        Self {
            device_path: device_path.to_string(),
            buffer_size,
        }
    }

    pub fn open_device(&self) -> Result<DriverHandle> {
        tracing::info!("opening driver device: {}", self.device_path);

        #[cfg(windows)]
        {
            use std::ffi::CString;
            use windows_sys::Win32::Foundation::GENERIC_READ;
            use windows_sys::Win32::Foundation::GENERIC_WRITE;
            use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
            use windows_sys::Win32::Storage::FileSystem::CreateFileA;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
            use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;

            let path = CString::new(self.device_path.as_str())
                .map_err(|_| EdrError::DriverError("invalid device path".into()))?;

            let handle = unsafe {
                CreateFileA(
                    path.as_ptr() as *const u8,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };

            if handle == INVALID_HANDLE_VALUE {
                return Err(EdrError::DriverError(
                    "failed to open driver device - driver may not be loaded".into(),
                ));
            }

            tracing::info!("driver device opened successfully");
            Ok(DriverHandle { handle })
        }

        #[cfg(not(windows))]
        {
            // Non-Windows stub for testing
            tracing::warn!("driver communication not supported on this platform");
            Err(EdrError::DriverNotLoaded)
        }
    }

    pub fn register_agent(&self, handle: &DriverHandle, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::FALSE;
            use windows_sys::Win32::System::IO::DeviceIoControl;

            let ioctl_code = ioctl::IOCTL_EDR_REGISTER_AGENT;
            let mut bytes_returned: u32 = 0;

            let result = unsafe {
                DeviceIoControl(
                    handle.handle,
                    ioctl_code,
                    std::ptr::from_ref(&pid) as _,
                    size_of::<u32>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == FALSE {
                return Err(EdrError::DriverError(
                    "IOCTL agent registration failed".into(),
                ));
            }

            tracing::info!("agent successfully registered to driver with PID {}", pid);
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = pid;
            let _ = handle;
            Ok(())
        }
    }

    pub fn read_telemetry(&self, handle: &DriverHandle) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::FALSE;
            use windows_sys::Win32::System::IO::DeviceIoControl;

            let mut buffer = vec![0u8; self.buffer_size as usize];
            let mut bytes_returned: u32 = 0;

            let ioctl_code = ioctl::IOCTL_EDR_GET_EVENTS;

            let result = unsafe {
                DeviceIoControl(
                    handle.handle,
                    ioctl_code,
                    std::ptr::null(),
                    0,
                    buffer.as_mut_ptr() as _,
                    buffer.len() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == FALSE {
                return Err(EdrError::DriverError("IOCTL read failed".into()));
            }

            buffer.truncate(bytes_returned as usize);
            Ok(buffer)
        }

        #[cfg(not(windows))]
        {
            Err(EdrError::DriverNotLoaded)
        }
    }

    pub fn scan_process_memory(&self, handle: &DriverHandle, pid: u32) -> Result<u32> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::FALSE;
            use windows_sys::Win32::System::IO::DeviceIoControl;

            let ioctl_code = ioctl::IOCTL_EDR_SCAN_PROCESS_MEMORY;
            let mut bytes_returned: u32 = 0;
            let mut output: u32 = 0;

            let result = unsafe {
                DeviceIoControl(
                    handle.handle,
                    ioctl_code,
                    std::ptr::from_ref(&pid) as _,
                    size_of::<u32>() as u32,
                    std::ptr::from_mut(&mut output) as _,
                    size_of::<u32>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == FALSE {
                return Err(EdrError::DriverError("IOCTL memory scan failed".into()));
            }

            tracing::info!(
                "driver scan_process_memory: PID={}, suspicious={}",
                pid,
                output
            );
            Ok(output)
        }

        #[cfg(not(windows))]
        {
            let _ = pid;
            let _ = handle;
            Ok(0)
        }
    }

    pub fn get_driver_stats(&self, handle: &DriverHandle) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::FALSE;
            use windows_sys::Win32::System::IO::DeviceIoControl;

            let mut buffer = vec![0u8; 256];
            let mut bytes_returned: u32 = 0;

            let ioctl_code = ioctl::IOCTL_EDR_GET_STATS;

            let result = unsafe {
                DeviceIoControl(
                    handle.handle,
                    ioctl_code,
                    std::ptr::null(),
                    0,
                    buffer.as_mut_ptr() as _,
                    buffer.len() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == FALSE {
                return Err(EdrError::DriverError("IOCTL stats read failed".into()));
            }

            buffer.truncate(bytes_returned as usize);
            Ok(buffer)
        }

        #[cfg(not(windows))]
        {
            Err(EdrError::DriverNotLoaded)
        }
    }
}

pub struct DriverHandle {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl DriverHandle {
    /// Get the raw Windows HANDLE for direct DeviceIoControl calls.
    #[cfg(windows)]
    pub fn as_raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle
    }
}

unsafe impl Send for DriverHandle {}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

pub mod ioctl;
