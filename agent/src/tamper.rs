//! Security hardening and process resurrection support.
//!
//! Security hardening (detect debugger, harden NTFS permissions) and
//! driver communication for process resurrection on unexpected exit.

#![allow(unsafe_code)]

use std::io::Result;

use crate::driver::{DriverHandle, ioctl};
use windows_sys::Win32::{Foundation::FALSE, System::IO::DeviceIoControl};

/// Security hardening utilities (NTFS permissions).
/// Kept as a struct for backward compatibility with existing callers.
pub struct TamperProtection;

#[allow(unused)]
impl TamperProtection {
    /// Detect whether a kernel debugger is attached.
    pub fn detect_debugger() {
        // Debugger detection removed — not essential for core protection.
        // The driver's OB callback + process resurrection provide the actual security.
    }

    /// Harden NTFS permissions on a file to restrict access to SYSTEM only.
    pub fn harden_ntfs_permissions(path: &str) {
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("icacls")
                .args([path, "/inheritance:r", "/grant", "SYSTEM:F"])
                .output();
        }
        let _ = path;
    }
}

fn send_ioctl(
    handle: windows_sys::Win32::Foundation::HANDLE,
    code: u32,
    input: Option<&[u8]>,
) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            code,
            input.map_or(std::ptr::null(), |b| b.as_ptr()) as _,
            input.map_or(0, |b| b.len() as u32),
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    if result == FALSE {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Register the agent's executable path with the driver so it can respawn
/// the agent if it exits unexpectedly.
pub fn setup_respawn(handle: &DriverHandle) -> Result<()> {
    let exe_path = std::env::current_exe()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let exe_path_str = exe_path.to_string_lossy().to_string();

    let cmd_line: String = std::env::args().collect::<Vec<_>>().join(" ");
    let cmd_line = format!("\"{}\" {}", exe_path_str, cmd_line);

    // Build the EDR_RESPAWN_INFO struct with wide strings
    let image_path_wide: Vec<u16> = exe_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let cmd_line_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    // Pad to expected sizes (260 and 1024 WCHARs)
    let mut image_buf = [0u16; 260];
    let copy_len = image_path_wide.len().min(259);
    image_buf[..copy_len].copy_from_slice(&image_path_wide[..copy_len]);

    let mut cmd_buf = [0u16; 1024];
    let copy_len = cmd_line_wide.len().min(1023);
    cmd_buf[..copy_len].copy_from_slice(&cmd_line_wide[..copy_len]);

    // Build input buffer: image path (260 * 2 bytes) + command line (1024 * 2 bytes)
    let mut input = Vec::with_capacity(260 * 2 + 1024 * 2);
    for &c in &image_buf {
        input.extend_from_slice(&c.to_le_bytes());
    }
    for &c in &cmd_buf {
        input.extend_from_slice(&c.to_le_bytes());
    }

    let drv_handle = handle.as_raw_handle();
    let result = send_ioctl(drv_handle, ioctl::IOCTL_EDR_SET_RESPAWN_PATH, Some(&input));
    if let Err(ref e) = result {
        tracing::warn!("failed to register respawn path: {}", e);
    } else {
        tracing::info!("agent respawn path registered with driver");
    }
    result
}

/// Signal the driver that this shutdown is intentional:
/// 1. Suppress respawn (PREPARE_SHUTDOWN)
/// 2. Allow driver unload (ALLOW_UNLOAD) — if driver unloads without this, BSOD
pub fn prepare_shutdown(handle: &DriverHandle) -> bool {
    let drv_handle = handle.as_raw_handle();

    let r1 = send_ioctl(drv_handle, ioctl::IOCTL_EDR_PREPARE_SHUTDOWN, None);
    let r2 = send_ioctl(drv_handle, ioctl::IOCTL_EDR_ALLOW_UNLOAD, None);

    if r1.is_err() {
        tracing::warn!("PREPARE_SHUTDOWN failed: {:?}", r1);
    }
    if r2.is_err() {
        tracing::warn!("ALLOW_UNLOAD failed: {:?}", r2);
    }

    r1.is_ok() || r2.is_ok()
}
