//! System restore feature: product key gating and snapshot management.
//!
//! The restore subsystem uses HMAC-SHA256 for driver activation.
//! The kernel driver has an embedded HMAC key; the license payload
//! contains the same key in `restore_activation_key_hex`.  The agent
//! reads the license, extracts the key, computes
//! HMAC-SHA256(payload_bytes, key), and sends it to the driver.
//! After successful activation, the driver gates all restore IOCTLs
//! behind the `RestoreActivated` flag.

#![allow(unsafe_code)]

pub mod vss;
pub mod scheduler;
pub mod boot_revert;

use std::io::Result;

use monolith_shared::license;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use crate::driver::{ioctl, DriverHandle};

type HmacSha256 = Hmac<Sha256>;

fn send_ioctl(handle: windows_sys::Win32::Foundation::HANDLE, code: u32, input: Option<&[u8]>) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
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
    if result == windows_sys::Win32::Foundation::FALSE {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Activate the restore feature with the driver.
pub fn activate_restore(handle: &DriverHandle) -> Result<bool> {
    let bundle = match license::find_license_file() {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::info!("no license found — restore activation skipped");
            return Ok(false);
        }
        Err(e) => {
            tracing::warn!("failed to parse license: {}", e);
            return Ok(false);
        }
    };

    if !bundle.has_feature("system_restore") {
        tracing::info!("license does not include system_restore feature");
        return Ok(false);
    }

    let license_content = match std::fs::read_to_string("configs/license.lic")
        .or_else(|_| std::fs::read_to_string("../configs/license.lic"))
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read license file: {}", e);
            return Ok(false);
        }
    };

    let payload_bytes = match decode_license_payload(&license_content) {
        Some(b) => b,
        None => {
            tracing::warn!("cannot decode license payload");
            return Ok(false);
        }
    };

    let payload_json: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("invalid license payload JSON: {}", e);
            return Ok(false);
        }
    };

    let hmac_key_hex = match payload_json.get("restore_activation_key_hex")
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => {
            tracing::warn!("license payload missing restore_activation_key_hex");
            return Ok(false);
        }
    };

    let hmac_key = match hex::decode(hmac_key_hex) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("invalid hex in restore_activation_key_hex: {}", e);
            return Ok(false);
        }
    };

    let mut mac = match HmacSha256::new_from_slice(&hmac_key) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("HMAC init failed: {}", e);
            return Ok(false);
        }
    };
    mac.update(&payload_bytes);
    let hmac_result = mac.finalize().into_bytes();

    let mut input = Vec::with_capacity(4 + payload_bytes.len() + 4 + 32);
    input.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
    input.extend_from_slice(&payload_bytes);
    input.extend_from_slice(&32u32.to_le_bytes());
    input.extend_from_slice(&hmac_result);

    let drv_handle = handle.as_raw_handle();
    match send_ioctl(drv_handle, ioctl::IOCTL_EDR_RESTORE_ACTIVATE, Some(&input)) {
        Ok(_) => {
            tracing::info!("restore feature activated with driver");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("restore activation IOCTL failed: {}", e);
            Ok(false)
        }
    }
}

/// Claim a partition for snapshot storage.
pub fn claim_partition(handle: &DriverHandle, drive_number: u32, partition_number: u32) -> Result<bool> {
    let drv_handle = handle.as_raw_handle();

    #[repr(C, packed)]
    struct ClaimInput {
        physical_drive_number: u32,
        partition_number: u32,
    }

    let input = ClaimInput {
        physical_drive_number: drive_number,
        partition_number,
    };
    let input_bytes = unsafe {
        let input_ptr: *const u8 = std::ptr::from_ref(&input).cast();
        std::slice::from_raw_parts(input_ptr, std::mem::size_of::<ClaimInput>())
    };

    match send_ioctl(drv_handle, ioctl::IOCTL_EDR_RESTORE_CLAIM_PARTITION, Some(input_bytes)) {
        Ok(_) => {
            tracing::info!("claimed partition {}/{}", drive_number, partition_number);
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("partition claim IOCTL failed: {}", e);
            Ok(false)
        }
    }
}

/// Query restore status from the driver.
pub fn restore_status(handle: &DriverHandle) -> Result<Option<bool>> {
    let drv_handle = handle.as_raw_handle();
    let mut output = [0u8; 4 + 32 + 128 + 8];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            drv_handle,
            ioctl::IOCTL_EDR_RESTORE_STATUS,
            std::ptr::null(),
            0,
            output.as_mut_ptr() as _,
            output.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if result == windows_sys::Win32::Foundation::FALSE {
        return Err(std::io::Error::last_os_error());
    }

    Ok(Some(output[0] != 0))
}

/// Deactivate restore feature.
#[allow(dead_code)]
pub fn deactivate_restore(handle: &DriverHandle) -> Result<bool> {
    let drv_handle = handle.as_raw_handle();
    match send_ioctl(drv_handle, ioctl::IOCTL_EDR_RESTORE_DEACTIVATE, None) {
        Ok(_) => {
            tracing::info!("restore feature deactivated");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("restore deactivation failed: {}", e);
            Ok(false)
        }
    }
}

fn decode_license_payload(content: &str) -> Option<Vec<u8>> {
    const LICENSE_BEGIN: &str = "-----BEGIN EDR LICENSE v1-----";
    const LICENSE_END: &str = "-----END EDR LICENSE v1-----";

    let stripped: String = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| *l != LICENSE_BEGIN && *l != LICENSE_END && !l.is_empty())
        .collect();

    let parts: Vec<&str> = stripped.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(parts[0]).ok()
}
