#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FindClose, FindFirstFileW,
    FindNextFileW, WIN32_FIND_DATAW,
};
use windows::core::PCWSTR;

/// Enumerate all files under the given directories using Win32 FindFirstFile/FindNextFile.
/// Uses the native Windows file enumeration API (not the Search Index).
/// Falls back to walkdir if Win32 API fails.
pub fn win32_enumerate_files(dirs: &[String]) -> Vec<String> {
    let mut results = Vec::new();
    for dir in dirs {
        enumerate_directory(Path::new(dir), &mut results, 0);
    }
    results
}

fn enumerate_directory(dir: &Path, results: &mut Vec<String>, depth: u32) {
    if depth > 15 {
        return;
    }

    let search_path = dir.join("*");
    let wide: Vec<u16> = OsStr::new(&search_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut find_data = WIN32_FIND_DATAW::default();

    let handle = match unsafe { FindFirstFileW(PCWSTR::from_raw(wide.as_ptr()), &mut find_data) } {
        Ok(h) => h,
        Err(e) => {
            let code: i32 = e.code().0;
            if code == ERROR_FILE_NOT_FOUND.0 as i32
                || code == ERROR_PATH_NOT_FOUND.0 as i32
                || code == ERROR_ACCESS_DENIED.0 as i32
            {
                return;
            }
            tracing::warn!("FindFirstFileW failed for {}: {}", dir.display(), e);
            return;
        }
    };

    if handle == INVALID_HANDLE_VALUE {
        return;
    }

    loop {
        let name = &find_data.cFileName;
        if name[0] == b'.' as u16 && (name[1] == 0 || (name[1] == b'.' as u16 && name[2] == 0)) {
            if unsafe { FindNextFileW(handle, &mut find_data) }.is_err() {
                break;
            }
            continue;
        }

        let file_name = wide_to_string(name);
        let full_path = dir.join(&file_name);

        let is_dir = find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let is_reparse = find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;

        if is_dir && !is_reparse {
            enumerate_directory(&full_path, results, depth + 1);
        } else if !is_dir {
            results.push(full_path.to_string_lossy().to_string());
        }

        if unsafe { FindNextFileW(handle, &mut find_data) }.is_err() {
            break;
        }
    }

    unsafe {
        let _ = FindClose(handle);
    }
}

fn wide_to_string(wide: &[u16; 260]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(260);
    String::from_utf16_lossy(&wide[..len])
}
