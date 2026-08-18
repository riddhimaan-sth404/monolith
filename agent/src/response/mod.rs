#![allow(unsafe_code)]
#![allow(missing_docs)]

use monolith_shared::error::Result;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub struct ResponseHandler;

impl ResponseHandler {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute_action(&self, action_type: &str, params: &serde_json::Value) -> Result<ActionResponse> {
        tracing::info!("executing response action: {}", action_type);

        match action_type {
            "terminate_process" => self.terminate_process(params).await,
            "quarantine_file" => self.quarantine_file(params).await,
            "restore_quarantine" => self.restore_quarantine(params).await,
            "delete_quarantine" => self.delete_quarantine(params).await,
            "isolate_endpoint" => self.isolate_endpoint().await,
            "release_isolation" => self.release_isolation().await,
            "restart_agent" => self.restart_agent().await,
            "trigger_quick_scan" => self.trigger_scan("quick").await,
            "trigger_full_scan" => self.trigger_scan("full").await,
            "collect_diagnostics" => self.collect_diagnostics().await,
            "run_sandbox" => self.run_sandbox(params).await,
            "update_policy" => self.update_policy(params).await,
            "scan_process_memory" => self.scan_process_memory(params).await,
            "shred_file" => self.shred_file(params).await,
            _ => Err(monolith_shared::error::EdrError::InvalidInput(
                format!("unknown action type: {}", action_type),
            )),
        }
    }

    async fn terminate_process(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let pid = params.get("pid").and_then(|v| v.as_u64())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("pid required".into()))?;

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
            use windows_sys::Win32::Foundation::{CloseHandle, FALSE};

            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid as u32);
                if handle.is_null() {
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to open process {} (access denied or not found)", pid),
                    });
                }
                let result = TerminateProcess(handle, 1);
                CloseHandle(handle);
                if result == 0 {
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to terminate process {}", pid),
                    });
                }
            }
        }

        Ok(ActionResponse {
            success: true,
            message: format!("process {} terminated", pid),
        })
    }

    async fn quarantine_file(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("path required".into()))?;

        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};

            let src_path = std::path::Path::new(path);
            let quarantine_dir = get_quarantine_dir();
            std::fs::create_dir_all(&quarantine_dir).ok();

            let file_name = src_path.file_name().unwrap_or(OsStr::new("unknown"));
            let dest = quarantine_dir.join(file_name);
            let dest_str = dest.to_string_lossy();

            let src_wide: Vec<u16> = OsStr::new(path).encode_wide().chain([0]).collect();
            let dest_wide: Vec<u16> = OsStr::new(dest_str.as_ref()).encode_wide().chain([0]).collect();

            unsafe {
                if MoveFileExW(src_wide.as_ptr(), dest_wide.as_ptr(), MOVEFILE_REPLACE_EXISTING) == 0 {
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to move file to quarantine: {}", path),
                    });
                }
            }

            // Write metadata
            let meta_path = dest.with_extension("meta");
            if let Ok(meta) = serde_json::to_string_pretty(&serde_json::json!({
                "original_path": path,
                "quarantined_at": chrono::Utc::now().to_rfc3339(),
                "file_name": file_name.to_string_lossy(),
            })) {
                std::fs::write(&meta_path, meta).ok();
            }

            return Ok(ActionResponse {
                success: true,
                message: format!("file quarantined: {} -> {}", path, dest_str),
            });
        }

        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(ActionResponse {
                success: true,
                message: format!("file quarantined: {}", path),
            })
        }
    }

    fn sanitize_quarantine_id(id: &str) -> Result<String> {
        if id.contains("..") || id.contains('/') || id.contains('\\') || id.contains('\0') {
            return Err(monolith_shared::error::EdrError::ValidationError(
                "invalid quarantine_id: path traversal detected".into(),
            ));
        }
        Ok(id.to_string())
    }

    async fn restore_quarantine(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let quarantine_id_raw = params.get("quarantine_id").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("quarantine_id required".into()))?;
        let quarantine_id = Self::sanitize_quarantine_id(quarantine_id_raw)?;

        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

            let quarantine_dir = get_quarantine_dir();
            let src = quarantine_dir.join(&quarantine_id);
            if !src.exists() {
                return Ok(ActionResponse {
                    success: false,
                    message: format!("quarantined file not found: {}", quarantine_id),
                });
            }

            let meta_path = src.with_extension("meta");
            let original_path = if meta_path.exists() {
                std::fs::read_to_string(&meta_path).unwrap_or_default()
            } else {
                String::new()
            };

            let original_path_parsed: String = serde_json::from_str::<serde_json::Value>(&original_path)
                .ok()
                .and_then(|v| v.get("original_path").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_default();

            let dest = if original_path_parsed.is_empty() {
                quarantine_dir.join(format!("restored_{}", quarantine_id))
            } else {
                PathBuf::from(&original_path_parsed)
            };

            let src_wide: Vec<u16> = OsStr::new(&src.to_string_lossy().as_ref()).encode_wide().chain([0]).collect();
            let dest_wide: Vec<u16> = OsStr::new(&dest.to_string_lossy().as_ref()).encode_wide().chain([0]).collect();

            unsafe {
                if MoveFileExW(src_wide.as_ptr(), dest_wide.as_ptr(), 0) == 0 {
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to restore file from quarantine: {}", quarantine_id),
                    });
                }
            }

            return Ok(ActionResponse {
                success: true,
                message: format!("quarantine restored to: {}", dest.display()),
            });
        }

        #[cfg(not(windows))]
        Ok(ActionResponse {
            success: true,
            message: format!("quarantine restored: {}", quarantine_id),
        })
    }

    async fn delete_quarantine(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let quarantine_id_raw = params.get("quarantine_id").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("quarantine_id required".into()))?;
        let quarantine_id = Self::sanitize_quarantine_id(quarantine_id_raw)?;

        let quarantine_dir = get_quarantine_dir();
        let path = quarantine_dir.join(&quarantine_id);
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
        let meta = path.with_extension("meta");
        if meta.exists() {
            std::fs::remove_file(&meta).ok();
        }

        Ok(ActionResponse {
            success: true,
            message: format!("quarantine deleted: {}", quarantine_id),
        })
    }

    async fn isolate_endpoint(&self) -> Result<ActionResponse> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // Block all outbound traffic via Windows Firewall
            let add = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    "name=EDR_Isolation",
                    "dir=out",
                    "action=block",
                    "remoteip=any",
                    "description=EDR endpoint isolation - blocks all outbound traffic",
                    "enable=yes",
                    "profile=any",
                ])
                .output();

            match add {
                Ok(o) if o.status.success() => {
                    tracing::info!("isolation firewall rule added");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!("failed to add isolation rule: {}", stderr);
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to add firewall rule: {}", stderr),
                    });
                }
                Err(e) => {
                    tracing::warn!("failed to run netsh: {}", e);
                    return Ok(ActionResponse {
                        success: false,
                        message: format!("failed to run netsh: {}", e),
                    });
                }
            }
        }

        Ok(ActionResponse {
            success: true,
            message: "endpoint isolated via firewall rules".to_string(),
        })
    }

    async fn release_isolation(&self) -> Result<ActionResponse> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let delete = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=EDR_Isolation"])
                .output();

            match delete {
                Ok(o) => tracing::info!(
                    "isolation released: {}",
                    String::from_utf8_lossy(&o.stdout).trim()
                ),
                Err(e) => tracing::warn!("failed to release isolation: {}", e),
            }
        }

        Ok(ActionResponse {
            success: true,
            message: "isolation released".to_string(),
        })
    }

    async fn restart_agent(&self) -> Result<ActionResponse> {
        tracing::info!("restarting agent");

        // Schedule restart via sc (service control)
        let _config_path = std::env::current_exe().unwrap_or_default();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            #[cfg(windows)]
            {
                use std::process::Command;

                // Try to restart via SC first, fallback to direct exec
                let result = Command::new("sc")
                    .args(["stop", "MonolithAgent"])
                    .output();
                if let Ok(o) = result {
                    tracing::info!("sc stop output: {}", String::from_utf8_lossy(&o.stdout));
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                let result = Command::new("sc")
                    .args(["start", "MonolithAgent"])
                    .output();
                if let Ok(o) = result {
                    tracing::info!("sc start output: {}", String::from_utf8_lossy(&o.stdout));
                }
            }
        });

        Ok(ActionResponse {
            success: true,
            message: "agent restart scheduled".to_string(),
        })
    }

    async fn trigger_scan(&self, scan_type: &str) -> Result<ActionResponse> {
        tracing::info!("triggering {} scan", scan_type);

        #[cfg(windows)]
        {
            use std::process::Command;
            // Start scanner service
            let result = Command::new("sc")
                .args(["start", "MonolithScanner"])
                .output();
            if let Ok(o) = result {
                tracing::info!("scanner start: {}", String::from_utf8_lossy(&o.stdout));
            }
        }

        Ok(ActionResponse {
            success: true,
            message: format!("{} scan triggered", scan_type),
        })
    }

    async fn collect_diagnostics(&self) -> Result<ActionResponse> {
        tracing::info!("collecting diagnostics");

        let output_dir = get_diagnostics_dir();
        std::fs::create_dir_all(&output_dir).ok();

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

        // Collect agent logs
        let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let log_dir = std::path::Path::new(&program_data).join("EDR").join("logs");
        if log_dir.exists() {
            let dest = output_dir.join(format!("logs_{}", timestamp));
            let _ = copy_dir_recursive(&log_dir, &dest);
        }

        // Collect config
        let config_paths = [
            std::path::Path::new(&program_data).join("EDR").join("config.toml"),
            std::path::Path::new(&program_data).join("EDR").join("config.yaml"),
        ];
        for cfg_path in &config_paths {
            if cfg_path.exists() {
                let fname = cfg_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let dest = output_dir.join(format!("config_{}", fname));
                let _ = std::fs::copy(cfg_path, &dest);
            }
        }

        // Collect system info
        let sysinfo_path = output_dir.join(format!("sysinfo_{}.json", timestamp));
        if let Ok(info) = collect_system_info_json() {
            let _ = std::fs::write(&sysinfo_path, info);
        }

        Ok(ActionResponse {
            success: true,
            message: format!("diagnostics collected to: {}", output_dir.display()),
        })
    }

    async fn update_policy(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let policy_content = params.get("policy").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("policy content required".into()))?;

        let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let policy_path = std::path::Path::new(&program_data).join("EDR").join("policy.json");
        let parent = policy_path.parent().unwrap();
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::write(&policy_path, policy_content);

        tracing::info!("policy updated and saved");

        Ok(ActionResponse {
            success: true,
            message: format!("policy updated: {} bytes", policy_content.len()),
        })
    }

    async fn run_sandbox(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("path required".into()))?;
        let timeout_ms = params.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(30000);

        tracing::info!("running sandbox on: {}", path);

        let job = crate::sandbox::JobObject::new(Some("EDR_Sandbox"))?;
        job.set_limits(256, timeout_ms, 3)?;

        let token = crate::sandbox::RestrictedToken::new()?;
        let (proc_handle, pid) = token.create_process(path)?;
        job.assign_process(proc_handle)?;

        let mut monitor = crate::sandbox::SandboxMonitor::new(timeout_ms);
        let _ = monitor.add_process(pid, path.to_string());

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::ResumeThread;
            unsafe { ResumeThread(proc_handle) };
        }

        let report = monitor.run();
        let report_json = serde_json::to_string(&report).unwrap_or_default();

        tracing::info!("sandbox result: score={} verdict={}", report.score(), report.verdict());

        Ok(ActionResponse {
            success: true,
            message: format!("sandbox completed: score={} verdict={} report={}", report.score(), report.verdict(), report_json),
        })
    }

    async fn scan_process_memory(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let pid = params.get("pid").and_then(|v| v.as_u64())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("pid required".into()))?;

        let driver = super::driver::DriverCommunicator::new("\\\\.\\EDR", 65536);
        let handle = driver.open_device()?;
        let count = driver.scan_process_memory(&handle, pid as u32)?;

        Ok(ActionResponse {
            success: true,
            message: format!("memory scan initiated for PID {} ({} suspicious regions found)", pid, count),
        })
    }

    async fn shred_file(&self, params: &serde_json::Value) -> Result<ActionResponse> {
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| monolith_shared::error::EdrError::ValidationError("path required".into()))?;

        let passes = params.get("passes").and_then(|v| v.as_u64()).unwrap_or(3);
        let path = std::path::Path::new(path);

        if !path.exists() {
            return Ok(ActionResponse {
                success: false,
                message: format!("file not found: {}", path.display()),
            });
        }

        if path.is_dir() {
            return Ok(ActionResponse {
                success: false,
                message: format!("cannot shred directory: {}", path.display()),
            });
        }

        let file_size = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) => return Ok(ActionResponse {
                success: false,
                message: format!("failed to get file metadata: {}", e),
            }),
        };

        if file_size == 0 {
            std::fs::remove_file(path).ok();
            return Ok(ActionResponse {
                success: true,
                message: format!("empty file removed: {}", path.display()),
            });
        }

        if file_size > 1024 * 1024 * 1024 {
            return Ok(ActionResponse {
                success: false,
                message: "file too large to shred (>1GB)".into(),
            });
        }

        for pass in 0..passes {
            if let Err(e) = overwrite_pass(path, pass, file_size) {
                return Ok(ActionResponse {
                    success: false,
                    message: format!("shred pass {} failed: {}", pass + 1, e),
                });
            }
        }

        if let Err(e) = std::fs::remove_file(path) {
            return Ok(ActionResponse {
                success: true,
                message: format!("file overwritten but deletion failed: {}", e),
            });
        }

        Ok(ActionResponse {
            success: true,
            message: format!("file shredded ({} passes, {} bytes): {}", passes, file_size, path.display()),
        })
    }
}

fn overwrite_pass(path: &std::path::Path, pass: u64, file_size: u64) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::io::{Write, Seek, SeekFrom};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)?;

    let chunk_size: u64 = 65536;
    let mut remaining = file_size;
    let mut offset: u64 = 0;

    while remaining > 0 {
        let this_chunk = remaining.min(chunk_size) as usize;
        let mut buf = vec![0u8; this_chunk];

        match pass {
            0 | 2 => {
                use rand::RngCore;
                let mut rng = rand::rngs::OsRng;
                rng.fill_bytes(&mut buf);
            }
            1 => {
                use rand::RngCore;
                let mut rng = rand::rngs::OsRng;
                rng.fill_bytes(&mut buf);
                for b in buf.iter_mut() {
                    *b = !*b;
                }
            }
            _ => {
                buf.fill(0);
            }
        }

        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&buf)?;
        file.flush()?;

        remaining -= this_chunk as u64;
        offset += this_chunk as u64;
    }

    file.flush()?;
    drop(file);

    Ok(())
}

fn get_quarantine_dir() -> PathBuf {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    std::path::Path::new(&program_data).join("EDR").join("Quarantine")
}

fn get_diagnostics_dir() -> PathBuf {
    let temp = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into());
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    std::path::Path::new(&temp).join(format!("EDR_Diagnostics_{}", timestamp))
}

fn copy_dir_recursive(src: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    if src.is_dir() {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let entry_type = entry.file_type()?;
            let dest_entry = dest.join(entry.file_name());
            if entry_type.is_dir() {
                copy_dir_recursive(&entry.path(), &dest_entry)?;
            } else {
                let _ = std::fs::copy(&entry.path(), &dest_entry);
            }
        }
    }
    Ok(())
}

fn collect_system_info_json() -> std::result::Result<String, Box<dyn std::error::Error>> {
    let info = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": std::env::var("COMPUTERNAME").unwrap_or_default(),
        "username": std::env::var("USERNAME").unwrap_or_default(),
        "domain": std::env::var("USERDOMAIN").unwrap_or_default(),
        "programdata": std::env::var("ProgramData").unwrap_or_default(),
        "temp": std::env::var("TEMP").unwrap_or_default(),
    });
    Ok(serde_json::to_string_pretty(&info)?)
}

pub struct ActionResponse {
    pub success: bool,
    pub message: String,
}
