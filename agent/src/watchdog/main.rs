#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(windows)]
define_windows_service!(ffi_service_main, watchdog_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    monolith_agent::tamper::TamperProtection::detect_debugger();

    #[cfg(windows)]
    {
        // Check if we should run as service
        let service_mode = std::env::args().any(|arg| arg == "--service");
        if service_mode {
            service_dispatcher::start("MonolithWatchdog", ffi_service_main)?;
            return Ok(());
        }
    }

    // Console mode
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Set a basic ctrlc handler if available
    let _ = r;

    run_watchdog(running);
    Ok(())
}

#[cfg(windows)]
fn watchdog_service_main(_arguments: Vec<std::ffi::OsString>) {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                r.store(false, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register("MonolithWatchdog", event_handler) {
        Ok(h) => h,
        Err(_) => return,
    };

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .ok();

    run_watchdog(running);

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .ok();
}

fn run_watchdog(running: Arc<AtomicBool>) {
    let mut check_count = 0;
    let mut heartbeat_stale_count = 0;

    let heartbeat_path = format!(
        "{}\\EDR\\.heartbeat",
        std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string())
    );

    while running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(5));
        check_count += 1;

        #[cfg(windows)]
        {
            // Check MonolithAgent Service Status
            let status = Command::new("sc").args(["query", "MonolithAgent"]).output();

            if let Ok(o) = status {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stdout.contains("STOPPED") {
                    heartbeat_stale_count += 1;
                    if heartbeat_stale_count >= 3 {
                        // 15 seconds stopped
                        let _ = Command::new("sc").args(["start", "MonolithAgent"]).output();
                        heartbeat_stale_count = 0;
                    }
                } else {
                    heartbeat_stale_count = 0;
                }
            }

            // Every 60 seconds, check .heartbeat file
            if check_count >= 12 {
                check_count = 0;
                if let Ok(metadata) = fs::metadata(&heartbeat_path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                            if elapsed.as_secs() > 120 {
                                // stale > 120s
                                let _ = Command::new("sc").args(["stop", "MonolithAgent"]).output();
                                thread::sleep(Duration::from_secs(5));
                                let _ =
                                    Command::new("sc").args(["start", "MonolithAgent"]).output();
                            }
                        }
                    }
                }
            }
        }
    }
}
