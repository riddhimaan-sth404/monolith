use axum::{Json, extract::State};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::server::AppState;

/// GET /api/v1/settings/hardware
pub async fn get_hardware(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let (total_gb, avail_gb) = get_ram_info();
    Ok(Json(json!({
        "total_ram_gb": total_gb,
        "available_ram_gb": avail_gb,
    })))
}

fn get_ram_info() -> (u64, f64) {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        if let Ok(out) = Command::new("wmic")
            .args([
                "OS",
                "get",
                "TotalVisibleMemorySize,FreePhysicalMemory",
                "/format:csv",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().skip(1) {
                let cols: Vec<&str> = line.split(',').collect();
                if cols.len() >= 3 {
                    if let (Ok(total_kb), Ok(free_kb)) =
                        (cols[1].trim().parse::<u64>(), cols[2].trim().parse::<u64>())
                    {
                        let total_gb = total_kb / (1024 * 1024);
                        let avail_gb = free_kb as f64 / (1024.0 * 1024.0);
                        return (total_gb, avail_gb);
                    }
                }
            }
        }
    }
    (0, 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ram_info_returns_non_zero() {
        let (total, avail) = get_ram_info();
        assert!(total > 0 || avail > 0.0);
    }
}
