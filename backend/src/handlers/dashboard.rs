use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::server::AppState;

pub async fn summary(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    // Alerts by severity
    let alert_counts = state.db.query_raw(
        "SELECT severity, COUNT(*) as cnt FROM alerts WHERE status != 'resolved' GROUP BY severity",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;

    let mut active = 0i64;
    let mut critical = 0i64;
    let mut high = 0i64;

    for row in &alert_counts {
        let sev = row.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let cnt = row.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
        active += cnt;
        match sev {
            "critical" => critical += cnt,
            "high" => high += cnt,
            _ => {}
        }
    }

    let active_iocs = state.db.query_raw(
        "SELECT COUNT(*) as cnt FROM iocs",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;
    let ioc_count = active_iocs.first()
        .and_then(|r| r.get(0))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let events_today = state.db.query_raw(
        "SELECT COUNT(*) as cnt FROM events WHERE date(timestamp) = date('now')",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;
    let events_count = events_today.first()
        .and_then(|r| r.get(0))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Agent / endpoint status
    let endpoints = state.db.query_raw(
        "SELECT id, hostname, status FROM endpoints ORDER BY last_seen DESC LIMIT 1",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;

    let (agent_running, hostname) = endpoints.first().map(|r| {
        let running = r.get(2).and_then(|v| v.as_str()) == Some("online");
        let host = r.get(1).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        (running, host)
    }).unwrap_or((false, "unknown".to_string()));

    // Last scan
    let last_scan = state.db.query_raw(
        "SELECT started_at FROM scan_results ORDER BY started_at DESC LIMIT 1",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;
    let last_scan_str = last_scan.first()
        .and_then(|r| r.get(0))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Mark stale pending scans as failed (>5 min old = trigger never spawned)
    let _ = state.db.execute(
        "UPDATE scan_results SET status = 'failed', completed_at = datetime('now')
         WHERE status = 'pending' AND started_at < datetime('now', '-300 seconds')",
        &[],
    ).await;

    // Active scans
    let active_scans = state.db.query_raw(
        "SELECT COUNT(*) as cnt FROM scan_results WHERE status IN ('pending', 'running')",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;
    let active_scans_count = active_scans.first()
        .and_then(|r| r.get(0))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Latest running scan progress
    let running_scan = state.db.query_raw(
        "SELECT id, status, scan_type, total_files, scanned_files, started_at, details
         FROM scan_results WHERE status IN ('pending', 'running') ORDER BY started_at DESC LIMIT 1",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;

    let running_scan_info = running_scan.first().map(|r| {
        let details_str = r.get(6).and_then(|v| v.as_str()).unwrap_or("{}");
        let details_value = serde_json::from_str::<Value>(details_str).unwrap_or(json!({}));
        let current_path = details_value
            .get("current_path")
            .and_then(|p| p.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let scanned_files = details_value
            .get("completed_files")
            .or_else(|| details_value.get("scanned_files"))
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| r.get(4).and_then(|v| v.as_i64()).unwrap_or(0));
        let total_files = details_value
            .get("total_files")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| r.get(3).and_then(|v| v.as_i64()).unwrap_or(0));
        json!({
            "id": r.get(0).and_then(|v| v.as_str()).unwrap_or(""),
            "status": r.get(1).and_then(|v| v.as_str()).unwrap_or(""),
            "scan_type": r.get(2).and_then(|v| v.as_str()).unwrap_or(""),
            "total_files": total_files,
            "scanned_files": scanned_files,
            "started_at": r.get(5).and_then(|v| v.as_str()).unwrap_or(""),
            "current_path": current_path,
            "phase": details_value.get("phase").and_then(|v| v.as_str()).unwrap_or(""),
            "scanner_engine": details_value.get("scanner_engine").and_then(|v| v.as_str()).unwrap_or("go_scanner"),
            "scanner_available": details_value.get("scanner_available").and_then(|v| v.as_bool()).unwrap_or(true),
        })
    }).unwrap_or(json!(null));

    // Last completed scan (for scan report)
    let last_done = state.db.query_raw(
        "SELECT scan_type, total_files, clean_files, suspicious_files, malicious_files, completed_at, started_at, details
         FROM scan_results WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;

    let last_completed = last_done.first().map(|r| {
        let details_str = r.get(7).and_then(|v| v.as_str()).unwrap_or("[]");
        let details_val: Value = serde_json::from_str(details_str).unwrap_or(json!([]));

        let (all_results, file_type_breakdown) = if details_val.is_array() {
            let results = details_val.as_array().cloned().unwrap_or_default();
            (results, json!({}))
        } else if let Some(obj) = details_val.as_object() {
            let results = obj.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let types = obj.get("file_types").cloned().unwrap_or(json!({}));
            (results, types)
        } else {
            (vec![], json!({}))
        };

        let threats: Vec<Value> = all_results.iter()
            .filter(|r| {
                r.get("verdict").and_then(|v| v.as_str()).map(|s| s != "clean").unwrap_or(false)
            })
            .cloned()
            .collect();

        // Compute score averages from all_results
        let n = all_results.len() as f64;
        let (heuristic_avg, ember_avg, fusion_avg) = if n > 0.0 {
            let h: f64 = all_results.iter().filter_map(|r| r.get("heuristic_score").and_then(|v| v.as_f64())).sum();
            let e: f64 = all_results.iter().filter_map(|r| r.get("ember_score").and_then(|v| v.as_f64())).sum();
            let f: f64 = all_results.iter().filter_map(|r| r.get("fusion_score").and_then(|v| v.as_f64())).sum();
            (h / n, e / n, f / n)
        } else {
            (0.0, 0.0, 0.0)
        };

        let completed_at_str = r.get(5).and_then(|v| v.as_str()).unwrap_or("");
        let started_at_str = r.get(6).and_then(|v| v.as_str()).unwrap_or("");
        let duration_secs = compute_duration_secs(started_at_str, completed_at_str);

        let scanner_engine = details_val.as_object()
            .and_then(|obj| obj.get("scanner_engine").and_then(|v| v.as_str()))
            .unwrap_or("go_scanner")
            .to_string();
        let scanner_available = details_val.as_object()
            .and_then(|obj| obj.get("scanner_available").and_then(|v| v.as_bool()))
            .unwrap_or(true);

        json!({
            "scan_type": r.get(0).and_then(|v| v.as_str()).unwrap_or(""),
            "total_files": r.get(1).and_then(|v| v.as_i64()).unwrap_or(0),
            "clean_files": r.get(2).and_then(|v| v.as_i64()).unwrap_or(0),
            "suspicious_files": r.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
            "malicious_files": r.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
            "completed_at": completed_at_str,
            "started_at": started_at_str,
            "duration_secs": duration_secs,
            "heuristic_score": heuristic_avg,
            "ember_score": ember_avg,
            "fusion_score": fusion_avg,
            "all_results": Value::Array(all_results),
            "threat_details": Value::Array(threats),
            "file_type_breakdown": file_type_breakdown,
            "scanner_engine": scanner_engine,
            "scanner_available": scanner_available,
        })
    }).unwrap_or(json!(null));

    // Top recent alerts
    let top_alerts = state.db.query_raw(
        "SELECT severity, title, created_at FROM alerts ORDER BY created_at DESC LIMIT 5",
        &[],
    ).await.map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("db error: {}", e)})),
    ))?;

    let top_alerts_list: Vec<Value> = top_alerts.iter().map(|r| {
        json!({
            "severity": r.get(0).and_then(|v| v.as_str()).unwrap_or(""),
            "title": r.get(1).and_then(|v| v.as_str()).unwrap_or(""),
            "created_at": r.get(2).and_then(|v| v.as_str()).unwrap_or(""),
        })
    }).collect();

    Ok(Json(json!({
        "alerts": {
            "active": active,
            "critical": critical,
            "high": high,
        },
        "active_iocs": ioc_count,
        "events_today": events_count,
        "active_scans": active_scans_count,
        "running_scan": running_scan_info,
        "last_completed_scan": last_completed,
        "protection": {
            "enabled": true,
        },
        "agent": {
            "running": agent_running,
            "hostname": hostname,
        },
        "last_scan": last_scan_str,
        "top_alerts": top_alerts_list,
    })))
}

fn compute_duration_secs(started_at: &str, completed_at: &str) -> i64 {
    if started_at.is_empty() || completed_at.is_empty() {
        return 0;
    }
    if let (Ok(start), Ok(end)) = (
        chrono::DateTime::parse_from_rfc3339(started_at),
        chrono::DateTime::parse_from_rfc3339(completed_at),
    ) {
        (end - start).num_seconds().max(0)
    } else if let (Ok(start), Ok(end)) = (
        chrono::NaiveDateTime::parse_from_str(started_at, "%Y-%m-%d %H:%M:%S"),
        chrono::NaiveDateTime::parse_from_str(completed_at, "%Y-%m-%d %H:%M:%S"),
    ) {
        (end - start).num_seconds().max(0)
    } else if let (Ok(start), Ok(end)) = (
        chrono::NaiveDateTime::parse_from_str(started_at, "%Y-%m-%dT%H:%M:%S"),
        chrono::NaiveDateTime::parse_from_str(completed_at, "%Y-%m-%dT%H:%M:%S"),
    ) {
        (end - start).num_seconds().max(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::compute_duration_secs;

    #[test]
    fn parses_sqlite_style_scan_timestamps() {
        assert_eq!(compute_duration_secs("2026-07-12 03:05:26", "2026-07-12 03:05:50"), 24);
    }

    #[test]
    fn parses_rfc3339_scan_timestamps() {
        assert_eq!(compute_duration_secs("2026-07-12T03:05:26Z", "2026-07-12T03:05:50Z"), 24);
    }
}
