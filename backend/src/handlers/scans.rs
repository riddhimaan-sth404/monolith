use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::handlers::require_perm;
use crate::scanner_client::ScannerClient;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize)]
pub struct ScanListQuery {
    pub status: Option<String>,
    pub endpoint_id: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ScanListQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(status) = &query.status {
        conditions.push("status = ?".to_string());
        params.push(DbParam::Text(status.clone()));
    }
    if let Some(eid) = &query.endpoint_id {
        conditions.push("endpoint_id = ?".to_string());
        params.push(DbParam::Text(eid.clone()));
    }

    params.push(DbParam::Integer(page_size as i64));
    params.push(DbParam::Integer(offset as i64));

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let scans = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM scan_results {} ORDER BY started_at DESC LIMIT ? OFFSET ?",
                where_clause
            ),
            &params,
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(json!({"scans": scans})))
}

#[derive(Debug, Deserialize)]
pub struct TriggerScanRequest {
    pub endpoint_id: Option<String>,
    pub scan_type: String,
    pub paths: Option<Vec<String>>,
}

pub async fn trigger(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<TriggerScanRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::ScanWrite)?;
    let scan_id = Uuid::new_v4().to_string();
    let endpoint_id = req.endpoint_id.unwrap_or_else(|| "localhost".to_string());
    tracing::info!("triggering scan {} for endpoint {}", scan_id, endpoint_id);

    let existing = state
        .db
        .query_raw(
            "SELECT id FROM endpoints WHERE id = ?1",
            &[DbParam::Text(endpoint_id.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    if existing.is_empty() {
        state.db.execute(
            "INSERT INTO endpoints (id, hostname, ip_address, os_version, status, agent_version, last_seen)
             VALUES (?1, ?2, '127.0.0.1', 'Windows', 'online', '1.0.0', datetime('now'))",
            &[
                DbParam::Text(endpoint_id.clone()),
                DbParam::Text("localhost".into()),
            ],
        ).await.map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create endpoint: {}", e)})),
        ))?;
    }

    let _ = state.db.execute(
        "UPDATE scan_results SET status = 'cancelled', completed_at = datetime('now') WHERE status IN ('pending', 'running')",
        &[],
    ).await;

    let scan_type = req.scan_type.clone();
    state
        .db
        .execute(
            "INSERT INTO scan_results (id, endpoint_id, scan_type, status, started_at, triggered_by)
             VALUES (?1, ?2, ?3, 'pending', datetime('now'), 'manual')",
            &[
                DbParam::Text(scan_id.clone()),
                DbParam::Text(endpoint_id),
                DbParam::Text(scan_type.clone()),
            ],
        )
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("scan trigger failed: {}", e)})),
        ))?;

    let app_state = state.clone();
    let sid = scan_id.clone();
    let st = scan_type.clone();
    let paths = req.paths.clone();

    tokio::spawn(async move {
        tracing::info!("scan {}: background task started", sid);

        let _ = app_state
            .db
            .execute(
                "UPDATE scan_results SET status = 'running' WHERE id = ?1",
                &[DbParam::Text(sid.clone())],
            )
            .await;

        let scanner = ScannerClient::new("127.0.0.1:50053");
        let use_scanner = scanner.get_status().await.is_ok();

        if use_scanner {
            tracing::info!("scan {}: using Go scanner", sid);
            if let Err(e) = scanner.start_scan(&st, paths.clone()).await {
                tracing::error!("scan {}: scanner start failed: {}", sid, e);
                let _ = app_state.db.execute(
                    "UPDATE scan_results SET status = 'failed', completed_at = datetime('now') WHERE id = ?1",
                    &[DbParam::Text(sid.clone())],
                ).await;
                return;
            }

            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(300);
            let mut completed_once = false;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                // Check if the scan has been cancelled in the database
                if let Ok(rows) = app_state
                    .db
                    .query_value(
                        "SELECT status FROM scan_results WHERE id = ?1",
                        &[DbParam::Text(sid.clone())],
                    )
                    .await
                {
                    if let Some(row) = rows.into_iter().next() {
                        if let Some(status) = row.get("status").and_then(|v| v.as_str()) {
                            if status == "cancelled" {
                                tracing::info!(
                                    "scan {}: cancel detected in database, stopping polling",
                                    sid
                                );
                                return;
                            }
                        }
                    }
                }

                let status = match scanner.get_status().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("scan {}: poll failed: {}", sid, e);
                        continue;
                    }
                };

                let details = json!({
                    "current_path": status.current_path,
                    "total_files": status.total_files,
                    "completed_files": status.completed_files,
                    "phase": status.phase,
                    "scanner_engine": "go_scanner",
                    "scanner_available": true,
                });
                let _ = app_state.db.execute(
                    "UPDATE scan_results SET scanned_files = ?1, total_files = ?2, details = ?3 WHERE id = ?4",
                    &[
                        DbParam::Integer(status.completed_files),
                        DbParam::Integer(status.total_files),
                        DbParam::Text(details.to_string()),
                        DbParam::Text(sid.clone()),
                    ],
                ).await;

                if status.status == "completed" {
                    if completed_once {
                        break;
                    }
                    completed_once = true;
                }

                if start.elapsed() > timeout {
                    tracing::warn!("scan {}: timeout", sid);
                    break;
                }
            }

            // Small delay so the scanner's subscriber goroutine can drain any
            // buffered results before we read them (avoids race with the channel).
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // Retry up to 3 times in case the subscriber goroutine hasn't flushed yet
            let mut results = Vec::new();
            for attempt in 0..3 {
                match scanner.get_results().await {
                    Ok(r) if !r.is_empty() => {
                        results = r;
                        break;
                    }
                    Ok(_) => {
                        tracing::warn!(
                            "scan {}: empty results on attempt {}, retrying...",
                            sid,
                            attempt + 1
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "scan {}: failed to fetch results (attempt {}): {}",
                            sid,
                            attempt + 1,
                            e
                        );
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let total = results.len() as i64;
            let clean = results.iter().filter(|r| r.verdict == "clean").count() as i64;
            let suspicious = results.iter().filter(|r| r.verdict == "suspicious").count() as i64;
            let malicious = results.iter().filter(|r| r.verdict == "malicious").count() as i64;

            if total == 0 {
                tracing::warn!(
                    "scan {}: got 0 results from scanner after 3 attempts; report will be empty",
                    sid
                );
            }

            let details = json!({
                "scanner_engine": "go_scanner",
                "scanner_available": true,
                "files": results,
            });
            let _ = app_state.db.execute(
                "UPDATE scan_results SET status = 'completed', completed_at = datetime('now'),
                 total_files = ?1, scanned_files = ?2, clean_files = ?3, suspicious_files = ?4, malicious_files = ?5,
                 details = ?6 WHERE id = ?7",
                &[
                    DbParam::Integer(total),
                    DbParam::Integer(total),
                    DbParam::Integer(clean),
                    DbParam::Integer(suspicious),
                    DbParam::Integer(malicious),
                    DbParam::Text(details.to_string()),
                    DbParam::Text(sid),
                ],
            ).await;
            tracing::info!("scan completed via scanner: {} files", total);
        } else {
            tracing::error!("scan {}: Go scanner not available on 127.0.0.1:50053", sid);
            let _ = app_state.db.execute(
                "UPDATE scan_results SET status = 'failed', completed_at = datetime('now') WHERE id = ?1",
                &[DbParam::Text(sid.clone())],
            ).await;
        }
    });

    Ok(Json(json!({
        "scan_id": scan_id,
        "message": "scan triggered successfully"
    })))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let scans = state
        .db
        .query_value(
            "SELECT * FROM scan_results WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let scan = scans.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "scan not found"})),
        )
    })?;

    Ok(Json(scan))
}

pub async fn cancel(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::ScanCancel)?;

    // Call cancel on the Go scanner daemon
    let scanner = ScannerClient::new("127.0.0.1:50053");
    if let Err(e) = scanner.cancel_scan().await {
        tracing::warn!("Failed to forward cancel request to Go scanner: {}", e);
    }

    state
        .db
        .execute(
            "UPDATE scan_results SET status = 'cancelled', completed_at = datetime('now') WHERE id = ?1 AND status IN ('pending', 'running')",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("cancel failed: {}", e)})),
        ))?;

    Ok(Json(json!({"message": "scan cancelled"})))
}

pub async fn list_quarantine(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let items = state
        .db
        .query_value(
            "SELECT id, endpoint_id, original_path, original_name, quarantine_path, file_size, status, threat_name, detection_rule, quarantined_at FROM quarantine_entries WHERE status != 'deleted' ORDER BY quarantined_at DESC",
            &[],
        )
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("database error: {}", e)})),
        ))?;

    Ok(Json(json!(items)))
}

pub async fn restore_quarantine(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    state
        .db
        .execute(
            "UPDATE quarantine_entries SET status = 'restored', restored_at = datetime('now') WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("restore failed: {}", e)})),
        ))?;

    Ok(Json(json!({"message": "item restored successfully"})))
}

pub async fn delete_quarantine(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    state
        .db
        .execute(
            "UPDATE quarantine_entries SET status = 'deleted', deleted_at = datetime('now') WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("delete failed: {}", e)})),
        ))?;

    Ok(Json(json!({"message": "quarantine entry deleted"})))
}
