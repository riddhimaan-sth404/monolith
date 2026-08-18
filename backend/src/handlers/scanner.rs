use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use uuid::Uuid;

use crate::server::AppState;
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize, Serialize)]
pub struct ScannerAlert {
    pub file_path: String,
    pub verdict: String,
    pub score: f64,
    pub matched_rules: Vec<String>,
    pub sha256: Option<String>,
    pub quarantined: Option<bool>,
}

pub async fn report(
    State(state): State<Arc<AppState>>,
    Json(alert): Json<ScannerAlert>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let alert_id = Uuid::new_v4().to_string();
    let alert_id_clone = alert_id.clone();
    let rule_id = format!("scanner:{}", alert.verdict);
    let title = format!("Scanner detected: {} ({})", alert.file_path, alert.verdict);
    let severity = if alert.verdict == "malicious" { "critical" } else { "high" };

    // Ensure the 'local' endpoint exists to satisfy the FK constraint
    let _ = state.db.execute(
        "INSERT OR IGNORE INTO endpoints (id, hostname, ip_address, os_version, agent_version, status)
         VALUES ('local', 'localhost', '127.0.0.1', 'Windows', '1.0.0', 'unknown')",
        &[],
    ).await;

    let _ = state.db.execute(
        "INSERT INTO alerts (id, endpoint_id, severity, title, description, score, status, rule_id, created_at)
         VALUES (?1, 'local', ?2, ?3, ?4, ?5, 'new', ?6, datetime('now'))",
        &[
            DbParam::Text(alert_id),
            DbParam::Text(severity.to_string()),
            DbParam::Text(title),
            DbParam::Text(serde_json::to_string(&alert).unwrap_or_default()),
            DbParam::Real(alert.score),
            DbParam::Text(rule_id),
        ],
    ).await.map_err(|e| {
        tracing::error!(error = %e, "scanner report: failed to insert alert");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create alert: {}", e)})),
        )
    })?;

    state.metrics.alerts_generated.fetch_add(1, Ordering::Relaxed);

    // Fire desktop notification (non-blocking)
    if alert.verdict == "malicious" || alert.verdict == "suspicious" {
        let notif_title = format!("EDR Alert: {}", alert.verdict);
        let notif_msg = format!("Scanner detected: {} - {}", alert.file_path, alert.verdict);
        crate::notifications::send_alert_notification(
            state.toast_script_path.clone(),
            &notif_title,
            &notif_msg,
        ).await;
    }

    Ok(Json(json!({"received": true, "alert_id": alert_id_clone})))
}
