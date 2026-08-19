use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::handlers::require_perm;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize)]
pub struct ReportListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ReportListQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);

    let reports = state
        .db
        .query_value(
            "SELECT * FROM scan_results WHERE status = 'completed' ORDER BY completed_at DESC LIMIT ? OFFSET ?",
            &[DbParam::Integer(page_size as i64), DbParam::Integer(((page - 1) * page_size) as i64)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(json!({"reports": reports})))
}

#[derive(Debug, Deserialize)]
pub struct GenerateReportRequest {
    pub report_type: String,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub format: Option<String>,
    pub endpoint_id: Option<String>,
}

pub async fn generate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<GenerateReportRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::ReportGenerate)?;
    let _format = req.format.unwrap_or_else(|| "json".to_string());

    match req.report_type.to_lowercase().as_str() {
        "threat_summary" => {
            let date_from = req
                .date_from
                .clone()
                .unwrap_or_else(|| "1970-01-01".to_string());
            let date_to = req
                .date_to
                .clone()
                .unwrap_or_else(|| "2099-12-31".to_string());
            let alerts = state
                .db
                .query_value(
                    "SELECT severity, COUNT(*) as count FROM alerts WHERE created_at >= ?1 AND created_at <= ?2 GROUP BY severity",
                    &[
                        DbParam::Text(date_from.clone()),
                        DbParam::Text(date_to.clone()),
                    ],
                )
                .await
                .map_err(|e| {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("database error: {}", e)})),
                    )
                })?;

            let top_alerts = state
                .db
                .query_value(
                    "SELECT title, severity, created_at FROM alerts WHERE created_at >= ?1 AND created_at <= ?2 ORDER BY severity DESC LIMIT 20",
                    &[
                        DbParam::Text(date_from),
                        DbParam::Text(date_to),
                    ],
                )
                .await
                .map_err(|e| {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("database error: {}", e)})),
                    )
                })?;

            Ok(Json(json!({
                "report_type": "threat_summary",
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "alert_by_severity": alerts,
                "top_alerts": top_alerts,
            })))
        }
        "endpoint_health" => {
            let endpoints = state
                .db
                .query_value(
                    "SELECT status, COUNT(*) as count FROM endpoints GROUP BY status",
                    &[],
                )
                .await
                .map_err(|e| {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("database error: {}", e)})),
                    )
                })?;

            Ok(Json(json!({
                "report_type": "endpoint_health",
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "endpoints": endpoints,
            })))
        }
        "ioc_inventory" => {
            let iocs = state
                .db
                .query_value(
                    "SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type",
                    &[],
                )
                .await
                .map_err(|e| {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("database error: {}", e)})),
                    )
                })?;

            Ok(Json(json!({
                "report_type": "ioc_inventory",
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "iocs_by_type": iocs,
            })))
        }
        _ => Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("unknown report type: {}", req.report_type)})),
        )),
    }
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
            Json(json!({"error": "report not found"})),
        )
    })?;

    Ok(Json(scan))
}

pub async fn download(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    // Look up scan result data
    let scans = state
        .db
        .query_value(
            "SELECT * FROM scan_results WHERE id = ?1",
            &[DbParam::Text(id.clone())],
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
            Json(json!({"error": "report not found"})),
        )
    })?;

    Ok(Json(json!({
        "report": scan,
        "format": "json",
        "filename": format!("report_{}.json", id),
    })))
}

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let logs = state
        .db
        .query_value(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100",
            &[],
        )
        .await
        .unwrap_or_default();

    Ok(Json(json!(logs)))
}
