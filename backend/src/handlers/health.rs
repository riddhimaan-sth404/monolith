use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::server::AppState;

pub async fn liveness(
    State(_state): State<Arc<AppState>>,
) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "monolith-backend",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn readiness(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    // Check database connectivity
    let db_ok = state
        .db
        .query_one_value("SELECT 1 as ok", &[])
        .await
        .is_ok();

    if !db_ok {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "error", "message": "database unreachable"})),
        ));
    }

    Ok(Json(json!({
        "status": "ok",
        "database": "connected",
        "uptime": chrono::Utc::now().to_rfc3339(),
    })))
}
