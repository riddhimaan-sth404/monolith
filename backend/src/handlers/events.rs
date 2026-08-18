use axum::{
    extract::{State, Path, Query},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::server::AppState;
use monolith_shared::db::DbParam;
use std::sync::atomic::Ordering;

#[derive(Debug, Deserialize)]
pub struct EventListQuery {
    pub event_type: Option<String>,
    pub endpoint_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub search: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct IngestEventRequest {
    pub endpoint_id: String,
    pub event_type: String,
    pub timestamp: Option<String>,
    pub data: Value,
}

pub async fn ingest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IngestEventRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let timestamp = req.timestamp.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string());
    let data_str = serde_json::to_string(&req.data).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(json!({"error": format!("invalid event data: {}", e)})))
    })?;

    let endpoint_id = req.endpoint_id.clone();
    state.db.execute(
        "INSERT INTO events (id, endpoint_id, event_type, timestamp, data, processed) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        &[
            DbParam::Text(event_id.clone()),
            DbParam::Text(req.endpoint_id),
            DbParam::Text(req.event_type.clone()),
            DbParam::Text(timestamp.clone()),
            DbParam::Text(data_str),
        ],
    ).await.map_err(|e| {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("failed to store event: {}", e)})))
    })?;

    state.metrics.events_ingested.fetch_add(1, Ordering::Relaxed);

    // Check allowlist
    let is_allowed = state.services.allowlist_service.is_event_allowed(&req.event_type, &req.data, &*state.db).await.unwrap_or(false);

    // Run detection
    let event_value = json!({
        "id": &event_id,
        "event_type": &req.event_type,
        "data": &req.data,
        "timestamp": &timestamp,
    });
    let detection_results = if is_allowed {
        tracing::info!("event {} ingestion skipped by allowlist", event_id);
        vec![]
    } else {
        state.detection_engine.evaluate_event(&event_value)
    };
    for result in &detection_results {
        let alert_id = uuid::Uuid::new_v4().to_string();
        let severity_json = serde_json::to_string(&json!(result.severity)).unwrap_or_default();
        let _ = state.db.execute(
            "INSERT INTO alerts (id, endpoint_id, event_id, rule_id, severity, title, score, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'new')",
            &[
                DbParam::Text(alert_id.clone()),
                DbParam::Text(endpoint_id.clone()),
                DbParam::Text(event_id.clone()),
                DbParam::Text(result.rule_id.clone()),
                DbParam::Text(severity_json.trim_matches('"').to_string()),
                DbParam::Text(result.rule_name.clone()),
                DbParam::Real(result.score),
            ],
        ).await;

        state.metrics.alerts_generated.fetch_add(1, Ordering::Relaxed);

        if result.severity == "high" || result.severity == "critical" {
            let notif_title = format!("EDR Alert: {}", result.severity);
            let notif_msg = format!("Event '{}' matched rule '{}'", req.event_type, result.rule_name);
            let path = state.toast_script_path.clone();
            tokio::spawn(async move {
                crate::notifications::send_alert_notification(path, &notif_title, &notif_msg).await;
            });
        }
    }

    if !detection_results.is_empty() {
        tracing::warn!(
            "detection triggered for event {}: {} match(es)",
            event_id,
            detection_results.len()
        );
    }

    let _ = state.event_bus.send(event_value);

    Ok(Json(json!({
        "id": event_id,
        "accepted": true,
        "detections": detection_results.len(),
    })))
}

/// GET /api/v1/metrics â€” Prometheus-format metrics
pub async fn metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let events = state.metrics.events_ingested.load(Ordering::Relaxed);
    let alerts = state.metrics.alerts_generated.load(Ordering::Relaxed);
    let requests = state.metrics.requests_total.load(Ordering::Relaxed);
    let errors = state.metrics.errors_total.load(Ordering::Relaxed);

    Ok(Json(json!({
        "events_ingested": events,
        "alerts_generated": alerts,
        "requests_total": requests,
        "errors_total": errors,
    })))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventListQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(et) = &query.event_type {
        conditions.push("event_type = ?".to_string());
        params.push(DbParam::Text(et.clone()));
    }
    if let Some(eid) = &query.endpoint_id {
        conditions.push("endpoint_id = ?".to_string());
        params.push(DbParam::Text(eid.clone()));
    }
    if let Some(from) = &query.from {
        conditions.push("timestamp >= ?".to_string());
        params.push(DbParam::Text(from.clone()));
    }
    if let Some(to) = &query.to {
        conditions.push("timestamp <= ?".to_string());
        params.push(DbParam::Text(to.clone()));
    }

    params.push(DbParam::Integer(page_size as i64));
    params.push(DbParam::Integer(offset as i64));

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let events = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM events {} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
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

    Ok(Json(json!({
        "events": events,
        "page": page,
        "page_size": page_size,
    })))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let events = state
        .db
        .query_value(
            "SELECT * FROM events WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let event = events.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "event not found"})),
        )
    })?;

    Ok(Json(event))
}

pub async fn ws_events(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let mut rx = state.event_bus.subscribe();
        while let Ok(msg) = rx.recv().await {
            let text = msg.to_string();
            if socket.send(axum::extract::ws::Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    })
}
