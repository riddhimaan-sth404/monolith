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
pub struct AlertListQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub endpoint_id: Option<String>,
    pub search: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertListQuery>,
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
    if let Some(severity) = &query.severity {
        conditions.push("severity = ?".to_string());
        params.push(DbParam::Text(severity.clone()));
    }
    if let Some(eid) = &query.endpoint_id {
        conditions.push("endpoint_id = ?".to_string());
        params.push(DbParam::Text(eid.clone()));
    }
    if let Some(from) = &query.from {
        conditions.push("created_at >= ?".to_string());
        params.push(DbParam::Text(from.clone()));
    }
    if let Some(to) = &query.to {
        conditions.push("created_at <= ?".to_string());
        params.push(DbParam::Text(to.clone()));
    }
    if let Some(search) = &query.search {
        conditions.push("(title LIKE ? OR description LIKE ?)".to_string());
        params.push(DbParam::Text(format!("%{}%", search)));
        params.push(DbParam::Text(format!("%{}%", search)));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as total FROM alerts {}", where_clause);
    let total = state
        .db
        .query_one_value(&count_sql, &params)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?
        .and_then(|r| r.get("total").and_then(|v| v.as_i64()).map(|i| i as u64))
        .unwrap_or(0);

    let mut query_params = params.clone();
    query_params.push(DbParam::Integer(page_size as i64));
    query_params.push(DbParam::Integer(offset as i64));

    let alerts = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM alerts {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                where_clause
            ),
            &query_params,
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(json!({
        "alerts": alerts,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total as f64 / page_size as f64).ceil() as u64
    })))
}

pub async fn summary(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let summary = state
        .db
        .query_value(
            "SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new,
                SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END) as acknowledged,
                SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END) as investigating,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN suppressed = 1 THEN 1 ELSE 0 END) as suppressed
            FROM alerts",
            &[],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(summary.into_iter().next().unwrap_or_default()))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let alerts = state
        .db
        .query_value("SELECT * FROM alerts WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let alert = alerts.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "alert not found"})),
        )
    })?;

    Ok(Json(alert))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    pub status: Option<String>,
    pub assigned_to: Option<String>,
    pub resolution_notes: Option<String>,
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAlertRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::AlertWrite)?;
    let mut updates = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(status) = &req.status {
        updates.push("status = ?");
        params.push(DbParam::Text(status.clone()));
        if status == "resolved" {
            updates.push("resolved_at = datetime('now')");
        }
        if status == "acknowledged" {
            updates.push("acknowledged_at = datetime('now')");
        }
    }
    if let Some(assigned_to) = &req.assigned_to {
        updates.push("assigned_to = ?");
        params.push(DbParam::Text(assigned_to.clone()));
    }
    if let Some(notes) = &req.resolution_notes {
        updates.push("resolution_notes = ?");
        params.push(DbParam::Text(notes.clone()));
    }

    if updates.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "no fields to update"})),
        ));
    }

    updates.push("updated_at = datetime('now')");
    params.push(DbParam::Text(id.clone()));

    let sql = format!("UPDATE alerts SET {} WHERE id = ?", updates.join(", "));
    state.db.execute(&sql, &params).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("update failed: {}", e)})),
        )
    })?;

    Ok(Json(json!({"message": "alert updated successfully"})))
}

pub async fn suppress(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::AlertWrite)?;
    state
        .db
        .execute(
            "UPDATE alerts SET suppressed = 1, updated_at = datetime('now') WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("suppress failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "alert suppressed"})))
}

pub async fn unsuppress(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::AlertWrite)?;
    state
        .db
        .execute(
            "UPDATE alerts SET suppressed = 0, updated_at = datetime('now') WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("unsuppress failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "alert unsuppressed"})))
}

pub async fn list_memory_alerts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let alerts = state
        .db
        .query_value("SELECT * FROM memory_alerts ORDER BY created_at DESC", &[])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;
    Ok(Json(json!(alerts)))
}

pub async fn list_registry_tamper(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let events = state
        .db
        .query_value(
            "SELECT * FROM registry_tamper_events ORDER BY created_at DESC",
            &[],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;
    Ok(Json(json!(events)))
}
