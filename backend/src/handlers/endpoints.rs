use axum::{
    extract::{State, Path, Query},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::require_perm;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize)]
pub struct EndpointQuery {
    pub status: Option<String>,
    pub search: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EndpointQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    // Build filter conditions
    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(status) = &query.status {
        conditions.push("status = ?");
        params.push(DbParam::Text(status.clone()));
    }
    if let Some(search) = &query.search {
        conditions.push("(hostname LIKE ? OR ip_address LIKE ?)");
        params.push(DbParam::Text(format!("%{}%", search)));
        params.push(DbParam::Text(format!("%{}%", search)));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as total FROM endpoints {}", where_clause);
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

    let sql = format!(
        "SELECT * FROM endpoints {} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        where_clause
    );

    let mut query_params = params;
    query_params.push(DbParam::Integer(page_size as i64));
    query_params.push(DbParam::Integer(offset as i64));

    let endpoints = state
        .db
        .query_value(&sql, &query_params)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(json!({
        "endpoints": endpoints,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total as f64 / page_size as f64).ceil() as u64
    })))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let endpoints = state
        .db
        .query_value(
            "SELECT * FROM endpoints WHERE id = ?1",
            &[DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let endpoint = endpoints.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "endpoint not found"})),
        )
    })?;

    Ok(Json(endpoint))
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::EndpointWrite)?;
    let allowed_fields = ["hostname", "policy_id", "tags", "custom_fields"];
    let mut updates = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    for field in &allowed_fields {
        if let Some(val) = body.get(*field) {
            updates.push(format!("{} = ?", field));
            params.push(DbParam::Text(val.to_string()));
        }
    }

    if updates.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "no valid fields to update"})),
        ));
    }

    params.push(DbParam::Text(id.clone()));

    let sql = format!("UPDATE endpoints SET {} WHERE id = ?", updates.join(", "));
    state.db.execute(&sql, &params).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("update failed: {}", e)})),
        )
    })?;

    Ok(Json(json!({"message": "endpoint updated successfully"})))
}

pub async fn isolate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::EndpointIsolate)?;
    let affected = state
        .db
        .execute(
            "UPDATE endpoints SET isolated = 1, status = 'isolated' WHERE id = ?1",
            &[DbParam::Text(id.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("isolate failed: {}", e)})),
            )
        })?;

    if affected == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "endpoint not found"})),
        ));
    }

    // Dispatch isolate action to agent via response action
    let action_id = uuid::Uuid::new_v4().to_string();
    state
        .db
        .execute(
            "INSERT INTO response_actions (id, endpoint_id, action_type, parameters, status, reason) VALUES (?1, ?2, 'isolate_endpoint', '{}', 'pending', 'admin initiated isolation')",
            &[DbParam::Text(action_id.clone()), DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("action creation failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "isolation initiated", "action_id": action_id})))
}

pub async fn release(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::EndpointWrite)?;
    let affected = state
        .db
        .execute(
            "UPDATE endpoints SET isolated = 0, status = 'online' WHERE id = ?1 AND isolated = 1",
            &[DbParam::Text(id.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("release failed: {}", e)})),
            )
        })?;

    if affected == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "endpoint not found or not isolated"})),
        ));
    }

    let action_id = uuid::Uuid::new_v4().to_string();
    state
        .db
        .execute(
            "INSERT INTO response_actions (id, endpoint_id, action_type, parameters, status, reason) VALUES (?1, ?2, 'release_isolation', '{}', 'pending', 'admin initiated release')",
            &[DbParam::Text(action_id.clone()), DbParam::Text(id)],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("action creation failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "release initiated", "action_id": action_id})))
}

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub event_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let _offset = (page - 1) * page_size;

    let mut conditions = vec!["endpoint_id = ?".to_string()];
    let mut params: Vec<DbParam> = vec![DbParam::Text(id)];

    if let Some(et) = &query.event_type {
        conditions.push("event_type = ?".to_string());
        params.push(DbParam::Text(et.clone()));
    }
    if let Some(from) = &query.from {
        conditions.push("timestamp >= ?".to_string());
        params.push(DbParam::Text(from.clone()));
    }
    if let Some(to) = &query.to {
        conditions.push("timestamp <= ?".to_string());
        params.push(DbParam::Text(to.clone()));
    }

    let where_clause = conditions.join(" AND ");

    let events = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM events WHERE {} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
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

pub async fn stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let stats = state
        .db
        .query_value(
            "SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
                SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline,
                SUM(CASE WHEN status = 'isolated' THEN 1 ELSE 0 END) as isolated,
                SUM(CASE WHEN isolated = 1 THEN 1 ELSE 0 END) as isolated_count
            FROM endpoints",
            &[],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    Ok(Json(stats.into_iter().next().unwrap_or_default()))
}
