use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::handlers::require_perm;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize)]
pub struct PolicyQuery {
    pub active: Option<bool>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PolicyQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let _offset = (page - 1) * page_size;

    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(active) = query.active {
        conditions.push("active = ?".to_string());
        params.push(DbParam::Integer(if active { 1 } else { 0 }));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let policies = state
        .db
        .query_value(
            &format!(
                "SELECT id, name, description, version, active, created_at, updated_at, created_by FROM policies {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
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

    Ok(Json(json!({"policies": policies})))
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub rules: Option<Value>,
    pub settings: Option<Value>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::PolicyWrite)?;
    let id = Uuid::new_v4().to_string();
    let rules = req.rules.unwrap_or(json!([]));
    let settings = req.settings.unwrap_or(json!({}));

    state
        .db
        .execute(
            "INSERT INTO policies (id, name, description, rules, settings) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                DbParam::Text(id.clone()),
                DbParam::Text(req.name),
                DbParam::Text(req.description.unwrap_or_default()),
                DbParam::Text(rules.to_string()),
                DbParam::Text(settings.to_string()),
            ],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::CONFLICT,
                Json(json!({"error": format!("policy creation failed: {}", e)})),
            )
        })?;

    Ok(Json(
        json!({"id": id, "message": "policy created successfully"}),
    ))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let policies = state
        .db
        .query_value("SELECT * FROM policies WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let policy = policies.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "policy not found"})),
        )
    })?;

    Ok(Json(policy))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rules: Option<Value>,
    pub settings: Option<Value>,
    pub active: Option<bool>,
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::PolicyWrite)?;
    let mut updates = vec!["version = version + 1".to_string()];
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(name) = &req.name {
        updates.push("name = ?".to_string());
        params.push(DbParam::Text(name.clone()));
    }
    if let Some(desc) = &req.description {
        updates.push("description = ?".to_string());
        params.push(DbParam::Text(desc.clone()));
    }
    if let Some(rules) = &req.rules {
        updates.push("rules = ?".to_string());
        params.push(DbParam::Text(rules.to_string()));
    }
    if let Some(settings) = &req.settings {
        updates.push("settings = ?".to_string());
        params.push(DbParam::Text(settings.to_string()));
    }
    if let Some(active) = req.active {
        updates.push("active = ?".to_string());
        params.push(DbParam::Integer(if active { 1 } else { 0 }));
    }

    updates.push("updated_at = datetime('now')".to_string());
    params.push(DbParam::Text(id.clone()));

    let sql = format!("UPDATE policies SET {} WHERE id = ?", updates.join(", "));
    state.db.execute(&sql, &params).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("update failed: {}", e)})),
        )
    })?;

    Ok(Json(json!({"message": "policy updated successfully"})))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::PolicyDelete)?;
    state
        .db
        .execute("DELETE FROM policies WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("delete failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "policy deleted successfully"})))
}

#[derive(Debug, Deserialize)]
pub struct AssignRequest {
    pub endpoint_id: String,
}

pub async fn assign(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<AssignRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::PolicyWrite)?;
    // Verify policy exists
    let policies = state
        .db
        .query_value(
            "SELECT id FROM policies WHERE id = ?1",
            &[DbParam::Text(id.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    if policies.is_empty() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "policy not found"})),
        ));
    }

    // Update endpoint with policy
    state
        .db
        .execute(
            "UPDATE endpoints SET policy_id = ?1 WHERE id = ?2",
            &[
                DbParam::Text(id.clone()),
                DbParam::Text(req.endpoint_id.clone()),
            ],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("assign failed: {}", e)})),
            )
        })?;

    Ok(Json(json!({"message": "policy assigned successfully"})))
}
