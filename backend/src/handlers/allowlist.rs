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
pub struct AllowlistListQuery {
    pub rule_type: Option<String>,
    pub search: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AllowlistListQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(rule_type) = &query.rule_type {
        conditions.push("rule_type = ?".to_string());
        params.push(DbParam::Text(rule_type.clone()));
    }
    if let Some(search) = &query.search {
        conditions.push("(value LIKE ? OR description LIKE ?)".to_string());
        params.push(DbParam::Text(format!("%{}%", search)));
        params.push(DbParam::Text(format!("%{}%", search)));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as total FROM allowlist {}", where_clause);
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

    let mut query_params = params;
    query_params.push(DbParam::Integer(page_size as i64));
    query_params.push(DbParam::Integer(offset as i64));

    let rules = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM allowlist {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateAllowlistRequest {
    pub rule_type: String,
    pub value: String,
    pub description: Option<String>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateAllowlistRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocWrite)?;
    let id = Uuid::new_v4().to_string();

    state
        .db
        .execute(
            "INSERT INTO allowlist (id, rule_type, value, description)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                DbParam::Text(id.clone()),
                DbParam::Text(req.rule_type),
                DbParam::Text(req.value),
                DbParam::Text(req.description.unwrap_or_default()),
            ],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::CONFLICT,
                Json(json!({"error": format!("allowlist rule creation failed: {}", e)})),
            )
        })?;

    Ok(Json(
        json!({"id": id, "message": "Allowlist rule created successfully"}),
    ))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocDelete)?;
    let affected = state
        .db
        .execute("DELETE FROM allowlist WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    if affected == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "Allowlist rule not found"})),
        ));
    }

    Ok(Json(
        json!({"message": "Allowlist rule deleted successfully"}),
    ))
}
