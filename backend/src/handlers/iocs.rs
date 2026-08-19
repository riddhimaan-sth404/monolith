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
pub struct IocListQuery {
    pub ioc_type: Option<String>,
    pub severity: Option<String>,
    pub search: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub expired: Option<bool>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<IocListQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut conditions = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(ioc_type) = &query.ioc_type {
        conditions.push("ioc_type = ?".to_string());
        params.push(DbParam::Text(ioc_type.clone()));
    }
    if let Some(severity) = &query.severity {
        conditions.push("severity = ?".to_string());
        params.push(DbParam::Text(severity.clone()));
    }
    if let Some(search) = &query.search {
        conditions.push("(value LIKE ? OR description LIKE ?)".to_string());
        params.push(DbParam::Text(format!("%{}%", search)));
        params.push(DbParam::Text(format!("%{}%", search)));
    }
    if query.expired == Some(false) {
        conditions.push("(expires_at IS NULL OR expires_at > datetime('now'))".to_string());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) as total FROM iocs {}", where_clause);
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

    let iocs = state
        .db
        .query_value(
            &format!(
                "SELECT * FROM iocs {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
        "iocs": iocs,
        "total": total,
        "page": page,
        "page_size": page_size,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateIocRequest {
    pub ioc_type: String,
    pub value: String,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub description: Option<String>,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
    pub expires_at: Option<String>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateIocRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocWrite)?;
    let id = Uuid::new_v4().to_string();
    let severity = req.severity.unwrap_or_else(|| "medium".to_string());
    let confidence = req.confidence.unwrap_or_else(|| "medium".to_string());
    let tags = req.tags.unwrap_or_default();

    state
        .db
        .execute(
            "INSERT INTO iocs (id, ioc_type, value, severity, confidence, description, source, tags, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                DbParam::Text(id.clone()),
                DbParam::Text(req.ioc_type),
                DbParam::Text(req.value),
                DbParam::Text(severity),
                DbParam::Text(confidence),
                DbParam::Text(req.description.unwrap_or_default()),
                DbParam::Text(req.source.unwrap_or_default()),
                DbParam::Text(serde_json::to_string(&tags).unwrap_or_default()),
                DbParam::Text(req.expires_at.unwrap_or_default()),
            ],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::CONFLICT,
                Json(json!({"error": format!("ioc creation failed: {}", e)})),
            )
        })?;

    Ok(Json(
        json!({"id": id, "message": "IOC created successfully"}),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub filename: String,
    pub content: String,
    pub format: String,
    pub dry_run: Option<bool>,
}

pub async fn import_(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocWrite)?;
    let dry_run = req.dry_run.unwrap_or(false);
    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut duplicates = 0u32;
    let mut errors: Vec<String> = Vec::new();

    match req.format.to_lowercase().as_str() {
        "csv" => {
            let mut reader = csv::ReaderBuilder::new()
                .flexible(true)
                .from_reader(req.content.as_bytes());

            for result in reader.records() {
                match result {
                    Ok(record) => {
                        if record.len() < 2 {
                            skipped += 1;
                            continue;
                        }
                        let ioc_type = record.get(0).unwrap_or("");
                        let value = record.get(1).unwrap_or("");

                        if ioc_type.is_empty() || value.is_empty() {
                            skipped += 1;
                            continue;
                        }

                        if !dry_run {
                            let id = Uuid::new_v4().to_string();
                            let severity = record.get(2).unwrap_or("medium");
                            let tags: Vec<String> = record
                                .get(3)
                                .map(|t| t.split(';').map(|s| s.trim().to_string()).collect())
                                .unwrap_or_default();

                            match state.db.execute(
                                "INSERT OR IGNORE INTO iocs (id, ioc_type, value, severity, tags) VALUES (?1, ?2, ?3, ?4, ?5)",
                                &[
                                    DbParam::Text(id),
                                    DbParam::Text(ioc_type.to_string()),
                                    DbParam::Text(value.to_string()),
                                    DbParam::Text(severity.to_string()),
                                    DbParam::Text(serde_json::to_string(&tags).unwrap_or_default()),
                                ],
                            ).await {
                                Ok(affected) => {
                                    if affected > 0 { imported += 1; } else { duplicates += 1; }
                                }
                                Err(e) => {
                                    errors.push(format!("insert error: {}", e));
                                    duplicates += 1;
                                }
                            }
                        } else {
                            imported += 1;
                        }
                    }
                    Err(e) => {
                        errors.push(format!("csv parse error: {}", e));
                        skipped += 1;
                    }
                }
            }
        }
        "json" => {
            let items: Vec<Value> = serde_json::from_str(&req.content).unwrap_or_default();
            for item in items {
                let ioc_type = item.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("");
                let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("");

                if ioc_type.is_empty() || value.is_empty() {
                    skipped += 1;
                    continue;
                }

                if !dry_run {
                    let id = Uuid::new_v4().to_string();
                    match state.db.execute(
                        "INSERT OR IGNORE INTO iocs (id, ioc_type, value, severity, description, source, tags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        &[
                            DbParam::Text(id),
                            DbParam::Text(ioc_type.to_string()),
                            DbParam::Text(value.to_string()),
                            DbParam::Text(item.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string()),
                            DbParam::Text(item.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                            DbParam::Text(item.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                            DbParam::Text(item.get("tags").map(|t| t.to_string()).unwrap_or_else(|| "[]".to_string())),
                        ],
                    ).await {
                        Ok(affected) => {
                            if affected > 0 { imported += 1; } else { duplicates += 1; }
                        }
                        Err(_) => { duplicates += 1; }
                    }
                } else {
                    imported += 1;
                }
            }
        }
        _ => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": format!("unsupported format: {}. Supported: csv, json", req.format)}),
                ),
            ));
        }
    }

    Ok(Json(json!({
        "total": imported + skipped + duplicates + errors.len() as u32,
        "imported": imported,
        "skipped": skipped,
        "duplicates": duplicates,
        "errors": errors,
    })))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let iocs = state
        .db
        .query_value("SELECT * FROM iocs WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let ioc = iocs.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "IOC not found"})),
        )
    })?;

    Ok(Json(ioc))
}

#[derive(Debug, Deserialize)]
pub struct UpdateIocRequest {
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub expires_at: Option<String>,
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateIocRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocWrite)?;
    let mut updates = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(severity) = &req.severity {
        updates.push("severity = ?");
        params.push(DbParam::Text(severity.clone()));
    }
    if let Some(confidence) = &req.confidence {
        updates.push("confidence = ?");
        params.push(DbParam::Text(confidence.clone()));
    }
    if let Some(desc) = &req.description {
        updates.push("description = ?");
        params.push(DbParam::Text(desc.clone()));
    }
    if let Some(tags) = &req.tags {
        updates.push("tags = ?");
        params.push(DbParam::Text(
            serde_json::to_string(tags).unwrap_or_default(),
        ));
    }
    if let Some(expires) = &req.expires_at {
        updates.push("expires_at = ?");
        params.push(DbParam::Text(expires.clone()));
    }

    if updates.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "no fields to update"})),
        ));
    }

    updates.push("updated_at = datetime('now')");
    params.push(DbParam::Text(id.clone()));

    let sql = format!("UPDATE iocs SET {} WHERE id = ?", updates.join(", "));
    state.db.execute(&sql, &params).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("update failed: {}", e)})),
        )
    })?;

    Ok(Json(json!({"message": "IOC updated successfully"})))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::IocDelete)?;
    let affected = state
        .db
        .execute("DELETE FROM iocs WHERE id = ?1", &[DbParam::Text(id)])
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("delete failed: {}", e)})),
            )
        })?;

    if affected == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "IOC not found"})),
        ));
    }

    Ok(Json(json!({"message": "IOC deleted successfully"})))
}
