use axum::{
    Extension, Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::handlers::require_perm;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileQuery {
    pub pc_profile: Option<String>,
    pub edr_profile: Option<String>,
}

pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let _ = auth;
    let result = state
        .db
        .query_raw(
            "SELECT profile_pc, profile_edr FROM endpoints WHERE id = ?1",
            &[DbParam::Text(id.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("db error: {}", e)})),
            )
        })?;

    let row = result.first().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "endpoint not found"})),
        )
    })?;

    Ok(Json(json!({
        "endpoint_id": id,
        "pc_profile": row.get(0).and_then(|v| v.as_str()).unwrap_or("balanced"),
        "edr_profile": row.get(1).and_then(|v| v.as_str()).unwrap_or("balanced"),
    })))
}

pub async fn set_profile(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(body): Json<ProfileQuery>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::EndpointProfileWrite)?;

    let mut updates = Vec::new();
    let mut params: Vec<DbParam> = Vec::new();

    if let Some(ref pc) = body.pc_profile {
        updates.push("profile_pc = ?");
        params.push(DbParam::Text(pc.clone()));
    }
    if let Some(ref edr) = body.edr_profile {
        updates.push("profile_edr = ?");
        params.push(DbParam::Text(edr.clone()));
    }

    if updates.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "no profile fields provided"})),
        ));
    }

    params.push(DbParam::Text(id.clone()));

    let sql = format!("UPDATE endpoints SET {} WHERE id = ?", updates.join(", "));

    state.db.execute(&sql, &params).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to update profile: {}", e)})),
        )
    })?;

    Ok(Json(json!({
        "endpoint_id": id,
        "status": "updated",
        "changes": body,
    })))
}
