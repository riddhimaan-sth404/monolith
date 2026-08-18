use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::require_perm;
use crate::server::AppState;
use monolith_shared::auth::{AuthContext, Permission};
use monolith_shared::db::DbParam;

#[derive(Deserialize)]
pub struct ShredRequest {
    pub path: String,
    pub passes: Option<u64>,
}

pub async fn shred_file(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(body): Json<ShredRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_perm(&auth, Permission::EndpointShred)?;

    let action_id = uuid::Uuid::new_v4().to_string();
    let params = json!({
        "path": body.path,
        "passes": body.passes.unwrap_or(3),
    });

    if let Err(e) = state.db.execute(
        "INSERT INTO response_actions (id, endpoint_id, action_type, parameters, status, reason, created_by, created_at)
         VALUES (?1, ?2, 'shred_file', ?3, 'pending', 'admin initiated file shred', ?4, datetime('now'))",
        &[
            DbParam::Text(action_id.clone()),
            DbParam::Text(id),
            DbParam::Text(params.to_string()),
            DbParam::Text(auth.username),
        ],
    ).await {
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create shred action: {}", e)})),
        ));
    }

    Ok(Json(json!({
        "action_id": action_id,
        "action_type": "shred_file",
        "parameters": params,
        "status": "pending",
        "message": format!("File shred action created for: {}", body.path),
    })))
}
