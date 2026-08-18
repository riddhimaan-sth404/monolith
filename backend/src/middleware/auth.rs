use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    http::StatusCode,
    Json,
};
use serde_json::json;
use monolith_shared::auth::AuthContext;
use monolith_shared::error::EdrError;

use crate::server::SharedAppState;

pub struct AuthLayer;

impl AuthLayer {
    pub fn new(_state: SharedAppState) -> AuthLayer {
        AuthLayer
    }
}

pub async fn auth_middleware(
    State(state): State<SharedAppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Skip auth for login, health, and activation/report endpoints
    let path = request.uri().path();
    if path == "/api/v1/login"
        || path == "/api/v1/login/mfa"
        || path == "/api/v1/license/status"
        || path == "/api/v1/health"
        || path == "/api/v1/health/ready"
        || path == "/api/v1/scanner/report"
        || path == "/api/v1/ws/events"
    {
        return Ok(next.run(request).await);
    }

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing authorization header"})),
            )
        })?;

    // Validate JWT
    let jwt_manager = state.config.auth.build_jwt_manager().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("JWT setup error: {}", e)})),
        )
    })?;

    let claims = jwt_manager.validate_token(auth_header).map_err(|e| {
        let (code, msg) = match e {
            EdrError::TokenExpired => (StatusCode::UNAUTHORIZED, "token expired".to_string()),
            _ => (StatusCode::UNAUTHORIZED, format!("invalid token: {}", e)),
        };
        (code, Json(json!({"error": msg})))
    })?;

    // Enforce session revocation checking
    let token_hash = monolith_shared::crypto::hash_token(auth_header);
    match state.db.query_value(
        "SELECT revoked FROM sessions WHERE token_hash = ?1",
        &[monolith_shared::db::DbParam::Text(token_hash)],
    ).await {
        Ok(rows) => {
            if let Some(row) = rows.into_iter().next() {
                let revoked = row.get("revoked").and_then(|v| v.as_i64()).unwrap_or(0);
                if revoked == 1 {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "token has been revoked"})),
                    ));
                }
            }
        }
        Err(e) => {
            tracing::error!("Database error checking session revocation: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "session verification failed"})),
            ));
        }
    }

    // Create auth context and attach to request extensions
    let auth_context = AuthContext::new(claims.sub, claims.username, monolith_shared::auth::Role::from_str(&claims.role).unwrap_or(monolith_shared::auth::Role::Viewer));

    request.extensions_mut().insert(auth_context);

    Ok(next.run(request).await)
}
