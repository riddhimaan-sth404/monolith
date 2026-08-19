use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::server::AppState;
use monolith_shared::auth::AuthContext;
use monolith_shared::crypto::{JwtManager, PasswordHashManager};
use monolith_shared::db::DbParam;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub username: String,
    pub role: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    // Look up user (include lockout fields)
    let users = state
        .db
        .query_value(
            "SELECT id, username, password_hash, role, enabled, failed_attempts, locked_until, mfa_secret, mfa_required FROM users WHERE username = ?1",
            &[DbParam::Text(req.username.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let user = users.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid credentials"})),
        )
    })?;

    let enabled = user.get("enabled").and_then(|v| v.as_i64()).unwrap_or(0);
    if enabled == 0 {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(json!({"error": "account disabled"})),
        ));
    }

    // Check account lockout
    let locked_until = user
        .get("locked_until")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !locked_until.is_empty() {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if locked_until > now.as_str() {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                Json(json!({"error": "account locked due to too many failed attempts"})),
            ));
        }
    }

    let user_id = user.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let username = user.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let user_id_owned = user_id.to_string();

    let password_hash = user
        .get("password_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let valid = match PasswordHashManager::verify(&req.password, password_hash) {
        Ok(v) => v,
        Err(e) => {
            let _ = state
                .db
                .execute(
                    "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?1",
                    &[DbParam::Text(user_id_owned.clone())],
                )
                .await;
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("password verification error: {}", e)})),
            ));
        }
    };

    if !valid {
        let _ = state.db.execute(
            "UPDATE users SET 
             failed_attempts = failed_attempts + 1,
             locked_until = CASE WHEN failed_attempts + 1 >= 10 THEN datetime('now', '+30 minutes') ELSE locked_until END
             WHERE id = ?1",
            &[DbParam::Text(user_id_owned.clone())],
        ).await;

        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid credentials"})),
        ));
    }

    // Reset failed attempts on successful login
    let _ = state
        .db
        .execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?1",
            &[DbParam::Text(user_id_owned)],
        )
        .await;

    let role = user
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("viewer");
    let mfa_required = user
        .get("mfa_required")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        == 1;
    let mfa_secret = user
        .get("mfa_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Issue JWT
    let jwt_manager = state.config.auth.build_jwt_manager().map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("JWT setup error: {}", e)})),
        )
    })?;

    if mfa_required && !mfa_secret.is_empty() {
        // Issue temporary 5-minute MFA token
        let temp_jwt_manager = state
            .config
            .auth
            .build_jwt_manager_custom(300, 300)
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("MFA JWT setup error: {}", e)})),
                )
            })?;
        let mfa_token = temp_jwt_manager
            .issue_token(user_id, username, "mfa_pending")
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("token generation error: {}", e)})),
                )
            })?;
        return Ok(Json(json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
        })));
    }

    let token = jwt_manager
        .issue_token(user_id, username, role)
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("token generation error: {}", e)})),
            )
        })?;

    let refresh_token = jwt_manager.issue_refresh_token(user_id).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("refresh token generation error: {}", e)})),
        )
    })?;

    // Update last login
    let _ = state
        .db
        .execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?1",
            &[DbParam::Text(user_id.to_string())],
        )
        .await;

    // Store session
    let session_id = uuid::Uuid::new_v4().to_string();
    let token_hash = monolith_shared::crypto::hash_token(&token);
    let _ = state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
            &[
                DbParam::Text(session_id),
                DbParam::Text(user_id.to_string()),
                DbParam::Text(token.clone()),
                DbParam::Text(token_hash),
                DbParam::Text(refresh_token.clone()),
            ],
        )
        .await;

    Ok(Json(json!({
        "token": token,
        "refresh_token": refresh_token,
        "user_id": user_id,
        "username": username,
        "role": role,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let jwt_manager = state.config.auth.build_jwt_manager().map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("JWT setup error: {}", e)})),
        )
    })?;

    let claims = jwt_manager
        .validate_token(&req.refresh_token)
        .map_err(|_| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid or expired refresh token"})),
            )
        })?;

    // Look up user for role
    let users = state
        .db
        .query_value(
            "SELECT id, username, role FROM users WHERE id = ?1",
            &[DbParam::Text(claims.sub.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let user = users.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "user not found"})),
        )
    })?;

    let user_id = user.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let username = user.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let role = user
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("viewer");

    let new_token = jwt_manager
        .issue_token(user_id, username, role)
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("token generation error: {}", e)})),
            )
        })?;

    let new_refresh = jwt_manager.issue_refresh_token(user_id).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("refresh token generation error: {}", e)})),
        )
    })?;

    // Store new session
    let session_id = uuid::Uuid::new_v4().to_string();
    let token_hash = monolith_shared::crypto::hash_token(&new_token);
    let _ = state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
            &[
                DbParam::Text(session_id),
                DbParam::Text(user_id.to_string()),
                DbParam::Text(new_token.clone()),
                DbParam::Text(token_hash),
                DbParam::Text(new_refresh.clone()),
            ],
        )
        .await;

    Ok(Json(json!({
        "token": new_token,
        "refresh_token": new_refresh,
    })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth_context): axum::extract::Extension<AuthContext>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    // Revoke all sessions for user
    let _ = state
        .db
        .execute(
            "UPDATE sessions SET revoked = 1 WHERE user_id = ?1",
            &[DbParam::Text(auth_context.user_id.clone())],
        )
        .await;

    Ok(Json(json!({"message": "logged out successfully"})))
}

#[derive(Debug, Deserialize)]
pub struct MfaLoginRequest {
    pub mfa_token: String,
    pub code: String,
}

pub async fn login_mfa(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MfaLoginRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let jwt_secret = state.config.auth.jwt_secret.as_bytes();
    let jwt_manager = JwtManager::new(
        jwt_secret,
        state.config.auth.jwt_expiration_secs,
        state.config.auth.refresh_expiration_secs,
    );

    let claims = jwt_manager.validate_token(&req.mfa_token).map_err(|e| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": format!("invalid MFA token: {}", e)})),
        )
    })?;

    if claims.role != "mfa_pending" {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid MFA token claims"})),
        ));
    }

    let users = state
        .db
        .query_value(
            "SELECT id, username, role, mfa_secret, mfa_required FROM users WHERE id = ?1",
            &[DbParam::Text(claims.sub.clone())],
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
        })?;

    let user = users.into_iter().next().ok_or_else(|| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "user not found"})),
        )
    })?;

    let mfa_secret = user
        .get("mfa_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if mfa_secret.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "MFA not configured for this user"})),
        ));
    }

    let secret = Secret::Encoded(mfa_secret.to_string());

    let secret_bytes = secret.to_bytes().map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to decode MFA secret: {}", e)})),
        )
    })?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Monolith EDR".to_string()),
        claims.username.clone(),
    )
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create TOTP instance: {}", e)})),
        )
    })?;

    let is_valid = totp.check_current(&req.code).unwrap_or(false);
    if !is_valid {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid MFA code"})),
        ));
    }

    let user_id = &claims.sub;
    let username = &claims.username;
    let role = user
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("viewer");

    let token = jwt_manager
        .issue_token(user_id, username, role)
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("token generation error: {}", e)})),
            )
        })?;

    let refresh_token = jwt_manager.issue_refresh_token(user_id).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("refresh token generation error: {}", e)})),
        )
    })?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let token_hash = monolith_shared::crypto::hash_token(&token);
    let _ = state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
            &[
                DbParam::Text(session_id),
                DbParam::Text(user_id.to_string()),
                DbParam::Text(token.clone()),
                DbParam::Text(token_hash),
                DbParam::Text(refresh_token.clone()),
            ],
        )
        .await;

    Ok(Json(json!({
        "token": token,
        "refresh_token": refresh_token,
        "user_id": user_id,
        "username": username,
        "role": role,
    })))
}
