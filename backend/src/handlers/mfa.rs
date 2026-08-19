use crate::server::AppState;
use axum::{Extension, Json, extract::State, http::StatusCode};
use monolith_shared::auth::AuthContext;
use monolith_shared::db::DbParam;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub secret: String,
    pub qr_code_uri: String,
}

pub async fn enroll_mfa(
    State(_state): State<Arc<AppState>>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> Result<Json<EnrollResponse>, (StatusCode, Json<Value>)> {
    let username = auth_ctx.username.clone();

    // Generate a secure base32 secret
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to generate TOTP secret bytes: {}", e)})),
            )
        })?,
        Some("Monolith EDR".to_string()),
        username.clone(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create TOTP instance: {}", e)})),
        )
    })?;

    let qr_code_uri = totp.get_url();

    Ok(Json(EnrollResponse {
        secret: secret_base32,
        qr_code_uri,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub secret: String,
    pub code: String,
}

pub async fn confirm_mfa(
    State(state): State<Arc<AppState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let secret = Secret::Encoded(req.secret.clone());

    let secret_bytes = secret.to_bytes().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to decode secret: {}", e)})),
        )
    })?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Monolith EDR".to_string()),
        auth_ctx.username.clone(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to create TOTP instance: {}", e)})),
        )
    })?;

    let is_valid = totp.check_current(&req.code).unwrap_or(false);
    if !is_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid TOTP code"})),
        ));
    }

    let result = state
        .db
        .execute(
            "UPDATE users SET mfa_secret = ?1, mfa_required = 1 WHERE id = ?2",
            &[
                DbParam::Text(req.secret.clone()),
                DbParam::Text(auth_ctx.user_id.clone()),
            ],
        )
        .await;

    match result {
        Ok(_) => Ok(Json(
            json!({"message": "MFA confirmed and enabled successfully"}),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to save MFA settings: {}", e)})),
        )),
    }
}

pub async fn disable_mfa(
    State(state): State<Arc<AppState>>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .db
        .execute(
            "UPDATE users SET mfa_secret = NULL, mfa_required = 0 WHERE id = ?1",
            &[DbParam::Text(auth_ctx.user_id.clone())],
        )
        .await;

    match result {
        Ok(_) => Ok(Json(json!({"message": "MFA disabled successfully"}))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to update database: {}", e)})),
        )),
    }
}
