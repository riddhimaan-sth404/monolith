use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::server::AppState;

#[derive(Debug, serde::Deserialize)]
pub struct UploadLicenseRequest {
    pub license_content: String,
}

pub async fn upload(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UploadLicenseRequest>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let bundle = crate::license::activate_with_license(state.clone(), &req.license_content).await?;

    let expires = bundle.expires_at().map(|dt| dt.to_rfc3339());
    let features = bundle.payload.config.features.clone();

    Ok(Json(json!({
        "status": "activated",
        "vendor": bundle.payload.vendor,
        "issued": bundle.payload.issued,
        "expires": expires,
        "features": features,
    })))
}

pub async fn status(
    _state: State<Arc<AppState>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    match monolith_shared::license::find_license_file() {
        Ok(Some(bundle)) => {
            let expires = bundle.expires_at().map(|dt| dt.to_rfc3339());
            let issued = bundle.issued_at().map(|dt| dt.to_rfc3339());
            Ok(Json(json!({
                "status": "active",
                "vendor": bundle.payload.vendor,
                "issued": issued,
                "expires": expires,
                "expired": bundle.is_expired(),
                "features": bundle.payload.config.features,
            })))
        }
        Ok(None) => Ok(Json(json!({
            "status": "no_license",
        }))),
        Err(e) => Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("license error: {}", e)})),
        )),
    }
}
