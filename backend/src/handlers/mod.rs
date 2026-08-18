pub mod auth;
pub mod endpoints;
pub mod events;
pub mod alerts;
pub mod iocs;
pub mod policies;
pub mod scans;
pub mod reports;
pub mod dashboard;
pub mod health;
pub mod license;
pub mod scanner;
pub mod settings;
pub mod allowlist;
pub mod mfa;
pub mod shred;
pub mod profiles;

use axum::http::StatusCode;
use axum::Json;
use monolith_shared::auth::{AuthContext, Permission};
use serde_json::json;

pub fn require_perm(
    auth: &AuthContext,
    permission: Permission,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    auth.require_permission(permission).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "insufficient permissions"})),
        )
    })
}

