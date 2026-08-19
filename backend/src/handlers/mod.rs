pub mod alerts;
pub mod allowlist;
pub mod auth;
pub mod dashboard;
pub mod endpoints;
pub mod events;
pub mod health;
pub mod iocs;
pub mod license;
pub mod mfa;
pub mod policies;
pub mod profiles;
pub mod reports;
pub mod scanner;
pub mod scans;
pub mod settings;
pub mod shred;

use axum::Json;
use axum::http::StatusCode;
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
