use axum::http::{HeaderName, HeaderValue, Method};
use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware::{auth, rate_limit, request_id};
use crate::server::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    let security_headers = SetResponseHeaderLayer::appending(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    let api_router = Router::new()
        // Authentication
        .route("/api/v1/login", post(handlers::auth::login))
        .route("/api/v1/login/mfa", post(handlers::auth::login_mfa))
        .route("/api/v1/refresh", post(handlers::auth::refresh_token))
        .route("/api/v1/logout", post(handlers::auth::logout))
        // MFA Enrollment & Management
        .route("/api/v1/users/mfa/enroll", post(handlers::mfa::enroll_mfa))
        .route(
            "/api/v1/users/mfa/confirm",
            post(handlers::mfa::confirm_mfa),
        )
        .route(
            "/api/v1/users/mfa/disable",
            post(handlers::mfa::disable_mfa),
        )
        // Dashboard
        .route("/api/v1/dashboard", get(handlers::dashboard::summary))
        // License management
        .route("/api/v1/license/upload", post(handlers::license::upload))
        .route("/api/v1/license/status", get(handlers::license::status))
        // Endpoints
        .route("/api/v1/endpoints", get(handlers::endpoints::list))
        .route("/api/v1/endpoints/stats", get(handlers::endpoints::stats))
        .route("/api/v1/endpoints/{id}", get(handlers::endpoints::get))
        .route("/api/v1/endpoints/{id}", put(handlers::endpoints::update))
        .route(
            "/api/v1/endpoints/{id}/isolate",
            post(handlers::endpoints::isolate),
        )
        .route(
            "/api/v1/endpoints/{id}/release",
            post(handlers::endpoints::release),
        )
        .route(
            "/api/v1/endpoints/{id}/events",
            get(handlers::endpoints::events),
        )
        // Events
        .route("/api/v1/events", get(handlers::events::list))
        .route("/api/v1/events/ingest", post(handlers::events::ingest))
        .route("/api/v1/events/{id}", get(handlers::events::get))
        .route("/api/v1/ws/events", get(handlers::events::ws_events))
        // Alerts
        .route("/api/v1/alerts", get(handlers::alerts::list))
        .route("/api/v1/alerts/summary", get(handlers::alerts::summary))
        .route(
            "/api/v1/alerts/memory",
            get(handlers::alerts::list_memory_alerts),
        )
        .route(
            "/api/v1/alerts/registry-tamper",
            get(handlers::alerts::list_registry_tamper),
        )
        .route("/api/v1/alerts/{id}", get(handlers::alerts::get))
        .route("/api/v1/alerts/{id}", put(handlers::alerts::update))
        .route(
            "/api/v1/alerts/{id}/suppress",
            post(handlers::alerts::suppress),
        )
        .route(
            "/api/v1/alerts/{id}/unsuppress",
            post(handlers::alerts::unsuppress),
        )
        // IOCs
        .route("/api/v1/iocs", get(handlers::iocs::list))
        .route("/api/v1/iocs", post(handlers::iocs::create))
        .route("/api/v1/iocs/import", post(handlers::iocs::import_))
        .route("/api/v1/iocs/{id}", get(handlers::iocs::get))
        .route("/api/v1/iocs/{id}", put(handlers::iocs::update))
        .route("/api/v1/iocs/{id}", delete(handlers::iocs::delete))
        // Allowlist
        .route("/api/v1/allowlist", get(handlers::allowlist::list))
        .route("/api/v1/allowlist", post(handlers::allowlist::create))
        .route(
            "/api/v1/allowlist/{id}",
            delete(handlers::allowlist::delete),
        )
        // Policies
        .route("/api/v1/policies", get(handlers::policies::list))
        .route("/api/v1/policies", post(handlers::policies::create))
        .route("/api/v1/policies/{id}", get(handlers::policies::get))
        .route("/api/v1/policies/{id}", put(handlers::policies::update))
        .route("/api/v1/policies/{id}", delete(handlers::policies::delete))
        .route(
            "/api/v1/policies/{id}/assign",
            post(handlers::policies::assign),
        )
        // Scans & Quarantine
        .route("/api/v1/scans", get(handlers::scans::list))
        .route("/api/v1/scans", post(handlers::scans::trigger))
        .route(
            "/api/v1/scans/quarantine",
            get(handlers::scans::list_quarantine),
        )
        .route("/api/v1/scans/{id}", get(handlers::scans::get))
        .route(
            "/api/v1/scans/{id}",
            delete(handlers::scans::delete_quarantine),
        )
        .route("/api/v1/scans/{id}/cancel", post(handlers::scans::cancel))
        .route(
            "/api/v1/scans/{id}/restore",
            post(handlers::scans::restore_quarantine),
        )
        // Reports & Audit Logs
        .route("/api/v1/reports", get(handlers::reports::list))
        .route("/api/v1/reports", post(handlers::reports::generate))
        .route(
            "/api/v1/reports/audit-logs",
            get(handlers::reports::list_audit_logs),
        )
        .route("/api/v1/reports/{id}", get(handlers::reports::get))
        .route(
            "/api/v1/reports/{id}/download",
            get(handlers::reports::download),
        )
        // Health
        .route("/api/v1/health", get(handlers::health::liveness))
        .route("/api/v1/health/ready", get(handlers::health::readiness))
        // Metrics
        .route("/api/v1/metrics", get(handlers::events::metrics))
        // Settings
        .route(
            "/api/v1/settings/hardware",
            get(handlers::settings::get_hardware),
        )
        // Scanner reports (internal, from Go scanner)
        .route("/api/v1/scanner/report", post(handlers::scanner::report))
        // Shred
        .route(
            "/api/v1/endpoints/{id}/shred",
            post(handlers::shred::shred_file),
        )
        // Profiles
        .route(
            "/api/v1/endpoints/{id}/profile",
            get(handlers::profiles::get_profile),
        )
        .route(
            "/api/v1/endpoints/{id}/profile",
            put(handlers::profiles::set_profile),
        );

    Router::new()
        .merge(api_router)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_id::request_id_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(security_headers)
        .layer(
            CorsLayer::new()
                .allow_origin(HeaderValue::from_static("https://localhost:7443"))
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([
                    HeaderName::from_static("authorization"),
                    HeaderName::from_static("content-type"),
                ]),
        )
        .with_state(state)
}
