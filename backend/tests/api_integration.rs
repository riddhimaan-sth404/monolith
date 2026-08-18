use std::sync::Arc;

use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Router,
};
use tower::ServiceExt;

use monolith_backend::config::{AppConfig, ServerConfig, AuthConfig, RateLimitingConfig, ResponseRulesConfig, NotificationsConfig};
use monolith_backend::server::AppState;
use monolith_backend::router::build_router;
use monolith_shared::config::{TlsConfig, DatabaseConfig, LoggingConfig, DatabaseKind};
use monolith_shared::crypto::JwtManager;
use monolith_shared::db::{SqliteDatabase, Database, MigrationManager};

async fn setup_test_app() -> (Router, String, AppConfig) {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test_integration.db");

    let config = AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            grpc_port: 0,
        },
        tls: TlsConfig {
            cert_path: "test-cert.pem".into(),
            key_path: "test-key.pem".into(),
            ca_cert_path: "test-ca.pem".into(),
        },
        database: DatabaseConfig {
            kind: DatabaseKind::Sqlite,
            path: db_path.to_str().unwrap().to_string(),
            max_connections: 1,
        },
        logging: LoggingConfig::default(),
        rate_limiting: RateLimitingConfig {
            enabled: false,
            ..Default::default()
        },
        response_rules: ResponseRulesConfig {
            enabled: false,
            ..Default::default()
        },
        notifications: NotificationsConfig {
            enabled: false,
            ..Default::default()
        },
        auth: AuthConfig {
            jwt_secret: "test-secret-key-at-least-32-characters-long!".into(),
            jwt_expiration_secs: 3600,
            refresh_expiration_secs: 86400,
            argon2_memory_cost: 19456,
            argon2_time_cost: 2,
            argon2_parallelism: 1,
            jwt_private_key_path: None,
            jwt_public_key_path: None,
        },
    };

    let db = SqliteDatabase::new(db_path.to_str().unwrap());
    let conn = db.connect(&config.database).await.unwrap();
    MigrationManager::new().run(&conn).await.unwrap();

    let state = Arc::new(AppState::new(config.clone(), Box::new(conn)));
    let app = build_router(state.clone());

    let jwt = JwtManager::new(
        config.auth.jwt_secret.as_bytes(),
        config.auth.jwt_expiration_secs,
        config.auth.refresh_expiration_secs,
    );
    let token = jwt.issue_token("test-user-id", "admin", "administrator").unwrap();
    let token_hash = monolith_shared::crypto::hash_token(&token);

    let valid_hash = monolith_shared::crypto::PasswordHashManager::hash("correct-password").unwrap();

    // Insert test user first to satisfy FOREIGN KEY constraint
    state.db.execute(
        "INSERT INTO users (id, username, password_hash, email, role, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        &[
            monolith_shared::db::DbParam::Text("test-user-id".to_string()),
            monolith_shared::db::DbParam::Text("admin".to_string()),
            monolith_shared::db::DbParam::Text(valid_hash),
            monolith_shared::db::DbParam::Text("admin@example.com".to_string()),
            monolith_shared::db::DbParam::Text("administrator".to_string()),
        ],
    ).await.unwrap();

    // Save token to sessions table to bypass revocation check
    state.db.execute(
        "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
        &[
            monolith_shared::db::DbParam::Text(uuid::Uuid::new_v4().to_string()),
            monolith_shared::db::DbParam::Text("test-user-id".to_string()),
            monolith_shared::db::DbParam::Text(token.clone()),
            monolith_shared::db::DbParam::Text(token_hash),
            monolith_shared::db::DbParam::Text("dummy-refresh-token".to_string()),
        ],
    ).await.unwrap();

    (app, token, config)
}

fn build_req(method: http::Method, path: &str, body: Option<&str>, token: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {}", token));
    if let Some(b) = body {
        let req = builder
            .header("Content-Type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap();
        return req;
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn test_health_liveness() {
    let (app, _token, _config) = setup_test_app().await;

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "monolith-backend");
}

#[tokio::test]
async fn test_health_readiness() {
    let (app, _token, _config) = setup_test_app().await;

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/api/v1/health/ready")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_returns_401_for_wrong_creds() {
    let (app, _token, _config) = setup_test_app().await;

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({"username": "admin", "password": "wrong"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_endpoints_list_with_auth() {
    let (app, token, _config) = setup_test_app().await;

    let req = build_req(http::Method::GET, "/api/v1/endpoints", None, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_alerts_list_with_auth() {
    let (app, token, _config) = setup_test_app().await;

    let req = build_req(http::Method::GET, "/api/v1/alerts", None, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_missing_auth_returns_401() {
    let (app, _token, _config) = setup_test_app().await;

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/api/v1/endpoints")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_token_returns_401() {
    let (app, _token, _config) = setup_test_app().await;

    let req = build_req(http::Method::GET, "/api/v1/endpoints", None, "invalid.token.here");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_endpoint_not_found_returns_404() {
    let (app, token, _config) = setup_test_app().await;

    let req = build_req(http::Method::GET, "/api/v1/endpoints/nonexistent-id", None, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_events_list_with_auth() {
    let (app, token, _config) = setup_test_app().await;

    let req = build_req(http::Method::GET, "/api/v1/events", None, &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
