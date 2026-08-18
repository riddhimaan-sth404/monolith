use std::sync::Arc;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Router,
};
use tower::ServiceExt;
use serde_json::json;

use monolith_backend::config::{AppConfig, ServerConfig, AuthConfig, RateLimitingConfig, ResponseRulesConfig, NotificationsConfig};
use monolith_backend::server::AppState;
use monolith_backend::router::build_router;
use monolith_shared::config::{TlsConfig, DatabaseConfig, LoggingConfig, DatabaseKind};
use monolith_shared::crypto::JwtManager;
use monolith_shared::db::{SqliteDatabase, Database, MigrationManager, DbParam};

async fn setup_stress_test_app(rate_limit_enabled: bool) -> (Router, String, Arc<AppState>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("stress_test.db");

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
            max_connections: 8,
        },
        logging: LoggingConfig::default(),
        rate_limiting: RateLimitingConfig {
            enabled: rate_limit_enabled,
            requests_per_second: 5,
            burst_size: 5,
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

    // Insert test user
    state.db.execute(
        "INSERT INTO users (id, username, password_hash, email, role, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        &[
            DbParam::Text("test-user-id".to_string()),
            DbParam::Text("admin".to_string()),
            DbParam::Text(valid_hash),
            DbParam::Text("admin@example.com".to_string()),
            DbParam::Text("administrator".to_string()),
        ],
    ).await.unwrap();

    // Save token to sessions table
    state.db.execute(
        "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
        &[
            DbParam::Text(uuid::Uuid::new_v4().to_string()),
            DbParam::Text("test-user-id".to_string()),
            DbParam::Text(token.clone()),
            DbParam::Text(token_hash),
            DbParam::Text("mock-refresh-token".to_string()),
        ],
    ).await.unwrap();

    // Register a test endpoint
    state.db.execute(
        "INSERT INTO endpoints (id, hostname, ip_address, os_version, agent_version, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            DbParam::Text("test-endpoint-id".to_string()),
            DbParam::Text("test-host".to_string()),
            DbParam::Text("127.0.0.1".to_string()),
            DbParam::Text("Windows 10".to_string()),
            DbParam::Text("1.0.0".to_string()),
            DbParam::Text("online".to_string()),
        ],
    ).await.unwrap();

    (app, token, state)
}

#[tokio::test]
async fn test_concurrent_event_ingestion_stress() {
    let (app, token, state) = setup_stress_test_app(false).await;
    let app_arc = Arc::new(app);

    let num_tasks = 10;
    let events_per_task = 30;
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let app_clone = app_arc.clone();
        let token_clone = token.clone();
        
        let handle = tokio::spawn(async move {
            for j in 0..events_per_task {
                let payload = json!({
                    "endpoint_id": "test-endpoint-id",
                    "event_type": "process_create",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "data": {
                        "process_id": 1000 + i * 100 + j,
                        "parent_process_id": 500,
                        "image_path": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": format!("cmd.exe /c echo task_{}_{}", i, j),
                        "user_sid": "S-1-5-18"
                    }
                });

                let req = Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/events/ingest")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header(http::header::AUTHORIZATION, format!("Bearer {}", token_clone))
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap();

                let response = app_clone.as_ref().clone().oneshot(req).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify all events are present in the DB
    let result = state.db.query_value(
        "SELECT COUNT(*) as count FROM events",
        &[]
    ).await.unwrap();
    
    let count = result.first()
        .and_then(|row| row.get("count"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
        
    assert_eq!(count, (num_tasks * events_per_task) as i64, "All events should be stored successfully in SQLite");
}

#[tokio::test]
async fn test_concurrent_rate_limiting_stress() {
    let (app, token, _state) = setup_stress_test_app(true).await;
    let app_arc = Arc::new(app);

    let num_requests = 30;
    let mut handles = Vec::new();

    for _ in 0..num_requests {
        let app_clone = app_arc.clone();
        let token_clone = token.clone();
        
        let handle = tokio::spawn(async move {
            let req = Request::builder()
                .method(http::Method::GET)
                .uri("/api/v1/health/ready")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token_clone))
                .body(Body::empty())
                .unwrap();

            app_clone.as_ref().clone().oneshot(req).await.unwrap()
        });
        handles.push(handle);
    }

    let mut too_many_requests_hit = false;
    for h in handles {
        let resp = h.await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            too_many_requests_hit = true;
        }
    }

    assert!(too_many_requests_hit, "Rate limiter should trigger and return 429 Too Many Requests under burst load");
}
