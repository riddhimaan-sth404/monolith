use monolith_agent::detection::alert::AlertManager;
use monolith_agent::detection::chain::ChainDetector;
use monolith_agent::detection::{DetectionAction, LocalDetectionEngine};
use serde_json::json;
use std::collections::HashMap;

// ──────────────────────────────────────────────
// Helper: build a minimal policy JSON like the backend would send
// ──────────────────────────────────────────────
fn make_policy(iocs: &[&str], extra_processes: &[&str]) -> Vec<u8> {
    let ioc_list: Vec<serde_json::Value> = iocs.iter().map(|v| json!({"value": v})).collect();
    let rule_list: Vec<serde_json::Value> = extra_processes
        .iter()
        .map(|p| json!({"process": p}))
        .collect();
    json!({
        "iocs": ioc_list,
        "detection_rules": rule_list,
    })
    .to_string()
    .into_bytes()
}

// ──────────────────────────────────────────────
// Scenario 1: Office macro → PowerShell → malware
// Simulates a real-world spear-phishing attack chain
// ──────────────────────────────────────────────
#[test]
fn test_attack_chain_office_to_powershell_to_malware() {
    let mut engine = LocalDetectionEngine::new();
    let mut alerts = AlertManager::new();

    // Phase 1: User opens malicious Word doc → WinWord spawns PowerShell
    // This triggers the office_script chain rule
    let action = engine.check_process_chain(1001, 2000, "powershell.exe", "winword.exe");
    assert!(
        action.is_some(),
        "should detect winword -> powershell spawn chain"
    );
    let a = action.unwrap();
    assert_eq!(a.action_type, "terminate_process");
    assert_eq!(a.severity, "high");
    assert_eq!(a.pid, 1001);
    assert_eq!(engine.detection_count(), 1);

    // Generate alert for the chain detection
    let alert = alerts.evaluate(
        "chain_office_script",
        &a.severity,
        "powershell.exe",
        a.pid,
        "winword.exe spawned powershell.exe (office_script chain)",
    );
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().severity, "high");

    // Phase 2: PowerShell downloads and executes malware.exe
    // Load IoCs simulating a policy sync after the initial compromise
    engine.load_iocs(&make_policy(
        &["malware.dll", "C:\\temp\\staged_payload.exe"],
        &[],
    ));

    // Detect malware.exe via process event
    let action = engine.check_process_event(1002, 1001, "C:\\temp\\staged_payload.exe", "");
    assert!(action.is_some(), "should detect IoC match on path");
    assert_eq!(action.unwrap().severity, "high");
    assert_eq!(engine.detection_count(), 2);
}

// ──────────────────────────────────────────────
// Scenario 2: Registry persistence → dropper in AppData
// After initial compromise, attacker establishes persistence
// ──────────────────────────────────────────────
#[test]
fn test_persistence_chain_registry_then_file_combo() {
    let mut engine = LocalDetectionEngine::new();
    let mut _alerts = AlertManager::new();

    // Step 1: Attacker writes to Run registry key (persistence)
    let reg_action = engine.check_registry_event(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate",
        1003,
    );
    assert!(reg_action.is_some(), "should detect registry persistence");
    assert_eq!(reg_action.unwrap().action_type, "alert_only");
    assert_eq!(engine.detection_count(), 1);

    // Step 2: Attacker drops evil.dll to AppData (combo with recent registry write)
    let file_action =
        engine.check_file_event("C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll", 1003);
    assert!(file_action.is_some(), "should detect registry+file combo");
    let fa = file_action.unwrap();
    assert_eq!(fa.action_type, "quarantine_file");
    assert_eq!(fa.severity, "critical", "combo detection must be critical");
    assert_eq!(engine.detection_count(), 2);

    // Step 3: Non-suspicious file in system32 should NOT trigger combo
    let no_match = engine.check_file_event("C:\\Windows\\System32\\kernel32.dll", 1004);
    assert!(no_match.is_none(), "system file should not trigger combo");
}

// ──────────────────────────────────────────────
// Scenario 3: Browser drive-by download → PowerShell
// ──────────────────────────────────────────────
#[test]
fn test_browser_drive_by_chain() {
    let mut engine = LocalDetectionEngine::new();

    // Chrome spawns PowerShell
    let action = engine.check_process_chain(2001, 3000, "powershell.exe", "chrome.exe");
    assert!(action.is_some(), "chrome -> powershell should be detected");
    assert_eq!(action.unwrap().severity, "high");

    // Edge spawns cmd.exe (not a rule, but Edge -> powershell IS a rule)
    assert!(
        engine
            .check_process_chain(2002, 3001, "cmd.exe", "msedge.exe")
            .is_none(),
        "msedge -> cmd is not a configured chain rule"
    );

    // Normal browser usage should not trigger
    let normal = engine.check_process_chain(2003, 3002, "notepad.exe", "chrome.exe");
    assert!(normal.is_none(), "chrome -> notepad is not suspicious");
}

// ──────────────────────────────────────────────
// Scenario 4: LOLBin chain with grandparent ancestry
// winword → notepad → powershell (grandparent detection)
// ──────────────────────────────────────────────
#[test]
fn test_grandparent_chain_detection_via_stored_spawn() {
    let mut engine = LocalDetectionEngine::new();

    // First, record winword → notepad (not a chain match by itself)
    assert!(
        engine
            .check_process_chain(3001, 4000, "notepad.exe", "winword.exe")
            .is_none()
    );
    assert_eq!(
        engine.detection_count(),
        0,
        "winword->notepad alone is not a match"
    );

    // Now notepad → powershell with parent_pid pointing to the recorded spawn
    let action = engine.check_process_chain(3002, 3001, "powershell.exe", "notepad.exe");
    assert!(
        action.is_some(),
        "should detect grandparent winword -> notepad -> powershell"
    );
    assert_eq!(action.unwrap().severity, "high");
    assert_eq!(engine.detection_count(), 1);
}

// ──────────────────────────────────────────────
// Scenario 5: IoC matching via check_event_json (simulating JSON events)
// ──────────────────────────────────────────────
#[test]
fn test_ioc_matching_via_json_events() {
    let mut engine = LocalDetectionEngine::new();
    engine.load_iocs(&make_policy(
        &[
            "a1b2c3d4e5f60000a1b2c3d4e5f60000a1b2c3d4e5f60000a1b2c3d4e5f60000",
            "C:\\malicious\\payload.dll",
            "evil.example.com",
            "192.168.1.100",
            "hklm\\software\\malicious\\corp\\run",
        ],
        &[],
    ));

    // SHA256 hash match
    let event =
        json!({"sha256": "a1b2c3d4e5f60000a1b2c3d4e5f60000a1b2c3d4e5f60000a1b2c3d4e5f60000"});
    let m = engine
        .check_event_json(&event.to_string())
        .expect("should match SHA256");
    assert_eq!(m.match_type, "ioc_sha256");
    assert_eq!(m.severity, "high");

    // Path match (nested under /data/path as ETW events would have)
    let event = json!({"data": {"path": "C:\\malicious\\payload.dll"}});
    let m = engine
        .check_event_json(&event.to_string())
        .expect("should match path");
    assert_eq!(m.match_type, "ioc_path");

    // Domain match
    let event = json!({"data": {"query": "evil.example.com"}});
    let m = engine
        .check_event_json(&event.to_string())
        .expect("should match domain");
    assert_eq!(m.match_type, "ioc_domain");
    assert_eq!(m.severity, "high");

    // IP address match (mapped to ioc_ip)
    let event = json!({"data": {"remote_address": "192.168.1.100"}});
    let m = engine
        .check_event_json(&event.to_string())
        .expect("should match IP");
    assert_eq!(m.match_type, "ioc_ip");
    assert_eq!(m.severity, "high");

    // Registry key match
    let event = json!({"data": {"key_path": "HKLM\\SOFTWARE\\Malicious\\Corp\\Run"}});
    let m = engine
        .check_event_json(&event.to_string())
        .expect("should match registry key");
    assert_eq!(m.match_type, "ioc_registry");
}

// ──────────────────────────────────────────────
// Scenario 6: AlertManager dedup and escalation
// After 3+ detections within 5 minutes, severity escalates to critical
// ──────────────────────────────────────────────
#[test]
fn test_alert_dedup_and_escalation_to_critical() {
    let mut alerts = AlertManager::new();

    // First two hits: medium
    let a1 = alerts
        .evaluate(
            "rule_001",
            "medium",
            "malware.exe",
            5001,
            "Malware detected",
        )
        .unwrap();
    assert_eq!(a1.severity, "medium");
    assert_eq!(a1.count, 1);

    let a2 = alerts
        .evaluate(
            "rule_001",
            "medium",
            "malware.exe",
            5001,
            "Malware detected",
        )
        .unwrap();
    assert_eq!(a2.severity, "medium");
    assert_eq!(a2.count, 2);

    // Third hit: escalates to critical
    let a3 = alerts
        .evaluate(
            "rule_001",
            "medium",
            "malware.exe",
            5001,
            "Malware detected",
        )
        .unwrap();
    assert_eq!(a3.severity, "critical");
    assert_eq!(a3.count, 3);
    assert_eq!(a3.rule_id, "rule_001");
    assert_eq!(a3.match_value, "malware.exe");
    assert_eq!(a3.pid, 5001);

    // Fourth hit: suppressed because count > 3, returns None
    let a4 = alerts.evaluate(
        "rule_001",
        "medium",
        "malware.exe",
        5001,
        "Malware detected",
    );
    assert!(a4.is_none());
}

// ──────────────────────────────────────────────
// Scenario 7: Full pipeline integration
// Simulates events as they would arrive from ETW in the uploader worker
// ──────────────────────────────────────────────
#[test]
fn test_full_pipeline_end_to_end_scenario() {
    let mut engine = LocalDetectionEngine::new();
    let mut alerts = AlertManager::new();

    // Load policy as the policy sync worker would
    engine.load_iocs(&make_policy(
        &["C:\\Windows\\Tasks\\updater.exe", "malicious.example.com"],
        &[],
    ));

    // ── Step 1: Process events (as from ETW process_handler) ──
    // Legitimate process: no match
    let mut results: Vec<DetectionAction> = Vec::new();
    let mut alert_events: Vec<String> = Vec::new();

    // Normal system activity
    assert!(
        engine
            .check_process_event(1, 0, "svchost.exe", "")
            .is_none()
    );
    assert!(
        engine
            .check_process_event(2, 0, "explorer.exe", "")
            .is_none()
    );

    // Chrome launching notepad is not suspicious
    assert!(
        engine
            .check_process_chain(3, 1, "notepad.exe", "chrome.exe")
            .is_none()
    );

    // ── Step 2: WMI launches PowerShell (lateral movement) ──
    let action = engine
        .check_process_chain(4, 0, "powershell.exe", "wmiprvse.exe")
        .expect("should detect WMI->PowerShell");
    assert_eq!(action.action_type, "terminate_process");
    assert_eq!(action.severity, "high");
    results.push(action);

    // Generate alert
    for a in &results {
        if let Some(alert) = alerts.evaluate(
            "chain_wmi",
            &a.severity,
            "powershell.exe",
            a.pid,
            "WMI spawned PowerShell",
        ) {
            alert_events.push(format!("{}/{}", alert.rule_id, alert.severity));
            assert_eq!(alert.severity, "high");
        }
    }

    // ── Step 3: Registry persistence ──
    let reg_action = engine
        .check_registry_event(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SvcHost",
            4,
        )
        .expect("should detect registry persistence");
    assert_eq!(reg_action.action_type, "alert_only");
    assert_eq!(reg_action.severity, "medium");
    if let Some(alert) = alerts.evaluate(
        "registry_persistence",
        &reg_action.severity,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SvcHost",
        reg_action.pid,
        "Registry persistence key set",
    ) {
        alert_events.push(format!("{}/{}", alert.rule_id, alert.severity));
        assert_eq!(alert.severity, "medium");
    }

    // ── Step 4: File drop in Tasks folder (IoC match) ──
    let file_action = engine
        .check_file_event("C:\\Windows\\Tasks\\updater.exe", 4)
        .expect("should detect IoC file match");
    assert_eq!(file_action.action_type, "quarantine_file");
    assert_eq!(file_action.severity, "high");
    if let Some(alert) = alerts.evaluate(
        "ioc_file",
        &file_action.severity,
        "C:\\Windows\\Tasks\\updater.exe",
        file_action.pid,
        "IoC file match: C:\\Windows\\Tasks\\updater.exe",
    ) {
        alert_events.push(format!("{}/{}", alert.rule_id, alert.severity));
    }

    // ── Step 5: File drop in AppData (registry combo → critical) ──
    let combo_action = engine
        .check_file_event(
            "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.ps1",
            4,
        )
        .expect("should detect registry+file combo");
    assert_eq!(combo_action.action_type, "quarantine_file");
    assert_eq!(
        combo_action.severity, "critical",
        "combo with recent registry write must be critical"
    );
    if let Some(alert) = alerts.evaluate(
        "combo_file_registry",
        &combo_action.severity,
        "backdoor.ps1",
        combo_action.pid,
        "Registry persistence + file drop in AppData",
    ) {
        alert_events.push(format!("{}/{}", alert.rule_id, alert.severity));
    }

    // Verify total detection count and all alert severities
    assert_eq!(
        engine.detection_count(),
        4,
        "should have 4 detections: WMI chain + registry + 2 file events"
    );

    // Verify all alert severities recorded
    let all_sevs: Vec<&str> = alert_events
        .iter()
        .map(|s| s.split('/').nth(1).unwrap())
        .collect();
    assert!(
        all_sevs.contains(&"critical"),
        "should have at least one critical alert"
    );
    assert!(all_sevs.contains(&"high"));
    assert!(all_sevs.contains(&"medium"));
}

// ──────────────────────────────────────────────
// Scenario 8: Multiple IoC types with realistic ETW-style JSON events
// ──────────────────────────────────────────────
#[test]
fn test_realistic_ioc_types_as_etw_would_emit() {
    let mut engine = LocalDetectionEngine::new();
    engine.load_iocs(&make_policy(
        &[
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "C:\\Users\\public\\malware\\ransomware.exe",
            "malicious-panel.xyz",
            "10.0.0.50",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MaliciousService",
        ],
        &[],
    ));

    // ETW file event with JSON payload
    let file_event = json!({
        "event_type": "EVENT_TYPE_FILE_CREATE",
        "data": {
            "path": "C:\\Users\\public\\malware\\ransomware.exe",
            "pid": 1044,
            "process_name": "cmd.exe"
        }
    });
    let m = engine
        .check_event_json(&file_event.to_string())
        .expect("file path IoC should match");
    assert_eq!(m.match_type, "ioc_path");

    // ETW DNS event
    let dns_event = json!({
        "event_type": "EVENT_TYPE_DNS_QUERY",
        "data": {
            "query": "malicious-panel.xyz",
            "pid": 1044
        }
    });
    let m = engine
        .check_event_json(&dns_event.to_string())
        .expect("domain IoC should match");
    assert_eq!(m.match_type, "ioc_domain");

    // ETW network event
    let net_event = json!({
        "event_type": "EVENT_TYPE_NETWORK_CONNECT",
        "data": {
            "remote_address": "10.0.0.50",
            "remote_port": 4444,
            "pid": 1044,
            "protocol": "TCP"
        }
    });
    let m = engine
        .check_event_json(&net_event.to_string())
        .expect("IP IoC should match");
    assert_eq!(m.match_type, "ioc_ip");

    // ETW registry event
    let reg_event = json!({
        "event_type": "EVENT_TYPE_REGISTRY_CHANGE",
        "data": {
            "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MaliciousService",
            "pid": 1044
        }
    });
    let m = engine
        .check_event_json(&reg_event.to_string())
        .expect("registry IoC should match");
    assert_eq!(m.match_type, "ioc_registry");
}

// ──────────────────────────────────────────────
// Scenario 9: Case insensitivity across all detection paths
// ETW events have varying casing
// ──────────────────────────────────────────────
#[test]
fn test_case_insensitivity_across_all_paths() {
    let mut engine = LocalDetectionEngine::new();
    engine.load_iocs(&make_policy(&["MALWARE.EXE"], &[]));

    // Process event with different casing
    let action = engine.check_process_event(9001, 0, "Malware.Exe", "");
    assert!(action.is_some(), "casing should not matter for IoC match");
    assert_eq!(action.unwrap().severity, "high");

    // Suspicious process with different casing
    let action = engine.check_process_event(9002, 0, "PowerShell.EXE", "powershell.exe -enc abc");
    assert!(
        action.is_some(),
        "casing should not matter for suspicious list"
    );
    assert_eq!(action.unwrap().severity, "medium");

    // Spawn chain with different casing
    let action = engine.check_process_chain(9003, 0, "POWERSHELL.EXE", "WINWORD.EXE");
    assert!(
        action.is_some(),
        "chain detection should be case-insensitive"
    );
    assert_eq!(action.unwrap().severity, "high");

    // Registry persistence with different casing
    let action = engine.check_registry_event(
        r"hklm\software\microsoft\windows\currentversion\run\evil",
        9004,
    );
    assert!(
        action.is_some(),
        "registry persistence should be case-insensitive"
    );
}

// ──────────────────────────────────────────────
// Scenario 10: IoC policy update mid-session
// Simulates the policy sync worker updating IoCs while detection is running
// ──────────────────────────────────────────────
#[test]
fn test_policy_update_mid_session() {
    let mut engine = LocalDetectionEngine::new();

    // No IoCs loaded yet → no match
    assert!(
        engine
            .check_process_event(10001, 0, "unknown.exe", "")
            .is_none()
    );
    assert_eq!(engine.ioc_count(), 0);

    // First policy sync adds IoCs
    engine.load_iocs(&make_policy(&["unknown.exe"], &[]));
    assert_eq!(engine.ioc_count(), 1);

    // Now the same process should be detected
    let action = engine.check_process_event(10001, 0, "unknown.exe", "");
    assert!(action.is_some(), "IoC should match after policy update");
    assert_eq!(action.unwrap().severity, "high");
    assert_eq!(engine.detection_count(), 1);

    // Second policy sync adds more IoCs
    engine.load_iocs(&make_policy(&["unknown.exe", "also_evil.exe"], &[]));
    assert_eq!(engine.ioc_count(), 2);

    // New IoC also detected
    let action = engine.check_process_event(10002, 0, "also_evil.exe", "");
    assert!(action.is_some(), "new IoC should match after policy update");
    assert_eq!(engine.detection_count(), 2);
}

// ──────────────────────────────────────────────
// Scenario 11: AlertManager alert_to_event metadata
// Verifies that alerts get proper metadata for the event buffer
// ──────────────────────────────────────────────
#[test]
fn test_alert_conversion_to_event_metadata() {
    let mut alerts = AlertManager::new();
    let alert = alerts.evaluate("rule_combo", "critical", "evil.ps1", 7777, "Combo detected");
    assert!(alert.is_some());
    let alert = alert.unwrap();

    // Convert to protobuf Event as uploader worker would
    let event = alerts.alert_to_event(&alert);
    let meta: HashMap<&str, &str> = event
        .metadata
        .iter()
        .map(|m| (m.key.as_str(), m.value.as_str()))
        .collect();

    assert_eq!(meta.get("source"), Some(&"local_detection"));
    assert_eq!(meta.get("alert.rule_id"), Some(&"rule_combo"));
    assert_eq!(meta.get("alert.severity"), Some(&"critical"));
    assert_eq!(meta.get("alert.match_value"), Some(&"evil.ps1"));
    assert_eq!(meta.get("alert.pid"), Some(&"7777"));
    assert_eq!(meta.get("alert.count"), Some(&"1"));
    assert!(meta.contains_key("alert.description"));
    assert!(event.id.is_some(), "alert event must have a UUID");
    assert!(
        event.id.as_ref().unwrap().value.len() == 16,
        "UUID must be 16 bytes"
    );
}

// ──────────────────────────────────────────────
// Scenario 12: No false positives for legitimate admin activity
// ──────────────────────────────────────────────
#[test]
fn test_no_false_positives_for_legitimate_activity() {
    let mut engine = LocalDetectionEngine::new();

    // Common admin tools and normal OS activity
    let safe_processes = [
        ("svchost.exe", "services.exe"),
        ("services.exe", "wininit.exe"),
        ("wininit.exe", "kernel.exe"),
        ("explorer.exe", "userinit.exe"),
        ("taskmgr.exe", "explorer.exe"),
        ("mmc.exe", "explorer.exe"),
        ("notepad.exe", "explorer.exe"),
        ("devenv.exe", "explorer.exe"),
        ("code.exe", "explorer.exe"),
        ("chrome.exe", "explorer.exe"),
        ("msedge.exe", "explorer.exe"),
        ("OUTLOOK.EXE", "explorer.exe"),
        ("Teams.exe", "explorer.exe"),
        ("Spotify.exe", "explorer.exe"),
        ("slack.exe", "explorer.exe"),
    ];

    // Register all spawns
    for (i, (child, parent)) in safe_processes.iter().enumerate() {
        let result = engine.check_process_chain(i as u32, 0, child, parent);
        assert!(
            result.is_none(),
            "false positive: {} spawned by {} should not match",
            child,
            parent
        );
    }

    // Safe file paths
    let safe_paths = [
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Users\\user\\Documents\\report.docx",
        "C:\\Users\\user\\Desktop\\notes.txt",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\notepad.lnk",
    ];

    for path in &safe_paths {
        let result = engine.check_file_event(path, 0);
        assert!(
            result.is_none(),
            "false positive: file path {} should not match",
            path
        );
    }

    // Safe registry paths
    let safe_reg_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Chrome",
        r"HKLM\SOFTWARE\Classes\.txt",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList",
    ];

    for key in &safe_reg_keys {
        let result = engine.check_registry_event(key, 0);
        assert!(
            result.is_none(),
            "false positive: registry key {} should not match",
            key
        );
    }

    assert_eq!(engine.detection_count(), 0, "no false positives allowed");
}

// ──────────────────────────────────────────────
// Scenario 13: ChainDetector directly tested with all 15 spawn chain rules
// ──────────────────────────────────────────────
#[test]
fn test_all_spawn_chain_rules() {
    let rules: Vec<(&str, &str, &str)> = vec![
        // (parent, child, expected_severity)
        ("winword.exe", "powershell.exe", "high"),
        ("excel.exe", "powershell.exe", "high"),
        ("outlook.exe", "powershell.exe", "high"),
        ("winword.exe", "cmd.exe", "high"),
        ("excel.exe", "cmd.exe", "high"),
        ("cmd.exe", "powershell.exe", "medium"),
        ("powershell.exe", "cmd.exe", "medium"),
        ("powershell.exe", "wscript.exe", "medium"),
        ("powershell.exe", "cscript.exe", "medium"),
        ("chrome.exe", "powershell.exe", "high"),
        ("msedge.exe", "powershell.exe", "high"),
        ("wmiprvse.exe", "powershell.exe", "high"),
        ("wmiprvse.exe", "cmd.exe", "medium"),
        ("rundll32.exe", "powershell.exe", "high"),
        ("mshta.exe", "powershell.exe", "high"),
    ];

    let mut cd = ChainDetector::new();
    for (i, (parent, child, expected_sev)) in rules.iter().enumerate() {
        let result = cd.check_spawn_chain(i as u32, 0, child, parent);
        assert!(
            result.is_some(),
            "chain rule {} -> {} should match",
            parent,
            child
        );
        assert_eq!(
            result.unwrap().severity,
            *expected_sev,
            "severity for {} -> {}",
            parent,
            child
        );
    }
}

// ──────────────────────────────────────────────
// Scenario 14: Negative test — non-matching events should never fire
// ──────────────────────────────────────────────
#[test]
fn test_negative_cases_for_all_event_types() {
    let mut engine = LocalDetectionEngine::new();

    // Non-suspicious process, no IoC, no chain
    assert!(
        engine
            .check_process_event(0, 0, "explorer.exe", "")
            .is_none()
    );
    assert!(
        engine
            .check_process_chain(0, 0, "explorer.exe", "wininit.exe")
            .is_none()
    );

    // No registry persistence
    assert!(
        engine
            .check_registry_event(r"HKLM\SOFTWARE\Classes\.exe", 0)
            .is_none()
    );
    assert!(
        engine
            .check_registry_event(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App",
                0
            )
            .is_none()
    );

    // No IoC file match, no registry combo
    assert!(
        engine
            .check_file_event("C:\\Windows\\System32\\calc.exe", 0)
            .is_none()
    );
    assert!(
        engine
            .check_file_event("C:\\Users\\user\\AppData\\Local\\temp\\readme.txt", 0)
            .is_none()
    );

    assert_eq!(engine.detection_count(), 0);
}

// ──────────────────────────────────────────────
// Scenario 15: Registry persistence key variations
// Tests all 6 persistence key patterns
// ──────────────────────────────────────────────
#[test]
fn test_all_registry_persistence_key_patterns() {
    let mut cd = ChainDetector::new();

    let persistence_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows Defender",
    ];

    for (i, key) in persistence_keys.iter().enumerate() {
        let result = cd.check_registry_event(key, i as u32);
        assert!(result.is_some(), "should detect persistence key: {}", key);
        assert_eq!(result.unwrap().action_type, "alert_only");
    }
}
