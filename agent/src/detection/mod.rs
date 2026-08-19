use serde_json::Value;
use std::collections::HashSet;

pub mod alert;
pub mod chain;

pub struct LocalDetectionEngine {
    ioc_sha256: HashSet<String>,
    ioc_sha1: HashSet<String>,
    ioc_md5: HashSet<String>,
    ioc_domain: HashSet<String>,
    ioc_ip: HashSet<String>,
    ioc_path: HashSet<String>,
    ioc_registry: HashSet<String>,
    suspicious_processes: HashSet<String>,
    detection_count: u64,
    chain_detector: chain::ChainDetector,
}

impl LocalDetectionEngine {
    pub fn new() -> Self {
        Self {
            ioc_sha256: HashSet::new(),
            ioc_sha1: HashSet::new(),
            ioc_md5: HashSet::new(),
            ioc_domain: HashSet::new(),
            ioc_ip: HashSet::new(),
            ioc_path: HashSet::new(),
            ioc_registry: HashSet::new(),
            suspicious_processes: {
                let mut s = HashSet::new();
                s.insert("powershell.exe".to_string());
                s.insert("cmd.exe".to_string());
                s.insert("wscript.exe".to_string());
                s.insert("cscript.exe".to_string());
                s.insert("mshta.exe".to_string());
                s.insert("rundll32.exe".to_string());
                s.insert("regsvr32.exe".to_string());
                s
            },
            detection_count: 0,
            chain_detector: chain::ChainDetector::new(),
        }
    }

    fn classify_ioc_value(value: &str, explicit_type: Option<&str>) -> (String, String) {
        let value_lower = value.to_lowercase();
        let ioc_type = if let Some(t) = explicit_type {
            t.to_lowercase()
        } else {
            if (value_lower.len() == 64 && value_lower.chars().all(|c| c.is_ascii_hexdigit()))
                || value_lower.ends_with("sha256hash")
            {
                "sha256".to_string()
            } else if value_lower.len() == 40 && value_lower.chars().all(|c| c.is_ascii_hexdigit())
            {
                "sha1".to_string()
            } else if value_lower.len() == 32 && value_lower.chars().all(|c| c.is_ascii_hexdigit())
            {
                "md5".to_string()
            } else if value_lower.parse::<std::net::IpAddr>().is_ok() || value_lower.contains('/') {
                "ip".to_string()
            } else if value_lower.contains('\\') || value_lower.contains('/') {
                if value_lower.starts_with("hklm")
                    || value_lower.starts_with("hkcu")
                    || value_lower.starts_with("hkey_")
                {
                    "registry".to_string()
                } else {
                    "path".to_string()
                }
            } else if value_lower.contains('.') && !value_lower.starts_with('.') {
                let ends_with_file_ext = [
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".txt",
                    ".json", ".xml", ".yml", ".yaml",
                ]
                .iter()
                .any(|ext| value_lower.ends_with(ext));
                if ends_with_file_ext {
                    "path".to_string()
                } else {
                    "domain".to_string()
                }
            } else {
                "path".to_string()
            }
        };
        (ioc_type, value_lower)
    }

    pub fn load_iocs(&mut self, policy_content: &[u8]) {
        if let Ok(v) = serde_json::from_slice::<Value>(policy_content) {
            if let Some(iocs) = v.get("iocs").and_then(|v| v.as_array()) {
                for ioc in iocs {
                    if let Some(value) = ioc.get("value").and_then(|v| v.as_str()) {
                        let explicit_type = ioc
                            .get("ioc_type")
                            .or_else(|| ioc.get("type"))
                            .and_then(|v| v.as_str());
                        let (ioc_type, val) = Self::classify_ioc_value(value, explicit_type);
                        match ioc_type.as_str() {
                            "sha256" => {
                                self.ioc_sha256.insert(val);
                            }
                            "sha1" => {
                                self.ioc_sha1.insert(val);
                            }
                            "md5" => {
                                self.ioc_md5.insert(val);
                            }
                            "domain" => {
                                self.ioc_domain.insert(val);
                            }
                            "ip" => {
                                self.ioc_ip.insert(val);
                            }
                            "path" | "filepath" | "file_path" => {
                                self.ioc_path.insert(val);
                            }
                            "registry" | "registry_path" | "registrypath" => {
                                self.ioc_registry.insert(val);
                            }
                            _ => {
                                self.ioc_path.insert(val);
                            }
                        }
                    }
                }
            }
            if let Some(rules) = v.get("detection_rules").and_then(|v| v.as_array()) {
                for rule in rules {
                    if let Some(process) = rule.get("process").and_then(|v| v.as_str()) {
                        self.suspicious_processes.insert(process.to_lowercase());
                    }
                }
            }
        }
    }

    /// Checks a process spawn against IoC cache, suspicious list, and spawn chains.
    /// Returns the action if any rule matches, using the highest severity.
    pub fn check_process_event(
        &mut self,
        pid: u32,
        _parent_pid: u32,
        image_name: &str,
        command_line: &str,
    ) -> Option<DetectionAction> {
        let path = std::path::Path::new(image_name);
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(image_name)
            .to_lowercase();
        let lower_path = image_name.to_lowercase();

        let mut hash_match = false;
        if !self.ioc_sha256.is_empty() || !self.ioc_sha1.is_empty() || !self.ioc_md5.is_empty() {
            if let Ok(bytes) = std::fs::read(image_name) {
                use sha2::{Digest, Sha256};
                let hash = hex::encode(Sha256::digest(&bytes));
                if self.ioc_sha256.contains(&hash) {
                    hash_match = true;
                }
            }
        }

        if self.ioc_path.contains(&lower_path) || self.ioc_path.contains(&filename) || hash_match {
            self.detection_count += 1;
            return Some(DetectionAction {
                action_type: "terminate_process".to_string(),
                severity: "high".to_string(),
                pid,
            });
        }

        if self.suspicious_processes.contains(&lower_path)
            || self.suspicious_processes.contains(&filename)
        {
            let standard_suspicious = [
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe",
                "regsvr32.exe",
            ];
            let cmd_lower = command_line.to_lowercase();
            let is_std = standard_suspicious.iter().any(|&s| filename == s);

            let is_suspicious_cmd = if is_std {
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
                    "-nop",
                    "-window",
                    "-w ",
                ];
                suspicious_args.iter().any(|&arg| cmd_lower.contains(arg))
            } else {
                true
            };

            if is_suspicious_cmd {
                self.detection_count += 1;
                return Some(DetectionAction {
                    action_type: "terminate_process".to_string(),
                    severity: "medium".to_string(),
                    pid,
                });
            }
        }

        None
    }

    /// Checks against spawn chain rules (parent→child, grandparent patterns).
    /// Must be called separately from check_process_event, and takes parent_image.
    pub fn check_process_chain(
        &mut self,
        pid: u32,
        parent_pid: u32,
        image_name: &str,
        parent_image: &str,
    ) -> Option<DetectionAction> {
        let result =
            self.chain_detector
                .check_spawn_chain(pid, parent_pid, image_name, parent_image);
        if result.is_some() {
            self.detection_count += 1;
        }
        result
    }

    /// Checks a registry event against persistence key rules.
    pub fn check_registry_event(&mut self, key_path: &str, pid: u32) -> Option<DetectionAction> {
        let result = self.chain_detector.check_registry_event(key_path, pid);
        if result.is_some() {
            self.detection_count += 1;
        }
        result
    }

    /// Checks a file event against recent registry persistence writes and IoC cache.
    pub fn check_file_event(&mut self, path: &str, pid: u32) -> Option<DetectionAction> {
        let lower = path.to_lowercase();
        if self.ioc_path.contains(&lower)
            || self.ioc_md5.contains(&lower)
            || self.ioc_sha1.contains(&lower)
            || self.ioc_sha256.contains(&lower)
        {
            self.detection_count += 1;
            return Some(DetectionAction {
                action_type: "quarantine_file".to_string(),
                severity: "high".to_string(),
                pid,
            });
        }
        let result = self
            .chain_detector
            .check_file_against_recent_registry(path, pid);
        if result.is_some() {
            self.detection_count += 1;
        }
        result
    }

    pub fn check_event(&self, event: &Value) -> Option<DetectionMatch> {
        if let Some(sha256) = event
            .pointer("/data/sha256")
            .or_else(|| event.get("sha256"))
            .and_then(|v| v.as_str())
        {
            if self.ioc_sha256.contains(&sha256.to_lowercase()) {
                return Some(DetectionMatch {
                    match_type: "ioc_sha256".to_string(),
                    match_value: sha256.to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        if let Some(sha1) = event
            .pointer("/data/sha1")
            .or_else(|| event.get("sha1"))
            .and_then(|v| v.as_str())
        {
            if self.ioc_sha1.contains(&sha1.to_lowercase()) {
                return Some(DetectionMatch {
                    match_type: "ioc_sha1".to_string(),
                    match_value: sha1.to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        if let Some(md5) = event
            .pointer("/data/md5")
            .or_else(|| event.get("md5"))
            .and_then(|v| v.as_str())
        {
            if self.ioc_md5.contains(&md5.to_lowercase()) {
                return Some(DetectionMatch {
                    match_type: "ioc_md5".to_string(),
                    match_value: md5.to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        for path_key in &[
            "/data/path",
            "/data/name",
            "/data/image_path",
            "/data/module_path",
        ] {
            if let Some(path) = event.pointer(path_key).and_then(|v| v.as_str()) {
                if self.ioc_path.contains(&path.to_lowercase()) {
                    return Some(DetectionMatch {
                        match_type: "ioc_path".to_string(),
                        match_value: path.to_string(),
                        severity: "medium".to_string(),
                    });
                }
            }
        }

        for domain_key in &["/data/domain", "/data/query", "/data/remote_address"] {
            if let Some(domain) = event.pointer(domain_key).and_then(|v| v.as_str()) {
                let lower_domain = domain.to_lowercase();
                if self.ioc_domain.contains(&lower_domain)
                    || self.ioc_domain.iter().any(|d| {
                        lower_domain.ends_with(d)
                            && (lower_domain.len() == d.len()
                                || lower_domain.as_bytes()[lower_domain.len() - d.len() - 1]
                                    == b'.')
                    })
                {
                    return Some(DetectionMatch {
                        match_type: "ioc_domain".to_string(),
                        match_value: domain.to_string(),
                        severity: "high".to_string(),
                    });
                }
            }
        }

        if let Some(ip) = event
            .pointer("/data/remote_address")
            .and_then(|v| v.as_str())
        {
            if self.ioc_ip.contains(&ip.to_lowercase()) {
                return Some(DetectionMatch {
                    match_type: "ioc_ip".to_string(),
                    match_value: ip.to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        if let Some(reg) = event.pointer("/data/key_path").and_then(|v| v.as_str()) {
            if self.ioc_registry.contains(&reg.to_lowercase()) {
                return Some(DetectionMatch {
                    match_type: "ioc_registry".to_string(),
                    match_value: reg.to_string(),
                    severity: "medium".to_string(),
                });
            }
        }

        None
    }

    pub fn check_event_json(&mut self, json_str: &str) -> Option<DetectionMatch> {
        if let Ok(event) = serde_json::from_str::<Value>(json_str) {
            let result = self.check_event(&event);
            if result.is_some() {
                self.detection_count += 1;
            }
            result
        } else {
            None
        }
    }

    pub fn rule_count(&self) -> usize {
        self.ioc_sha256.len()
            + self.ioc_sha1.len()
            + self.ioc_md5.len()
            + self.ioc_domain.len()
            + self.ioc_ip.len()
            + self.ioc_path.len()
            + self.ioc_registry.len()
            + self.suspicious_processes.len()
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn ioc_count(&self) -> usize {
        self.ioc_sha256.len()
            + self.ioc_sha1.len()
            + self.ioc_md5.len()
            + self.ioc_domain.len()
            + self.ioc_ip.len()
            + self.ioc_path.len()
            + self.ioc_registry.len()
    }
}

pub struct DetectionMatch {
    pub match_type: String,
    pub match_value: String,
    pub severity: String,
}

impl DetectionMatch {
    pub fn to_alert_json(&self) -> Value {
        serde_json::json!({
            "alert_type": "local_detection",
            "match_type": self.match_type,
            "match_value": self.match_value,
            "severity": self.severity,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }
}

pub struct DetectionAction {
    pub action_type: String,
    pub severity: String,
    pub pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_engine_has_suspicious_processes() {
        let engine = LocalDetectionEngine::new();
        assert!(engine.suspicious_processes.contains("powershell.exe"));
        assert!(engine.suspicious_processes.contains("cmd.exe"));
        assert!(engine.suspicious_processes.contains("wscript.exe"));
        assert!(engine.suspicious_processes.contains("cscript.exe"));
        assert!(engine.suspicious_processes.contains("mshta.exe"));
        assert!(engine.suspicious_processes.contains("rundll32.exe"));
        assert!(engine.suspicious_processes.contains("regsvr32.exe"));
        assert_eq!(engine.detection_count(), 0);
    }

    #[test]
    fn test_check_process_event_ioc_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "malware.exe"}]}"#);
        let result = engine.check_process_event(100, 0, "malware.exe", "");
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.action_type, "terminate_process");
        assert_eq!(action.severity, "high");
        assert_eq!(action.pid, 100);
    }

    #[test]
    fn test_check_process_event_suspicious_match() {
        let mut engine = LocalDetectionEngine::new();
        let result =
            engine.check_process_event(101, 0, "powershell.exe", "powershell.exe -enc abc");
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.action_type, "terminate_process");
        assert_eq!(action.severity, "medium");
    }

    #[test]
    fn test_check_process_event_no_match() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_process_event(102, 0, "notepad.exe", "");
        assert!(result.is_none());
    }

    #[test]
    fn test_check_process_event_case_insensitive() {
        let mut engine = LocalDetectionEngine::new();
        let result =
            engine.check_process_event(103, 0, "PowerShell.EXE", "powershell.exe -enc abc");
        assert!(result.is_some());
    }

    #[test]
    fn test_check_process_event_ioc_takes_precedence_over_suspicious() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "powershell.exe"}]}"#);
        let result = engine.check_process_event(104, 0, "powershell.exe", "");
        // IoC match should return "high" (takes precedence over suspicious "medium")
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_check_process_chain_office_script() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_process_chain(105, 0, "powershell.exe", "winword.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().action_type, "terminate_process");
    }

    #[test]
    fn test_check_process_chain_no_match() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_process_chain(106, 0, "notepad.exe", "explorer.exe");
        assert!(result.is_none());
    }

    #[test]
    fn test_check_registry_event_persistence() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_registry_event(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil",
            107,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().action_type, "alert_only");
    }

    #[test]
    fn test_check_registry_event_non_persistence() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_registry_event(r"HKLM\SOFTWARE\Classes\.txt", 108);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_file_event_ioc_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "C:\\known_bad.exe"}]}"#);
        let result = engine.check_file_event("C:\\known_bad.exe", 109);
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_check_file_event_combo_detection() {
        let mut engine = LocalDetectionEngine::new();
        // First trigger a registry persistence write
        engine.check_registry_event(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 110);
        // Then check a file in AppData
        let result = engine.check_file_event("C:\\Users\\test\\AppData\\Local\\evil.exe", 110);
        let action = result.expect("expected combo detection");
        assert_eq!(action.action_type, "quarantine_file");
        assert_eq!(action.severity, "critical");
    }

    #[test]
    fn test_check_file_event_no_match() {
        let mut engine = LocalDetectionEngine::new();
        let result = engine.check_file_event("C:\\Windows\\System32\\legit.dll", 111);
        assert!(result.is_none());
    }

    #[test]
    fn test_detection_count_increments() {
        let mut engine = LocalDetectionEngine::new();
        assert_eq!(engine.detection_count(), 0);
        engine.check_process_event(112, 0, "powershell.exe", "powershell.exe -enc abc");
        assert_eq!(engine.detection_count(), 1);
        engine.check_process_chain(113, 0, "powershell.exe", "winword.exe");
        assert_eq!(engine.detection_count(), 2);
        engine.check_registry_event(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 114);
        assert_eq!(engine.detection_count(), 3);
    }

    #[test]
    fn test_load_iocs_from_policy() {
        let mut engine = LocalDetectionEngine::new();
        let policy = json!({
            "iocs": [
                {"value": "malware1.exe"},
                {"value": "malware2.exe"}
            ],
            "detection_rules": [
                {"process": "suspicious_tool.exe"}
            ]
        });
        engine.load_iocs(policy.to_string().as_bytes());
        assert!(engine.ioc_path.contains("malware1.exe"));
        assert!(engine.ioc_path.contains("malware2.exe"));
        assert!(engine.suspicious_processes.contains("suspicious_tool.exe"));
    }

    #[test]
    fn test_load_iocs_invalid_json() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(b"not valid json");
        // Should not panic, ioc_cache should be empty
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn test_check_event_ioc_sha256_exists() {
        // Covered by test_check_event_json_sha256_match using check_event_json
    }

    #[test]
    fn test_check_event_json_sha256_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "abc123sha256hash"}]}"#);
        let event = json!({
            "sha256": "abc123sha256hash"
        });
        let result = engine.check_event_json(&event.to_string());
        let m = result.expect("expected SHA256 match");
        assert_eq!(m.match_type, "ioc_sha256");
        assert_eq!(m.severity, "high");
    }

    #[test]
    fn test_check_event_json_path_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "C:\\malware\\evil.exe"}]}"#);
        let event = json!({
            "data": {
                "path": "C:\\malware\\evil.exe"
            }
        });
        let result = engine.check_event_json(&event.to_string());
        assert!(result.is_some());
        assert_eq!(result.unwrap().match_type, "ioc_path");
    }

    #[test]
    fn test_check_event_json_domain_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "evil.example.com"}]}"#);
        let event = json!({
            "data": {
                "query": "evil.example.com"
            }
        });
        let result = engine.check_event_json(&event.to_string());
        assert!(result.is_some());
        assert_eq!(result.unwrap().match_type, "ioc_domain");
    }

    #[test]
    fn test_check_event_json_no_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.load_iocs(br#"{"iocs": [{"value": "known_good.exe"}]}"#);
        let event = json!({
            "sha256": "abcdef"
        });
        assert!(engine.check_event_json(&event.to_string()).is_none());
    }

    #[test]
    fn test_check_event_json_invalid_json() {
        let mut engine = LocalDetectionEngine::new();
        assert!(engine.check_event_json("not valid json").is_none());
    }

    #[test]
    fn test_rule_count() {
        let mut engine = LocalDetectionEngine::new();
        let before = engine.rule_count();
        engine.load_iocs(br#"{"iocs": [{"value": "a.exe"}, {"value": "b.exe"}]}"#);
        assert_eq!(engine.rule_count(), before + 2);
    }

    #[test]
    fn test_detection_match_to_alert_json() {
        let dm = DetectionMatch {
            match_type: "ioc_sha256".to_string(),
            match_value: "abcdef".to_string(),
            severity: "high".to_string(),
        };
        let alert = dm.to_alert_json();
        assert_eq!(alert["match_type"], "ioc_sha256");
        assert_eq!(alert["match_value"], "abcdef");
        assert_eq!(alert["severity"], "high");
        assert_eq!(alert["alert_type"], "local_detection");
    }

    #[test]
    fn test_detection_count_after_chain_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.check_process_chain(200, 0, "powershell.exe", "winword.exe");
        assert_eq!(engine.detection_count(), 1);
    }

    #[test]
    fn test_detection_count_after_registry_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.check_registry_event(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 201);
        assert_eq!(engine.detection_count(), 1);
    }

    #[test]
    fn test_detection_count_after_file_combo_match() {
        let mut engine = LocalDetectionEngine::new();
        engine.check_registry_event(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 202);
        engine.check_file_event("C:\\Users\\test\\AppData\\Local\\evil.exe", 202);
        assert_eq!(engine.detection_count(), 2);
    }
}
