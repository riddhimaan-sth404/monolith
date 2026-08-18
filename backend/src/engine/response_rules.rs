use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionSource {
    Yara,
    Heuristic,
    Ember,
    Correlation,
    Ioc,
}

impl std::str::FromStr for DetectionSource {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "yara" => Ok(DetectionSource::Yara),
            "heuristic" => Ok(DetectionSource::Heuristic),
            "ember" => Ok(DetectionSource::Ember),
            "correlation" => Ok(DetectionSource::Correlation),
            "ioc" => Ok(DetectionSource::Ioc),
            _ => Err(format!("unknown detection source: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CorrelationType {
    CredentialDumping,
    Ransomware,
    Lolbin,
    Persistence,
    Exfiltration,
    IndicatorRemoval,
    Masquerading,
    BruteForce,
    PowershellSuspicious,
    Discovery,
    NetworkScanning,
    RemoteAccess,
}

impl std::str::FromStr for CorrelationType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "credential_dumping" => Ok(CorrelationType::CredentialDumping),
            "ransomware" => Ok(CorrelationType::Ransomware),
            "lolbin" => Ok(CorrelationType::Lolbin),
            "persistence" => Ok(CorrelationType::Persistence),
            "exfiltration" => Ok(CorrelationType::Exfiltration),
            "indicator_removal" => Ok(CorrelationType::IndicatorRemoval),
            "masquerading" => Ok(CorrelationType::Masquerading),
            "brute_force" => Ok(CorrelationType::BruteForce),
            "powershell_suspicious" => Ok(CorrelationType::PowershellSuspicious),
            "discovery" => Ok(CorrelationType::Discovery),
            "network_scanning" => Ok(CorrelationType::NetworkScanning),
            "remote_access" => Ok(CorrelationType::RemoteAccess),
            _ => Err(format!("unknown correlation type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    MinSeverity { value: u32 },
    Source { sources: Vec<DetectionSource> },
    Correlation { correlation_types: Vec<CorrelationType> },
    MinScore { value: f64 },
    MaxScore { value: f64 },
    Composite {
        op: String,
        conditions: Vec<RuleCondition>,
    },
}

impl RuleCondition {
    pub fn matches(&self, alert: &AlertInfo) -> bool {
        match self {
            RuleCondition::MinSeverity { value } => alert.severity_score >= *value,
            RuleCondition::Source { sources } => {
                sources.iter().any(|s| alert.sources.contains(s))
            }
            RuleCondition::Correlation { correlation_types } => {
                if let Some(ref ct) = alert.correlation_type {
                    correlation_types.contains(ct)
                } else {
                    false
                }
            }
            RuleCondition::MinScore { value } => alert.score >= *value,
            RuleCondition::MaxScore { value } => alert.score <= *value,
            RuleCondition::Composite { op, conditions } => {
                match op.to_lowercase().as_str() {
                    "and" => conditions.iter().all(|c| c.matches(alert)),
                    "or" => conditions.iter().any(|c| c.matches(alert)),
                    _ => false,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleAction {
    IsolateEndpoint,
    QuarantineFile,
    TerminateProcess,
    RunSandbox,
    KillAndQuarantine,
    ShredFile,
    AlertOnly,
}

impl RuleAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::IsolateEndpoint => "isolate_endpoint",
            RuleAction::QuarantineFile => "quarantine_file",
            RuleAction::TerminateProcess => "terminate_process",
            RuleAction::RunSandbox => "run_sandbox",
            RuleAction::KillAndQuarantine => "kill_and_quarantine",
            RuleAction::ShredFile => "shred_file",
            RuleAction::AlertOnly => "alert_only",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    pub id: String,
    pub name: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub cooldown_secs: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AlertInfo {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub severity_score: u32,
    pub score: f64,
    pub endpoint_id: String,
    pub sources: Vec<DetectionSource>,
    pub correlation_type: Option<CorrelationType>,
    pub file_path: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct MatchedAction {
    pub rule_id: String,
    pub action: RuleAction,
    pub target_endpoint: String,
    pub parameters: serde_json::Value,
}

pub struct RuleEngine {
    rules: Vec<ResponseRule>,
    cooldowns: HashMap<String, Instant>,
}

impl RuleEngine {
    pub fn new(rules: Vec<ResponseRule>) -> Self {
        Self {
            rules,
            cooldowns: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, alert: &AlertInfo) -> Vec<MatchedAction> {
        let mut actions = Vec::new();
        let now = Instant::now();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let cool_key = format!("{}:{}", rule.id, alert.endpoint_id);
            if let Some(last) = self.cooldowns.get(&cool_key) {
                if now.duration_since(*last).as_secs() < rule.cooldown_secs {
                    continue;
                }
            }

            if rule.condition.matches(alert) {
                let params = Self::build_params(alert, &rule.action);
                actions.push(MatchedAction {
                    rule_id: rule.id.clone(),
                    action: rule.action.clone(),
                    target_endpoint: alert.endpoint_id.clone(),
                    parameters: params,
                });
                self.cooldowns.insert(cool_key, now);
            }
        }

        actions
    }

    fn build_params(alert: &AlertInfo, action: &RuleAction) -> serde_json::Value {
        match action {
            RuleAction::IsolateEndpoint => serde_json::json!({}),
            RuleAction::QuarantineFile => {
                serde_json::json!({ "path": alert.file_path.as_deref().unwrap_or("") })
            }
            RuleAction::TerminateProcess => {
                serde_json::json!({ "pid": alert.pid.unwrap_or(0) })
            }
            RuleAction::RunSandbox => {
                serde_json::json!({ "path": alert.file_path.as_deref().unwrap_or("") })
            }
            RuleAction::KillAndQuarantine => serde_json::json!({
                "pid": alert.pid.unwrap_or(0),
                "path": alert.file_path.as_deref().unwrap_or(""),
            }),
            RuleAction::ShredFile => {
                serde_json::json!({ "path": alert.file_path.as_deref().unwrap_or("") })
            }
            RuleAction::AlertOnly => serde_json::json!({}),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn enabled_rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

pub fn default_rules() -> Vec<ResponseRule> {
    vec![
        ResponseRule {
            id: "auto_kill_known_bad_hash".into(),
            name: "Kill and quarantine known-bad hash".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Source { sources: vec![DetectionSource::Ioc] },
                    RuleCondition::MinSeverity { value: 5 },
                ],
            },
            action: RuleAction::KillAndQuarantine,
            cooldown_secs: 30,
            enabled: true,
        },
        ResponseRule {
            id: "auto_isolate_credential_dumping".into(),
            name: "Isolate endpoint on credential dumping".into(),
            condition: RuleCondition::Correlation {
                correlation_types: vec![CorrelationType::CredentialDumping],
            },
            action: RuleAction::IsolateEndpoint,
            cooldown_secs: 300,
            enabled: true,
        },
        ResponseRule {
            id: "auto_isolate_ransomware".into(),
            name: "Isolate endpoint on ransomware pattern".into(),
            condition: RuleCondition::Correlation {
                correlation_types: vec![CorrelationType::Ransomware],
            },
            action: RuleAction::IsolateEndpoint,
            cooldown_secs: 120,
            enabled: true,
        },
        ResponseRule {
            id: "auto_kill_lolbin_chain".into(),
            name: "Terminate process on suspicious LOLBin chain".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Correlation {
                        correlation_types: vec![CorrelationType::Lolbin],
                    },
                    RuleCondition::MinSeverity { value: 4 },
                ],
            },
            action: RuleAction::TerminateProcess,
            cooldown_secs: 60,
            enabled: true,
        },
        ResponseRule {
            id: "auto_quarantine_yara_high".into(),
            name: "Quarantine file on high-severity YARA match".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Source { sources: vec![DetectionSource::Yara] },
                    RuleCondition::MinSeverity { value: 4 },
                ],
            },
            action: RuleAction::QuarantineFile,
            cooldown_secs: 60,
            enabled: true,
        },
        ResponseRule {
            id: "auto_quarantine_ember_malicious".into(),
            name: "Quarantine file when EMBER score > 0.8".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Source { sources: vec![DetectionSource::Ember] },
                    RuleCondition::MinScore { value: 8.0 },
                ],
            },
            action: RuleAction::QuarantineFile,
            cooldown_secs: 60,
            enabled: true,
        },
        ResponseRule {
            id: "auto_sandbox_ember_gray".into(),
            name: "Run sandbox on EMBER gray zone (0.3-0.8)".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Source { sources: vec![DetectionSource::Ember] },
                    RuleCondition::MinScore { value: 3.0 },
                    RuleCondition::MaxScore { value: 7.999 },
                ],
            },
            action: RuleAction::RunSandbox,
            cooldown_secs: 300,
            enabled: true,
        },
        ResponseRule {
            id: "auto_quarantine_persistence".into(),
            name: "Quarantine file on suspicious persistence".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Correlation {
                        correlation_types: vec![CorrelationType::Persistence],
                    },
                    RuleCondition::MinSeverity { value: 3 },
                ],
            },
            action: RuleAction::QuarantineFile,
            cooldown_secs: 120,
            enabled: true,
        },
        ResponseRule {
            id: "auto_isolate_log_clearing".into(),
            name: "Isolate endpoint on log clearing".into(),
            condition: RuleCondition::Correlation {
                correlation_types: vec![CorrelationType::IndicatorRemoval],
            },
            action: RuleAction::IsolateEndpoint,
            cooldown_secs: 300,
            enabled: true,
        },
        ResponseRule {
            id: "auto_kill_masquerading".into(),
            name: "Terminate process on masquerading".into(),
            condition: RuleCondition::Composite {
                op: "and".into(),
                conditions: vec![
                    RuleCondition::Correlation {
                        correlation_types: vec![CorrelationType::Masquerading],
                    },
                    RuleCondition::MinSeverity { value: 4 },
                ],
            },
            action: RuleAction::TerminateProcess,
            cooldown_secs: 120,
            enabled: true,
        },
        ResponseRule {
            id: "auto_isolate_exfiltration".into(),
            name: "Isolate endpoint on data exfiltration".into(),
            condition: RuleCondition::Correlation {
                correlation_types: vec![CorrelationType::Exfiltration],
            },
            action: RuleAction::IsolateEndpoint,
            cooldown_secs: 300,
            enabled: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alert(severity_score: u32, sources: Vec<DetectionSource>, correlation: Option<CorrelationType>, score: f64) -> AlertInfo {
        AlertInfo {
            rule_id: "test".into(),
            rule_name: "test".into(),
            severity: "high".into(),
            severity_score,
            score,
            endpoint_id: "ep-1".into(),
            sources,
            correlation_type: correlation,
            file_path: Some("C:\\malware.exe".into()),
            pid: Some(1234),
        }
    }

    #[test]
    fn test_min_severity_matches() {
        let cond = RuleCondition::MinSeverity { value: 4 };
        assert!(cond.matches(&test_alert(5, vec![], None, 0.0)));
        assert!(!cond.matches(&test_alert(3, vec![], None, 0.0)));
    }

    #[test]
    fn test_source_matches() {
        let cond = RuleCondition::Source { sources: vec![DetectionSource::Ioc] };
        assert!(cond.matches(&test_alert(0, vec![DetectionSource::Ioc], None, 0.0)));
        assert!(!cond.matches(&test_alert(0, vec![DetectionSource::Yara], None, 0.0)));
    }

    #[test]
    fn test_correlation_matches() {
        let cond = RuleCondition::Correlation {
            correlation_types: vec![CorrelationType::CredentialDumping],
        };
        assert!(cond.matches(&test_alert(0, vec![], Some(CorrelationType::CredentialDumping), 0.0)));
        assert!(!cond.matches(&test_alert(0, vec![], Some(CorrelationType::Lolbin), 0.0)));
    }

    #[test]
    fn test_composite_and_all_match() {
        let cond = RuleCondition::Composite {
            op: "and".into(),
            conditions: vec![
                RuleCondition::MinSeverity { value: 4 },
                RuleCondition::Source { sources: vec![DetectionSource::Ioc] },
            ],
        };
        assert!(cond.matches(&test_alert(5, vec![DetectionSource::Ioc], None, 0.0)));
        assert!(!cond.matches(&test_alert(3, vec![DetectionSource::Ioc], None, 0.0)));
        assert!(!cond.matches(&test_alert(5, vec![DetectionSource::Yara], None, 0.0)));
    }

    #[test]
    fn test_composite_or_any_match() {
        let cond = RuleCondition::Composite {
            op: "or".into(),
            conditions: vec![
                RuleCondition::MinSeverity { value: 4 },
                RuleCondition::Source { sources: vec![DetectionSource::Ioc] },
            ],
        };
        assert!(cond.matches(&test_alert(5, vec![], None, 0.0)));
        assert!(cond.matches(&test_alert(0, vec![DetectionSource::Ioc], None, 0.0)));
        assert!(!cond.matches(&test_alert(0, vec![DetectionSource::Yara], None, 0.0)));
    }

    #[test]
    fn test_rule_engine_disabled_rule() {
        let mut engine = RuleEngine::new(vec![
            ResponseRule {
                id: "test".into(),
                name: "test".into(),
                condition: RuleCondition::MinSeverity { value: 1 },
                action: RuleAction::AlertOnly,
                cooldown_secs: 0,
                enabled: false,
            },
        ]);
        let alert = test_alert(5, vec![], None, 0.0);
        let actions = engine.evaluate(&alert);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_rule_engine_cooldown() {
        let mut engine = RuleEngine::new(vec![
            ResponseRule {
                id: "test".into(),
                name: "test".into(),
                condition: RuleCondition::MinSeverity { value: 1 },
                action: RuleAction::AlertOnly,
                cooldown_secs: 3600,
                enabled: true,
            },
        ]);
        let alert = test_alert(5, vec![], None, 0.0);
        let first = engine.evaluate(&alert);
        assert_eq!(first.len(), 1);
        let second = engine.evaluate(&alert);
        assert!(second.is_empty());
    }

    #[test]
    fn test_rule_engine_matches() {
        let mut engine = RuleEngine::new(vec![
            ResponseRule {
                id: "test".into(),
                name: "test".into(),
                condition: RuleCondition::Composite {
                    op: "and".into(),
                    conditions: vec![
                        RuleCondition::Correlation {
                            correlation_types: vec![CorrelationType::CredentialDumping],
                        },
                    ],
                },
                action: RuleAction::IsolateEndpoint,
                cooldown_secs: 300,
                enabled: true,
            },
        ]);
        let alert = test_alert(5, vec![], Some(CorrelationType::CredentialDumping), 0.0);
        let actions = engine.evaluate(&alert);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, RuleAction::IsolateEndpoint);
        assert_eq!(actions[0].target_endpoint, "ep-1");
    }

    #[test]
    fn test_build_params_quarantine() {
        let alert = test_alert(5, vec![], None, 0.0);
        let params = RuleEngine::build_params(&alert, &RuleAction::QuarantineFile);
        assert_eq!(params["path"], "C:\\malware.exe");
    }

    #[test]
    fn test_default_rules_loaded() {
        let rules = default_rules();
        assert_eq!(rules.len(), 11);
        assert!(rules.iter().all(|r| r.enabled));
    }
}
