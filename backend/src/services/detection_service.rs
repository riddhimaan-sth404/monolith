use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::Value;

use crate::engine::detection::{DetectionEngine, DetectionResult};
use crate::engine::response_rules::{self, RuleEngine, AlertInfo, DetectionSource, CorrelationType, MatchedAction, ResponseRule};
use monolith_shared::db::DatabaseConnection;
use monolith_shared::error::Result;
use monolith_shared::db::DbParam;

pub struct DetectionService {
    engine: DetectionEngine,
    rule_engine: Arc<Mutex<RuleEngine>>,
    toast_script_path: Option<Arc<str>>,
}

impl DetectionService {
    pub fn new(rules: Vec<ResponseRule>, toast_script_path: Option<Arc<str>>) -> Self {
        Self {
            engine: DetectionEngine::new(),
            rule_engine: Arc::new(Mutex::new(RuleEngine::new(rules))),
            toast_script_path,
        }
    }

    pub fn detection_engine(&self) -> &DetectionEngine {
        &self.engine
    }

    pub fn rule_engine(&self) -> &Arc<Mutex<RuleEngine>> {
        &self.rule_engine
    }

    pub async fn process_event(
        &self,
        event: &Value,
        endpoint_id: &str,
        db: &dyn DatabaseConnection,
    ) -> Result<Vec<String>> {
        let mut action_ids = Vec::new();

        if event.get("source").and_then(|v| v.as_str()) == Some("local_detection") {
            let rule_id = event.get("alert.rule_id").and_then(|v| v.as_str()).unwrap_or("agent_alert");
            let severity = event.get("alert.severity").and_then(|v| v.as_str()).unwrap_or("high");
            let _match_value = event.get("alert.match_value").and_then(|v| v.as_str()).unwrap_or("agent_detection");
            let description = event.get("alert.description").and_then(|v| v.as_str()).unwrap_or("");
            let score = event.get("alert.count").and_then(|v| v.as_str()).and_then(|s| s.parse::<f64>().ok()).unwrap_or(1.0);

            // 1. Create standard Alert record
            let alert_id = uuid::Uuid::new_v4().to_string();
            let _ = db.execute(
                "INSERT INTO alerts (id, endpoint_id, severity, title, description, score, status, rule_id, created_at, hit_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'new', ?7, datetime('now'), 1)",
                &[
                    DbParam::Text(alert_id.clone()),
                    DbParam::Text(endpoint_id.to_string()),
                    DbParam::Text(severity.to_string()),
                    DbParam::Text(format!("Agent Alert: {}", rule_id)),
                    DbParam::Text(description.to_string()),
                    DbParam::Real(score),
                    DbParam::Text(rule_id.to_string()),
                ],
            ).await;

            // 2. Memory Alert record
            if rule_id == "memory_scan" {
                let process_id = event.get("memory.process_id").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let process_name = event.get("memory.process_name").and_then(|v| v.as_str()).unwrap_or("unknown");
                let region_base = event.get("memory.region_base").and_then(|v| v.as_str()).unwrap_or("0x0");
                let matched_rules = event.get("memory.matched_rules").and_then(|v| v.as_str()).unwrap_or("");
                let yara_matches = event.get("memory.yara_matches").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let contains_pe = event.get("memory.contains_pe").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let verdict = event.get("memory.verdict").and_then(|v| v.as_str()).unwrap_or("suspicious");

                let memory_alert_id = uuid::Uuid::new_v4().to_string();
                let _ = db.execute(
                    "INSERT INTO memory_alerts (id, endpoint_id, process_id, process_name, region_base, region_size, matched_rules, yara_matches, contains_pe, verdict, created_at, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, datetime('now'), 'new')",
                    &[
                        DbParam::Text(memory_alert_id),
                        DbParam::Text(endpoint_id.to_string()),
                        DbParam::Integer(process_id),
                        DbParam::Text(process_name.to_string()),
                        DbParam::Text(region_base.to_string()),
                        DbParam::Text(matched_rules.to_string()),
                        DbParam::Integer(yara_matches),
                        DbParam::Integer(contains_pe),
                        DbParam::Text(verdict.to_string()),
                    ]
                ).await;
            }

            // 3. Registry Tamper record
            if rule_id == "registry_tamper" {
                let key_path = event.get("registry.key_path").and_then(|v| v.as_str()).unwrap_or("unknown");
                let operation = event.get("registry.operation").and_then(|v| v.as_str()).unwrap_or("blocked_write");
                let offending_pid = event.get("registry.offending_pid").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let offending_process = event.get("registry.offending_process").and_then(|v| v.as_str()).unwrap_or("unknown");
                let old_value = event.get("registry.old_value").and_then(|v| v.as_str()).unwrap_or("");
                let new_value = event.get("registry.new_value").and_then(|v| v.as_str()).unwrap_or("");
                let blocked = event.get("registry.blocked").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);

                let tamper_id = uuid::Uuid::new_v4().to_string();
                let _ = db.execute(
                    "INSERT INTO registry_tamper_events (id, endpoint_id, key_path, operation, offending_pid, offending_process, old_value, new_value, blocked, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))",
                    &[
                        DbParam::Text(tamper_id),
                        DbParam::Text(endpoint_id.to_string()),
                        DbParam::Text(key_path.to_string()),
                        DbParam::Text(operation.to_string()),
                        DbParam::Integer(offending_pid),
                        DbParam::Text(offending_process.to_string()),
                        DbParam::Text(old_value.to_string()),
                        DbParam::Text(new_value.to_string()),
                        DbParam::Integer(blocked),
                    ]
                ).await;
            }

            return Ok(action_ids);
        }

        let results = self.engine.evaluate_event(event);

        for result in &results {
            self.create_alert(result, endpoint_id, db).await?;

            let alert_info = self.build_alert_info(result, endpoint_id);
            let actions = {
                let mut rules = self.rule_engine.lock().await;
                rules.evaluate(&alert_info)
            };

            for matched in &actions {
                if let Some(id) = self.create_action(matched, db).await? {
                    action_ids.push(id);
                }
            }
        }

        Ok(action_ids)
    }

    fn build_alert_info(&self, result: &DetectionResult, endpoint_id: &str) -> AlertInfo {
        let severity_score = match result.severity.as_str() {
            "critical" => 5u32,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            _ => 1,
        };

        let sources = self.extract_sources(&result.tags);

        let correlation_type = result.tags.iter()
            .find_map(|t| t.parse::<CorrelationType>().ok());

        AlertInfo {
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            severity: result.severity.clone(),
            severity_score,
            score: result.score,
            endpoint_id: endpoint_id.to_string(),
            sources,
            correlation_type,
            file_path: result.matched_fields.get("file_path").cloned(),
            pid: result.matched_fields.get("pid").and_then(|v| v.parse().ok()),
        }
    }

    fn extract_sources(&self, tags: &[String]) -> Vec<DetectionSource> {
        let mut sources = Vec::new();
        for tag in tags {
            if let Ok(source) = tag.parse::<DetectionSource>() {
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
        }
        if sources.is_empty() {
            sources.push(DetectionSource::Yara);
        }
        sources
    }

    async fn create_alert(&self, result: &DetectionResult, endpoint_id: &str, db: &dyn DatabaseConnection) -> Result<String> {
        let tag_list = result.tags.join(",");

        // Try to find a matching alert created in the last 5 minutes that is still "new"
        let existing = db.query_one_value(
            "SELECT id, hit_count FROM alerts 
             WHERE endpoint_id = ?1 AND rule_id = ?2 AND title = ?3 AND status = 'new'
             AND datetime(created_at) >= datetime('now', '-5 minutes')
             LIMIT 1",
            &[
                DbParam::Text(endpoint_id.to_string()),
                DbParam::Text(result.rule_id.clone()),
                DbParam::Text(result.rule_name.clone()),
            ]
        ).await?;

        if let Some(row) = existing {
            let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let current_hits = row.get("hit_count").and_then(|v| v.as_i64()).unwrap_or(1);
            db.execute(
                "UPDATE alerts SET hit_count = ?1, updated_at = datetime('now') WHERE id = ?2",
                &[
                    DbParam::Integer(current_hits + 1),
                    DbParam::Text(id.clone()),
                ]
            ).await?;
            tracing::info!("alert deduplicated: id={} rule={} severity={} new_hits={}",
                id, result.rule_id, result.severity, current_hits + 1);
            return Ok(id);
        }

        let alert_id = uuid::Uuid::new_v4().to_string();

        db.execute(
            "INSERT INTO alerts (id, endpoint_id, severity, title, description, score, status, rule_id, mitre_technique_id, tags, created_at, hit_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'new', ?7, ?8, ?9, datetime('now'), 1)",
            &[
                DbParam::Text(alert_id.clone()),
                DbParam::Text(endpoint_id.to_string()),
                DbParam::Text(result.severity.clone()),
                DbParam::Text(result.rule_name.clone()),
                DbParam::Text(format!("Detection: {} matched by rule '{}' (score: {:.1})",
                    result.rule_name, result.rule_id, result.score)),
                DbParam::Real(result.score),
                DbParam::Text(result.rule_id.clone()),
                DbParam::Text(result.mitre_technique_id.clone().unwrap_or_default()),
                DbParam::Text(tag_list),
            ],
        ).await?;

        tracing::info!("alert created: id={} rule={} severity={} score={:.1}",
            alert_id, result.rule_id, result.severity, result.score);

        // Fire desktop notification (non-blocking)
        if result.severity == "high" || result.severity == "critical" {
            let notif_title = format!("EDR Alert: {}", result.severity);
            let notif_msg = format!("Rule '{}' matched (score: {:.1})", result.rule_name, result.score);
            let path = self.toast_script_path.clone();
            tokio::spawn(async move {
                crate::notifications::send_alert_notification(path, &notif_title, &notif_msg).await;
            });
        }

        Ok(alert_id)
    }

    async fn create_action(&self, matched: &MatchedAction, db: &dyn DatabaseConnection) -> Result<Option<String>> {
        if matched.action == response_rules::RuleAction::AlertOnly {
            return Ok(None);
        }

        let action_id = uuid::Uuid::new_v4().to_string();
        let action_type = matched.action.as_str();
        let params = matched.parameters.to_string();

        db.execute(
            "INSERT INTO response_actions (id, endpoint_id, action_type, parameters, status, created_by, rule_id, created_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', 'auto_response', ?5, datetime('now'))",
            &[
                DbParam::Text(action_id.clone()),
                DbParam::Text(matched.target_endpoint.clone()),
                DbParam::Text(action_type.to_string()),
                DbParam::Text(params),
                DbParam::Text(matched.rule_id.clone()),
            ],
        ).await?;

        tracing::info!("auto-response action created: id={} type={} endpoint={} rule={}",
            action_id, action_type, matched.target_endpoint, matched.rule_id);

        Ok(Some(action_id))
    }

    pub async fn load_rules_from_config(&self, rules: Vec<ResponseRule>) {
        let mut engine = self.rule_engine.lock().await;
        *engine = RuleEngine::new(rules);
        tracing::info!("loaded {} response rules", engine.rule_count());
    }

    pub fn rule_count(&self) -> usize {
        let engine = self.rule_engine.try_lock()
            .map(|e| e.rule_count())
            .unwrap_or(0);
        engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::response_rules::default_rules;

    #[test]
    fn test_default_rules_sizes() {
        let rules = default_rules();
        assert_eq!(rules.len(), 11);
    }

    #[test]
    fn test_extract_sources_from_tags() {
        let service = DetectionService::new(default_rules(), None);

        let tags = vec![
            "correlation".to_string(),
            "ioc".to_string(),
            "credential_access".to_string(),
        ];
        let sources = service.extract_sources(&tags);
        assert!(sources.contains(&DetectionSource::Ioc));
        assert!(sources.contains(&DetectionSource::Correlation));
    }

    struct MockDb;
    #[async_trait::async_trait]
    impl DatabaseConnection for MockDb {
        async fn execute(&self, _sql: &str, _params: &[DbParam]) -> Result<u64> { Ok(1) }
        async fn execute_batch(&self, _sql: &str) -> Result<()> { Ok(()) }
        async fn query<T: serde::de::DeserializeOwned + Send>(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<T>> { Ok(vec![]) }
        async fn query_one<T: serde::de::DeserializeOwned + Send>(&self, _sql: &str, _params: &[DbParam]) -> Result<Option<T>> { Ok(None) }
        async fn query_value(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<Value>> { Ok(vec![]) }
        async fn query_one_value(&self, _sql: &str, _params: &[DbParam]) -> Result<Option<Value>> { Ok(None) }
        async fn query_raw(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<Vec<Value>>> { Ok(vec![]) }
        async fn last_insert_rowid(&self) -> Result<i64> { Ok(1) }
        async fn begin_transaction(&self) -> Result<Box<dyn monolith_shared::db::Transaction>> {
            Ok(Box::new(MockTx))
        }
    }

    struct MockTx;
    #[async_trait::async_trait]
    impl monolith_shared::db::Transaction for MockTx {
        async fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
        async fn rollback(self: Box<Self>) -> Result<()> { Ok(()) }
        async fn execute(&self, _sql: &str, _params: &[DbParam]) -> Result<u64> { Ok(1) }
    }
}
