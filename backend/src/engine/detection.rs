use serde_json::Value;
use std::collections::HashMap;
use dashmap::DashMap;

pub struct DetectionEngine {
    ioc_matcher: super::ioc_matcher::IocMatcher,
    correlation_engine: super::correlation::CorrelationEngine,
    rule_cache: DashMap<String, Value>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            ioc_matcher: super::ioc_matcher::IocMatcher::new(),
            correlation_engine: super::correlation::CorrelationEngine::new(),
            rule_cache: DashMap::new(),
        }
    }

    pub fn evaluate_event(&self, event: &Value) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // 1. IOC matching
        if let Some(ioc_results) = self.ioc_matcher.match_event(event) {
            for r in ioc_results {
                results.push(r);
            }
        }

        // 2. Rule-based detection
        for rule in self.rule_cache.iter() {
            if let Some(result) = self.evaluate_rule(event, &rule.value()) {
                results.push(result);
            }
        }

        // 3. Behavioral correlation
        if let Some(result) = self.correlation_engine.analyze(event) {
            results.push(result);
        }

        results
    }

    fn evaluate_rule(&self, event: &Value, rule: &Value) -> Option<DetectionResult> {
        let conditions = rule.get("conditions")?;
        let enabled = rule.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        if !enabled {
            return None;
        }

        let matched = self.check_conditions(event, conditions);
        if !matched {
            return None;
        }

        Some(DetectionResult {
            rule_id: rule.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            rule_name: rule.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            severity: rule.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string(),
            confidence: rule.get("confidence").and_then(|v| v.as_str()).unwrap_or("medium").to_string(),
            mitre_technique_id: rule.get("mitre_technique_ids").and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tags: rule.get("tags").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            score: self.calculate_score(rule),
            matched_fields: HashMap::new(),
        })
    }

    fn get_field<'a>(&self, event: &'a Value, field: &str) -> Option<&'a Value> {
        event.get(field).or_else(|| event.get("data").and_then(|d| d.get(field)))
    }

    fn check_conditions(&self, event: &Value, conditions: &Value) -> bool {
        match conditions {
            Value::Object(map) => {
                for (field, condition) in map {
                    let event_val = self.get_field(event, field);
                    match condition {
                        Value::String(pattern) => {
                            if let Some(v) = event_val.and_then(|v| v.as_str()) {
                                if !v.contains(pattern.as_str()) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        }
                        Value::Array(arr) => {
                            if let Some(v) = event_val.and_then(|v| v.as_str()) {
                                if !arr.iter().any(|c| c.as_str().map_or(false, |s| v.contains(s))) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        }
                        Value::Object(sub_conditions) => {
                            if !self.check_conditions(event_val.unwrap_or(&Value::Null), &Value::Object(sub_conditions.clone())) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn calculate_score(&self, rule: &Value) -> f64 {
        let severity = rule.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");
        let confidence = rule.get("confidence").and_then(|v| v.as_str()).unwrap_or("medium");

        let severity_score = match severity {
            "critical" => 10.0,
            "high" => 8.0,
            "medium" => 5.0,
            "low" => 2.0,
            _ => 1.0,
        };

        let confidence_score = match confidence {
            "verified" => 1.0,
            "high" => 0.9,
            "medium" => 0.7,
            "low" => 0.4,
            _ => 0.1,
        };

        severity_score * confidence_score
    }

    pub fn load_iocs(&self, iocs: &[Value]) {
        self.ioc_matcher.load_iocs(iocs);
    }

    pub fn load_rules(&self, rules: Vec<Value>) {
        for rule in rules {
            if let Some(id) = rule.get("id").and_then(|v| v.as_str()) {
                self.rule_cache.insert(id.to_string(), rule);
            }
        }
    }

    pub fn clear_rules(&self) {
        self.rule_cache.clear();
    }
}

pub struct DetectionResult {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub confidence: String,
    pub mitre_technique_id: Option<String>,
    pub tags: Vec<String>,
    pub score: f64,
    pub matched_fields: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: &str, data: serde_json::Value) -> Value {
        serde_json::json!({
            "event_type": event_type,
            "data": data,
            "timestamp": "2024-01-01T00:00:00Z",
        })
    }

    fn make_rule(id: &str, name: &str, severity: &str, field: &str, pattern: &str) -> Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "severity": severity,
            "confidence": "high",
            "enabled": true,
            "conditions": { field: pattern },
            "tags": ["test"],
        })
    }

    #[test]
    fn test_evaluate_event_no_match() {
        let engine = DetectionEngine::new();
        let event = make_event("process_create", serde_json::json!({"name": "notepad.exe"}));
        let results = engine.evaluate_event(&event);
        assert!(results.is_empty());
    }

    #[test]
    fn test_evaluate_rule_match() {
        let engine = DetectionEngine::new();
        let rule = make_rule("rule-1", "Test Rule", "high", "name", "malware");
        engine.load_rules(vec![rule]);

        let event = make_event("process_create", serde_json::json!({"name": "malware.exe"}));
        let results = engine.evaluate_event(&event);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "rule-1");
        assert_eq!(results[0].severity, "high");
    }

    #[test]
    fn test_evaluate_rule_disabled() {
        let engine = DetectionEngine::new();
        let mut rule = make_rule("rule-1", "Disabled Rule", "high", "name", "malware");
        rule["enabled"] = serde_json::Value::Bool(false);
        engine.load_rules(vec![rule]);

        let event = make_event("process_create", serde_json::json!({"name": "malware.exe"}));
        let results = engine.evaluate_event(&event);
        assert!(results.is_empty());
    }

    #[test]
    fn test_evaluate_rule_array_condition() {
        let engine = DetectionEngine::new();
        let rule = serde_json::json!({
            "id": "rule-2",
            "name": "Array Match",
            "severity": "critical",
            "confidence": "high",
            "enabled": true,
            "conditions": { "name": ["malware", "virus", "trojan"] },
            "tags": [],
        });
        engine.load_rules(vec![rule]);

        let event = make_event("process_create", serde_json::json!({"name": "virus.exe"}));
        let results = engine.evaluate_event(&event);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_calculate_score() {
        let engine = DetectionEngine::new();
        let rule = serde_json::json!({
            "severity": "critical",
            "confidence": "high",
        });
        let val = Value::Object(serde_json::Map::new());
        let score = engine.calculate_score(&rule);
        assert!((score - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_score_low_confidence() {
        let engine = DetectionEngine::new();
        let rule = serde_json::json!({
            "severity": "low",
            "confidence": "low",
        });
        let score = engine.calculate_score(&rule);
        assert!((score - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_clear_rules() {
        let engine = DetectionEngine::new();
        let rule = make_rule("rule-1", "Test", "high", "name", "test");
        engine.load_rules(vec![rule]);
        engine.clear_rules();
        assert!(engine.rule_cache.is_empty());
    }
}
