use serde_json::Value;

pub struct RuleService;

impl RuleService {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_event_against_rules(&self, event: &Value, rules: &[Value]) -> Vec<Value> {
        let mut matches = Vec::new();

        for rule in rules {
            if !rule
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
            {
                continue;
            }

            let conditions = rule.get("conditions").and_then(|v| v.as_object());
            if let Some(conds) = conditions {
                if self.match_conditions(event, conds) {
                    matches.push(rule.clone());
                }
            }
        }

        matches
    }

    fn match_conditions(&self, event: &Value, conditions: &serde_json::Map<String, Value>) -> bool {
        for (key, condition) in conditions {
            let event_val = event.get(key);
            match condition {
                Value::String(s) => {
                    if let Some(ev) = event_val.and_then(|v| v.as_str()) {
                        if !ev.contains(s.as_str()) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                Value::Array(arr) => {
                    if let Some(ev) = event_val.and_then(|v| v.as_str()) {
                        if !arr
                            .iter()
                            .any(|c| c.as_str().map_or(false, |s| ev.contains(s)))
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }
}
