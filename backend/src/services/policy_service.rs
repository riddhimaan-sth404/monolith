use crate::error::ServiceResult;
use serde_json::Value;

pub struct PolicyService;

impl PolicyService {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_policy_rules(&self, rules: &Value) -> ServiceResult<()> {
        if !rules.is_array() {
            return Err(monolith_shared::error::EdrError::ValidationError(
                "policy rules must be an array".into(),
            ));
        }

        for rule in rules.as_array().unwrap() {
            if rule.get("name").and_then(|v| v.as_str()).is_none() {
                return Err(monolith_shared::error::EdrError::ValidationError(
                    "each rule must have a 'name' field".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn increment_version(&self, current: u32) -> u32 {
        current + 1
    }
}
