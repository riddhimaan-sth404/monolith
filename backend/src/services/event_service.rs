use crate::error::ServiceResult;
use monolith_shared::types::EventId;
use serde_json::Value;
use uuid::Uuid;

pub struct EventService;

impl EventService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_event_id(&self) -> EventId {
        Uuid::new_v4()
    }

    pub fn validate_event(&self, event: &Value) -> ServiceResult<()> {
        // Validate required fields
        if event.get("event_type").and_then(|v| v.as_str()).is_none() {
            return Err(monolith_shared::error::EdrError::ValidationError(
                "event_type is required".into(),
            ));
        }
        if event.get("timestamp").and_then(|v| v.as_str()).is_none() {
            return Err(monolith_shared::error::EdrError::ValidationError(
                "timestamp is required".into(),
            ));
        }
        Ok(())
    }

    pub fn enrich_event(&self, mut event: Value) -> Value {
        let now = chrono::Utc::now().to_rfc3339();
        if let Some(obj) = event.as_object_mut() {
            obj.insert("collected_at".into(), Value::String(now));
            if obj.get("id").is_none() {
                obj.insert(
                    "id".into(),
                    Value::String(self.generate_event_id().to_string()),
                );
            }
        }
        event
    }
}
