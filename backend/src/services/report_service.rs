use crate::error::ServiceResult;
use serde_json::Value;

pub struct ReportService;

impl ReportService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_threat_summary(&self, alerts: &[Value]) -> Value {
        let total = alerts.len();
        let critical = alerts
            .iter()
            .filter(|a| a.get("severity").and_then(|v| v.as_str()) == Some("critical"))
            .count();
        let high = alerts
            .iter()
            .filter(|a| a.get("severity").and_then(|v| v.as_str()) == Some("high"))
            .count();
        let medium = alerts
            .iter()
            .filter(|a| a.get("severity").and_then(|v| v.as_str()) == Some("medium"))
            .count();
        let low = alerts
            .iter()
            .filter(|a| a.get("severity").and_then(|v| v.as_str()) == Some("low"))
            .count();

        serde_json::json!({
            "total_alerts": total,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "generated_at": chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn export_json(&self, data: &Value) -> ServiceResult<String> {
        Ok(serde_json::to_string_pretty(data)?)
    }

    pub fn export_csv(&self, data: &[Value], fields: &[&str]) -> ServiceResult<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(fields)
            .map_err(|e| monolith_shared::error::EdrError::SerializationError(e.to_string()))?;

        for row in data {
            let values: Vec<String> = fields
                .iter()
                .map(|f| {
                    row.get(*f)
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default()
                })
                .collect();
            wtr.write_record(&values)
                .map_err(|e| monolith_shared::error::EdrError::SerializationError(e.to_string()))?;
        }

        let result = wtr
            .into_inner()
            .map_err(|e| monolith_shared::error::EdrError::SerializationError(e.to_string()))?;
        Ok(String::from_utf8(result)
            .map_err(|e| monolith_shared::error::EdrError::SerializationError(e.to_string()))?)
    }
}
