use uuid::Uuid;
use monolith_shared::types::{AlertId, AlertSeverity, AlertStatus};

pub struct AlertService;

impl AlertService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_alert_id(&self) -> AlertId {
        Uuid::new_v4()
    }

    pub fn calculate_severity_score(&self, severity: &AlertSeverity) -> f64 {
        match severity {
            AlertSeverity::Info => 1.0,
            AlertSeverity::Low => 2.0,
            AlertSeverity::Medium => 5.0,
            AlertSeverity::High => 8.0,
            AlertSeverity::Critical => 10.0,
        }
    }

    pub fn valid_status_transition(&self, current: &AlertStatus, next: &AlertStatus) -> bool {
        match (current, next) {
            (AlertStatus::New, AlertStatus::Acknowledged) => true,
            (AlertStatus::New, AlertStatus::Dismissed) => true,
            (AlertStatus::Acknowledged, AlertStatus::Investigating) => true,
            (AlertStatus::Acknowledged, AlertStatus::Dismissed) => true,
            (AlertStatus::Investigating, AlertStatus::Resolved) => true,
            (AlertStatus::Investigating, AlertStatus::Dismissed) => true,
            _ => false,
        }
    }
}
