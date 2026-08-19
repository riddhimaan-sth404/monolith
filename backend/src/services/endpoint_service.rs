use crate::error::ServiceResult;
use chrono::{DateTime, Utc};
use monolith_shared::types::{Endpoint, EndpointStatus};
use uuid::Uuid;

pub struct EndpointService;

impl EndpointService {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_status(&self, last_seen: &DateTime<Utc>, isolated: bool) -> EndpointStatus {
        if isolated {
            return EndpointStatus::Isolated;
        }

        let elapsed = Utc::now() - *last_seen;
        if elapsed.num_seconds() < 120 {
            EndpointStatus::Online
        } else {
            EndpointStatus::Offline
        }
    }

    pub fn register_endpoint(
        &self,
        hostname: String,
        ip_address: String,
        os_version: String,
        agent_version: String,
    ) -> Endpoint {
        Endpoint {
            id: Uuid::new_v4(),
            hostname,
            ip_address,
            os_version,
            os_architecture: String::new(),
            agent_version,
            driver_version: None,
            scanner_version: None,
            status: EndpointStatus::Online,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            policy_id: None,
            isolated: false,
            tags: Vec::new(),
        }
    }

    pub fn validate_endpoint_id(&self, id: &str) -> ServiceResult<Uuid> {
        Ok(Uuid::parse_str(id).map_err(|e| {
            monolith_shared::error::EdrError::Internal(format!("invalid UUID: {}", e))
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_calculate_status_isolated() {
        let service = EndpointService::new();
        let last_seen = Utc::now();
        assert_eq!(
            service.calculate_status(&last_seen, true),
            EndpointStatus::Isolated
        );
    }

    #[test]
    fn test_calculate_status_online_within_120s() {
        let service = EndpointService::new();
        let last_seen = Utc::now() - chrono::Duration::seconds(60);
        assert_eq!(
            service.calculate_status(&last_seen, false),
            EndpointStatus::Online
        );
    }

    #[test]
    fn test_calculate_status_offline_after_120s() {
        let service = EndpointService::new();
        let last_seen = Utc::now() - chrono::Duration::seconds(180);
        assert_eq!(
            service.calculate_status(&last_seen, false),
            EndpointStatus::Offline
        );
    }

    #[test]
    fn test_register_endpoint() {
        let service = EndpointService::new();
        let endpoint = service.register_endpoint(
            "WIN-DESKTOP".into(),
            "192.168.1.100".into(),
            "Windows 11 Pro".into(),
            "1.0.0".into(),
        );
        assert_eq!(endpoint.hostname, "WIN-DESKTOP");
        assert_eq!(endpoint.ip_address, "192.168.1.100");
        assert_eq!(endpoint.os_version, "Windows 11 Pro");
        assert_eq!(endpoint.agent_version, "1.0.0");
        assert_eq!(endpoint.status, EndpointStatus::Online);
        assert!(!endpoint.isolated);
        assert!(endpoint.tags.is_empty());
    }

    #[test]
    fn test_validate_endpoint_id_valid_uuid() {
        let service = EndpointService::new();
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let result = service.validate_endpoint_id(uuid_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid_str);
    }

    #[test]
    fn test_validate_endpoint_id_invalid() {
        let service = EndpointService::new();
        let result = service.validate_endpoint_id("not-a-uuid");
        assert!(result.is_err());
    }
}
