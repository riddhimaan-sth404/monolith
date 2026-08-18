use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EndpointId = Uuid;
pub type UserId = Uuid;
pub type AlertId = Uuid;
pub type EventId = Uuid;
pub type ScanId = Uuid;
pub type PolicyId = String;
pub type IocId = String;
pub type RuleId = String;
pub type ActionId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EndpointStatus {
    Online,
    Offline,
    Isolated,
    Decommissioned,
}

impl std::fmt::Display for EndpointStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointStatus::Online => write!(f, "online"),
            EndpointStatus::Offline => write!(f, "offline"),
            EndpointStatus::Isolated => write!(f, "isolated"),
            EndpointStatus::Decommissioned => write!(f, "decommissioned"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn score(&self) -> u32 {
        match self {
            AlertSeverity::Info => 1,
            AlertSeverity::Low => 2,
            AlertSeverity::Medium => 3,
            AlertSeverity::High => 4,
            AlertSeverity::Critical => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IocType {
    Sha256,
    Sha1,
    Md5,
    Domain,
    Url,
    Ip,
    Certificate,
    RegistryPath,
    FilePath,
    Yara,
    Sigma,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub session_id: String,
    pub integrity_level: String,
    pub user_sid: String,
    pub user_name: String,
    pub hashes: Option<FileHashes>,
    pub start_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub role: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub mfa_secret: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: EndpointId,
    pub hostname: String,
    pub ip_address: String,
    pub os_version: String,
    pub os_architecture: String,
    pub agent_version: String,
    pub driver_version: Option<String>,
    pub scanner_version: Option<String>,
    pub status: EndpointStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub policy_id: Option<PolicyId>,
    pub isolated: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub page: u32,
    pub page_size: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_endpoint_status_display() {
        assert_eq!(EndpointStatus::Online.to_string(), "online");
        assert_eq!(EndpointStatus::Offline.to_string(), "offline");
        assert_eq!(EndpointStatus::Isolated.to_string(), "isolated");
        assert_eq!(EndpointStatus::Decommissioned.to_string(), "decommissioned");
    }

    #[test]
    fn test_alert_severity_score() {
        assert_eq!(AlertSeverity::Info.score(), 1);
        assert_eq!(AlertSeverity::Low.score(), 2);
        assert_eq!(AlertSeverity::Medium.score(), 3);
        assert_eq!(AlertSeverity::High.score(), 4);
        assert_eq!(AlertSeverity::Critical.score(), 5);
    }

    #[test]
    fn test_pagination_defaults() {
        let params = PaginationParams::default();
        assert_eq!(params.page, 1);
        assert_eq!(params.page_size, 50);
    }

    #[test]
    fn test_file_hashes_new() {
        let hashes = FileHashes {
            sha256: Some("abc".into()),
            sha1: None,
            md5: None,
        };
        assert_eq!(hashes.sha256.as_deref(), Some("abc"));
        assert!(hashes.sha1.is_none());
    }

    #[test]
    fn test_process_info_defaults() {
        let info = ProcessInfo {
            pid: 1234,
            parent_pid: 1,
            name: "test.exe".into(),
            path: "C:\\Windows\\test.exe".into(),
            command_line: "test.exe --flag".into(),
            session_id: "1".into(),
            integrity_level: "Medium".into(),
            user_sid: "S-1-5-21-...".into(),
            user_name: "SYSTEM".into(),
            hashes: None,
            start_time: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "test.exe");
    }

    #[test]
    fn test_serde_enums() {
        let json = r#""online""#;
        let status: EndpointStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status, EndpointStatus::Online);

        let json = r#""critical""#;
        let severity: AlertSeverity = serde_json::from_str(json).unwrap();
        assert_eq!(severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_uuid_type_aliases() {
        let id = uuid::Uuid::new_v4();
        let _eid: EndpointId = id;
        let _uid: UserId = id;
        let _aid: AlertId = id;
        let _evid: EventId = id;
        let _sid: ScanId = id;
        let _acid: ActionId = id;
    }
}
