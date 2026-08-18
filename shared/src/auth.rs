use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use once_cell::sync::Lazy;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    Administrator,
    Analyst,
    Viewer,
    Automation,
}

impl Role {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "administrator" | "admin" => Some(Role::Administrator),
            "analyst" => Some(Role::Analyst),
            "viewer" => Some(Role::Viewer),
            "automation" | "bot" => Some(Role::Automation),
            _ => None,
        }
    }

    pub fn permissions(&self) -> &'static [Permission] {
        static PERMISSIONS: Lazy<HashMap<Role, Vec<Permission>>> = Lazy::new(|| {
            let mut m = HashMap::new();
            m.insert(
                Role::Administrator,
                vec![
                    Permission::UserRead,
                    Permission::UserWrite,
                    Permission::UserDelete,
                    Permission::EndpointRead,
                    Permission::EndpointWrite,
                    Permission::EndpointIsolate,
                    Permission::AlertRead,
                    Permission::AlertWrite,
                    Permission::EventRead,
                    Permission::IocRead,
                    Permission::IocWrite,
                    Permission::IocDelete,
                    Permission::PolicyRead,
                    Permission::PolicyWrite,
                    Permission::PolicyDelete,
                    Permission::ScanRead,
                    Permission::ScanWrite,
                    Permission::ScanCancel,
                    Permission::ReportRead,
                    Permission::ReportGenerate,
                    Permission::ResponseExecute,
                    Permission::SettingsRead,
                    Permission::SettingsWrite,
                    Permission::AuditLogRead,
                    Permission::LicenseManage,
                    Permission::EndpointShred,
                    Permission::EndpointProfileWrite,
                ],
            );
            m.insert(
                Role::Analyst,
                vec![
                    Permission::EndpointRead,
                    Permission::AlertRead,
                    Permission::AlertWrite,
                    Permission::EventRead,
                    Permission::IocRead,
                    Permission::IocWrite,
                    Permission::PolicyRead,
                    Permission::ScanRead,
                    Permission::ScanWrite,
                    Permission::ReportRead,
                    Permission::ReportGenerate,
                    Permission::ResponseExecute,
                ],
            );
            m.insert(
                Role::Viewer,
                vec![
                    Permission::EndpointRead,
                    Permission::AlertRead,
                    Permission::EventRead,
                    Permission::IocRead,
                    Permission::PolicyRead,
                    Permission::ScanRead,
                    Permission::ReportRead,
                ],
            );
            m.insert(
                Role::Automation,
                vec![
                    Permission::EndpointRead,
                    Permission::AlertRead,
                    Permission::EventRead,
                    Permission::IocRead,
                    Permission::ScanRead,
                    Permission::ScanWrite,
                ],
            );
            m
        });

        PERMISSIONS.get(self).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Users
    UserRead,
    UserWrite,
    UserDelete,
    // Endpoints
    EndpointRead,
    EndpointWrite,
    EndpointIsolate,
    // Alerts
    AlertRead,
    AlertWrite,
    // Events
    EventRead,
    // IOCs
    IocRead,
    IocWrite,
    IocDelete,
    // Policies
    PolicyRead,
    PolicyWrite,
    PolicyDelete,
    // Scans
    ScanRead,
    ScanWrite,
    ScanCancel,
    // Reports
    ReportRead,
    ReportGenerate,
    // Response
    ResponseExecute,
    // Settings
    SettingsRead,
    SettingsWrite,
    // Audit
    AuditLogRead,
    // License
    LicenseManage,
    // Response actions
    EndpointShred,
    EndpointProfileWrite,
}

impl Permission {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user:read" => Some(Permission::UserRead),
            "user:write" => Some(Permission::UserWrite),
            "user:delete" => Some(Permission::UserDelete),
            "endpoint:read" => Some(Permission::EndpointRead),
            "endpoint:write" => Some(Permission::EndpointWrite),
            "endpoint:isolate" => Some(Permission::EndpointIsolate),
            "alert:read" => Some(Permission::AlertRead),
            "alert:write" => Some(Permission::AlertWrite),
            "event:read" => Some(Permission::EventRead),
            "ioc:read" => Some(Permission::IocRead),
            "ioc:write" => Some(Permission::IocWrite),
            "ioc:delete" => Some(Permission::IocDelete),
            "policy:read" => Some(Permission::PolicyRead),
            "policy:write" => Some(Permission::PolicyWrite),
            "policy:delete" => Some(Permission::PolicyDelete),
            "scan:read" => Some(Permission::ScanRead),
            "scan:write" => Some(Permission::ScanWrite),
            "scan:cancel" => Some(Permission::ScanCancel),
            "report:read" => Some(Permission::ReportRead),
            "report:generate" => Some(Permission::ReportGenerate),
            "response:execute" => Some(Permission::ResponseExecute),
            "settings:read" => Some(Permission::SettingsRead),
            "settings:write" => Some(Permission::SettingsWrite),
            "audit:read" => Some(Permission::AuditLogRead),
            "license:manage" => Some(Permission::LicenseManage),
            "endpoint:shred" => Some(Permission::EndpointShred),
            "endpoint:profile:write" => Some(Permission::EndpointProfileWrite),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub username: String,
    pub role: Role,
}

impl AuthContext {
    pub fn new(user_id: String, username: String, role: Role) -> Self {
        Self {
            user_id,
            username,
            role,
        }
    }

    pub fn check_permission(&self, permission: Permission) -> bool {
        self.role.has_permission(permission)
    }

    pub fn require_permission(&self, permission: Permission) -> Result<(), crate::error::EdrError> {
        if self.check_permission(permission) {
            Ok(())
        } else {
            Err(crate::error::EdrError::AuthorizationFailed(
                format!("missing required permission: {:?}", permission),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EdrError;

    #[test]
    fn test_administrator_has_all_permissions() {
        let admin = AuthContext::new("1".into(), "admin".into(), Role::Administrator);
        assert!(admin.check_permission(Permission::UserRead));
        assert!(admin.check_permission(Permission::UserWrite));
        assert!(admin.check_permission(Permission::UserDelete));
        assert!(admin.check_permission(Permission::EndpointRead));
        assert!(admin.check_permission(Permission::EndpointWrite));
        assert!(admin.check_permission(Permission::EndpointIsolate));
        assert!(admin.check_permission(Permission::AlertRead));
        assert!(admin.check_permission(Permission::AlertWrite));
        assert!(admin.check_permission(Permission::EventRead));
        assert!(admin.check_permission(Permission::IocRead));
        assert!(admin.check_permission(Permission::IocWrite));
        assert!(admin.check_permission(Permission::IocDelete));
        assert!(admin.check_permission(Permission::PolicyRead));
        assert!(admin.check_permission(Permission::PolicyWrite));
        assert!(admin.check_permission(Permission::PolicyDelete));
        assert!(admin.check_permission(Permission::ScanRead));
        assert!(admin.check_permission(Permission::ScanWrite));
        assert!(admin.check_permission(Permission::ScanCancel));
        assert!(admin.check_permission(Permission::ReportRead));
        assert!(admin.check_permission(Permission::ReportGenerate));
        assert!(admin.check_permission(Permission::ResponseExecute));
        assert!(admin.check_permission(Permission::SettingsRead));
        assert!(admin.check_permission(Permission::SettingsWrite));
        assert!(admin.check_permission(Permission::AuditLogRead));
        assert!(admin.check_permission(Permission::LicenseManage));
    }

    #[test]
    fn test_viewer_limited_permissions() {
        let viewer = AuthContext::new("2".into(), "viewer".into(), Role::Viewer);
        assert!(viewer.check_permission(Permission::EndpointRead));
        assert!(viewer.check_permission(Permission::AlertRead));
        assert!(viewer.check_permission(Permission::EventRead));
        assert!(viewer.check_permission(Permission::IocRead));
        assert!(viewer.check_permission(Permission::PolicyRead));
        assert!(viewer.check_permission(Permission::ScanRead));
        assert!(viewer.check_permission(Permission::ReportRead));

        assert!(!viewer.check_permission(Permission::UserWrite));
        assert!(!viewer.check_permission(Permission::UserDelete));
        assert!(!viewer.check_permission(Permission::EndpointWrite));
        assert!(!viewer.check_permission(Permission::EndpointIsolate));
        assert!(!viewer.check_permission(Permission::AlertWrite));
        assert!(!viewer.check_permission(Permission::IocWrite));
        assert!(!viewer.check_permission(Permission::IocDelete));
        assert!(!viewer.check_permission(Permission::PolicyWrite));
        assert!(!viewer.check_permission(Permission::PolicyDelete));
        assert!(!viewer.check_permission(Permission::ScanWrite));
        assert!(!viewer.check_permission(Permission::ScanCancel));
        assert!(!viewer.check_permission(Permission::ReportGenerate));
        assert!(!viewer.check_permission(Permission::ResponseExecute));
        assert!(!viewer.check_permission(Permission::SettingsRead));
        assert!(!viewer.check_permission(Permission::SettingsWrite));
        assert!(!viewer.check_permission(Permission::AuditLogRead));
        assert!(!viewer.check_permission(Permission::LicenseManage));
    }

    #[test]
    fn test_automation_permissions() {
        let automation = AuthContext::new("4".into(), "bot".into(), Role::Automation);
        assert!(automation.check_permission(Permission::EndpointRead));
        assert!(automation.check_permission(Permission::AlertRead));
        assert!(automation.check_permission(Permission::EventRead));
        assert!(automation.check_permission(Permission::IocRead));
        assert!(automation.check_permission(Permission::ScanRead));
        assert!(automation.check_permission(Permission::ScanWrite));
        assert!(!automation.check_permission(Permission::UserWrite));
        assert!(!automation.check_permission(Permission::ResponseExecute));
    }

    #[test]
    fn test_require_permission_ok() {
        let admin = AuthContext::new("1".into(), "admin".into(), Role::Administrator);
        assert!(admin.require_permission(Permission::UserWrite).is_ok());
    }

    #[test]
    fn test_require_permission_fails() {
        let viewer = AuthContext::new("3".into(), "v".into(), Role::Viewer);
        assert!(viewer.require_permission(Permission::UserWrite).is_err());
        match viewer.require_permission(Permission::UserWrite) {
            Err(EdrError::AuthorizationFailed(msg)) => {
                assert!(msg.contains("UserWrite"));
            }
            _ => panic!("expected AuthorizationFailed"),
        }
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::from_str("administrator"), Some(Role::Administrator));
        assert_eq!(Role::from_str("admin"), Some(Role::Administrator));
        assert_eq!(Role::from_str("ADMIN"), Some(Role::Administrator));
        assert_eq!(Role::from_str("analyst"), Some(Role::Analyst));
        assert_eq!(Role::from_str("viewer"), Some(Role::Viewer));
        assert_eq!(Role::from_str("automation"), Some(Role::Automation));
        assert_eq!(Role::from_str("bot"), Some(Role::Automation));
        assert_eq!(Role::from_str("unknown"), None);
        assert_eq!(Role::from_str(""), None);
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!(Permission::from_str("user:read"), Some(Permission::UserRead));
        assert_eq!(Permission::from_str("user:write"), Some(Permission::UserWrite));
        assert_eq!(Permission::from_str("user:delete"), Some(Permission::UserDelete));
        assert_eq!(Permission::from_str("endpoint:read"), Some(Permission::EndpointRead));
        assert_eq!(Permission::from_str("endpoint:write"), Some(Permission::EndpointWrite));
        assert_eq!(Permission::from_str("endpoint:isolate"), Some(Permission::EndpointIsolate));
        assert_eq!(Permission::from_str("alert:read"), Some(Permission::AlertRead));
        assert_eq!(Permission::from_str("alert:write"), Some(Permission::AlertWrite));
        assert_eq!(Permission::from_str("event:read"), Some(Permission::EventRead));
        assert_eq!(Permission::from_str("ioc:read"), Some(Permission::IocRead));
        assert_eq!(Permission::from_str("ioc:write"), Some(Permission::IocWrite));
        assert_eq!(Permission::from_str("ioc:delete"), Some(Permission::IocDelete));
        assert_eq!(Permission::from_str("policy:read"), Some(Permission::PolicyRead));
        assert_eq!(Permission::from_str("policy:write"), Some(Permission::PolicyWrite));
        assert_eq!(Permission::from_str("policy:delete"), Some(Permission::PolicyDelete));
        assert_eq!(Permission::from_str("scan:read"), Some(Permission::ScanRead));
        assert_eq!(Permission::from_str("scan:write"), Some(Permission::ScanWrite));
        assert_eq!(Permission::from_str("scan:cancel"), Some(Permission::ScanCancel));
        assert_eq!(Permission::from_str("report:read"), Some(Permission::ReportRead));
        assert_eq!(Permission::from_str("report:generate"), Some(Permission::ReportGenerate));
        assert_eq!(Permission::from_str("response:execute"), Some(Permission::ResponseExecute));
        assert_eq!(Permission::from_str("settings:read"), Some(Permission::SettingsRead));
        assert_eq!(Permission::from_str("settings:write"), Some(Permission::SettingsWrite));
        assert_eq!(Permission::from_str("audit:read"), Some(Permission::AuditLogRead));
        assert_eq!(Permission::from_str("license:manage"), Some(Permission::LicenseManage));
        assert_eq!(Permission::from_str("invalid"), None);
    }

    #[test]
    fn test_role_serde() {
        let role = Role::Analyst;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"Analyst\"");
        let deserialized: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Role::Analyst);
    }

    #[test]
    fn test_permission_serde() {
        let perm = Permission::IocDelete;
        let json = serde_json::to_string(&perm).unwrap();
        assert_eq!(json, "\"IocDelete\"");
        let deserialized: Permission = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Permission::IocDelete);
    }
}
