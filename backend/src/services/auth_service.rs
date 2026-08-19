use crate::error::ServiceResult;
use monolith_shared::auth::{AuthContext, Role};
use monolith_shared::crypto::PasswordHashManager;

pub struct AuthService;

impl AuthService {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_credentials(&self, password: &str, hash: &str) -> ServiceResult<bool> {
        Ok(PasswordHashManager::verify(password, hash)?)
    }

    pub fn create_auth_context(
        &self,
        user_id: String,
        username: String,
        role_str: String,
    ) -> AuthContext {
        let role = Role::from_str(&role_str).unwrap_or(Role::Viewer);
        AuthContext::new(user_id, username, role)
    }

    pub fn validate_role_transition(
        &self,
        current_role: &str,
        new_role: &str,
    ) -> ServiceResult<bool> {
        let hierarchy = ["viewer", "analyst", "administrator"];
        let current_idx = hierarchy
            .iter()
            .position(|r| *r == current_role)
            .unwrap_or(0);
        let new_idx = hierarchy.iter().position(|r| *r == new_role).unwrap_or(0);
        // Only allow assigning roles at or below the current user's level
        Ok(new_idx <= current_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monolith_shared::auth::Role;

    #[test]
    fn test_create_auth_context_known_role() {
        let service = AuthService::new();
        let ctx =
            service.create_auth_context("user-1".into(), "alice".into(), "administrator".into());
        assert_eq!(ctx.user_id, "user-1");
        assert_eq!(ctx.username, "alice");
        assert_eq!(ctx.role, Role::Administrator);
    }

    #[test]
    fn test_create_auth_context_unknown_role_defaults_to_viewer() {
        let service = AuthService::new();
        let ctx = service.create_auth_context("user-2".into(), "bob".into(), "superadmin".into());
        assert_eq!(ctx.role, Role::Viewer);
    }

    #[test]
    fn test_validate_role_transition_admin_can_assign_any() {
        let service = AuthService::new();
        assert!(
            service
                .validate_role_transition("administrator", "administrator")
                .unwrap()
        );
        assert!(
            service
                .validate_role_transition("administrator", "analyst")
                .unwrap()
        );
        assert!(
            service
                .validate_role_transition("administrator", "viewer")
                .unwrap()
        );
    }

    #[test]
    fn test_validate_role_transition_analyst_cannot_assign_admin() {
        let service = AuthService::new();
        assert!(
            !service
                .validate_role_transition("analyst", "administrator")
                .unwrap()
        );
        assert!(
            service
                .validate_role_transition("analyst", "analyst")
                .unwrap()
        );
        assert!(
            service
                .validate_role_transition("analyst", "viewer")
                .unwrap()
        );
    }

    #[test]
    fn test_validate_role_transition_viewer_cannot_promote() {
        let service = AuthService::new();
        assert!(
            !service
                .validate_role_transition("viewer", "administrator")
                .unwrap()
        );
        assert!(
            !service
                .validate_role_transition("viewer", "analyst")
                .unwrap()
        );
        assert!(
            service
                .validate_role_transition("viewer", "viewer")
                .unwrap()
        );
    }
}
