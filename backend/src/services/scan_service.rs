use uuid::Uuid;
use monolith_shared::types::ScanId;
use crate::error::ServiceResult;

pub struct ScanService;

impl ScanService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_scan_id(&self) -> ScanId {
        Uuid::new_v4()
    }

    pub fn validate_scan_paths(&self, paths: &[String]) -> ServiceResult<()> {
        for path in paths {
            if path.is_empty() {
                return Err(monolith_shared::error::EdrError::ValidationError(
                    "scan path must not be empty".into(),
                ));
            }
            if !path.starts_with("C:\\") && !path.starts_with("D:\\") {
                return Err(monolith_shared::error::EdrError::ValidationError(
                    format!("invalid scan path: {}", path),
                ));
            }
        }
        Ok(())
    }
}
