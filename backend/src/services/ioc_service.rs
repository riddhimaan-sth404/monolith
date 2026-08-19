use crate::error::ServiceResult;
use monolith_shared::types::IocType;
use std::collections::HashSet;

pub struct IocService;

impl IocService {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_ioc_value(&self, ioc_type: &IocType, value: &str) -> ServiceResult<()> {
        match ioc_type {
            IocType::Sha256 => {
                if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(monolith_shared::error::EdrError::ValidationError(
                        "SHA256 must be 64 hex characters".into(),
                    ));
                }
            }
            IocType::Sha1 => {
                if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(monolith_shared::error::EdrError::ValidationError(
                        "SHA1 must be 40 hex characters".into(),
                    ));
                }
            }
            IocType::Md5 => {
                if value.len() != 32 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(monolith_shared::error::EdrError::ValidationError(
                        "MD5 must be 32 hex characters".into(),
                    ));
                }
            }
            IocType::Domain | IocType::Url | IocType::Ip => {
                if value.is_empty() {
                    return Err(monolith_shared::error::EdrError::ValidationError(
                        "value must not be empty".into(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn deduplicate_iocs(&self, values: &[String]) -> HashSet<String> {
        values.iter().cloned().collect()
    }
}
