use crate::error::{EdrError, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::ed25519::signature::Verifier;
use serde::{Deserialize, Serialize};

const VENDOR_PUBLIC_KEY_HEX: &str = "84900f37fd5206c6cc9c5dec6f93bafd1f2db6aa5231e26f24751f14009e24c2";
const LICENSE_BEGIN: &str = "-----BEGIN EDR LICENSE v1-----";
const LICENSE_END: &str = "-----END EDR LICENSE v1-----";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseConfig {
    #[serde(default)]
    pub jwt_secret: String,

    #[serde(default)]
    pub quarantine_key: String,

    #[serde(default)]
    pub server_port: Option<u16>,

    #[serde(default)]
    pub grpc_port: Option<u16>,

    #[serde(default)]
    pub ws_port: Option<u16>,

    #[serde(default)]
    pub tls_cert_pem: Option<String>,

    #[serde(default)]
    pub tls_key_pem: Option<String>,

    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub vendor: String,
    pub issued: String,
    pub expires: String,
    #[serde(default)]
    pub hw_fingerprint: String,
    pub config: LicenseConfig,
}

#[derive(Debug, Clone)]
pub struct LicenseBundle {
    pub payload: LicensePayload,
}

impl LicenseBundle {
    pub fn is_expired(&self) -> bool {
        DateTime::parse_from_rfc3339(&self.payload.expires)
            .map(|exp| exp < Utc::now())
            .unwrap_or(true)
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.payload.expires)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    }

    pub fn issued_at(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.payload.issued)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    }

    pub fn verify_fingerprint(&self, machine_fingerprint: &str) -> bool {
        if self.payload.hw_fingerprint.is_empty() {
            return true;
        }
        self.payload.hw_fingerprint == machine_fingerprint
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.payload.config.features.iter().any(|f| f == feature)
    }
}

pub fn parse_license_file(content: &str) -> Result<LicenseBundle> {
    let stripped = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| *line != LICENSE_BEGIN && *line != LICENSE_END && !line.is_empty())
        .collect::<Vec<_>>()
        .join("");

    let engine = base64::engine::general_purpose::STANDARD;
    let parts: Vec<&str> = stripped.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(EdrError::ConfigError("invalid license format: expected payload.signature".into()));
    }

    let payload_bytes = engine.decode(parts[0])
        .map_err(|e| EdrError::ConfigError(format!("invalid license base64 payload: {}", e)))?;
    let sig_bytes = engine.decode(parts[1])
        .map_err(|e| EdrError::ConfigError(format!("invalid license base64 signature: {}", e)))?;

    let pub_bytes = hex::decode(VENDOR_PUBLIC_KEY_HEX)
        .map_err(|e| EdrError::ConfigError(format!("invalid public key hex: {}", e)))?;
    if pub_bytes.len() != 32 {
        return Err(EdrError::ConfigError("invalid public key length".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);
    let verifying_key = VerifyingKey::from_bytes(&arr)
        .map_err(|e| EdrError::ConfigError(format!("invalid public key: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(EdrError::ConfigError("invalid signature length".into()));
    }
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| EdrError::ConfigError(format!("invalid signature: {}", e)))?;

    verifying_key.verify(&payload_bytes, &sig)
        .map_err(|_| EdrError::ConfigError("license signature verification failed".into()))?;

    let payload_str = String::from_utf8(payload_bytes)
        .map_err(|_| EdrError::ConfigError("license payload is not valid UTF-8".into()))?;
    let payload: LicensePayload = serde_json::from_str(&payload_str)
        .map_err(|e| EdrError::ConfigError(format!("invalid license payload JSON: {}", e)))?;

    let bundle = LicenseBundle { payload };

    if bundle.is_expired() {
        return Err(EdrError::ConfigError("license has expired".into()));
    }

    Ok(bundle)
}

pub fn find_license_file() -> Result<Option<LicenseBundle>> {
    let paths = [
        "configs/license.lic",
        "../configs/license.lic",
    ];

    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(bundle) = parse_license_file(&content) {
                return Ok(Some(bundle));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_armor() {
        let result = parse_license_file("not-a-valid-license-format");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty() {
        let result = parse_license_file("");
        assert!(result.is_err());
    }

    #[test]
    fn test_license_expired() {
        let payload = LicensePayload {
            vendor: "Test".into(),
            issued: "2020-01-01T00:00:00Z".into(),
            expires: "2020-06-01T00:00:00Z".into(),
            hw_fingerprint: String::new(),
            config: LicenseConfig {
                jwt_secret: String::new(),
                quarantine_key: String::new(),
                server_port: None,
                grpc_port: None,
                ws_port: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                features: vec![],
            },
        };
        let bundle = LicenseBundle { payload };
        assert!(bundle.is_expired());
    }

    #[test]
    fn test_license_not_expired() {
        let far_future = Utc::now() + chrono::Duration::days(365);
        let payload = LicensePayload {
            vendor: "Test".into(),
            issued: Utc::now().to_rfc3339(),
            expires: far_future.to_rfc3339(),
            hw_fingerprint: String::new(),
            config: LicenseConfig {
                jwt_secret: String::new(),
                quarantine_key: String::new(),
                server_port: None,
                grpc_port: None,
                ws_port: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                features: vec![],
            },
        };
        let bundle = LicenseBundle { payload };
        assert!(!bundle.is_expired());
    }

    #[test]
    fn test_verify_fingerprint_match() {
        let bundle = LicenseBundle {
            payload: LicensePayload {
                hw_fingerprint: "abc123".into(),
                ..create_test_payload()
            },
        };
        assert!(bundle.verify_fingerprint("abc123"));
        assert!(!bundle.verify_fingerprint("wrong"));
    }

    #[test]
    fn test_verify_fingerprint_empty() {
        let bundle = LicenseBundle {
            payload: LicensePayload {
                hw_fingerprint: String::new(),
                ..create_test_payload()
            },
        };
        assert!(bundle.verify_fingerprint("anything"));
    }

    #[test]
    fn test_has_feature() {
        let bundle = LicenseBundle {
            payload: LicensePayload {
                config: LicenseConfig {
                    features: vec!["core".into()],
                    ..Default::default()
                },
                ..create_test_payload()
            },
        };
        assert!(bundle.has_feature("core"));
        assert!(!bundle.has_feature("sandbox"));
    }

    fn create_test_payload() -> LicensePayload {
        let future = Utc::now() + chrono::Duration::days(30);
        LicensePayload {
            vendor: "Test".into(),
            issued: Utc::now().to_rfc3339(),
            expires: future.to_rfc3339(),
            hw_fingerprint: String::new(),
            config: LicenseConfig::default(),
        }
    }
}
