use monolith_shared::config::{
    ConfigError, ConfigLoader, DatabaseConfig, LoggingConfig, TlsConfig,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub grpc_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8443,
            grpc_port: 9443,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRulesConfig {
    pub enabled: bool,
    pub path: String,
}

impl Default for ResponseRulesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "configs/response_rules.toml".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_second: u64,
    pub burst_size: u64,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub rate_limiting: RateLimitingConfig,
    pub response_rules: ResponseRulesConfig,
    pub notifications: NotificationsConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration_secs: u64,
    pub refresh_expiration_secs: u64,
    pub argon2_memory_cost: u32,
    pub argon2_time_cost: u32,
    pub argon2_parallelism: u32,
    pub jwt_private_key_path: Option<String>,
    pub jwt_public_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    pub enabled: bool,
    pub toast_script_path: String,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            toast_script_path: "backend/scripts/send-toast.ps1".to_string(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "CHANGE_ME_GENERATE_SECURE_RANDOM_64_BYTES".to_string(),
            jwt_expiration_secs: 3600,
            refresh_expiration_secs: 86400,
            argon2_memory_cost: 19456,
            argon2_time_cost: 2,
            argon2_parallelism: 1,
            jwt_private_key_path: None,
            jwt_public_key_path: None,
        }
    }
}

impl AuthConfig {
    pub fn build_jwt_manager_custom(
        &self,
        exp_secs: u64,
        refresh_exp_secs: u64,
    ) -> Result<monolith_shared::crypto::JwtManager, String> {
        if let (Some(priv_path), Some(pub_path)) =
            (&self.jwt_private_key_path, &self.jwt_public_key_path)
        {
            if !priv_path.is_empty() && !pub_path.is_empty() {
                let priv_key = std::fs::read(priv_path)
                    .map_err(|e| format!("Failed to read private key from {}: {}", priv_path, e))?;
                let pub_key = std::fs::read(pub_path)
                    .map_err(|e| format!("Failed to read public key from {}: {}", pub_path, e))?;

                return monolith_shared::crypto::JwtManager::new_rsa(
                    &priv_key,
                    &pub_key,
                    exp_secs,
                    refresh_exp_secs,
                )
                .map_err(|e| format!("Failed to initialize RS256 JWT Manager: {}", e));
            }
        }

        Ok(monolith_shared::crypto::JwtManager::new(
            self.jwt_secret.as_bytes(),
            exp_secs,
            refresh_exp_secs,
        ))
    }

    pub fn build_jwt_manager(&self) -> Result<monolith_shared::crypto::JwtManager, String> {
        self.build_jwt_manager_custom(self.jwt_expiration_secs, self.refresh_expiration_secs)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            tls: TlsConfig {
                cert_path: "certs/server.pem".to_string(),
                key_path: "certs/server.key".to_string(),
                ca_cert_path: "certs/ca.pem".to_string(),
            },
            database: DatabaseConfig::default(),
            logging: LoggingConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            response_rules: ResponseRulesConfig::default(),
            notifications: NotificationsConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monolith_shared::config::ConfigLoader;

    #[test]
    fn test_server_config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.grpc_port, 9443);
    }

    #[test]
    fn test_rate_limiting_defaults() {
        let cfg = RateLimitingConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.requests_per_second, 100);
        assert_eq!(cfg.burst_size, 200);
    }

    #[test]
    fn test_auth_config_defaults() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.jwt_secret, "CHANGE_ME_GENERATE_SECURE_RANDOM_64_BYTES");
        assert_eq!(cfg.jwt_expiration_secs, 3600);
        assert_eq!(cfg.refresh_expiration_secs, 86400);
        assert_eq!(cfg.argon2_memory_cost, 19456);
        assert_eq!(cfg.argon2_time_cost, 2);
        assert_eq!(cfg.argon2_parallelism, 1);
    }

    #[test]
    fn test_app_config_defaults() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.server.port, 8443);
        assert_eq!(cfg.database.path, "data/edr.db");
        assert_eq!(cfg.tls.cert_path, "certs/server.pem");
        assert!(cfg.response_rules.enabled);
    }

    #[test]
    fn test_validate_fails_on_zero_port() {
        let mut cfg = AppConfig::default();
        cfg.server.port = 0;
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("port"));
    }

    #[test]
    fn test_validate_fails_on_short_jwt_secret() {
        let mut cfg = AppConfig::default();
        cfg.auth.jwt_secret = "short".to_string();
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("jwt_secret"));
    }

    #[test]
    fn test_validate_fails_on_empty_tls_paths() {
        let mut cfg = AppConfig::default();
        cfg.auth.jwt_secret = "a".repeat(32);
        cfg.tls.cert_path = String::new();
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TLS"));
    }

    #[test]
    fn test_validate_succeeds_with_valid_config() {
        let mut cfg = AppConfig::default();
        cfg.auth.jwt_secret = "a".repeat(32);
        let result = cfg.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_toml_roundtrip() {
        let cfg = AppConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.server.port, cfg.server.port);
        assert_eq!(parsed.database.path, cfg.database.path);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = AppConfig::load("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }
}

impl ConfigLoader for AppConfig {
    fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content_bytes = std::fs::read(path.as_ref())?;

        let content = String::from_utf8(content_bytes)
            .map_err(|e| ConfigError::ValidationError(format!("Invalid UTF-8 in config: {}", e)))?;
        let mut config: AppConfig = toml::from_str(&content)?;

        // Allow env var to override JWT secret (avoids storing secrets in config files)
        if let Ok(secret) = std::env::var("EDR_JWT_SECRET") {
            if !secret.is_empty() {
                config.auth.jwt_secret = secret;
            }
        }

        // Apply license-based config (takes precedence over file + env)
        if let Ok(Some(license_cfg)) = crate::license::load_licensed_config() {
            crate::license::apply_to_appconfig(&mut config, &license_cfg);
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::ValidationError(
                "server.port must be > 0".into(),
            ));
        }
        if self.auth.jwt_secret.len() < 32 {
            return Err(ConfigError::ValidationError(
                "auth.jwt_secret must be at least 32 characters".into(),
            ));
        }
        if self.auth.jwt_secret.starts_with("CHANGE_ME_")
            || self.auth.jwt_secret == "CHANGE_ME_GENERATE_SECURE_RANDOM_64_BYTES"
        {
            return Err(ConfigError::ValidationError(
                "auth.jwt_secret must not be the default value. Set EDR_JWT_SECRET env var or configure a unique secret.".into(),
            ));
        }
        if self.tls.cert_path.is_empty() || self.tls.key_path.is_empty() {
            return Err(ConfigError::ValidationError(
                "TLS cert and key paths required".into(),
            ));
        }
        Ok(())
    }
}
