use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("validation error: {0}")]
    ValidationError(String),
}

pub trait ConfigLoader: Sized {
    fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError>;
    fn validate(&self) -> Result<(), ConfigError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub directory: String,
    pub rotation: LogRotation,
    pub compression: bool,
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            directory: "logs".to_string(),
            rotation: LogRotation::Daily,
            compression: true,
            max_files: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARNING"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    Hourly,
    Daily,
    Weekly,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub kind: DatabaseKind,
    pub path: String,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            kind: DatabaseKind::Sqlite,
            path: "data/edr.db".to_string(),
            max_connections: 16,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_secs: u64,
    pub refresh_expiration_secs: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            expiration_secs: 3600,
            refresh_expiration_secs: 86400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 19456,
            time_cost: 2,
            parallelism: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_config_defaults() {
        let cfg = LoggingConfig::default();
        assert_eq!(cfg.level, LogLevel::Info);
        assert_eq!(cfg.format, LogFormat::Json);
        assert_eq!(cfg.directory, "logs");
        assert_eq!(cfg.rotation, LogRotation::Daily);
        assert!(cfg.compression);
        assert_eq!(cfg.max_files, 30);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "TRACE");
        assert_eq!(LogLevel::Debug.to_string(), "DEBUG");
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Warning.to_string(), "WARNING");
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
        assert_eq!(LogLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_database_config_defaults() {
        let cfg = DatabaseConfig::default();
        assert_eq!(cfg.kind, DatabaseKind::Sqlite);
        assert_eq!(cfg.path, "data/edr.db");
        assert_eq!(cfg.max_connections, 16);
    }

    #[test]
    fn test_jwt_config_defaults() {
        let cfg = JwtConfig::default();
        assert!(cfg.secret.is_empty());
        assert_eq!(cfg.expiration_secs, 3600);
        assert_eq!(cfg.refresh_expiration_secs, 86400);
    }

    #[test]
    fn test_argon2_config_defaults() {
        let cfg = Argon2Config::default();
        assert_eq!(cfg.memory_cost, 19456);
        assert_eq!(cfg.time_cost, 2);
        assert_eq!(cfg.parallelism, 1);
    }

    #[test]
    fn test_toml_roundtrip() {
        let cfg = LoggingConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: LoggingConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.level, cfg.level);
        assert_eq!(parsed.format, cfg.format);
        assert_eq!(parsed.directory, cfg.directory);
    }

    #[test]
    fn test_toml_parse_log_level() {
        let toml_str = r#"level = "debug"
format = "text"
directory = "/var/log/edr"
rotation = "hourly"
compression = false
max_files = 7"#;
        let cfg: LoggingConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.level, LogLevel::Debug);
        assert_eq!(cfg.format, LogFormat::Text);
        assert_eq!(cfg.directory, "/var/log/edr");
        assert_eq!(cfg.rotation, LogRotation::Hourly);
        assert!(!cfg.compression);
        assert_eq!(cfg.max_files, 7);
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::ValidationError("bad config".into());
        assert_eq!(err.to_string(), "validation error: bad config");
    }
}
