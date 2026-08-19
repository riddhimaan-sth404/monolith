use monolith_shared::config::{
    ConfigError, ConfigLoader, DatabaseConfig, LoggingConfig, TlsConfig,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent: AgentSettings,
    pub server: ServerConnection,
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub heartbeat: HeartbeatConfig,
    pub offline_queue: OfflineQueueConfig,
    pub driver: DriverConfig,
    pub scanner: ScannerConnection,
    pub polling: PollingConfig,
    pub service: ServiceSettings,
    #[serde(default)]
    pub memory_scanner: MemoryScannerConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
    #[serde(default)]
    pub restore: RestoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScannerConfig {
    pub enabled: bool,
    pub max_region_size_mb: u64,
    pub cooldown_secs: u64,
    pub periodic_sweep_interval_secs: u64,
    pub skip_signed_processes: bool,
    pub excluded_process_names: Vec<String>,
}

impl Default for MemoryScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_region_size_mb: 8,
            cooldown_secs: 60,
            periodic_sweep_interval_secs: 300,
            skip_signed_processes: true,
            excluded_process_names: vec![
                "chrome.exe".to_string(),
                "firefox.exe".to_string(),
                "msedge.exe".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSettings {
    pub endpoint_id: String,
    pub log_level: String,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            endpoint_id: "auto".to_string(),
            log_level: "INFO".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnection {
    pub host: String,
    pub rest_port: u16,
    pub grpc_port: u16,
}

impl Default for ServerConnection {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            rest_port: 8443,
            grpc_port: 9443,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    pub interval_secs: u64,
    pub retry_interval_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            retry_interval_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineQueueConfig {
    pub max_size: u32,
    pub flush_batch_size: u32,
}

impl Default for OfflineQueueConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            flush_batch_size: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverConfig {
    pub name: String,
    pub buffer_size: u32,
    pub poll_interval_ms: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            name: "\\\\.\\EDR".to_string(),
            buffer_size: 65536,
            poll_interval_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConnection {
    pub address: String,
    pub timeout_secs: u64,
    pub event_listener_port: u16,
    pub api_url: String,
}

impl Default for ScannerConnection {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:50072".to_string(),
            timeout_secs: 30,
            event_listener_port: 8090,
            api_url: "http://127.0.0.1:50053".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollingConfig {
    pub policy_interval_secs: u64,
    pub ioc_interval_secs: u64,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            policy_interval_secs: 60,
            ioc_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSettings {
    pub display_name: String,
    pub description: String,
    pub start_type: String,
    pub dependencies: Vec<String>,
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            display_name: "EDR Endpoint Agent".to_string(),
            description: "Endpoint Detection and Response Agent".to_string(),
            start_type: "auto".to_string(),
            dependencies: vec!["EDRDriver".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub auto_tune: bool,
    pub edr_profile: String,
    pub pc_profile_override: Option<String>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            auto_tune: true,
            edr_profile: "balanced".to_string(),
            pc_profile_override: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreConfig {
    pub enabled: bool,
    pub auto_install_snapshots: bool,
    pub max_snapshots: u32,
    pub volume: String,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_install_snapshots: true,
            max_snapshots: 14,
            volume: "C:".to_string(),
        }
    }
}

impl ConfigLoader for AgentConfig {
    fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content_bytes = std::fs::read(path.as_ref())?;

        // Enforce config file signing
        let sig_path = path.as_ref().with_extension("toml.sig");
        if sig_path.exists() {
            let sig_bytes = std::fs::read(&sig_path)?;
            if !monolith_shared::crypto::verify_config(&content_bytes, &sig_bytes) {
                return Err(ConfigError::ValidationError(
                    "Configuration file signature mismatch - tampering suspected".into(),
                ));
            }
        } else {
            // First run or missing signature: sign the configuration file and save signature
            let sig_bytes = monolith_shared::crypto::sign_config(&content_bytes);
            let _ = std::fs::write(&sig_path, sig_bytes);
        }

        let content = String::from_utf8(content_bytes)
            .map_err(|e| ConfigError::ValidationError(format!("Invalid UTF-8 in config: {}", e)))?;
        let config: AgentConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.host.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "server.host must not be empty".into(),
            ));
        }
        if self.server.grpc_port == 0 {
            return Err(ConfigError::ValidationError(
                "server.grpc_port must be 1-65535".into(),
            ));
        }
        if self.server.rest_port == 0 {
            return Err(ConfigError::ValidationError(
                "server.rest_port must be 1-65535".into(),
            ));
        }
        if self.driver.name.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "driver.name must not be empty".into(),
            ));
        }
        if self.driver.buffer_size < 4096 {
            return Err(ConfigError::ValidationError(
                "driver.buffer_size must be >= 4096".into(),
            ));
        }
        if self.driver.poll_interval_ms == 0 {
            return Err(ConfigError::ValidationError(
                "driver.poll_interval_ms must be > 0".into(),
            ));
        }
        if self.heartbeat.interval_secs == 0 {
            return Err(ConfigError::ValidationError(
                "heartbeat.interval_secs must be > 0".into(),
            ));
        }
        if self.offline_queue.max_size == 0 {
            return Err(ConfigError::ValidationError(
                "offline_queue.max_size must be > 0".into(),
            ));
        }
        if self.polling.policy_interval_secs == 0 {
            return Err(ConfigError::ValidationError(
                "polling.policy_interval_secs must be > 0".into(),
            ));
        }
        if self.scanner.address.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "scanner.address must not be empty".into(),
            ));
        }
        if self.scanner.api_url.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "scanner.api_url must not be empty".into(),
            ));
        }
        if self.database.path.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "database.path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monolith_shared::config::ConfigError;

    fn valid_config() -> AgentConfig {
        AgentConfig {
            agent: AgentSettings {
                endpoint_id: "test-host".to_string(),
                log_level: "INFO".to_string(),
            },
            server: ServerConnection {
                host: "127.0.0.1".to_string(),
                rest_port: 8443,
                grpc_port: 9443,
            },
            tls: TlsConfig {
                ca_cert_path: "certs/ca.pem".to_string(),
                cert_path: "certs/agent.pem".to_string(),
                key_path: "certs/agent-key.pem".to_string(),
            },
            database: DatabaseConfig {
                kind: monolith_shared::config::DatabaseKind::Sqlite,
                path: "C:\\ProgramData\\Monolith\\agent.db".to_string(),
                max_connections: 4,
            },
            logging: LoggingConfig {
                level: monolith_shared::config::LogLevel::Info,
                format: monolith_shared::config::LogFormat::Json,
                directory: "C:\\ProgramData\\Monolith\\logs".to_string(),
                rotation: monolith_shared::config::LogRotation::Daily,
                compression: true,
                max_files: 7,
            },
            heartbeat: HeartbeatConfig {
                interval_secs: 30,
                retry_interval_secs: 5,
            },
            offline_queue: OfflineQueueConfig {
                max_size: 10000,
                flush_batch_size: 100,
            },
            driver: DriverConfig {
                name: "\\\\.\\EDR".to_string(),
                buffer_size: 65536,
                poll_interval_ms: 100,
            },
            scanner: ScannerConnection {
                address: "127.0.0.1:50072".to_string(),
                timeout_secs: 30,
                event_listener_port: 8090,
                api_url: "http://127.0.0.1:50053".to_string(),
            },
            polling: PollingConfig {
                policy_interval_secs: 60,
                ioc_interval_secs: 300,
            },
            service: ServiceSettings::default(),
            memory_scanner: Default::default(),
            performance: Default::default(),
            restore: Default::default(),
        }
    }

    #[test]
    fn test_valid_config_passes_validation() {
        let cfg = valid_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_empty_host_fails() {
        let mut cfg = valid_config();
        cfg.server.host = "   ".to_string();
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("host")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_grpc_port_zero_fails() {
        let mut cfg = valid_config();
        cfg.server.grpc_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_rest_port_zero_fails() {
        let mut cfg = valid_config();
        cfg.server.rest_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_empty_driver_name_fails() {
        let mut cfg = valid_config();
        cfg.driver.name = "".to_string();
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("driver.name")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_buffer_size_less_than_4096_fails() {
        let mut cfg = valid_config();
        cfg.driver.buffer_size = 1000;
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("buffer_size")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_buffer_size_4096_passes() {
        let mut cfg = valid_config();
        cfg.driver.buffer_size = 4096;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_poll_interval_zero_fails() {
        let mut cfg = valid_config();
        cfg.driver.poll_interval_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_heartbeat_interval_zero_fails() {
        let mut cfg = valid_config();
        cfg.heartbeat.interval_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_offline_queue_max_size_zero_fails() {
        let mut cfg = valid_config();
        cfg.offline_queue.max_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_polling_interval_zero_fails() {
        let mut cfg = valid_config();
        cfg.polling.policy_interval_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_empty_scanner_address_fails() {
        let mut cfg = valid_config();
        cfg.scanner.address = "".to_string();
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("scanner.address")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_empty_scanner_api_url_fails() {
        let mut cfg = valid_config();
        cfg.scanner.api_url = "".to_string();
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("scanner.api_url")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_empty_database_path_fails() {
        let mut cfg = valid_config();
        cfg.database.path = "".to_string();
        match cfg.validate() {
            Err(ConfigError::ValidationError(msg)) => assert!(msg.contains("database.path")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_whitespace_host_fails() {
        let mut cfg = valid_config();
        cfg.server.host = "   ".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_whitespace_driver_name_fails() {
        let mut cfg = valid_config();
        cfg.driver.name = "   ".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_default_values_are_valid() {
        let cfg = AgentConfig {
            agent: Default::default(),
            server: Default::default(),
            tls: TlsConfig {
                ca_cert_path: "certs/ca.pem".to_string(),
                cert_path: "certs/agent.pem".to_string(),
                key_path: "certs/agent-key.pem".to_string(),
            },
            database: DatabaseConfig {
                kind: monolith_shared::config::DatabaseKind::Sqlite,
                path: "C:\\ProgramData\\Monolith\\agent.db".to_string(),
                max_connections: 4,
            },
            logging: LoggingConfig {
                level: monolith_shared::config::LogLevel::Info,
                format: monolith_shared::config::LogFormat::Json,
                directory: "C:\\ProgramData\\Monolith\\logs".to_string(),
                rotation: monolith_shared::config::LogRotation::Daily,
                compression: true,
                max_files: 7,
            },
            heartbeat: Default::default(),
            offline_queue: Default::default(),
            driver: Default::default(),
            scanner: Default::default(),
            polling: Default::default(),
            service: Default::default(),
            memory_scanner: Default::default(),
            performance: Default::default(),
            restore: Default::default(),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_e2e_config_roundtrip() {
        let cfg = valid_config();
        let toml_str = toml::to_string(&cfg).expect("serialize");
        let parsed: AgentConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(cfg.server.host, parsed.server.host);
        assert_eq!(cfg.server.grpc_port, parsed.server.grpc_port);
        assert_eq!(cfg.driver.name, parsed.driver.name);
        assert_eq!(cfg.driver.buffer_size, parsed.driver.buffer_size);
        assert_eq!(cfg.scanner.address, parsed.scanner.address);
        assert_eq!(cfg.database.path, parsed.database.path);
    }
}
