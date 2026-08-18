use tracing_subscriber::{
    fmt,
    prelude::*,
    registry,
    EnvFilter,
};
use tracing_appender::rolling;
use serde_json::Value;
use std::str::FromStr;

use crate::config::{LogFormat, LogRotation, LoggingConfig};

pub fn init_logging(config: &LoggingConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&config.directory)?;

    let env_filter = EnvFilter::from_str(&config.level.to_string())
        .unwrap_or_else(|_| EnvFilter::new("INFO"));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true);

    match config.format {
        LogFormat::Json => {
            let file_appender = match config.rotation {
                LogRotation::Hourly => rolling::hourly(&config.directory, "edr"),
                LogRotation::Daily => rolling::daily(&config.directory, "edr"),
                LogRotation::Weekly => rolling::minutely(&config.directory, "edr"), // approx weekly
                LogRotation::Never => rolling::never(&config.directory, "edr"),
            };

            let json_file = fmt::layer()
                .json()
                .with_writer(file_appender)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);

            let json_stdout = fmt::layer()
                .json()
                .with_writer(std::io::stdout);

            registry()
                .with(env_filter)
                .with(json_file)
                .with(json_stdout)
                .init();
        }
        LogFormat::Text => {
            let file_appender = match config.rotation {
                LogRotation::Hourly => rolling::hourly(&config.directory, "edr"),
                LogRotation::Daily => rolling::daily(&config.directory, "edr"),
                LogRotation::Weekly => rolling::minutely(&config.directory, "edr"),
                LogRotation::Never => rolling::never(&config.directory, "edr"),
            };

            let text_file = fmt::layer()
                .with_writer(file_appender);

            registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(text_file)
                .init();
        }
    }

    tracing::info!("logging initialized: level={}, format={:?}, dir={}", 
        config.level, config.format, config.directory);

    Ok(())
}

pub fn structured_event(
    level: tracing::Level,
    message: impl std::fmt::Display,
    fields: Vec<(&str, Value)>,
) {
    let mut json = serde_json::json!({
        "message": message.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    for (key, value) in fields {
        json[key] = value;
    }

    match level {
        tracing::Level::TRACE => tracing::trace!("{}", json.to_string()),
        tracing::Level::DEBUG => tracing::debug!("{}", json.to_string()),
        tracing::Level::INFO => tracing::info!("{}", json.to_string()),
        tracing::Level::WARN => tracing::warn!("{}", json.to_string()),
        tracing::Level::ERROR => tracing::error!("{}", json.to_string()),
    }
}

#[macro_export]
macro_rules! log_json {
    ($level:expr, $msg:expr, $($key:expr => $val:expr),* $(,)?) => {
        $crate::logging::structured_event(
            $level,
            $msg,
            vec![$(($key, ::serde_json::Value::from($val))),*],
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogLevel;
    use tempfile::TempDir;

    #[test]
    fn test_logging_init() {
        let dir = TempDir::new().unwrap();
        let config = LoggingConfig {
            level: LogLevel::Debug,
            format: LogFormat::Json,
            directory: dir.path().to_str().unwrap().to_string(),
            rotation: LogRotation::Never,
            compression: false,
            max_files: 5,
        };
        assert!(init_logging(&config).is_ok());
        tracing::info!("test message");
        // Verify log file was created
        let entries = std::fs::read_dir(dir.path()).unwrap();
        assert!(entries.count() > 0);
    }
}
