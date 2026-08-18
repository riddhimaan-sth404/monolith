#![allow(missing_docs)]
use std::path::PathBuf;
use std::sync::Arc;
use clap::Parser;
use monolith_backend::{config::AppConfig, server::Server};
use monolith_shared::config::{ConfigLoader, DatabaseKind};
use monolith_shared::db::{Database, PostgresDatabase, SqliteDatabase};
use monolith_shared::logging::init_logging;

#[derive(Parser)]
#[command(name = "monolith-backend", version, about = "Monolith Management Server")]
struct Cli {
    #[arg(short, long, default_value = "configs/backend.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Apply NTFS ACL hardening to configuration files on Windows
    #[cfg(target_os = "windows")]
    {
        if let Some(path_str) = cli.config.to_str() {
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/inheritance:d"])
                .output();
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/remove", "*S-1-5-32-545"])
                .output();
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/grant", "*S-1-5-32-544:F"])
                .output();
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/grant", "*S-1-5-18:F"])
                .output();

            let sig_path = cli.config.with_extension("toml.sig");
            if sig_path.exists() {
                if let Some(sig_str) = sig_path.to_str() {
                    let _ = std::process::Command::new("icacls")
                        .args([sig_str, "/inheritance:d"])
                        .output();
                    let _ = std::process::Command::new("icacls")
                        .args([sig_str, "/remove", "*S-1-5-32-545"])
                        .output();
                    let _ = std::process::Command::new("icacls")
                        .args([sig_str, "/grant", "*S-1-5-32-544:F"])
                        .output();
                    let _ = std::process::Command::new("icacls")
                        .args([sig_str, "/grant", "*S-1-5-18:F"])
                        .output();
                }
            }
        }
    }

    // Load configuration
    let config = AppConfig::load(&cli.config)?;

    // Initialize logging
    init_logging(&config.logging).map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;

    tracing::info!("starting EDR backend server");

    // Initialize database (supports both SQLite and PostgreSQL)
    tracing::info!("connecting to {:?}: {}", config.database.kind, config.database.path);
    let conn: Box<dyn monolith_shared::db::DatabaseConnection> = match config.database.kind {
        DatabaseKind::Sqlite => {
            let db = SqliteDatabase::new(&config.database.path);
            Box::new(db.connect(&config.database).await?)
        }
        DatabaseKind::Postgres => {
            let db = PostgresDatabase::new();
            Box::new(db.connect(&config.database).await?)
        }
    };

    // Run migrations
    let migration_mgr = monolith_shared::db::MigrationManager::new();
    migration_mgr.run(&*conn).await?;

    // Seed/Reset default admin account (admin / admin) and unlock account
    if let Ok(password_hash) = monolith_shared::crypto::PasswordHashManager::hash("admin") {
        let _ = conn.execute(
            "INSERT INTO users (id, username, password_hash, email, role, enabled, failed_attempts, locked_until)
             VALUES ('usr-admin-001', 'admin', ?1, 'admin@monolith.local', 'administrator', 1, 0, NULL)
             ON CONFLICT(username) DO UPDATE SET password_hash = ?1, enabled = 1, failed_attempts = 0, locked_until = NULL",
            &[monolith_shared::db::DbParam::Text(password_hash)],
        ).await;
    }

    // Build application state
    let state = Arc::new(monolith_backend::server::AppState::new(
        config.clone(),
        conn,
    ));

    // Initialize detection service with response rules
    monolith_backend::server::initialize_detection_service(&state, &config);

    // Start server
    let server = Server::new(config, state);
    server.run().await?;

    Ok(())
}
