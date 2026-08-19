use super::DbParam;
use super::traits::DatabaseConnection;
use crate::error::Result;

pub struct MigrationManager {
    migrations: Vec<Migration>,
}

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

impl Default for MigrationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrationManager {
    pub fn new() -> Self {
        Self {
            migrations: Self::define_migrations(),
        }
    }

    fn define_migrations() -> Vec<Migration> {
        vec![
            Migration {
                version: 1,
                name: "initial_schema",
                sql: include_str!("../../migrations/001_initial_schema.sql"),
            },
            Migration {
                version: 2,
                name: "ioc_and_rules",
                sql: include_str!("../../migrations/002_ioc_and_rules.sql"),
            },
            Migration {
                version: 3,
                name: "audit_and_schedules",
                sql: include_str!("../../migrations/003_audit_and_schedules.sql"),
            },
            Migration {
                version: 4,
                name: "scans_and_quarantine",
                sql: include_str!("../../migrations/004_scans_and_quarantine.sql"),
            },
            Migration {
                version: 5,
                name: "license_activation",
                sql: include_str!("../../migrations/005_license_activation.sql"),
            },
            Migration {
                version: 6,
                name: "alert_dedup",
                sql: include_str!("../../migrations/006_alert_dedup.sql"),
            },
            Migration {
                version: 7,
                name: "allowlist",
                sql: include_str!("../../migrations/007_allowlist.sql"),
            },
            Migration {
                version: 8,
                name: "session_token_hash",
                sql: include_str!("../../migrations/008_session_token_hash.sql"),
            },
            Migration {
                version: 9,
                name: "mfa_required_flag",
                sql: include_str!("../../migrations/009_mfa_required_flag.sql"),
            },
            Migration {
                version: 10,
                name: "audit_log_chaining",
                sql: include_str!("../../migrations/010_audit_log_chaining.sql"),
            },
            Migration {
                version: 11,
                name: "heartbeats_table",
                sql: include_str!("../../migrations/011_heartbeats_table.sql"),
            },
            Migration {
                version: 12,
                name: "memory_and_registry",
                sql: include_str!("../../migrations/012_memory_and_registry.sql"),
            },
        ]
    }

    pub async fn run(&self, conn: &dyn DatabaseConnection) -> Result<()> {
        // Create migration tracking table if it doesn't exist
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .await?;

        // Read applied migrations
        let rows = conn
            .query_raw("SELECT version FROM _migrations ORDER BY version", &[])
            .await?;
        let applied_versions: std::collections::HashSet<u32> = rows
            .iter()
            .map(|r| {
                let v: i64 = r.first().and_then(|v| v.as_i64()).unwrap_or(0);
                v as u32
            })
            .collect();

        for migration in &self.migrations {
            if !applied_versions.contains(&migration.version) {
                tracing::info!(
                    "applying migration {}: {}",
                    migration.version,
                    migration.name
                );
                conn.execute_batch(migration.sql).await?;
                conn.execute(
                    "INSERT INTO _migrations (version, name) VALUES (?1, ?2)",
                    &[
                        DbParam::Integer(migration.version as i64),
                        DbParam::Text(migration.name.to_string()),
                    ],
                )
                .await?;
            }
        }

        Ok(())
    }

    pub fn pending_migrations(&self, _conn: &dyn DatabaseConnection) -> Result<Vec<u32>> {
        // In this simple SQLite manager, all defined migrations are expected to be applied.
        Ok(self.migrations.iter().map(|m| m.version).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseConfig, DatabaseKind};
    use crate::db::Database;
    use crate::db::sqlite::SqliteDatabase;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_migration_run() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("migrate.db");
        let db = SqliteDatabase::new(db_path.to_str().unwrap());
        let config = DatabaseConfig {
            kind: DatabaseKind::Sqlite,
            path: db_path.to_str().unwrap().to_string(),
            max_connections: 1,
            ..Default::default()
        };
        let conn = db.connect(&config).await.unwrap();

        let mgr = MigrationManager::new();
        mgr.run(&conn).await.unwrap();

        // Verify migrations table
        let result = conn
            .query_raw("SELECT COUNT(*) as cnt FROM _migrations", &[])
            .await
            .unwrap();
        let count: i64 = result
            .first()
            .and_then(|r| r.first())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        assert_eq!(count, 12, "all 12 migrations should be recorded");

        // Running again should be idempotent
        mgr.run(&conn).await.unwrap();
        let result2 = conn
            .query_raw("SELECT COUNT(*) as cnt FROM _migrations", &[])
            .await
            .unwrap();
        let count2: i64 = result2
            .first()
            .and_then(|r| r.first())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        assert_eq!(count2, 12, "re-running should not add duplicates");

        db.close(conn).await.unwrap();
    }
}
