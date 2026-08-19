use crate::db::{DatabaseConnection, DbParam};
use crate::error::Result;
use ring::digest;

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: String,
    pub hash: Option<String>,
    pub prev_hash: Option<String>,
}

pub struct AuditLogger;

impl AuditLogger {
    /// Appends a cryptographically chained audit log entry.
    pub async fn log(
        conn: &dyn DatabaseConnection,
        user_id: Option<&str>,
        username: Option<&str>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<&str>,
        details: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        result_status: &str,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // 1. Retrieve the previous hash
        let prev_hash = match conn
            .query_one_value(
                "SELECT hash FROM audit_logs ORDER BY rowid DESC LIMIT 1",
                &[],
            )
            .await?
        {
            Some(row) => row
                .get("hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            None => None,
        };

        let prev_hash_str = prev_hash.clone().unwrap_or_default();

        // 2. Compute the cryptographic hash for this entry
        let details_str = details.unwrap_or("");
        let input_to_hash = format!(
            "{}{}{}{}{}{}{}{}{}",
            timestamp,
            user_id.unwrap_or(""),
            username.unwrap_or(""),
            action,
            target_type.unwrap_or(""),
            target_id.unwrap_or(""),
            details_str,
            result_status,
            prev_hash_str
        );

        let hash_output = digest::digest(&digest::SHA256, input_to_hash.as_bytes());
        let hash_hex = hex::encode(hash_output.as_ref());

        // 3. Insert the chained audit log into database
        conn.execute(
            "INSERT INTO audit_logs (id, timestamp, user_id, username, action, target_type, target_id, details, ip_address, user_agent, result, hash, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            &[
                DbParam::Text(id.clone()),
                DbParam::Text(timestamp),
                user_id.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                username.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                DbParam::Text(action.to_string()),
                target_type.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                target_id.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                details.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                ip_address.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                user_agent.map(|s| DbParam::Text(s.to_string())).unwrap_or(DbParam::Null),
                DbParam::Text(result_status.to_string()),
                DbParam::Text(hash_hex.clone()),
                prev_hash.map(|s| DbParam::Text(s)).unwrap_or(DbParam::Null),
            ],
        )
        .await?;

        Ok(hash_hex)
    }

    /// Verifies the integrity of the complete audit log trail.
    /// Returns true if the cryptographic chain is intact, or false if tampering is detected.
    pub async fn verify_trail(conn: &dyn DatabaseConnection) -> Result<bool> {
        let rows = conn
            .query_value(
                "SELECT id, timestamp, user_id, username, action, target_type, target_id, details, result, hash, prev_hash 
                 FROM audit_logs ORDER BY rowid ASC",
                &[],
            )
            .await?;

        let mut expected_prev_hash: Option<String> = None;

        for row in rows {
            let timestamp = row.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let user_id = row.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
            let username = row.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let action = row.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let target_type = row
                .get("target_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target_id = row.get("target_id").and_then(|v| v.as_str()).unwrap_or("");
            let details = row.get("details").and_then(|v| v.as_str()).unwrap_or("");
            let result_status = row.get("result").and_then(|v| v.as_str()).unwrap_or("");
            let stored_hash = row.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            let stored_prev_hash = row.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("");

            // 1. Verify prev_hash matches the previous record's hash
            match &expected_prev_hash {
                Some(h) => {
                    if h != stored_prev_hash {
                        return Ok(false);
                    }
                }
                None => {
                    if !stored_prev_hash.is_empty() {
                        return Ok(false);
                    }
                }
            }

            // 2. Re-compute this record's hash
            let input_to_hash = format!(
                "{}{}{}{}{}{}{}{}{}",
                timestamp,
                user_id,
                username,
                action,
                target_type,
                target_id,
                details,
                result_status,
                stored_prev_hash
            );

            let hash_output = digest::digest(&digest::SHA256, input_to_hash.as_bytes());
            let computed_hash = hex::encode(hash_output.as_ref());

            if computed_hash != stored_hash {
                return Ok(false);
            }

            expected_prev_hash = Some(stored_hash.to_string());
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use crate::db::Database;
    use crate::db::MigrationManager;
    use crate::db::SqliteDatabase;

    #[tokio::test]
    async fn test_audit_logging_chaining() {
        let db = SqliteDatabase::new(":memory:");
        let conn = db.connect(&DatabaseConfig::default()).await.unwrap();
        MigrationManager::new().run(&conn).await.unwrap();

        // 1. Log three entries
        let _h1 = AuditLogger::log(
            &conn,
            Some("u1"),
            Some("user1"),
            "action1",
            Some("target1"),
            Some("t1"),
            Some("details1"),
            Some("127.0.0.1"),
            Some("agent1"),
            "success",
        )
        .await
        .unwrap();

        let _h2 = AuditLogger::log(
            &conn,
            Some("u2"),
            Some("user2"),
            "action2",
            None,
            None,
            None,
            None,
            None,
            "success",
        )
        .await
        .unwrap();

        let _h3 = AuditLogger::log(
            &conn, None, None, "action3", None, None, None, None, None, "failure",
        )
        .await
        .unwrap();

        // 2. Verify audit trail is intact
        assert!(AuditLogger::verify_trail(&conn).await.unwrap());

        // 3. Tamper with the trail: modify action3's result to "success"
        conn.execute(
            "UPDATE audit_logs SET result = 'success' WHERE action = 'action3'",
            &[],
        )
        .await
        .unwrap();

        // 4. Verify audit trail fails verification!
        assert!(!AuditLogger::verify_trail(&conn).await.unwrap());
    }
}
