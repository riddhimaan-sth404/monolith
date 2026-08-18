use monolith_shared::db::traits::DatabaseConnection;
use monolith_shared::db::DbParam;
use monolith_shared::error::Result;

pub struct LocalStore<C: DatabaseConnection> {
    conn: std::sync::Arc<C>,
}

impl<C: DatabaseConnection> LocalStore<C> {
    pub fn new(conn: std::sync::Arc<C>) -> Self {
        Self { conn }
    }

    pub async fn store_event(&self, event: &serde_json::Value) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("unknown");
        let data = serde_json::to_string(event)?;

        self.conn
            .execute(
                "INSERT INTO events (id, endpoint_id, event_type, timestamp, data) 
                 VALUES (?1, 'local', ?2, datetime('now'), ?3)",
                &[
                    DbParam::Text(id),
                    DbParam::Text(event_type.to_string()),
                    DbParam::Text(data),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn store_offline_event(&self, message_type: &str, payload: &serde_json::Value) -> Result<()> {
        let payload_str = serde_json::to_string(payload)?;

        self.conn
            .execute(
                "INSERT INTO offline_queue (endpoint_id, message_type, payload) 
                 VALUES ('local', ?1, ?2)",
                &[
                    DbParam::Text(message_type.to_string()),
                    DbParam::Text(payload_str),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn get_pending_uploads(&self, batch_size: u32) -> Result<Vec<serde_json::Value>> {
        self.conn
            .query::<serde_json::Value>(
                "SELECT * FROM offline_queue ORDER BY priority DESC, created_at ASC LIMIT ?1",
                &[DbParam::Integer(batch_size as i64)],
            )
            .await
    }

    pub async fn remove_offline_entry(&self, id: i64) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM offline_queue WHERE id = ?1",
                &[DbParam::Integer(id)],
            )
            .await?;
        Ok(())
    }

    pub async fn store_ioc(&self, ioc: &serde_json::Value) -> Result<()> {
        let ioc_id = ioc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let ioc_type = ioc.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("");
        let value = ioc.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let severity = ioc.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");

        self.conn
            .execute(
                "INSERT OR REPLACE INTO iocs (id, ioc_type, value, severity) VALUES (?1, ?2, ?3, ?4)",
                &[
                    DbParam::Text(ioc_id.to_string()),
                    DbParam::Text(ioc_type.to_string()),
                    DbParam::Text(value.to_string()),
                    DbParam::Text(severity.to_string()),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn clear_iocs(&self) -> Result<()> {
        self.conn.execute("DELETE FROM iocs", &[]).await?;
        Ok(())
    }

    pub async fn store_scan_result(&self, result: &serde_json::Value) -> Result<()> {
        let scan_id = result.get("scan_id").and_then(|v| v.as_str()).unwrap_or("");
        let file_path = result.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
        let verdict = result.get("verdict").and_then(|v| v.as_str()).unwrap_or("unknown");

        self.conn
            .execute(
                "INSERT INTO scan_results (id, endpoint_id, scan_type, status, details) 
                 VALUES (?1, 'local', 'scan', 'completed', ?2)",
                &[
                    DbParam::Text(scan_id.to_string()),
                    DbParam::Text(serde_json::json!({"file_path": file_path, "verdict": verdict}).to_string()),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn get_settings(&self, key: &str) -> Result<Option<String>> {
        let result = self
            .conn
            .query_one::<serde_json::Value>(
                "SELECT value FROM agent_local_store WHERE key = ?1 AND category = 'settings'",
                &[DbParam::Text(key.to_string())],
            )
            .await?;

        Ok(result.and_then(|r| r.get("value").and_then(|v| v.as_str()).map(|s| s.to_string())))
    }

    pub async fn set_settings(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO agent_local_store (key, value, category) VALUES (?1, ?2, 'settings')",
                &[DbParam::Text(key.to_string()), DbParam::Text(value.to_string())],
            )
            .await?;

        Ok(())
    }

    pub async fn get_queue_depth(&self) -> Result<u32> {
        let result = self
            .conn
            .query_one::<serde_json::Value>(
                "SELECT COUNT(*) as cnt FROM offline_queue",
                &[],
            )
            .await?;

        Ok(result.and_then(|r| r.get("cnt").and_then(|v| v.as_i64()).map(|i| i as u32)).unwrap_or(0))
    }
}
