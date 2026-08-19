use async_trait::async_trait;
use monolith_shared::db::traits::{DatabaseConnection, Repository};
use monolith_shared::error::Result;

pub struct UserRepository;

#[async_trait]
impl Repository<serde_json::Value, String> for UserRepository {
    async fn find_by_id(
        &self,
        conn: &dyn DatabaseConnection,
        id: String,
    ) -> Result<Option<serde_json::Value>> {
        conn.query_one_value(
            "SELECT * FROM users WHERE id = ?1",
            &[monolith_shared::db::DbParam::Text(id)],
        )
        .await
    }

    async fn find_all(&self, conn: &dyn DatabaseConnection) -> Result<Vec<serde_json::Value>> {
        conn.query_value("SELECT * FROM users ORDER BY created_at DESC", &[])
            .await
    }

    async fn insert(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<String> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, email, role) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                monolith_shared::db::DbParam::Text(id.clone()),
                monolith_shared::db::DbParam::Text(entity.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("password_hash").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("role").and_then(|v| v.as_str()).unwrap_or("viewer").to_string()),
            ],
        ).await?;
        Ok(id)
    }

    async fn update(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<bool> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let affected = conn
            .execute(
                "UPDATE users SET email = ?1, role = ?2 WHERE id = ?3",
                &[
                    monolith_shared::db::DbParam::Text(
                        entity
                            .get("email")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    monolith_shared::db::DbParam::Text(
                        entity
                            .get("role")
                            .and_then(|v| v.as_str())
                            .unwrap_or("viewer")
                            .to_string(),
                    ),
                    monolith_shared::db::DbParam::Text(id),
                ],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn delete(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let affected = conn
            .execute(
                "DELETE FROM users WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn count(&self, conn: &dyn DatabaseConnection) -> Result<u64> {
        let result = conn
            .query_one_value("SELECT COUNT(*) as cnt FROM users", &[])
            .await?;
        Ok(result
            .and_then(|r| r.get("cnt").and_then(|v| v.as_i64()).map(|i| i as u64))
            .unwrap_or(0))
    }

    async fn exists(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let result = conn
            .query_one_value(
                "SELECT 1 as exists_flag FROM users WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(result.is_some())
    }
}

pub struct EndpointRepository;

#[async_trait]
impl Repository<serde_json::Value, String> for EndpointRepository {
    async fn find_by_id(
        &self,
        conn: &dyn DatabaseConnection,
        id: String,
    ) -> Result<Option<serde_json::Value>> {
        conn.query_one_value(
            "SELECT * FROM endpoints WHERE id = ?1",
            &[monolith_shared::db::DbParam::Text(id)],
        )
        .await
    }

    async fn find_all(&self, conn: &dyn DatabaseConnection) -> Result<Vec<serde_json::Value>> {
        conn.query_value("SELECT * FROM endpoints ORDER BY last_seen DESC", &[])
            .await
    }

    async fn insert(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<String> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        conn.execute(
            "INSERT INTO endpoints (id, hostname, ip_address, os_version, agent_version, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                monolith_shared::db::DbParam::Text(id.clone()),
                monolith_shared::db::DbParam::Text(entity.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("ip_address").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("os_version").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("agent_version").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text("online".to_string()),
            ],
        ).await?;
        Ok(id)
    }

    async fn update(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<bool> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let affected = conn.execute(
            "UPDATE endpoints SET hostname = ?1, ip_address = ?2, last_seen = datetime('now') WHERE id = ?3",
            &[
                monolith_shared::db::DbParam::Text(entity.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("ip_address").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(id),
            ],
        ).await?;
        Ok(affected > 0)
    }

    async fn delete(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let affected = conn
            .execute(
                "DELETE FROM endpoints WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn count(&self, conn: &dyn DatabaseConnection) -> Result<u64> {
        let result = conn
            .query_one_value("SELECT COUNT(*) as cnt FROM endpoints", &[])
            .await?;
        Ok(result
            .and_then(|r| r.get("cnt").and_then(|v| v.as_i64()).map(|i| i as u64))
            .unwrap_or(0))
    }

    async fn exists(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let result = conn
            .query_one_value(
                "SELECT 1 as exists_flag FROM endpoints WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(result.is_some())
    }
}

pub struct AlertRepository;

#[async_trait]
impl Repository<serde_json::Value, String> for AlertRepository {
    async fn find_by_id(
        &self,
        conn: &dyn DatabaseConnection,
        id: String,
    ) -> Result<Option<serde_json::Value>> {
        conn.query_one_value(
            "SELECT * FROM alerts WHERE id = ?1",
            &[monolith_shared::db::DbParam::Text(id)],
        )
        .await
    }

    async fn find_all(&self, conn: &dyn DatabaseConnection) -> Result<Vec<serde_json::Value>> {
        conn.query_value("SELECT * FROM alerts ORDER BY created_at DESC", &[])
            .await
    }

    async fn insert(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<String> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        conn.execute(
            "INSERT INTO alerts (id, endpoint_id, severity, status, title, description, score) VALUES (?1, ?2, ?3, 'new', ?4, ?5, ?6)",
            &[
                monolith_shared::db::DbParam::Text(id.clone()),
                monolith_shared::db::DbParam::Text(entity.get("endpoint_id").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string()),
                monolith_shared::db::DbParam::Text(entity.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0).to_string()),
            ],
        ).await?;
        Ok(id)
    }

    async fn update(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<bool> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let affected = conn
            .execute(
                "UPDATE alerts SET status = ?1, updated_at = datetime('now') WHERE id = ?2",
                &[
                    monolith_shared::db::DbParam::Text(
                        entity
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("new")
                            .to_string(),
                    ),
                    monolith_shared::db::DbParam::Text(id),
                ],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn delete(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let affected = conn
            .execute(
                "DELETE FROM alerts WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn count(&self, conn: &dyn DatabaseConnection) -> Result<u64> {
        let result = conn
            .query_one_value("SELECT COUNT(*) as cnt FROM alerts", &[])
            .await?;
        Ok(result
            .and_then(|r| r.get("cnt").and_then(|v| v.as_i64()).map(|i| i as u64))
            .unwrap_or(0))
    }

    async fn exists(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let result = conn
            .query_one_value(
                "SELECT 1 as exists_flag FROM alerts WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(result.is_some())
    }
}

pub struct AllowlistRepository;

#[async_trait]
impl Repository<serde_json::Value, String> for AllowlistRepository {
    async fn find_by_id(
        &self,
        conn: &dyn DatabaseConnection,
        id: String,
    ) -> Result<Option<serde_json::Value>> {
        conn.query_one_value(
            "SELECT * FROM allowlist WHERE id = ?1",
            &[monolith_shared::db::DbParam::Text(id)],
        )
        .await
    }

    async fn find_all(&self, conn: &dyn DatabaseConnection) -> Result<Vec<serde_json::Value>> {
        conn.query_value("SELECT * FROM allowlist ORDER BY created_at DESC", &[])
            .await
    }

    async fn insert(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<String> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        conn.execute(
            "INSERT INTO allowlist (id, rule_type, value, description) VALUES (?1, ?2, ?3, ?4)",
            &[
                monolith_shared::db::DbParam::Text(id.clone()),
                monolith_shared::db::DbParam::Text(
                    entity
                        .get("rule_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                monolith_shared::db::DbParam::Text(
                    entity
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                monolith_shared::db::DbParam::Text(
                    entity
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
            ],
        )
        .await?;
        Ok(id)
    }

    async fn update(
        &self,
        conn: &dyn DatabaseConnection,
        entity: &serde_json::Value,
    ) -> Result<bool> {
        let id = entity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let affected = conn
            .execute(
                "UPDATE allowlist SET value = ?1, description = ?2 WHERE id = ?3",
                &[
                    monolith_shared::db::DbParam::Text(
                        entity
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    monolith_shared::db::DbParam::Text(
                        entity
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    monolith_shared::db::DbParam::Text(id),
                ],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn delete(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let affected = conn
            .execute(
                "DELETE FROM allowlist WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn count(&self, conn: &dyn DatabaseConnection) -> Result<u64> {
        let result = conn
            .query_one_value("SELECT COUNT(*) as cnt FROM allowlist", &[])
            .await?;
        Ok(result
            .and_then(|r| r.get("cnt").and_then(|v| v.as_i64()).map(|i| i as u64))
            .unwrap_or(0))
    }

    async fn exists(&self, conn: &dyn DatabaseConnection, id: String) -> Result<bool> {
        let result = conn
            .query_one_value(
                "SELECT 1 as exists_flag FROM allowlist WHERE id = ?1",
                &[monolith_shared::db::DbParam::Text(id)],
            )
            .await?;
        Ok(result.is_some())
    }
}
