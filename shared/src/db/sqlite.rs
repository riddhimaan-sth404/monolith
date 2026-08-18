use async_trait::async_trait;
use rusqlite::{params_from_iter, Connection, OpenFlags};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::config::DatabaseConfig;
use crate::error::{EdrError, Result};
use super::traits::{Database, DatabaseConnection, DbParam, Transaction};

pub struct SqliteDatabase {
    path: String,
}

impl SqliteDatabase {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    type Conn = SqliteConnection;

    async fn connect(&self, _config: &DatabaseConfig) -> Result<Self::Conn> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| EdrError::DatabaseError(format!("failed to open sqlite: {}", e)))?;

        // Performance optimization
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;
             PRAGMA cache_size=-64000;",
        )
        .map_err(|e| EdrError::DatabaseError(format!("sqlite pragma setup failed: {}", e)))?;

        Ok(SqliteConnection {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn close(&self, _conn: Self::Conn) -> Result<()> {
        Ok(())
    }
}

pub struct SqliteConnection {
    conn: Arc<Mutex<Connection>>,
}

fn to_rusqlite_params(params: &[DbParam]) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    params
        .iter()
        .map(|p| -> Box<dyn rusqlite::types::ToSql> {
            match p {
                DbParam::Null => Box::new(rusqlite::types::Null),
                DbParam::Boolean(b) => Box::new(*b),
                DbParam::Integer(i) => Box::new(*i),
                DbParam::Real(f) => Box::new(*f),
                DbParam::Text(s) => Box::new(s.clone()),
                DbParam::Blob(b) => Box::new(b.clone()),
            }
        })
        .collect()
}

#[async_trait]
impl DatabaseConnection for SqliteConnection {
    async fn execute(&self, sql: &str, params: &[DbParam]) -> Result<u64> {
        let conn = self.conn.lock().await;
        let rparams = to_rusqlite_params(params);
        let count = conn
            .execute(sql, params_from_iter(rparams.iter().map(|p| p.as_ref())))
            .map_err(|e| EdrError::DatabaseError(format!("execute failed: {} - SQL: {}", e, sql)))?;
        Ok(count as u64)
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(sql)
            .map_err(|e| EdrError::DatabaseError(format!("batch execute failed: {} - SQL: {}", e, sql)))?;
        Ok(())
    }

    async fn query<T: DeserializeOwned + Send>(&self, sql: &str, params: &[DbParam]) -> Result<Vec<T>> {
        let conn = self.conn.lock().await;
        let rparams = to_rusqlite_params(params);
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| EdrError::DatabaseError(format!("prepare failed: {} - SQL: {}", e, sql)))?;

        let column_names = stmt.column_names().iter().map(|name| name.to_string()).collect::<Vec<_>>();
        let rows = stmt
            .query_map(params_from_iter(rparams.iter().map(|p| p.as_ref())), |row| {
                let mut json_map = serde_json::Map::new();
                for (i, col_name) in column_names.iter().enumerate() {
                    let val: rusqlite::types::Value = row.get_unwrap(i);
                    let json_val = rusqlite_value_to_json(val);
                    json_map.insert(col_name.clone(), json_val);
                }
                Ok(Value::Object(json_map))
            })
            .map_err(|e| EdrError::DatabaseError(format!("query failed: {} - SQL: {}", e, sql)))?;

        let mut results = Vec::new();
        for row in rows {
            let json_val = row.map_err(|e| EdrError::DatabaseError(format!("row error: {}", e)))?;
            let entity: T = serde_json::from_value(json_val)
                .map_err(|e| EdrError::DeserializationError(format!("deserialize failed: {}", e)))?;
            results.push(entity);
        }
        Ok(results)
    }

    async fn query_one<T: DeserializeOwned + Send>(&self, sql: &str, params: &[DbParam]) -> Result<Option<T>> {
        let mut results = self.query::<T>(sql, params).await?;
        Ok(results.pop())
    }

    async fn query_value(&self, sql: &str, params: &[DbParam]) -> Result<Vec<Value>> {
        self.query::<Value>(sql, params).await
    }

    async fn query_one_value(&self, sql: &str, params: &[DbParam]) -> Result<Option<Value>> {
        self.query_one::<Value>(sql, params).await
    }

    async fn query_raw(&self, sql: &str, params: &[DbParam]) -> Result<Vec<Vec<Value>>> {
        let conn = self.conn.lock().await;
        let rparams = to_rusqlite_params(params);
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| EdrError::DatabaseError(format!("prepare failed: {}", e)))?;

        let column_count = stmt.column_count();
        let rows = stmt
            .query_map(params_from_iter(rparams.iter().map(|p| p.as_ref())), |row| {
                let mut row_vals = Vec::with_capacity(column_count);
                for i in 0..column_count {
                    let val: rusqlite::types::Value = row.get_unwrap(i);
                    row_vals.push(rusqlite_value_to_json(val));
                }
                Ok(row_vals)
            })
            .map_err(|e| EdrError::DatabaseError(format!("query_raw failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| EdrError::DatabaseError(format!("row error: {}", e)))?);
        }
        Ok(results)
    }

    async fn last_insert_rowid(&self) -> Result<i64> {
        let conn = self.conn.lock().await;
        Ok(conn.last_insert_rowid())
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>> {
        let conn = self.conn.lock().await;
        conn.execute_batch("BEGIN TRANSACTION")
            .map_err(|e| EdrError::DatabaseError(format!("begin transaction failed: {}", e)))?;
        Ok(Box::new(SqliteTransaction {
            conn: self.conn.clone(),
        }))
    }
}

fn rusqlite_value_to_json(val: rusqlite::types::Value) -> Value {
    match val {
        rusqlite::types::Value::Null => Value::Null,
        rusqlite::types::Value::Integer(i) => Value::Number(i.into()),
        rusqlite::types::Value::Real(f) => {
            serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        rusqlite::types::Value::Text(s) => Value::String(s),
        rusqlite::types::Value::Blob(b) => Value::String(hex::encode(b)),
    }
}

pub struct SqliteTransaction {
    conn: Arc<Mutex<Connection>>,
}

#[async_trait]
impl Transaction for SqliteTransaction {
    async fn commit(self: Box<Self>) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch("COMMIT")
            .map_err(|e| EdrError::DatabaseError(format!("commit failed: {}", e)))?;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch("ROLLBACK")
            .map_err(|e| EdrError::DatabaseError(format!("rollback failed: {}", e)))?;
        Ok(())
    }

    async fn execute(&self, sql: &str, params: &[DbParam]) -> Result<u64> {
        let conn = self.conn.lock().await;
        let rparams = to_rusqlite_params(params);
        let count = conn
            .execute(sql, params_from_iter(rparams.iter().map(|p| p.as_ref())))
            .map_err(|e| EdrError::DatabaseError(format!("txn execute failed: {}", e)))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseConfig, DatabaseKind};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_sqlite_connect_and_execute() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let db = SqliteDatabase::new(db_path.to_str().unwrap());
        let config = DatabaseConfig {
            kind: DatabaseKind::Sqlite,
            path: db_path.to_str().unwrap().to_string(),
            max_connections: 1,
        };
        let conn = db.connect(&config).await.unwrap();
        conn.execute_batch("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);").await.unwrap();
        conn.execute("INSERT INTO test (name) VALUES (?1)", &["hello".into()]).await.unwrap();
        let count = conn.query_one::<serde_json::Value>("SELECT COUNT(*) as cnt FROM test", &[]).await.unwrap();
        assert!(count.is_some());
        db.close(conn).await.unwrap();
    }

    #[tokio::test]
    async fn test_transaction_rollback() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("txn.db");
        let db = SqliteDatabase::new(db_path.to_str().unwrap());
        let config = DatabaseConfig {
            kind: DatabaseKind::Sqlite,
            path: db_path.to_str().unwrap().to_string(),
            max_connections: 1,
        };
        let conn = db.connect(&config).await.unwrap();
        conn.execute_batch("CREATE TABLE txn_test (id INTEGER PRIMARY KEY, val TEXT);").await.unwrap();

        // Begin transaction and insert
        let txn = conn.begin_transaction().await.unwrap();
        txn.execute("INSERT INTO txn_test (val) VALUES (?1)", &["should_rollback".into()]).await.unwrap();
        txn.rollback().await.unwrap();

        // Verify rollback
        let count = conn.query_one::<serde_json::Value>("SELECT COUNT(*) as cnt FROM txn_test", &[]).await.unwrap();
        let cnt = count.unwrap().get("cnt").and_then(|v| v.as_i64()).unwrap_or(-1);
        assert_eq!(cnt, 0);

        db.close(conn).await.unwrap();
    }
}
