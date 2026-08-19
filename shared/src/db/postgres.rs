use super::traits::{Database, DatabaseConnection, DbParam, Transaction};
use crate::config::DatabaseConfig;
use crate::error::{EdrError, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::postgres::{PgArguments, PgPoolOptions, PgRow};
use sqlx::query::Query;
use sqlx::{Column, Row};
use std::sync::Arc;

pub struct PostgresDatabase;

impl PostgresDatabase {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Database for PostgresDatabase {
    type Conn = PostgresConnection;

    async fn connect(&self, config: &DatabaseConfig) -> Result<Self::Conn> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.path)
            .await
            .map_err(|e| {
                EdrError::DatabaseError(format!("failed to connect to postgres: {}", e))
            })?;

        Ok(PostgresConnection {
            pool: Arc::new(pool),
        })
    }

    async fn close(&self, conn: Self::Conn) -> Result<()> {
        conn.pool.close().await;
        Ok(())
    }
}

pub struct PostgresConnection {
    pool: Arc<sqlx::PgPool>,
}

/// Convert a PgRow to serde_json::Value by iterating columns
fn row_to_json(row: &PgRow) -> Value {
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let val = row.try_get::<Option<String>, _>(name).ok().flatten();
        match val {
            Some(s) => {
                map.insert(name.to_string(), Value::String(s));
            }
            None => {
                map.insert(name.to_string(), Value::Null);
            }
        }
    }
    Value::Object(map)
}

/// Convert positional ? or ?N placeholders to sqlx $N style
fn convert_placeholders(sql: &str) -> String {
    let mut result = String::new();
    let mut param_index = 1;
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' {
            // Check if it's a numbered placeholder like ?1, ?2, ...
            if i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                // Parse the digits
                let mut digits = String::new();
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    digits.push(chars[j]);
                    j += 1;
                }
                result.push('$');
                result.push_str(&digits);
                i = j;
            } else {
                // Unnumbered placeholder, map to the current param_index
                result.push_str(&format!("${}", param_index));
                param_index += 1;
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

fn bind_params<'q>(
    query: Query<'q, sqlx::Postgres, PgArguments>,
    params: &'q [DbParam],
) -> Query<'q, sqlx::Postgres, PgArguments> {
    let mut q = query;
    for param in params {
        q = match param {
            DbParam::Null => q.bind(None::<String>),
            DbParam::Boolean(b) => q.bind(*b),
            DbParam::Integer(i) => q.bind(*i),
            DbParam::Real(f) => q.bind(*f),
            DbParam::Text(s) => q.bind(s.clone()),
            DbParam::Blob(b) => q.bind(b.clone()),
        };
    }
    q
}

#[async_trait]
impl DatabaseConnection for PostgresConnection {
    async fn execute(&self, sql: &str, params: &[DbParam]) -> Result<u64> {
        let pg_sql = convert_placeholders(sql);
        let query = bind_params(sqlx::query(&pg_sql), params);

        let result = query.execute(&*self.pool).await.map_err(|e| {
            EdrError::DatabaseError(format!("postgres execute failed: {} - SQL: {}", e, pg_sql))
        })?;

        Ok(result.rows_affected())
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        sqlx::query(sql).execute(&*self.pool).await.map_err(|e| {
            EdrError::DatabaseError(format!("postgres batch execute failed: {}", e))
        })?;
        Ok(())
    }

    async fn query<T: DeserializeOwned + Send>(
        &self,
        sql: &str,
        params: &[DbParam],
    ) -> Result<Vec<T>> {
        let pg_sql = convert_placeholders(sql);
        let query = bind_params(sqlx::query(&pg_sql), params);

        let rows = query.fetch_all(&*self.pool).await.map_err(|e| {
            EdrError::DatabaseError(format!("postgres query failed: {} - SQL: {}", e, pg_sql))
        })?;

        let results: Vec<T> = rows
            .iter()
            .filter_map(|row| {
                let json_val = row_to_json(row);
                serde_json::from_value(json_val).ok()
            })
            .collect();

        Ok(results)
    }

    async fn query_one<T: DeserializeOwned + Send>(
        &self,
        sql: &str,
        params: &[DbParam],
    ) -> Result<Option<T>> {
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
        let pg_sql = convert_placeholders(sql);
        let query = bind_params(sqlx::query(&pg_sql), params);

        let rows = query
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| EdrError::DatabaseError(format!("postgres query_raw failed: {}", e)))?;

        let results: Vec<Vec<Value>> = rows
            .iter()
            .map(|row| {
                let json_val = row_to_json(row);
                vec![json_val]
            })
            .collect();

        Ok(results)
    }

    async fn last_insert_rowid(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT LASTVAL()")
            .fetch_one(&*self.pool)
            .await
            .map_err(|e| EdrError::DatabaseError(format!("last_insert_rowid failed: {}", e)))?;
        Ok(row.0)
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>> {
        // Note: proper sqlx transaction support requires lifetime management.
        // For now, we provide a simple no-op transaction wrapper.
        // Full transaction support can be added when the Transaction trait
        // is updated to support lifetime parameters.
        Err(EdrError::NotImplemented)
    }
}

/// Placeholder transaction — PostgreSQL transactions not yet implemented
/// due to sqlx Transaction<'_, Postgres> lifetime constraints with
/// the current trait interface.
pub struct PostgresTransaction;

#[async_trait]
impl Transaction for PostgresTransaction {
    async fn commit(self: Box<Self>) -> Result<()> {
        Err(EdrError::NotImplemented)
    }

    async fn rollback(self: Box<Self>) -> Result<()> {
        Err(EdrError::NotImplemented)
    }

    async fn execute(&self, _sql: &str, _params: &[DbParam]) -> Result<u64> {
        Err(EdrError::NotImplemented)
    }
}
