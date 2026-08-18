use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use crate::error::Result;
use crate::config::DatabaseConfig;

/// Database parameter types for cross-database compatibility.
#[derive(Debug, Clone)]
pub enum DbParam {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<i64> for DbParam {
    fn from(v: i64) -> Self { DbParam::Integer(v) }
}

impl From<f64> for DbParam {
    fn from(v: f64) -> Self { DbParam::Real(v) }
}

impl From<String> for DbParam {
    fn from(v: String) -> Self { DbParam::Text(v) }
}

impl From<&str> for DbParam {
    fn from(v: &str) -> Self { DbParam::Text(v.to_string()) }
}

impl From<Vec<u8>> for DbParam {
    fn from(v: Vec<u8>) -> Self { DbParam::Blob(v) }
}

/// Generic database connection trait.
#[async_trait]
pub trait DatabaseConnection: Send + Sync {
    async fn execute(&self, sql: &str, params: &[DbParam]) -> Result<u64>;
    async fn execute_batch(&self, sql: &str) -> Result<()>;
    async fn query<T: DeserializeOwned + Send>(&self, sql: &str, params: &[DbParam]) -> Result<Vec<T>>
    where
        Self: Sized;
    async fn query_one<T: DeserializeOwned + Send>(&self, sql: &str, params: &[DbParam]) -> Result<Option<T>>
    where
        Self: Sized;
    async fn query_value(&self, sql: &str, params: &[DbParam]) -> Result<Vec<Value>>;
    async fn query_one_value(&self, sql: &str, params: &[DbParam]) -> Result<Option<Value>>;
    async fn query_raw(&self, sql: &str, params: &[DbParam]) -> Result<Vec<Vec<Value>>>;
    async fn last_insert_rowid(&self) -> Result<i64>;
    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>>;
}

/// Transaction trait for rollback/commit.
#[async_trait]
pub trait Transaction: Send + Sync {
    async fn commit(self: Box<Self>) -> Result<()>;
    async fn rollback(self: Box<Self>) -> Result<()>;
    async fn execute(&self, sql: &str, params: &[DbParam]) -> Result<u64>;
}

/// Database factory trait for creating connections.
#[async_trait]
pub trait Database: Send + Sync {
    type Conn: DatabaseConnection;
    async fn connect(&self, config: &DatabaseConfig) -> Result<Self::Conn>;
    async fn close(&self, conn: Self::Conn) -> Result<()>;
}

/// Repository trait for basic CRUD operations.
#[async_trait]
pub trait Repository<T: Send + Sync, ID: Send + Sync>: Send + Sync {
    async fn find_by_id(&self, conn: &dyn DatabaseConnection, id: ID) -> Result<Option<T>>;
    async fn find_all(&self, conn: &dyn DatabaseConnection) -> Result<Vec<T>>;
    async fn insert(&self, conn: &dyn DatabaseConnection, entity: &T) -> Result<ID>;
    async fn update(&self, conn: &dyn DatabaseConnection, entity: &T) -> Result<bool>;
    async fn delete(&self, conn: &dyn DatabaseConnection, id: ID) -> Result<bool>;
    async fn count(&self, conn: &dyn DatabaseConnection) -> Result<u64>;
    async fn exists(&self, conn: &dyn DatabaseConnection, id: ID) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockConn;

    #[async_trait]
    impl DatabaseConnection for MockConn {
        async fn execute(&self, _sql: &str, _params: &[DbParam]) -> Result<u64> { Ok(1) }
        async fn execute_batch(&self, _sql: &str) -> Result<()> { Ok(()) }
        async fn query<T: DeserializeOwned + Send>(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<T>> { Ok(vec![]) }
        async fn query_one<T: DeserializeOwned + Send>(&self, _sql: &str, _params: &[DbParam]) -> Result<Option<T>> { Ok(None) }
        async fn query_value(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<Value>> { Ok(vec![]) }
        async fn query_one_value(&self, _sql: &str, _params: &[DbParam]) -> Result<Option<Value>> { Ok(None) }
        async fn query_raw(&self, _sql: &str, _params: &[DbParam]) -> Result<Vec<Vec<Value>>> { Ok(vec![]) }
        async fn last_insert_rowid(&self) -> Result<i64> { Ok(1) }
        async fn begin_transaction(&self) -> Result<Box<dyn Transaction>> { Ok(Box::new(MockTx)) }
    }

    struct MockTx;
    #[async_trait]
    impl Transaction for MockTx {
        async fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
        async fn rollback(self: Box<Self>) -> Result<()> { Ok(()) }
        async fn execute(&self, _sql: &str, _params: &[DbParam]) -> Result<u64> { Ok(1) }
    }

    #[tokio::test]
    async fn test_trait_object_usage() {
        let conn: &dyn DatabaseConnection = &MockConn;
        assert_eq!(conn.execute("TEST", &[]).await.unwrap(), 1);
    }
}
