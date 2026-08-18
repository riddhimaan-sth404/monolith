use thiserror::Error;

pub type Result<T> = std::result::Result<T, EdrError>;

#[derive(Debug, Error)]
pub enum EdrError {
    // Authentication errors
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("authorization failed: {0}")]
    AuthorizationFailed(String),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("token expired")]
    TokenExpired,
    #[error("invalid credentials")]
    InvalidCredentials,

    // Database errors
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("migration error: {0}")]
    MigrationError(String),
    #[error("record not found: {0}")]
    NotFound(String),
    #[error("duplicate record: {0}")]
    Duplicate(String),

    // Validation errors
    #[error("validation error: {0}")]
    ValidationError(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),

    // Network/communication errors
    #[error("gRPC error: {0}")]
    GrpcError(String),
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("timeout")]
    Timeout,
    #[error("TLS error: {0}")]
    TlsError(String),

    // Configuration errors
    #[error("configuration error: {0}")]
    ConfigError(String),

    // Crypto errors
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    // IO errors
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    // Serialization errors
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    // Driver errors
    #[error("driver error: {0}")]
    DriverError(String),
    #[error("driver not loaded")]
    DriverNotLoaded,

    // Scanner errors
    #[error("scanner error: {0}")]
    ScannerError(String),

    // Internal errors
    #[error("internal error: {0}")]
    Internal(String),
    #[error("unexpected error: {0}")]
    Unexpected(String),
    #[error("not implemented")]
    NotImplemented,
    #[error("Windows API error: {0}")]
    WindowsError(String),
}

impl EdrError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            EdrError::ConnectionError(_)
                | EdrError::Timeout
                | EdrError::GrpcError(_)
                | EdrError::DatabaseError(_)
        )
    }

    pub fn http_status_code(&self) -> u16 {
        match self {
            EdrError::AuthenticationFailed(_) => 401,
            EdrError::AuthorizationFailed(_) => 403,
            EdrError::InvalidToken(_) => 401,
            EdrError::TokenExpired => 401,
            EdrError::InvalidCredentials => 401,
            EdrError::NotFound(_) => 404,
            EdrError::Duplicate(_) => 409,
            EdrError::ValidationError(_) => 400,
            EdrError::InvalidInput(_) => 400,
            EdrError::ConfigError(_) => 500,
            EdrError::Internal(_) => 500,
            _ => 500,
        }
    }
}

impl From<rusqlite::Error> for EdrError {
    fn from(e: rusqlite::Error) -> Self {
        EdrError::DatabaseError(e.to_string())
    }
}

impl From<serde_json::Error> for EdrError {
    fn from(e: serde_json::Error) -> Self {
        EdrError::SerializationError(e.to_string())
    }
}

impl From<anyhow::Error> for EdrError {
    fn from(e: anyhow::Error) -> Self {
        EdrError::Internal(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_messages() {
        assert_eq!(
            EdrError::AuthenticationFailed("bad creds".into()).to_string(),
            "authentication failed: bad creds"
        );
        assert_eq!(
            EdrError::AuthorizationFailed("no access".into()).to_string(),
            "authorization failed: no access"
        );
        assert_eq!(EdrError::TokenExpired.to_string(), "token expired");
        assert_eq!(EdrError::InvalidCredentials.to_string(), "invalid credentials");
        assert_eq!(
            EdrError::DatabaseError("disk full".into()).to_string(),
            "database error: disk full"
        );
        assert_eq!(
            EdrError::NotFound("user".into()).to_string(),
            "record not found: user"
        );
        assert_eq!(
            EdrError::DriverNotLoaded.to_string(),
            "driver not loaded"
        );
        assert_eq!(EdrError::NotImplemented.to_string(), "not implemented");
    }

    #[test]
    fn test_is_retryable() {
        assert!(EdrError::ConnectionError("reset".into()).is_retryable());
        assert!(EdrError::Timeout.is_retryable());
        assert!(EdrError::GrpcError("unavailable".into()).is_retryable());
        assert!(EdrError::DatabaseError("locked".into()).is_retryable());

        assert!(!EdrError::AuthenticationFailed("bad".into()).is_retryable());
        assert!(!EdrError::NotFound("missing".into()).is_retryable());
        assert!(!EdrError::ValidationError("invalid".into()).is_retryable());
        assert!(!EdrError::NotImplemented.is_retryable());
    }

    #[test]
    fn test_http_status_codes() {
        assert_eq!(EdrError::AuthenticationFailed("x".into()).http_status_code(), 401);
        assert_eq!(EdrError::AuthorizationFailed("x".into()).http_status_code(), 403);
        assert_eq!(EdrError::InvalidToken("x".into()).http_status_code(), 401);
        assert_eq!(EdrError::TokenExpired.http_status_code(), 401);
        assert_eq!(EdrError::InvalidCredentials.http_status_code(), 401);
        assert_eq!(EdrError::NotFound("x".into()).http_status_code(), 404);
        assert_eq!(EdrError::Duplicate("x".into()).http_status_code(), 409);
        assert_eq!(EdrError::ValidationError("x".into()).http_status_code(), 400);
        assert_eq!(EdrError::InvalidInput("x".into()).http_status_code(), 400);
        assert_eq!(EdrError::ConfigError("x".into()).http_status_code(), 500);
        assert_eq!(EdrError::Internal("x".into()).http_status_code(), 500);
        assert_eq!(EdrError::Timeout.http_status_code(), 500);
    }

    #[test]
    fn test_from_rusqlite_error() {
        let inner = rusqlite::Error::InvalidParameterName("foo".into());
        let err: EdrError = inner.into();
        assert!(matches!(err, EdrError::DatabaseError(_)));
    }

    #[test]
    fn test_from_serde_json_error() {
        let inner = serde_json::from_str::<()>("invalid").unwrap_err();
        let err: EdrError = inner.into();
        assert!(matches!(err, EdrError::SerializationError(_)));
    }

    #[test]
    fn test_from_anyhow_error() {
        let inner = anyhow::anyhow!("something went wrong");
        let err: EdrError = inner.into();
        assert!(matches!(err, EdrError::Internal(_)));
    }

    #[test]
    fn test_result_type_alias() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = Err(EdrError::NotImplemented);
        assert!(err.is_err());
    }
}
