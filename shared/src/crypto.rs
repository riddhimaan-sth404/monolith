use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use crate::error::{EdrError, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // subject (user_id)
    pub username: String,
    pub role: String,
    pub exp: usize,         // expiry timestamp
    pub iat: usize,         // issued at
    pub jti: String,        // JWT ID (unique token identifier)
}

pub struct PasswordHashManager;

impl PasswordHashManager {
    pub fn hash(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| EdrError::CryptoError(format!("password hashing failed: {}", e)))?;
        Ok(hash.to_string())
    }

    pub fn verify(password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| EdrError::CryptoError(format!("invalid password hash: {}", e)))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
    expiration_secs: u64,
    refresh_expiration_secs: u64,
}

impl JwtManager {
    pub fn new(secret: &[u8], expiration_secs: u64, refresh_expiration_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: jsonwebtoken::Algorithm::HS256,
            expiration_secs,
            refresh_expiration_secs,
        }
    }

    pub fn new_rsa(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        expiration_secs: u64,
        refresh_expiration_secs: u64,
    ) -> Result<Self> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| EdrError::CryptoError(format!("Invalid private key PEM: {}", e)))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|e| EdrError::CryptoError(format!("Invalid public key PEM: {}", e)))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            algorithm: jsonwebtoken::Algorithm::RS256,
            expiration_secs,
            refresh_expiration_secs,
        })
    }

    pub fn issue_token(&self, user_id: &str, username: &str, role: &str) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            exp: (now + Duration::seconds(self.expiration_secs as i64)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let header = Header::new(self.algorithm);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| EdrError::CryptoError(format!("JWT encoding failed: {}", e)))
    }

    pub fn issue_refresh_token(&self, user_id: &str) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            username: String::new(),
            role: String::new(),
            exp: (now + Duration::seconds(self.refresh_expiration_secs as i64)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let header = Header::new(self.algorithm);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| EdrError::CryptoError(format!("refresh token encoding failed: {}", e)))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(self.algorithm);
        validation.leeway = 0;
        let token_data = decode::<Claims>(
            token,
            &self.decoding_key,
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => EdrError::TokenExpired,
            _ => EdrError::InvalidToken(format!("token validation failed: {}", e)),
        })?;

        Ok(token_data.claims)
    }
}

/// Computes SHA-256 hash of the token and returns it as a hex string
pub fn hash_token(token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    hex::encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "SecureP@ssw0rd!";
        let hash = PasswordHashManager::hash(password).unwrap();
        assert!(PasswordHashManager::verify(password, &hash).unwrap());
        assert!(!PasswordHashManager::verify("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_password_hash_different_each_time() {
        let password = "SamePassword";
        let hash1 = PasswordHashManager::hash(password).unwrap();
        let hash2 = PasswordHashManager::hash(password).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_password_hash_empty_string() {
        let hash = PasswordHashManager::hash("").unwrap();
        assert!(PasswordHashManager::verify("", &hash).unwrap());
    }

    #[test]
    fn test_password_hash_unicode() {
        let password = "pässwörd-key";
        let hash = PasswordHashManager::hash(password).unwrap();
        assert!(PasswordHashManager::verify(password, &hash).unwrap());
    }

    #[test]
    fn test_password_hash_very_long() {
        let password = "a".repeat(1000);
        let hash = PasswordHashManager::hash(&password).unwrap();
        assert!(PasswordHashManager::verify(&password, &hash).unwrap());
    }

    #[test]
    fn test_jwt_issue_and_validate() {
        let secret = b"my-secret-key-at-least-32-bytes-long-for-security";
        let jwt = JwtManager::new(secret, 3600, 86400);
        let token = jwt.issue_token("user-1", "admin", "administrator").unwrap();
        let claims = jwt.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.username, "admin");
        assert_eq!(claims.role, "administrator");
        assert!(claims.jti.len() > 0);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_jwt_invalid_token() {
        let secret = b"my-secret-key-at-least-32-bytes-long-for-security";
        let jwt = JwtManager::new(secret, 3600, 86400);
        let result = jwt.validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_tampered_token() {
        let secret = b"my-secret-key-at-least-32-bytes-long-for-security";
        let jwt = JwtManager::new(secret, 3600, 86400);
        let mut token = jwt.issue_token("user-1", "admin", "admin").unwrap();
        token.push_str("x");
        let result = jwt.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_wrong_secret() {
        let jwt1 = JwtManager::new(b"secret-one-12345678901234567890", 3600, 86400);
        let jwt2 = JwtManager::new(b"secret-two-09876543210987654321", 3600, 86400);
        let token = jwt1.issue_token("user-1", "admin", "admin").unwrap();
        let result = jwt2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_expired_token() {
        let secret = b"test-secret-32-bytes-long-here!!!!!";
        let expired_claims = Claims {
            sub: "user-1".into(),
            username: "admin".into(),
            role: "admin".into(),
            exp: (Utc::now() - Duration::seconds(1)).timestamp() as usize,
            iat: (Utc::now() - Duration::seconds(60)).timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = encode(&Header::default(), &expired_claims, &EncodingKey::from_secret(secret)).unwrap();
        let jwt = JwtManager::new(secret, 3600, 86400);
        let result = jwt.validate_token(&token);
        assert!(matches!(result, Err(EdrError::TokenExpired)));
    }

    #[test]
    fn test_issue_refresh_token() {
        let secret = b"my-secret-key-at-least-32-bytes-long-for-security";
        let jwt = JwtManager::new(secret, 3600, 86400);
        let token = jwt.issue_refresh_token("user-1").unwrap();
        let claims = jwt.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert!(claims.username.is_empty());
    }

    #[test]
    fn test_claims_json_roundtrip() {
        let claims = Claims {
            sub: "user-1".into(),
            username: "admin".into(),
            role: "administrator".into(),
            exp: 9999999999,
            iat: 1000000000,
            jti: "unique-id".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.jti, claims.jti);
    }

    #[test]
    fn test_config_signing_roundtrip() {
        let data = b"some config contents to sign";
        let signature = super::sign_config(data);
        assert!(super::verify_config(data, &signature));
        assert!(!super::verify_config(b"tampered content", &signature));
    }
}

fn derive_hardware_key() -> Vec<u8> {
    use ring::digest;
    let mut data = Vec::new();
    
    // Add environment variables for stable unique seed
    for var in &[
        "COMPUTERNAME",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
    ] {
        if let Ok(val) = std::env::var(var) {
            data.extend_from_slice(val.as_bytes());
        }
    }
    
    // Static pepper
    data.extend_from_slice(b"MONOLITH_EDR_CONFIG_INTEGRITY_PEPPER_SECURE_987654321");
    
    let hash = digest::digest(&digest::SHA256, &data);
    hash.as_ref().to_vec()
}

pub fn sign_config(config_bytes: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let key_bytes = derive_hardware_key();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let tag = hmac::sign(&key, config_bytes);
    tag.as_ref().to_vec()
}

pub fn verify_config(config_bytes: &[u8], signature_bytes: &[u8]) -> bool {
    use ring::hmac;
    let key_bytes = derive_hardware_key();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    hmac::verify(&key, config_bytes, signature_bytes).is_ok()
}

