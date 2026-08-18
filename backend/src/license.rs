use std::path::Path;
use std::sync::Arc;
use monolith_shared::error::{EdrError, Result};
use monolith_shared::license::{self, LicenseBundle, LicenseConfig};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

const LICENSED_CONFIG_PATH: &str = "data/licensed_config.bin";

pub fn load_license() -> Result<Option<LicenseBundle>> {
    license::find_license_file()
}

pub fn extract_config(bundle: &LicenseBundle) -> LicenseConfig {
    bundle.payload.config.clone()
}

pub fn save_licensed_config(config: &LicenseConfig) -> Result<()> {
    let json = serde_json::to_vec(config)
        .map_err(|e| EdrError::SerializationError(e.to_string()))?;
    let encrypted = encrypt_machine_local(&json)?;
    if let Some(parent) = Path::new(LICENSED_CONFIG_PATH).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(LICENSED_CONFIG_PATH, &encrypted)
        .map_err(|e| EdrError::IoError(e))?;
    Ok(())
}

pub fn load_licensed_config() -> Result<Option<LicenseConfig>> {
    let data = match std::fs::read(LICENSED_CONFIG_PATH) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let decrypted = decrypt_machine_local(&data)?;
    let config: LicenseConfig = serde_json::from_slice(&decrypted)
        .map_err(|e| EdrError::DeserializationError(e.to_string()))?;
    Ok(Some(config))
}

pub fn apply_to_appconfig(
    config: &mut crate::config::AppConfig,
    license_config: &LicenseConfig,
) {
    if !license_config.jwt_secret.is_empty() {
        config.auth.jwt_secret = license_config.jwt_secret.clone();
    }
    if !license_config.quarantine_key.is_empty() {
        // Pass through for scanner/agent to consume
    }
    if let Some(port) = license_config.server_port {
        config.server.port = port;
    }
    if let Some(grpc_port) = license_config.grpc_port {
        config.server.grpc_port = grpc_port;
    }
    if let Some(ref cert) = license_config.tls_cert_pem {
        if let Some(ref key) = license_config.tls_key_pem {
            let cert_path = "certs/licensed_server.pem";
            let key_path = "certs/licensed_server.key";
            let _ = std::fs::write(cert_path, cert);
            let _ = std::fs::write(key_path, key);
            config.tls.cert_path = cert_path.to_string();
            config.tls.key_path = key_path.to_string();
        }
    }
}

fn derive_machine_key() -> Result<LessSafeKey> {
    let mut seed = Vec::new();
    for var in &["COMPUTERNAME", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "NUMBER_OF_PROCESSORS", "OS"] {
        if let Ok(val) = std::env::var(var) {
            seed.extend_from_slice(val.as_bytes());
        }
    }
    seed.extend_from_slice(b"MONOLITH_LICENSED_CONFIG_STORE_V1");

    let hash = digest::digest(&digest::SHA256, &seed);
    let unbound_key = UnboundKey::new(&AES_256_GCM, hash.as_ref())
        .map_err(|e| EdrError::CryptoError(format!("key setup failed: {}", e)))?;
    Ok(LessSafeKey::new(unbound_key))
}

fn encrypt_machine_local(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = derive_machine_key()?;
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| EdrError::CryptoError(format!("rng failed: {}", e)))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| EdrError::CryptoError(format!("encryption failed: {}", e)))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    Ok(result)
}

fn decrypt_machine_local(ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(EdrError::CryptoError("invalid ciphertext".into()));
    }
    let key = derive_machine_key()?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&ciphertext[..12]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext[12..].to_vec();
    let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| EdrError::CryptoError("decryption failed (wrong machine?)".into()))?;
    Ok(plaintext.to_vec())
}

pub async fn activate_with_license(
    state: Arc<crate::server::AppState>,
    license_content: &str,
) -> std::result::Result<LicenseBundle, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    let bundle = license::parse_license_file(license_content)
        .map_err(|e| {
            (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": format!("invalid license: {}", e)})))
        })?;

    let config = extract_config(&bundle);
    save_licensed_config(&config).map_err(|e| {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error": format!("failed to save license config: {}", e)})))
    })?;

    // Apply config to AppState
    let mut app_config = state.config.clone();
    apply_to_appconfig(&mut app_config, &config);
    // Note: In production, the config would be hot-reloaded or the server restarted

    Ok(bundle)
}
