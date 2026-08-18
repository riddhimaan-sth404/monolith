use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStore {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl TokenStore {
    pub fn path() -> PathBuf {
        let base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("monolith");
        std::fs::create_dir_all(&base).ok();
        base.join("token")
    }

    pub fn load() -> Option<Self> {
        let path = Self::path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path();
        let s = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, s)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn delete() {
        let path = Self::path();
        std::fs::remove_file(&path).ok();
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| chrono::Utc::now().timestamp() >= exp)
            .unwrap_or(false)
    }
}
