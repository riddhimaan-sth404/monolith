use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: String,
    #[serde(default = "default_output")]
    pub output: String,
    #[serde(default = "default_insecure")]
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert: Option<String>,
}

fn default_output() -> String {
    "table".into()
}

fn default_insecure() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "https://127.0.0.1:8443".into(),
            output: "table".into(),
            insecure: false,
            ca_cert: None,
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        let base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("monolith");
        std::fs::create_dir_all(&base).ok();
        base.join("config.toml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path();
        let s = toml::to_string_pretty(self)?;
        std::fs::write(&path, s)?;
        Ok(())
    }
}
