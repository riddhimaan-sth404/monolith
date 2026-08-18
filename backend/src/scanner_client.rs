use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

fn deserialize_null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let v = Option::<T>::deserialize(d)?;
    Ok(v.unwrap_or_default())
}

/// HTTP client for the Go scanner's scan API.
pub struct ScannerClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct StartResponse {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct StatusResponse {
    pub active_jobs: i64,
    pub total_files: i64,
    pub completed_files: i64,
    pub status: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub current_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ScanResult {
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_size: i64,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub heuristic_score: f64,
    #[serde(default)]
    pub ember_score: f64,
    #[serde(default)]
    pub fusion_score: f64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub matched_rules: Vec<String>,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub pe_info: Option<Value>,
}

impl ScannerClient {
    pub fn new(addr: &str) -> Self {
        Self {
            base_url: format!("http://{}", addr),
            client: reqwest::Client::new(),
        }
    }

    /// Start a scan on the Go scanner.
    pub async fn start_scan(
        &self,
        scan_type: &str,
        paths: Option<Vec<String>>,
    ) -> Result<StartResponse, String> {
        let mut body = serde_json::json!({"scan_type": scan_type});
        if let Some(p) = paths {
            body["paths"] = serde_json::json!(p);
        }
        let resp = self
            .client
            .post(format!("{}/api/scan/start", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("scanner API unreachable: {}", e))?;
        resp.json::<StartResponse>()
            .await
            .map_err(|e| format!("invalid response: {}", e))
    }

    /// Get current scan status.
    pub async fn get_status(&self) -> Result<StatusResponse, String> {
        let resp = self
            .client
            .get(format!("{}/api/scan/status", self.base_url))
            .send()
            .await
            .map_err(|e| format!("scanner API unreachable: {}", e))?;
        resp.json::<StatusResponse>()
            .await
            .map_err(|e| format!("invalid response: {}", e))
    }

    /// Get all scan results collected so far.
    pub async fn get_results(&self) -> Result<Vec<ScanResult>, String> {
        let resp = self
            .client
            .get(format!("{}/api/scan/results", self.base_url))
            .send()
            .await
            .map_err(|e| format!("scanner API unreachable: {}", e))?;
        resp.json::<Vec<ScanResult>>()
            .await
            .map_err(|e| format!("invalid response: {}", e))
    }

    /// Cancel the active scan on the Go scanner.
    pub async fn cancel_scan(&self) -> Result<(), String> {
        let resp = self
            .client
            .post(format!("{}/api/scan/cancel", self.base_url))
            .send()
            .await
            .map_err(|e| format!("scanner API unreachable: {}", e))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("scanner cancel request failed: {}", resp.status()))
        }
    }
}
