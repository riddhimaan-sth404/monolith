use crate::auth::TokenStore;
use crate::config::Config;
use anyhow::{Context, bail};
use reqwest::Client as ReqwestClient;
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Debug, serde::Deserialize)]
pub struct ActivateResponse {
    pub token: String,
    pub expires_at: Option<i64>,
}

pub struct MonolithClient {
    pub client: ReqwestClient,
    pub base_url: String,
    pub token: Option<TokenStore>,
    #[allow(dead_code)]
    pub output: String,
}

impl MonolithClient {
    pub fn new(config: &Config, token: Option<TokenStore>) -> anyhow::Result<Self> {
        let mut builder = ReqwestClient::builder().user_agent("mono-cli/1.0.0");

        if let Some(ref ca_path) = config.ca_cert {
            let pem_bytes = std::fs::read(ca_path)
                .with_context(|| format!("failed to read CA cert at {}", ca_path))?;
            let cert = reqwest::tls::Certificate::from_pem(&pem_bytes)
                .context("failed to parse CA cert PEM")?;
            builder = builder.add_root_certificate(cert);
        }

        if config.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        Ok(Self {
            client: builder.build()?,
            base_url: config.server.trim_end_matches('/').to_string(),
            token,
            output: config.output.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_header(&self) -> Option<String> {
        self.token
            .as_ref()
            .map(|t| format!("Bearer {}", t.access_token))
    }

    #[allow(dead_code)]
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let mut req = self.client.get(&self.url(path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", &auth);
        }
        let resp = req.send().await.context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_raw(&self, path: &str) -> anyhow::Result<Value> {
        let mut req = self.client.get(&self.url(path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", &auth);
        }
        let resp = req.send().await.context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn post_raw(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        let mut req = self.client.post(&self.url(path)).json(body);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", &auth);
        }
        let resp = req.send().await.context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn put_raw(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        let mut req = self.client.put(&self.url(path)).json(body);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", &auth);
        }
        let resp = req.send().await.context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn delete_raw(&self, path: &str) -> anyhow::Result<Value> {
        let mut req = self.client.delete(&self.url(path));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", &auth);
        }
        let resp = req.send().await.context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn activate(
        &self,
        product_key: &str,
        fingerprint: &str,
    ) -> anyhow::Result<ActivateResponse> {
        let body = serde_json::json!({
            "product_key": product_key,
            "hardware_fingerprint": fingerprint,
        });
        let resp = self
            .client
            .post(&self.url("/api/v1/activate"))
            .json(&body)
            .send()
            .await
            .context("Failed to connect to server")?;
        self.check_status(&resp).await?;
        let response: ActivateResponse = resp.json().await?;
        Ok(response)
    }

    async fn check_status(&self, resp: &reqwest::Response) -> anyhow::Result<()> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let msg = match status.as_u16() {
            401 => "Authentication failed. Run `mono self activate` to re-activate.".into(),
            403 => "Access denied.".into(),
            404 => "Resource not found.".into(),
            409 => "Product key already activated on different hardware.".into(),
            429 => "Rate limited. Wait and try again.".into(),
            c => format!("Server error {}", c),
        };
        bail!("{}", msg)
    }

    pub async fn ws_url(&self) -> String {
        let ws_base = self
            .base_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        format!("{}/api/v1/ws/events", ws_base)
    }
}
