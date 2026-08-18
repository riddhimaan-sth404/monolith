use crate::grpc::client::GrpcClient;
use monolith_shared::error::Result;
use serde_json::Value;

pub struct TelemetryUploader;

impl TelemetryUploader {
    pub fn new() -> Self {
        Self
    }

    pub async fn upload(&self, events: Vec<Value>) -> Result<u32> {
        if events.is_empty() {
            return Ok(0);
        }

        tracing::debug!("uploading {} events", events.len());

        let server_address = std::env::var("monolith_backend_GRPC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9443".to_string());
        let mut client = GrpcClient::new(&server_address, Vec::new());
        client.connect().await?;
        let accepted = client.upload_events(events).await?;
        tracing::info!("uploaded {} events successfully", accepted);
        Ok(accepted)
    }
}
