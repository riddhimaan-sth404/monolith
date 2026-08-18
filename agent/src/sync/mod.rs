use monolith_shared::error::Result;

pub mod heartbeat;
pub mod telemetry;

pub struct SyncManager {
    heartbeat_sender: heartbeat::HeartbeatSender,
    telemetry_uploader: telemetry::TelemetryUploader,
    online: bool,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            heartbeat_sender: heartbeat::HeartbeatSender::new(),
            telemetry_uploader: telemetry::TelemetryUploader::new(),
            online: false,
        }
    }

    pub async fn send_heartbeat(&self) -> Result<bool> {
        if !self.online {
            return Ok(false);
        }
        self.heartbeat_sender.send().await
    }

    pub async fn upload_events(&self, events: Vec<serde_json::Value>) -> Result<u32> {
        if !self.online {
            return Ok(0);
        }
        self.telemetry_uploader.upload(events).await
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    pub fn is_online(&self) -> bool {
        self.online
    }
}
