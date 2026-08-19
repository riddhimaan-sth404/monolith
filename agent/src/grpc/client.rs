use monolith_protobuf::proto::v1::endpoint_service_client::EndpointServiceClient;
use monolith_protobuf::proto::v1::{self as pb};
use monolith_shared::error::{EdrError, Result};
use tonic::Streaming;
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;

pub struct GrpcClient {
    server_address: String,
    connected: bool,
    client: Option<EndpointServiceClient<Channel>>,
    endpoint_id: String,
    ca_cert_pem: Vec<u8>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<Vec<u8>>,
    token: Option<String>,
}

impl GrpcClient {
    pub fn new(address: &str, ca_cert_pem: Vec<u8>) -> Self {
        Self {
            server_address: address.to_string(),
            connected: false,
            client: None,
            endpoint_id: String::new(),
            ca_cert_pem,
            client_cert_pem: None,
            client_key_pem: None,
            token: None,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    fn auth_req<T>(&self, inner: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(inner);
        if let Some(token) = &self.token {
            let value = format!("Bearer {}", token).parse().unwrap();
            req.metadata_mut().insert("authorization", value);
        }
        req
    }

    pub fn with_mtls(
        address: &str,
        ca_cert_pem: Vec<u8>,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        Self {
            server_address: address.to_string(),
            connected: false,
            client: None,
            endpoint_id: String::new(),
            ca_cert_pem,
            client_cert_pem: Some(cert_pem),
            client_key_pem: Some(key_pem),
            token: None,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        tracing::info!("connecting to backend gRPC: {}", self.server_address);

        let address = if self.server_address.starts_with("http://")
            || self.server_address.starts_with("https://")
        {
            self.server_address.clone()
        } else {
            format!("https://{}", self.server_address)
        };

        let ca_cert = Certificate::from_pem(self.ca_cert_pem.clone());
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .domain_name("localhost");

        if let (Some(cert_pem), Some(key_pem)) =
            (self.client_cert_pem.as_ref(), self.client_key_pem.as_ref())
        {
            let identity = tonic::transport::Identity::from_pem(cert_pem.clone(), key_pem.clone());
            tls = tls.identity(identity);
        }

        let channel = Channel::from_shared(address.clone())
            .map_err(|e| {
                EdrError::ConnectionError(format!("invalid gRPC address {}: {}", address, e))
            })?
            .tls_config(tls)
            .map_err(|e| EdrError::ConnectionError(format!("TLS config error: {}", e)))?
            .connect()
            .await
            .map_err(|e| {
                EdrError::ConnectionError(format!("failed to connect to {}: {}", address, e))
            })?;

        self.client = Some(EndpointServiceClient::new(channel));
        self.connected = true;
        tracing::info!("connected to backend gRPC server");
        Ok(())
    }

    pub async fn register(
        &mut self,
        hostname: &str,
        os_version: &str,
        agent_version: &str,
    ) -> Result<String> {
        let request = tonic::Request::new(pb::RegisterRequest {
            hostname: hostname.to_string(),
            os_version: os_version.to_string(),
            agent_version: agent_version.to_string(),
            os_architecture: String::new(),
            certificate_thumbprint: String::new(),
        });

        let response = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .register_endpoint(request)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?;

        let reply = response.into_inner();
        if let Some(uuid) = reply.endpoint_id {
            let id_str = uuid::Uuid::from_bytes(uuid.value.try_into().map_err(|_| {
                EdrError::ConnectionError("invalid endpoint UUID from server".into())
            })?)
            .to_string();
            self.endpoint_id = id_str;
        }

        let token = reply.api_token;
        if !token.is_empty() {
            self.set_token(token.clone());
        }
        tracing::info!("registered with backend, endpoint_id={}", self.endpoint_id);
        Ok(token)
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        self.client = None;
        self.connected = false;
        self.connect().await
    }

    pub fn set_endpoint_id(&mut self, id: &str) {
        self.endpoint_id = id.to_string();
    }

    pub async fn send_heartbeat(&mut self, heartbeat: &serde_json::Value) -> Result<bool> {
        if !self.connected {
            return Err(EdrError::ConnectionError("not connected".into()));
        }

        let endpoint_id = if self.endpoint_id.is_empty() {
            None
        } else {
            uuid::Uuid::parse_str(&self.endpoint_id)
                .ok()
                .map(|id| pb::Uuid {
                    value: id.as_bytes().to_vec(),
                })
        };

        let request = self.auth_req(pb::HeartbeatRequest {
            endpoint_id,
            timestamp: None,
            status: 0,
            cpu_usage: heartbeat
                .get("cpu_usage")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
            memory_usage: heartbeat
                .get("memory_usage")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
            disk_free_bytes: heartbeat
                .get("disk_free_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            event_queue_depth: heartbeat
                .get("event_queue_depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            driver_loaded: heartbeat
                .get("driver_loaded")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            scanner_connected: heartbeat
                .get("scanner_connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            driver_events_collected: heartbeat
                .get("driver_events_collected")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            driver_events_dropped: heartbeat
                .get("driver_events_dropped")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            driver_version: heartbeat
                .get("driver_version")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            scanner_version: String::new(),
        });

        let response = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .heartbeat(request)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?;

        Ok(response.into_inner().ack)
    }

    pub async fn upload_events(&mut self, events: Vec<serde_json::Value>) -> Result<u32> {
        let proto_events: Vec<pb::Event> = events.iter().map(|_| pb::Event::default()).collect();
        self.upload_events_proto(&proto_events).await
    }

    pub async fn upload_events_proto(&mut self, events: &[pb::Event]) -> Result<u32> {
        if !self.connected {
            return Err(EdrError::ConnectionError("not connected".into()));
        }

        let endpoint_uuid = if self.endpoint_id.is_empty() {
            None
        } else {
            uuid::Uuid::parse_str(&self.endpoint_id)
                .ok()
                .map(|id| pb::Uuid {
                    value: id.as_bytes().to_vec(),
                })
        };

        let events_clone: Vec<pb::Event> = events
            .iter()
            .map(|evt| {
                let mut e = evt.clone();
                if e.endpoint_id.is_none() {
                    e.endpoint_id = endpoint_uuid.clone();
                }
                e
            })
            .collect();
        let stream = futures::stream::iter(events_clone.into_iter());
        let req = self.auth_req(stream);
        let response = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .upload_events(req)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?;

        Ok(response.into_inner().events_accepted)
    }

    pub async fn sync_policy(&mut self) -> Result<pb::PolicyResponse> {
        if !self.connected {
            return Err(EdrError::ConnectionError("not connected".into()));
        }

        let request = self.auth_req(pb::PolicyRequest {
            endpoint_id: self
                .endpoint_id
                .parse()
                .ok()
                .map(|id: uuid::Uuid| pb::Uuid {
                    value: id.into_bytes().to_vec(),
                }),
            current_policy_version: String::new(),
        });

        let response = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .sync_policy(request)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?;

        Ok(response.into_inner())
    }

    pub async fn get_pending_actions(&mut self) -> Result<Vec<pb::ResponseAction>> {
        if !self.connected {
            return Err(EdrError::ConnectionError("not connected".into()));
        }

        let request = self.auth_req(pb::ActionRequest {
            endpoint_id: self
                .endpoint_id
                .parse()
                .ok()
                .map(|id: uuid::Uuid| pb::Uuid {
                    value: id.into_bytes().to_vec(),
                }),
            last_action_id: String::new(),
        });

        let mut stream: Streaming<pb::ResponseAction> = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .get_actions(request)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?
            .into_inner();

        let mut actions = Vec::new();
        use tokio_stream::StreamExt;
        while let Some(action) = stream.next().await {
            match action {
                Ok(a) => actions.push(a),
                Err(e) => tracing::warn!("error reading action stream: {}", e),
            }
        }

        Ok(actions)
    }

    pub async fn report_action_status(&mut self, action_id: &str, status: &str) -> Result<bool> {
        if !self.connected {
            return Err(EdrError::ConnectionError("not connected".into()));
        }

        let state_val = match status {
            "completed" => pb::action_status::ActionState::ActionCompleted as i32,
            "failed" => pb::action_status::ActionState::ActionFailed as i32,
            _ => pb::action_status::ActionState::ActionPending as i32,
        };

        let request = self.auth_req(pb::ActionStatus {
            action_id: action_id.to_string(),
            endpoint_id: self
                .endpoint_id
                .parse()
                .ok()
                .map(|id: uuid::Uuid| pb::Uuid {
                    value: id.into_bytes().to_vec(),
                }),
            r#type: pb::ResponseActionType::ResponseActionUnspecified as i32,
            state: state_val,
            result_message: String::new(),
            started_at: None,
            completed_at: None,
        });

        let response = self
            .client
            .as_mut()
            .ok_or_else(|| EdrError::ConnectionError("client not initialized".into()))?
            .report_action_status(request)
            .await
            .map_err(|e| EdrError::GrpcError(e.to_string()))?;

        Ok(response.into_inner().received)
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub async fn disconnect(&mut self) {
        self.client = None;
        self.connected = false;
        tracing::info!("disconnected from backend gRPC server");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_returns_error_for_invalid_address() {
        let mut client = GrpcClient::new("not a valid address", Vec::new());
        let err = client.connect().await.unwrap_err();
        assert!(matches!(err, EdrError::ConnectionError(_)));
    }
}
