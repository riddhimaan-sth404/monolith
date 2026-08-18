use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::config::AppConfig;
use crate::server::AppState;
use monolith_protobuf::proto::v1 as pb;
use monolith_protobuf::proto::v1::endpoint_service_server::{EndpointService, EndpointServiceServer};
use monolith_protobuf::proto::v1::scanner_service_server::{ScannerService, ScannerServiceServer};
use monolith_shared::db::DbParam;
use monolith_shared::error::EdrError;

pub async fn start_grpc_server(
    config: AppConfig,
    state: Arc<AppState>,
) -> Result<(), anyhow::Error> {
    let addr_str = format!("{}:{}", config.server.host, config.server.grpc_port);
    info!("starting gRPC server on {}", addr_str);
    let addr: std::net::SocketAddr = addr_str.parse()?;

    // Load TLS for gRPC
    let cert = tokio::fs::read(&config.tls.cert_path).await?;
    let key = tokio::fs::read(&config.tls.key_path).await?;
    let identity = tonic::transport::Identity::from_pem(cert, key);

    let jwt_manager = Arc::new(config.auth.build_jwt_manager()
        .map_err(|e| anyhow::anyhow!("failed to build JWT manager for gRPC: {}", e))?);
    let jwt_for_scanner = jwt_manager.clone();

    let scanner_interceptor = move |req: Request<()>| {
        let token = req.metadata().get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;

        jwt_for_scanner.validate_token(token).map_err(|e| {
            match e {
                EdrError::TokenExpired => Status::unauthenticated("token expired"),
                _ => Status::unauthenticated("invalid token"),
            }
        })?;

        Ok(req)
    };

    tonic::transport::Server::builder()
        .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))?
        .add_service(EndpointServiceServer::new(EndpointServiceImpl::new(state.clone(), jwt_manager)))
        .add_service(ScannerServiceServer::with_interceptor(ScannerServiceImpl, scanner_interceptor))
        .serve(addr)
        .await?;

    Ok(())
}

// ===== EndpointService =====

struct EndpointServiceImpl {
    state: Arc<AppState>,
    jwt_manager: Arc<monolith_shared::crypto::JwtManager>,
}

impl EndpointServiceImpl {
    fn new(state: Arc<AppState>, jwt_manager: Arc<monolith_shared::crypto::JwtManager>) -> Self {
        Self { state, jwt_manager }
    }

    fn check_auth<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let token = req.metadata().get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;
        self.jwt_manager.validate_token(token).map_err(|e| {
            match e {
                EdrError::TokenExpired => Status::unauthenticated("token expired"),
                _ => Status::unauthenticated("invalid token"),
            }
        })?;
        Ok(())
    }
}

#[tonic::async_trait]
impl EndpointService for EndpointServiceImpl {
    async fn register_endpoint(
        &self,
        request: Request<pb::RegisterRequest>,
    ) -> Result<Response<pb::RegisterResponse>, Status> {
        let req = request.into_inner();
        let hostname = req.hostname.clone();
        let os_version = req.os_version.clone();
        let agent_version = req.agent_version.clone();
        info!("RegisterEndpoint: hostname={}", hostname);

        let endpoint_id = uuid::Uuid::new_v4().to_string();
        let _ = self.state.db.execute(
            "INSERT OR REPLACE INTO endpoints (id, hostname, ip_address, os_version, agent_version, status, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, 'online', datetime('now'), datetime('now'))",
            &[
                DbParam::Text(endpoint_id.clone()),
                DbParam::Text(hostname.clone()),
                // IP address should come from gRPC connection context in production
                DbParam::Text(String::new()),
                DbParam::Text(os_version),
                DbParam::Text(agent_version),
            ],
        ).await;

        let api_token = self.jwt_manager
            .issue_token(&endpoint_id, &hostname, "endpoint")
            .unwrap_or_default();

        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::RegisterResponse {
            endpoint_id: Some(pb::Uuid { value: uuid::Uuid::parse_str(&endpoint_id).unwrap_or_default().into_bytes().to_vec() }),
            api_token,
            registered_at: Some(ts),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<pb::HeartbeatRequest>,
    ) -> Result<Response<pb::HeartbeatResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let endpoint_id_str = req.endpoint_id
            .as_ref()
            .map(|u| uuid_from_proto(u.clone()).to_string())
            .unwrap_or_default();

        let telemetry_state = if req.driver_loaded { "healthy" } else { "blackout" };
        let signature_status = "valid";
        let heartbeat_id = uuid::Uuid::new_v4().to_string();
        let timestamp_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let _ = self.state.db.execute(
            "INSERT INTO heartbeats (id, endpoint_id, timestamp, hostname, ip_address, agent_version, telemetry_state, signature_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                DbParam::Text(heartbeat_id),
                DbParam::Text(endpoint_id_str.clone()),
                DbParam::Text(timestamp_str),
                DbParam::Null,
                DbParam::Null,
                DbParam::Text(req.agent_version.clone()),
                DbParam::Text(telemetry_state.to_string()),
                DbParam::Text(signature_status.to_string()),
            ]
        ).await;

        let _ = self.state.db.execute(
            "UPDATE endpoints SET last_seen = datetime('now'), status = 'online' WHERE id = ?1",
            &[DbParam::Text(endpoint_id_str)],
        ).await;

        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::HeartbeatResponse {
            ack: true,
            server_time: Some(ts),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_update_available: false,
            ioc_update_available: false,
            action_pending: false,
            pending_actions: vec![],
        }))
    }

    async fn upload_events(
        &self,
        request: Request<tonic::Streaming<pb::Event>>,
    ) -> Result<Response<pb::UploadResponse>, Status> {
        self.check_auth(&request)?;
        let mut stream = request.into_inner();
        let mut accepted: u32 = 0;
        let mut rejected: u32 = 0;

        while let Some(event) = stream.next().await {
            match event {
                Ok(evt) => {
                    let event_id = uuid::Uuid::new_v4().to_string();
                    let data = extract_event_data(&evt);
                    let data_str = serde_json::to_string(&data).unwrap_or_default();

                    let endpoint_id = evt.endpoint_id
                        .map(|u| uuid_from_proto(u).to_string())
                        .unwrap_or_default();
                    if !endpoint_id.is_empty() {
                        // Ensure the endpoint row exists to satisfy FK constraint
                        let _ = self.state.db.execute(
                            "INSERT OR IGNORE INTO endpoints (id, hostname, status, first_seen, last_seen)
                             VALUES (?1, 'unknown', 'online', datetime('now'), datetime('now'))",
                            &[DbParam::Text(endpoint_id.clone())],
                        ).await;
                    }
                    let endpoint_id_clone = endpoint_id.clone();
                    let event_type_name = event_type_to_str(evt.event_type);

                    let result = self.state.db.execute(
                        "INSERT INTO events (id, endpoint_id, event_type, timestamp, data, processed)
                         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                        &[
                            DbParam::Text(event_id),
                            DbParam::Text(endpoint_id_clone),
                            DbParam::Text(event_type_name.to_string()),
                            DbParam::Text(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string()),
                            DbParam::Text(data_str),
                        ],
                    ).await;

                    match result {
                        Ok(_) => {
                            accepted += 1;
                            self.state.metrics.events_ingested.fetch_add(1, Ordering::Relaxed);

                            // Run detection + auto-response on stored event
                            if let Some(ds) = self.state.detection_service.get() {
                                let _ = ds.process_event(&data, &endpoint_id, &*self.state.db).await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("failed to store event: {}", e);
                            rejected += 1;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("error in event stream: {}", e);
                    rejected += 1;
                }
            }
        }

        Ok(Response::new(pb::UploadResponse {
            events_accepted: accepted,
            events_rejected: rejected,
            error_messages: vec![],
        }))
    }

    async fn sync_policy(
        &self,
        request: Request<pb::PolicyRequest>,
    ) -> Result<Response<pb::PolicyResponse>, Status> {
        self.check_auth(&request)?;
        let _req = request.into_inner();
        let policies = self.state.db.query_value(
            "SELECT id, name, version, rules, settings FROM policies WHERE active = 1 LIMIT 1",
            &[],
        ).await.map_err(|e| Status::internal(format!("db error: {}", e)))?;

        let policy = policies.into_iter().next();
        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::PolicyResponse {
            policy_id: policy.as_ref().and_then(|p| p.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())).unwrap_or_default(),
            policy_version: policy.as_ref().and_then(|p| p.get("version").and_then(|v| v.as_str()).map(|s| s.to_string())).unwrap_or_default(),
            policy_content: policy.as_ref().and_then(|p| p.get("rules").and_then(|v| v.as_str()).map(|s| s.as_bytes().to_vec())).unwrap_or_default(),
            updated_at: Some(ts),
        }))
    }

    async fn report_alert(
        &self,
        request: Request<pb::Alert>,
    ) -> Result<Response<pb::AlertAck>, Status> {
        self.check_auth(&request)?;
        let alert = request.into_inner();
        let alert_id = uuid::Uuid::new_v4().to_string();
        let endpoint_id_str = alert.endpoint_id
            .as_ref()
            .map(|u| uuid_from_proto(u.clone()).to_string())
            .unwrap_or_default();
        let severity_str = match alert.severity {
            1 => "info",
            2 => "low",
            3 => "medium",
            4 => "high",
            5 => "critical",
            _ => "unspecified",
        };

        let alert_id_clone = alert_id.clone();
        let title_clone = alert.title.clone();
        let _ = self.state.db.execute(
            "INSERT INTO alerts (id, endpoint_id, severity, title, description, score, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'new')",
            &[
                DbParam::Text(alert_id_clone),
                DbParam::Text(endpoint_id_str),
                DbParam::Text(severity_str.to_string()),
                DbParam::Text(alert.title),
                DbParam::Text(alert.description),
                DbParam::Real(alert.score),
            ],
        ).await;

        self.state.metrics.alerts_generated.fetch_add(1, Ordering::Relaxed);

        if severity_str == "high" || severity_str == "critical" {
            let notif_title = format!("EDR Alert: {}", severity_str);
            let notif_msg = format!("Agent reported: {}", title_clone);
            let path = self.state.toast_script_path.clone();
            tokio::spawn(async move {
                crate::notifications::send_alert_notification(path, &notif_title, &notif_msg).await;
            });
        }

        Ok(Response::new(pb::AlertAck {
            received: true,
            alert_id,
        }))
    }

    type GetActionsStream = ReceiverStream<Result<pb::ResponseAction, Status>>;

    async fn get_actions(
        &self,
        request: Request<pb::ActionRequest>,
    ) -> Result<Response<Self::GetActionsStream>, Status> {
        self.check_auth(&request)?;
        let (tx, rx) = mpsc::channel(100);
        // Check for pending response actions in DB
        let actions = self.state.db.query_value(
            "SELECT id, endpoint_id, action_type, parameters FROM response_actions
             WHERE status = 'pending' AND endpoint_id = ?1",
            &[DbParam::Text("".to_string())],
        ).await.unwrap_or_default();

        for action in actions {
            let _ = tx.send(Ok(pb::ResponseAction {
                id: action.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                r#type: 0,
                parameters: action.get("parameters").and_then(|v| v.as_str()).unwrap_or("").as_bytes().to_vec(),
                issued_at: None,
                issued_by: String::new(),
                reason: String::new(),
            })).await;
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_action_status(
        &self,
        request: Request<pb::ActionStatus>,
    ) -> Result<Response<pb::ActionAck>, Status> {
        self.check_auth(&request)?;
        let status = request.into_inner();
        let state_str = match status.state {
            2 => "completed",
            3 => "failed",
            4 => "rejected",
            _ => "pending",
        };
        let _ = self.state.db.execute(
            "UPDATE response_actions SET status = ?1, completed_at = datetime('now') WHERE id = ?2",
            &[
                DbParam::Text(state_str.to_string()),
                DbParam::Text(status.action_id),
            ],
        ).await;

        Ok(Response::new(pb::ActionAck { received: true }))
    }

    async fn sync_io_cs(
        &self,
        _request: Request<pb::IocCacheRequest>,
    ) -> Result<Response<pb::IocCacheResponse>, Status> {
        let iocs = self.state.db.query_value(
            "SELECT id, ioc_type, value FROM iocs WHERE active = 1",
            &[],
        ).await.map_err(|e| Status::internal(format!("db error: {}", e)))?;

        let updated: Vec<pb::Ioc> = iocs.into_iter().map(|ioc| {
            pb::Ioc {
                id: ioc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                ioc_type: ioc.get("ioc_type").and_then(|v| v.as_str()).map(|s| match s {
                    "sha256" => pb::Ioctype::IocTypeSha256 as i32,
                    "sha1" => pb::Ioctype::IocTypeSha1 as i32,
                    "md5" => pb::Ioctype::IocTypeMd5 as i32,
                    "domain" => pb::Ioctype::IocTypeDomain as i32,
                    "url" => pb::Ioctype::IocTypeUrl as i32,
                    "ip" => pb::Ioctype::IocTypeIp as i32,
                    "certificate" => pb::Ioctype::IocTypeCertificate as i32,
                    "registry" => pb::Ioctype::IocTypeRegistryPath as i32,
                    "file_path" => pb::Ioctype::IocTypeFilePath as i32,
                    "yara" => pb::Ioctype::IocTypeYara as i32,
                    "sigma" => pb::Ioctype::IocTypeSigma as i32,
                    _ => pb::Ioctype::IocTypeUnspecified as i32,
                }).unwrap_or(0),
                value: ioc.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                severity: pb::Severity::Unspecified as i32,
                confidence: pb::Confidence::Unspecified as i32,
                tags: vec![],
                description: String::new(),
                source: String::new(),
                reference: String::new(),
                expires_at: None,
                created_at: None,
                created_by: String::new(),
                updated_at: None,
                updated_by: String::new(),
                mitre_technique_id: String::new(),
                mitre_tactic: String::new(),
                malware_family: String::new(),
                comments: vec![],
            }
        }).collect();

        Ok(Response::new(pb::IocCacheResponse {
            new_version: chrono::Utc::now().timestamp() as u32,
            updated_iocs: updated,
            deleted_ioc_ids: vec![],
            full_sync: true,
        }))
    }
}

// ===== ScannerService (backend side â€” forwards to scanner gRPC) =====

struct ScannerServiceImpl;

#[tonic::async_trait]
impl ScannerService for ScannerServiceImpl {
    type StreamScanResultsStream = ReceiverStream<Result<pb::ScanResult, Status>>;

    async fn start_scan(
        &self,
        _request: Request<pb::ScanRequest>,
    ) -> Result<Response<pb::ScanStatusMessage>, Status> {
        info!("ScannerService::StartScan");
        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::ScanStatusMessage {
            scan_id: String::new(),
            status: pb::ScanStatus::Pending as i32,
            scan_type: 0,
            started_at: Some(ts),
            completed_at: None,
            total_files: 0,
            scanned_files: 0,
            infected_files: 0,
            quarantined_files: 0,
            errors: 0,
            progress_percent: 0.0,
            current_path: String::new(),
            scan_speed_files_per_sec: 0.0,
        }))
    }

    async fn stop_scan(
        &self,
        _request: Request<pb::StopRequest>,
    ) -> Result<Response<pb::ScanStatusMessage>, Status> {
        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::ScanStatusMessage {
            scan_id: String::new(),
            status: pb::ScanStatus::Cancelled as i32,
            scan_type: 0,
            started_at: None,
            completed_at: Some(ts),
            total_files: 0,
            scanned_files: 0,
            infected_files: 0,
            quarantined_files: 0,
            errors: 0,
            progress_percent: 0.0,
            current_path: String::new(),
            scan_speed_files_per_sec: 0.0,
        }))
    }

    async fn get_scan_status(
        &self,
        _request: Request<pb::StatusRequest>,
    ) -> Result<Response<pb::ScanStatusMessage>, Status> {
        let now = chrono::Utc::now();
        let ts = prost_types::Timestamp { seconds: now.timestamp(), nanos: now.timestamp_subsec_nanos() as i32 };
        Ok(Response::new(pb::ScanStatusMessage {
            scan_id: String::new(),
            status: pb::ScanStatus::Completed as i32,
            scan_type: 0,
            started_at: None,
            completed_at: Some(ts),
            total_files: 0,
            scanned_files: 0,
            infected_files: 0,
            quarantined_files: 0,
            errors: 0,
            progress_percent: 0.0,
            current_path: String::new(),
            scan_speed_files_per_sec: 0.0,
        }))
    }

    async fn stream_scan_results(
        &self,
        _request: Request<pb::StatusRequest>,
    ) -> Result<Response<Self::StreamScanResultsStream>, Status> {
        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let _ = tx.send(Ok(pb::ScanResult::default())).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_scan_summary(
        &self,
        _request: Request<pb::ScanSummary>,
    ) -> Result<Response<pb::ScanAck>, Status> {
        Ok(Response::new(pb::ScanAck { received: true }))
    }

    async fn scanner_health(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::ScannerHealthResponse>, Status> {
        Ok(Response::new(pb::ScannerHealthResponse {
            healthy: true,
            version: "1.0.0".to_string(),
            uptime_seconds: chrono::Utc::now().timestamp() as u64,
            rules_loaded: 0,
            active_workers: 0,
            cpu_usage: 0.0,
            memory_bytes: 0,
        }))
    }
}

fn extract_event_data(evt: &pb::Event) -> serde_json::Value {
    use pb::event::Payload;

    match &evt.payload {
        Some(Payload::ProcessCreate(pce)) => {
            if let Some(proc) = &pce.process {
                serde_json::json!({
                    "pid": proc.pid,
                    "parent_pid": proc.parent_pid,
                    "name": proc.name,
                    "path": proc.path,
                    "command_line": proc.command_line,
                    "user_sid": proc.user_sid,
                    "integrity_level": proc.integrity_level,
                    "parent_name": pce.parent_name,
                })
            } else {
                serde_json::json!({"pid": 0})
            }
        }
        Some(Payload::ProcessExit(pex)) => {
            serde_json::json!({
                "pid": pex.pid,
                "exit_code": pex.exit_code,
                "run_time_nanos": pex.run_time_nanos,
            })
        }
        Some(Payload::ThreadCreate(tc)) => {
            serde_json::json!({
                "pid": tc.pid,
                "tid": tc.tid,
                "creator_pid": tc.creator_pid,
                "creator_tid": tc.creator_tid,
            })
        }
        Some(Payload::ThreadExit(te)) => {
            serde_json::json!({
                "pid": te.pid,
                "tid": te.tid,
                "exit_code": te.exit_code,
            })
        }
        Some(Payload::ModuleLoad(ml)) => {
            serde_json::json!({
                "pid": ml.pid,
                "module_path": ml.module_path,
                "module_name": ml.module_name,
                "base_address": format!("0x{:x}", ml.base_address),
                "module_size": ml.module_size,
            })
        }
        Some(Payload::RegistryChange(rc)) => {
            serde_json::json!({
                "pid": rc.pid,
                "key_path": rc.key_path,
                "value_name": rc.value_name,
                "old_value": rc.old_value,
                "new_value": rc.new_value,
            })
        }
        Some(Payload::NetworkConnect(nc)) => {
            serde_json::json!({
                "pid": nc.pid,
                "process_name": nc.process_name,
                "local_address": nc.local_address,
                "local_port": nc.local_port,
                "remote_address": nc.remote_address,
                "remote_port": nc.remote_port,
            })
        }
        Some(Payload::FileEvent(fe)) => {
            serde_json::json!({
                "path": fe.path,
                "name": fe.name,
                "extension": fe.extension,
                "size": fe.size,
            })
        }
        Some(Payload::DnsQuery(dq)) => {
            serde_json::json!({
                "pid": dq.pid,
                "process_name": dq.process_name,
                "query": dq.query,
                "answers": dq.answers,
            })
        }
        Some(Payload::DriverLoad(dl)) => {
            serde_json::json!({
                "driver_path": dl.driver_path,
                "driver_name": dl.driver_name,
                "publisher": dl.publisher,
                "version": dl.version,
            })
        }
        Some(Payload::ServiceCreate(sc)) => {
            serde_json::json!({
                "service_name": sc.service_name,
                "display_name": sc.display_name,
                "image_path": sc.image_path,
                "service_type": sc.service_type,
            })
        }
        Some(Payload::UserLogon(ul)) => {
            serde_json::json!({
                "user_sid": ul.user_sid,
                "user_name": ul.user_name,
                "domain": ul.domain,
                "session_id": ul.session_id,
            })
        }
        Some(Payload::UserLogoff(ul)) => {
            serde_json::json!({
                "user_sid": ul.user_sid,
                "user_name": ul.user_name,
                "session_id": ul.session_id,
            })
        }
        Some(Payload::Powershell(ps)) => {
            serde_json::json!({
                "pid": ps.pid,
                "process_name": ps.process_name,
                "command": ps.command,
                "script_path": ps.script_path,
            })
        }
        Some(Payload::Wmi(wmi)) => {
            serde_json::json!({
                "pid": wmi.pid,
                "namespace": wmi.namespace,
                "class_name": wmi.class_name,
                "query": wmi.query,
            })
        }
        Some(Payload::ScheduledTask(st)) => {
            serde_json::json!({
                "task_name": st.task_name,
                "task_path": st.task_path,
                "task_command": st.task_command,
                "task_arguments": st.task_arguments,
                "trigger_type": st.trigger_type,
            })
        }
        Some(Payload::UsbInsert(usb)) => {
            serde_json::json!({
                "device_id": usb.device_id,
                "vendor_id": usb.vendor_id,
                "product_id": usb.product_id,
                "serial_number": usb.serial_number,
            })
        }
        Some(Payload::DriverTelemetry(dt)) => {
            serde_json::json!({
                "pid": dt.pid,
                "tid": dt.tid,
                "image_path": dt.image_path,
                "command_line": dt.command_line,
            })
        }
        Some(Payload::ScannerResult(sr)) => {
            serde_json::json!({
                "file_path": sr.file_path,
                "malicious": sr.malicious,
                "score": sr.score,
            })
        }
        Some(Payload::MemorySuspicious(ms)) => {
            if let Some(s) = &ms.suspicious {
                serde_json::json!({
                    "process_id": s.process_id,
                    "process_name": s.process_name,
                    "base_address": format!("0x{:x}", s.base_address),
                    "region_size": s.region_size,
                    "protect": format!("0x{:x}", s.protect),
                    "memory_type": s.memory_type,
                    "suspicion_flags": s.suspicion_flags,
                })
            } else {
                serde_json::json!({"process_id": 0})
            }
        }
        None => {
            let map = extract_metadata(evt);
            serde_json::Value::Object(map)
        }
    }
}

fn extract_metadata(evt: &pb::Event) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for entry in &evt.metadata {
        map.insert(entry.key.clone(), serde_json::Value::String(entry.value.clone()));
    }
    map
}

fn event_type_to_str(v: i32) -> &'static str {
    match v {
        1 => "process_create",
        2 => "process_exit",
        3 => "thread_create",
        4 => "thread_exit",
        5 => "module_load",
        6 => "registry_change",
        7 => "file_create",
        8 => "file_delete",
        9 => "file_modify",
        10 => "file_rename",
        11 => "network_connect",
        12 => "dns_query",
        13 => "driver_load",
        14 => "service_create",
        15 => "scheduled_task",
        16 => "usb_insert",
        17 => "user_logon",
        18 => "user_logoff",
        19 => "powershell_command",
        20 => "wmi_event",
        21 => "driver_event",
        22 => "scanner_result",
        23 => "memory_scan",
        24 => "registry_tamper",
        _ => "unspecified",
    }
}

fn uuid_from_proto(u: pb::Uuid) -> uuid::Uuid {
    uuid::Uuid::from_bytes(u.value.try_into().unwrap_or([0u8; 16]))
}


