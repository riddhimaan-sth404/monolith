#![allow(missing_docs)]

use monolith_shared::config::ConfigLoader;
use monolith_shared::db::Database;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

use monolith_protobuf::proto::v1;

use monolith_agent::metrics::AgentMetrics;
use monolith_agent::resilience::circuit_breaker::CircuitBreaker;

use monolith_agent::config;

struct AgentService;

impl AgentService {
    fn run() -> Result<(), Box<dyn std::error::Error>> {
        set_panic_hook();

        monolith_agent::tamper::TamperProtection::detect_debugger();

        let config_path = "configs/agent.toml";
        monolith_agent::tamper::TamperProtection::harden_ntfs_permissions(config_path);
        if std::path::Path::new("configs/agent.toml.sig").exists() {
            monolith_agent::tamper::TamperProtection::harden_ntfs_permissions(
                "configs/agent.toml.sig",
            );
        }
        let config = config::AgentConfig::load(config_path)?;
        monolith_shared::logging::init_logging(&config.logging)
            .map_err(|e| format!("Failed to initialize logging: {}", e))?;

        tracing::info!(target: "agent", "starting Monolith agent service");

        let db_path = config.database.path.clone();
        let db = monolith_shared::db::SqliteDatabase::new(&db_path);
        let rt = tokio::runtime::Runtime::new()?;

        rt.block_on(async {
            let db_config = monolith_shared::config::DatabaseConfig {
                kind: monolith_shared::config::DatabaseKind::Sqlite,
                path: db_path.to_string(),
                max_connections: 4,
            };

            let conn = Arc::new(db.connect(&db_config).await.map_err(|e| {
                tracing::error!("database connection failed: {}", e);
                e
            })?);

            let migration_mgr = monolith_shared::db::MigrationManager::new();
            if let Err(e) = migration_mgr.run(&*conn).await {
                tracing::error!("migration failed: {}", e);
            }

            run_agent(config, conn).await.map_err(|e| {
                tracing::error!("agent error: {}", e);
                e
            })
        })?;

        Ok(())
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| String::from("unknown"))
}

fn os_version() -> String {
    format!(
        "Windows {} {}",
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    )
}

async fn run_agent(
    config: config::AgentConfig,
    conn: Arc<impl monolith_shared::db::DatabaseConnection + 'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(config);
    tracing::info!(target: "agent", "agent initialized, starting workers");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::warn!(target: "agent", "received Ctrl+C, preparing shutdown");

        // Signal driver: this exit is intentional — suppress respawn + allow driver unload
        r.store(false, Ordering::Relaxed);
    });

    // Connect to backend gRPC
    let grpc_addr = format!("{}:{}", config.server.host, config.server.grpc_port);
    let ca_pem = std::fs::read(&config.tls.ca_cert_path).unwrap_or_else(|_| {
        tracing::warn!(
            "failed to read CA cert at {}, using empty TLS config",
            config.tls.ca_cert_path
        );
        Vec::new()
    });
    let mut grpc_client = monolith_agent::grpc::client::GrpcClient::new(&grpc_addr, ca_pem);
    let mut _is_registered = false;
    match grpc_client.connect().await {
        Ok(_) => {
            tracing::info!(target: "agent", worker = "grpc", "connected to backend gRPC");
            // Register endpoint to obtain JWT token
            let hostname = hostname();
            let os_version = os_version();
            match grpc_client
                .register(&hostname, &os_version, env!("CARGO_PKG_VERSION"))
                .await
            {
                Ok(token) if !token.is_empty() => {
                    tracing::info!(target: "agent", "registered with backend, got JWT token");
                    _is_registered = true;
                }
                Ok(_) => {
                    tracing::warn!(target: "agent", "registration succeeded but no token returned")
                }
                Err(e) => tracing::warn!(target: "agent", "registration failed: {}", e),
            }
        }
        Err(e) => {
            tracing::warn!(target: "agent", worker = "grpc", "initial gRPC connection failed (will retry): {}", e)
        }
    }
    let grpc_client = Arc::new(Mutex::new(grpc_client));

    // Open driver device
    let driver = monolith_agent::driver::DriverCommunicator::new(
        &config.driver.name,
        config.driver.buffer_size,
    );
    let driver_handle = driver.open_device().ok();
    if let Some(ref h) = driver_handle {
        let current_pid = std::process::id();
        if let Err(e) = driver.register_agent(h, current_pid) {
            tracing::warn!(target: "agent", "failed to register agent with driver: {}", e);
        } else {
            // Register respawn path so driver can relaunch us if we crash
            let _ = monolith_agent::tamper::setup_respawn(h);
            // Activate restore feature (non-fatal if it fails)
            let _ = monolith_agent::restore::activate_restore(h);
        }
    }
    let driver_arc = Arc::new(driver);
    let driver_handle = Arc::new(Mutex::new(driver_handle));

    // Shared event buffer
    let event_buffer: Arc<Mutex<VecDeque<v1::Event>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(10000)));

    // Local detection engine + alert manager
    let detection_engine = Arc::new(Mutex::new(
        monolith_agent::detection::LocalDetectionEngine::new(),
    ));
    let alert_manager = Arc::new(Mutex::new(
        monolith_agent::detection::alert::AlertManager::new(),
    ));

    // Pipeline resilience
    let upload_circuit = Arc::new(CircuitBreaker::new(5, 30));
    let policy_circuit = Arc::new(CircuitBreaker::new(3, 60));
    let action_circuit = Arc::new(CircuitBreaker::new(3, 30));
    let metrics = Arc::new(AgentMetrics::new());

    // No tamper protection needed — driver's OB callback strips PROCESS_TERMINATE
    // from handles opened against us, and process resurrection covers unexpected exits.

    let mut handles = Vec::new();

    // Worker 1: Driver reader
    {
        let driver = driver_arc.clone();
        let driver_handle = driver_handle.clone();
        let event_buffer = event_buffer.clone();
        let running = running.clone();
        let poll_ms = config.driver.poll_interval_ms;
        let metrics = metrics.clone();

        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(poll_ms));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let handle_guard = driver_handle.lock().await;
                let raw_data = match handle_guard.as_ref().map(|h| driver.read_telemetry(h)) {
                    Some(Ok(data)) => {
                        metrics.driver_disconnected.store(false, Ordering::Relaxed);
                        if data.is_empty() {
                            drop(handle_guard);
                            continue;
                        }
                        data
                    }
                    Some(Err(e)) => {
                        metrics.driver_disconnected.store(true, Ordering::Relaxed);
                        tracing::warn!("failed to read telemetry: {}", e);
                        drop(handle_guard);
                        continue;
                    }
                    None => {
                        metrics.driver_disconnected.store(true, Ordering::Relaxed);
                        drop(handle_guard);
                        continue;
                    }
                };
                drop(handle_guard);

                let events = monolith_agent::tlv_parser::parse_events(&raw_data);
                if !events.is_empty() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    metrics
                        .last_telemetry_event_time
                        .store(now, Ordering::Relaxed);
                    let count = events.len();
                    let mut buf = event_buffer.lock().await;
                    for event in events {
                        if buf.len() < 10000 {
                            buf.push_back(event);
                            metrics.events_created.fetch_add(1, Ordering::Relaxed);
                        } else {
                            metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!("event buffer full, dropping event");
                            break;
                        }
                    }
                    if count > 0 {
                        tracing::trace!("driver reader: pushed {} events", count);
                    }
                }
            }
        }));
    }

    // Worker 2: Event uploader with circuit breaker + retry
    {
        // Shared upload buffer to decouple detection from uploading
        let upload_buffer: Arc<Mutex<VecDeque<v1::Event>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(10000)));

        // Worker 2a: Detection poller (runs local detection on raw events and queues them for upload)
        {
            let event_buffer = event_buffer.clone();
            let upload_buffer = upload_buffer.clone();
            let running = running.clone();
            let detection_engine = detection_engine.clone();
            let alert_manager = alert_manager.clone();
            let metrics = metrics.clone();
            let config = config.clone();
            let driver = driver_arc.clone();
            let driver_handle = driver_handle.clone();

            handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_millis(500)
            );
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let batch = {
                    let mut buf = event_buffer.lock().await;
                    let count = buf.len().min(100);
                    buf.drain(..count).collect::<Vec<_>>()
                };

                if batch.is_empty() {
                    continue;
                }

                let mut alerts_to_queue = Vec::new();

                // Run local detection + alert escalation
                {
                    let mut engine = detection_engine.lock().await;
                    let mut alerts = alert_manager.lock().await;
                    for event in &batch {
                        match &event.payload {
                            Some(v1::event::Payload::ProcessCreate(pe)) => {
                                if let Some(proc_info) = &pe.process {
                                    let action = engine.check_process_event(proc_info.pid, proc_info.parent_pid, &proc_info.path, &proc_info.command_line)
                                        .or_else(|| engine.check_process_chain(proc_info.pid, proc_info.parent_pid, &proc_info.name, &pe.parent_name));
                                    if let Some(action) = action {
                                        metrics.detections.fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(
                                            target: "agent.detection", worker = "detection",
                                            action = %action.action_type, pid = proc_info.pid,
                                            severity = %action.severity,
                                            "detection triggered",
                                        );
                                        if let Some(alert) = alerts.evaluate(
                                            "suspicious_process",
                                            &action.severity,
                                            &proc_info.name,
                                            proc_info.pid,
                                            &format!("{} detected: {}", action.action_type, proc_info.name),
                                        ) {
                                            let alert_event = alerts.alert_to_event(&alert);
                                            alerts_to_queue.push(alert_event);
                                        }
                                        let handler = monolith_agent::response::ResponseHandler::new();
                                        let params = serde_json::json!({"pid": proc_info.pid});
                                        if handler.execute_action(&action.action_type, &params).await.is_ok() {
                                            metrics.actions_executed.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Some(v1::event::Payload::FileEvent(fe)) => {
                                if let Some(action) =
                                    engine.check_file_event(&fe.path, fe.pid)
                                {
                                    metrics.detections.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(
                                        target: "agent.detection", worker = "detection",
                                        action = %action.action_type, path = %fe.path,
                                        severity = %action.severity,
                                        "detection triggered",
                                    );
                                    if let Some(alert) = alerts.evaluate(
                                        "file_ioc",
                                        &action.severity,
                                        &fe.path,
                                        fe.pid,
                                        &format!("{} detected: {}", action.action_type, fe.path),
                                    ) {
                                        let alert_event = alerts.alert_to_event(&alert);
                                        alerts_to_queue.push(alert_event);
                                    }
                                    let handler = monolith_agent::response::ResponseHandler::new();
                                    let params = serde_json::json!({"path": fe.path});
                                    if handler.execute_action(&action.action_type, &params).await.is_ok() {
                                        metrics.actions_executed.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Some(v1::event::Payload::RegistryChange(re)) => {
                                let is_protected = re.key_path.contains("MonolithAgent")
                                    || re.key_path.contains("MonolithWatchdog")
                                    || re.key_path.contains("EDRDriver")
                                    || re.key_path.contains("SOFTWARE\\Monolith");

                                if is_protected && re.pid != std::process::id() {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    let ts = prost_types::Timestamp {
                                        seconds: now as i64,
                                        nanos: 0,
                                    };
                                    let alert_event = v1::Event {
                                        id: Some(v1::Uuid {
                                            value: uuid::Uuid::new_v4().as_bytes().to_vec(),
                                        }),
                                        endpoint_id: None,
                                        event_type: v1::EventType::RegistryTamper.into(),
                                        timestamp: Some(ts.clone()),
                                        collected_at: Some(ts),
                                        sequence_number: 0,
                                        payload: None,
                                        metadata: vec![
                                            v1::MetadataEntry { key: "source".to_string(), value: "local_detection".to_string() },
                                            v1::MetadataEntry { key: "alert.rule_id".to_string(), value: "registry_tamper".to_string() },
                                            v1::MetadataEntry { key: "alert.severity".to_string(), value: "critical".to_string() },
                                            v1::MetadataEntry { key: "alert.match_value".to_string(), value: re.key_path.clone() },
                                            v1::MetadataEntry { key: "alert.pid".to_string(), value: re.pid.to_string() },
                                            v1::MetadataEntry { key: "alert.description".to_string(), value: format!("Registry write to protected key blocked: {}", re.key_path) },
                                            v1::MetadataEntry { key: "registry.key_path".to_string(), value: re.key_path.clone() },
                                            v1::MetadataEntry { key: "registry.operation".to_string(), value: "blocked_write".to_string() },
                                            v1::MetadataEntry { key: "registry.offending_pid".to_string(), value: re.pid.to_string() },
                                            v1::MetadataEntry { key: "registry.offending_process".to_string(), value: re.process_name.clone() },
                                            v1::MetadataEntry { key: "registry.old_value".to_string(), value: re.old_value.clone() },
                                            v1::MetadataEntry { key: "registry.new_value".to_string(), value: re.new_value.clone() },
                                            v1::MetadataEntry { key: "registry.blocked".to_string(), value: "1".to_string() },
                                        ],
                                    };
                                    alerts_to_queue.push(alert_event);
                                } else if let Some(action) = engine.check_registry_event(&re.key_path, re.pid) {
                                    metrics.detections.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(
                                        target: "agent.detection", worker = "detection",
                                        action = %action.action_type, key = %re.key_path,
                                        severity = %action.severity,
                                        "detection triggered",
                                    );
                                    if let Some(alert) = alerts.evaluate(
                                        "registry_persistence",
                                        &action.severity,
                                        &re.key_path,
                                        re.pid,
                                        &format!("Registry persistence detected: {}", re.key_path),
                                    ) {
                                        let alert_event = alerts.alert_to_event(&alert);
                                        alerts_to_queue.push(alert_event);
                                    }
                                }
                            }
                            Some(v1::event::Payload::MemorySuspicious(ms)) => {
                                if let Some(s) = &ms.suspicious {
                                    metrics.detections.fetch_add(1, Ordering::Relaxed);
                                    let flags_desc = if s.suspicion_flags & 1 != 0 { "RWX" } else { "" };
                                    let desc = format!(
                                        "Memory suspicious in {} (PID {}): addr=0x{:x} size={} protect=0x{:x} type={} flags={}",
                                        s.process_name, s.process_id, s.base_address, s.region_size,
                                        s.protect, s.memory_type, s.suspicion_flags,
                                    );
                                    tracing::warn!(target: "agent.detection", "{}", desc);
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    let ts = prost_types::Timestamp { seconds: now as i64, nanos: 0 };
                                    let alert_event = v1::Event {
                                        id: Some(v1::Uuid { value: uuid::Uuid::new_v4().as_bytes().to_vec() }),
                                        endpoint_id: None,
                                        event_type: v1::EventType::MemorySuspicious.into(),
                                        timestamp: Some(ts.clone()),
                                        collected_at: Some(ts),
                                        sequence_number: 0,
                                        payload: None,
                                        metadata: vec![
                                            v1::MetadataEntry { key: "source".to_string(), value: "kernel_driver".to_string() },
                                            v1::MetadataEntry { key: "alert.rule_id".to_string(), value: "kernel_memory_suspicious".to_string() },
                                            v1::MetadataEntry { key: "alert.severity".to_string(), value: if s.suspicion_flags & 1 != 0 { "critical".to_string() } else { "high".to_string() } },
                                            v1::MetadataEntry { key: "alert.match_value".to_string(), value: s.process_name.clone() },
                                            v1::MetadataEntry { key: "alert.pid".to_string(), value: s.process_id.to_string() },
                                            v1::MetadataEntry { key: "alert.description".to_string(), value: desc },
                                            v1::MetadataEntry { key: "memory.process_id".to_string(), value: s.process_id.to_string() },
                                            v1::MetadataEntry { key: "memory.process_name".to_string(), value: s.process_name.clone() },
                                            v1::MetadataEntry { key: "memory.base_address".to_string(), value: format!("0x{:x}", s.base_address) },
                                            v1::MetadataEntry { key: "memory.region_size".to_string(), value: s.region_size.to_string() },
                                            v1::MetadataEntry { key: "memory.protect".to_string(), value: format!("0x{:x}", s.protect) },
                                            v1::MetadataEntry { key: "memory.type".to_string(), value: s.memory_type.to_string() },
                                            v1::MetadataEntry { key: "memory.suspicion_flags".to_string(), value: s.suspicion_flags.to_string() },
                                            v1::MetadataEntry { key: "memory.suspicion_rwx".to_string(), value: if s.suspicion_flags & 1 != 0 { "1".to_string() } else { "0".to_string() } },
                                            v1::MetadataEntry { key: "memory.suspicion_private_exec".to_string(), value: if s.suspicion_flags & 2 != 0 { "1".to_string() } else { "0".to_string() } },
                                            v1::MetadataEntry { key: "memory.suspicion_unbacked_exec".to_string(), value: if s.suspicion_flags & 4 != 0 { "1".to_string() } else { "0".to_string() } },
                                            v1::MetadataEntry { key: "memory.flags_desc".to_string(), value: flags_desc.to_string() },
                                        ],
                                    };
                                    alerts_to_queue.push(alert_event);
                                }
                            }
                            Some(v1::event::Payload::ModuleLoad(ml)) => {
                                let pid = ml.pid;
                                let config_clone = config.clone();
                                let upload_buffer_clone = upload_buffer.clone();
                                let driver = driver.clone();
                                let driver_handle = driver_handle.clone();
                                tokio::spawn(async move {
                                    // Kernel-mode memory scan via driver IOCTL
                                    // Results flow through ring buffer → Worker 1 → detection pipeline
                                    if let Some(ref h) = *driver_handle.lock().await {
                                        match driver.scan_process_memory(h, pid) {
                                            Ok(count) => {
                                                if count > 0 {
                                                    tracing::warn!(
                                                        target: "agent.detection", worker = "module_load",
                                                        pid = pid, suspicious = count,
                                                        "kernel memory scan found suspicious regions in process",
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::trace!("kernel memory scan failed: {}", e);
                                            }
                                        }
                                    }
                                    let results = monolith_agent::memory_scanner::scan_process(pid, &*config_clone).await;
                                    if !results.is_empty() {
                                        let mut upload = upload_buffer_clone.lock().await;
                                        for res in results {
                                            let msg = format!(
                                                "Memory threat detected in {} (PID {}): {} YARA rules triggered, verdict: {}",
                                                res.process_name, res.process_id, res.matched_rules.len(), res.verdict
                                            );
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            let ts = prost_types::Timestamp {
                                                seconds: now as i64,
                                                nanos: 0,
                                            };
                                            let alert_event = v1::Event {
                                                id: Some(v1::Uuid {
                                                    value: uuid::Uuid::new_v4().as_bytes().to_vec(),
                                                }),
                                                endpoint_id: None,
                                                event_type: v1::EventType::MemoryScan.into(),
                                                timestamp: Some(ts.clone()),
                                                collected_at: Some(ts),
                                                sequence_number: 0,
                                                payload: None,
                                                metadata: vec![
                                                    v1::MetadataEntry { key: "source".to_string(), value: "local_detection".to_string() },
                                                    v1::MetadataEntry { key: "alert.rule_id".to_string(), value: "memory_scan".to_string() },
                                                    v1::MetadataEntry { key: "alert.severity".to_string(), value: "high".to_string() },
                                                    v1::MetadataEntry { key: "alert.match_value".to_string(), value: res.process_name.clone() },
                                                    v1::MetadataEntry { key: "alert.pid".to_string(), value: res.process_id.to_string() },
                                                    v1::MetadataEntry { key: "alert.description".to_string(), value: msg.clone() },
                                                    v1::MetadataEntry { key: "memory.process_id".to_string(), value: res.process_id.to_string() },
                                                    v1::MetadataEntry { key: "memory.process_name".to_string(), value: res.process_name.clone() },
                                                    v1::MetadataEntry { key: "memory.region_base".to_string(), value: format!("0x{:x}", res.region_base) },
                                                    v1::MetadataEntry { key: "memory.matched_rules".to_string(), value: res.matched_rules.join(",") },
                                                    v1::MetadataEntry { key: "memory.yara_matches".to_string(), value: res.yara_matches.to_string() },
                                                    v1::MetadataEntry { key: "memory.contains_pe".to_string(), value: if res.contains_pe { "1".to_string() } else { "0".to_string() } },
                                                    v1::MetadataEntry { key: "memory.verdict".to_string(), value: res.verdict.clone() },
                                                ],
                                            };
                                            if upload.len() < 10000 {
                                                upload.push_back(alert_event);
                                            }
                                        }
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                }

                // Push processed events and generated alerts to upload queue
                {
                    let mut up_buf = upload_buffer.lock().await;
                    for ev in alerts_to_queue {
                        if up_buf.len() < 10000 {
                            up_buf.push_back(ev);
                        }
                    }
                    for ev in batch {
                        if up_buf.len() < 10000 {
                            up_buf.push_back(ev);
                        }
                    }
                }
            }
        }));
        }

        // Worker 2b: Uploader poller (drains upload queue and uploads via gRPC)
        {
            let grpc_client = grpc_client.clone();
            let upload_buffer = upload_buffer.clone();
            let running = running.clone();
            let upload_circuit = upload_circuit.clone();
            let conn = conn.clone();
            let metrics = metrics.clone();

            handles.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                let local_store = monolith_agent::db::LocalStore::new(conn);

                loop {
                    interval.tick().await;
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    if upload_circuit.is_available() {
                        if let Ok(pending) = local_store.get_pending_uploads(10).await {
                            for record in pending {
                                let id = record.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                                let payload = record.get("payload");
                                if let Some(payload_str) = payload.and_then(|v| v.as_str()) {
                                    if let Ok(parsed) =
                                        serde_json::from_str::<serde_json::Value>(payload_str)
                                    {
                                        if let Some(arr) = parsed.as_array() {
                                            let mut batch = Vec::new();
                                            for item in arr {
                                                if let Some(b64) = item.as_str() {
                                                    use base64::{
                                                        Engine as _,
                                                        engine::general_purpose::STANDARD as BASE64,
                                                    };
                                                    if let Ok(bytes) = BASE64.decode(b64) {
                                                        use prost::Message;
                                                        if let Ok(ev) =
                                                            v1::Event::decode(&bytes[..])
                                                        {
                                                            batch.push(ev);
                                                        }
                                                    }
                                                }
                                            }
                                            if !batch.is_empty() {
                                                let mut client = grpc_client.lock().await;
                                                match client.upload_events_proto(&batch).await {
                                                    Ok(accepted) => {
                                                        metrics.events_uploaded.fetch_add(
                                                            accepted as u64,
                                                            Ordering::Relaxed,
                                                        );
                                                        let _ = local_store
                                                            .remove_offline_entry(id)
                                                            .await;
                                                    }
                                                    Err(e) => {
                                                        upload_circuit.on_failure();
                                                        tracing::warn!(
                                                            "offline event upload failed: {}",
                                                            e
                                                        );
                                                        if let Err(re) = client.reconnect().await {
                                                            tracing::error!(
                                                                "reconnect failed: {}",
                                                                re
                                                            );
                                                        }
                                                        break; // Stop offline upload on error
                                                    }
                                                }
                                            } else {
                                                let _ = local_store.remove_offline_entry(id).await;
                                            }
                                        } else {
                                            let _ = local_store.remove_offline_entry(id).await;
                                        }
                                    } else {
                                        let _ = local_store.remove_offline_entry(id).await;
                                    }
                                } else {
                                    let _ = local_store.remove_offline_entry(id).await;
                                }
                            }
                        }
                    }

                    let batch = {
                        let mut buf = upload_buffer.lock().await;
                        let count = buf.len().min(100);
                        buf.drain(..count).collect::<Vec<_>>()
                    };

                    if batch.is_empty() {
                        continue;
                    }

                    // Upload via gRPC with circuit breaker
                    if !upload_circuit.is_available() {
                        tracing::debug!("upload circuit open, queueing {} events", batch.len());
                        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
                        use prost::Message;
                        let b64_events: Vec<String> = batch
                            .iter()
                            .map(|ev| {
                                let mut buf = Vec::new();
                                ev.encode(&mut buf).unwrap();
                                BASE64.encode(&buf)
                            })
                            .collect();
                        let payload = serde_json::json!(b64_events);
                        let _ = local_store
                            .store_offline_event("events_batch", &payload)
                            .await;
                        continue;
                    }

                    let mut client = grpc_client.lock().await;
                    let upload_result = client.upload_events_proto(&batch).await;

                    match upload_result {
                        Ok(accepted) => {
                            metrics
                                .events_uploaded
                                .fetch_add(accepted as u64, Ordering::Relaxed);
                            upload_circuit.on_success();
                        }
                        Err(e) => {
                            metrics
                                .events_upload_failed
                                .fetch_add(batch.len() as u64, Ordering::Relaxed);
                            upload_circuit.on_failure();
                            tracing::warn!("event upload failed ({} events): {}", batch.len(), e);
                            if let Err(re) = client.reconnect().await {
                                tracing::error!("reconnect failed: {}", re);
                            }
                            use base64::{
                                Engine as _, engine::general_purpose::STANDARD as BASE64,
                            };
                            use prost::Message;
                            let b64_events: Vec<String> = batch
                                .iter()
                                .map(|ev| {
                                    let mut buf = Vec::new();
                                    ev.encode(&mut buf).unwrap();
                                    BASE64.encode(&buf)
                                })
                                .collect();
                            let payload = serde_json::json!(b64_events);
                            let _ = local_store
                                .store_offline_event("events_batch", &payload)
                                .await;
                        }
                    }
                }
            }));
        }
    }

    // Worker 3: Heartbeat sender
    {
        let grpc_client = grpc_client.clone();
        let driver = driver_arc.clone();
        let driver_handle = driver_handle.clone();
        let running = running.clone();
        let interval_secs = config.heartbeat.interval_secs;
        let metrics = metrics.clone();

        handles.push(tokio::spawn(async move {
            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let stats_raw = {
                    let handle_guard = driver_handle.lock().await;
                    handle_guard
                        .as_ref()
                        .and_then(|h| driver.get_driver_stats(h).ok())
                };

                let last_event = metrics.last_telemetry_event_time.load(Ordering::Relaxed);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let is_disconnected = metrics.driver_disconnected.load(Ordering::Relaxed);

                // Telemetry blackout if disconnected or if no events received for > 5 minutes
                let is_blackout = is_disconnected || (now > last_event && now - last_event > 300);

                let mut heartbeat =
                    monolith_agent::sync::heartbeat::collect_system_status(stats_raw.as_deref());

                if let Some(obj) = heartbeat.as_object_mut() {
                    if is_blackout {
                        obj.insert("driver_loaded".to_string(), serde_json::Value::Bool(false));
                        obj.insert(
                            "telemetry_state".to_string(),
                            serde_json::Value::String("blackout".to_string()),
                        );
                    } else {
                        obj.insert(
                            "telemetry_state".to_string(),
                            serde_json::Value::String("healthy".to_string()),
                        );
                    }
                }

                let mut client = grpc_client.lock().await;
                if let Err(e) = client.send_heartbeat(&heartbeat).await {
                    tracing::warn!("heartbeat failed: {}", e);
                    if let Err(re) = client.reconnect().await {
                        tracing::error!("reconnect failed: {}", re);
                    }
                } else {
                    let program_data = std::env::var("PROGRAMDATA")
                        .unwrap_or_else(|_| "C:\\ProgramData".to_string());
                    let hb_path = format!("{}\\EDR\\.heartbeat", program_data);
                    if let Err(e) = std::fs::write(&hb_path, chrono::Utc::now().to_rfc3339()) {
                        tracing::warn!("failed to write local heartbeat file: {}", e);
                    }
                }

                // Random jitter: 5-15% of the interval
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(12345);
                let min_jitter = interval_secs * 5 / 100;
                let max_jitter = interval_secs * 15 / 100;
                let jitter = if max_jitter > min_jitter {
                    min_jitter + (nanos as u64 % (max_jitter - min_jitter))
                } else {
                    min_jitter
                };
                let sleep_secs = interval_secs + jitter;
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }
        }));
    }

    // Worker 4: Policy sync + IOC loader with circuit breaker
    {
        let grpc_client = grpc_client.clone();
        let running = running.clone();
        let interval_secs = config.polling.policy_interval_secs;
        let detection_engine = detection_engine.clone();
        let policy_circuit = policy_circuit.clone();

        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                if !policy_circuit.is_available() {
                    tracing::debug!("policy sync circuit open, skipping");
                    continue;
                }

                let mut client = grpc_client.lock().await;
                match client.sync_policy().await {
                    Ok(policy) => {
                        policy_circuit.on_success();
                        tracing::debug!(
                            "policy synced: id={}, version={} ({} bytes)",
                            policy.policy_id,
                            policy.policy_version,
                            policy.policy_content.len(),
                        );
                        let mut engine = detection_engine.lock().await;
                        engine.load_iocs(&policy.policy_content);
                    }
                    Err(e) => {
                        policy_circuit.on_failure();
                        tracing::warn!("policy sync failed: {}", e);
                    }
                }
            }
        }));
    }

    // Worker 5: System info collector (low-frequency, every 5 min)
    {
        let event_buffer = event_buffer.clone();
        let running = running.clone();
        let metrics = metrics.clone();

        handles.push(tokio::spawn(async move {
            let collector = monolith_agent::collector::SystemInfoCollector::new();
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let raw_events = collector.collect();
                if !raw_events.is_empty() {
                    let mut buf = event_buffer.lock().await;
                    for ev in raw_events {
                        if buf.len() >= 10000 {
                            break;
                        }
                        let json_str = serde_json::to_string(&ev).unwrap_or_default();
                        let pb_event = v1::Event {
                            id: Some(v1::Uuid {
                                value: uuid::Uuid::new_v4().as_bytes().to_vec(),
                            }),
                            endpoint_id: None,
                            event_type: v1::EventType::Unspecified.into(),
                            timestamp: Some(prost_types::Timestamp::default()),
                            collected_at: None,
                            sequence_number: 0,
                            payload: None,
                            metadata: vec![v1::MetadataEntry {
                                key: "raw_json".into(),
                                value: json_str,
                            }],
                        };
                        buf.push_back(pb_event);
                        metrics.events_created.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Worker 6: Health monitor
    {
        let running = running.clone();
        let driver_handle = driver_handle.clone();

        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let driver_ok = driver_handle.lock().await.is_some();
                tracing::debug!("health check: driver_loaded={}", driver_ok);
            }
        }));
    }

    // Worker 7: Response action listener with circuit breaker
    {
        let grpc_client = grpc_client.clone();
        let running = running.clone();
        let action_circuit = action_circuit.clone();
        let metrics = metrics.clone();

        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                if !action_circuit.is_available() {
                    tracing::trace!("action listener circuit open, skipping");
                    continue;
                }

                let mut client = grpc_client.lock().await;
                let actions = match client.get_pending_actions().await {
                    Ok(a) => {
                        action_circuit.on_success();
                        a
                    }
                    Err(e) => {
                        action_circuit.on_failure();
                        tracing::trace!("get_actions error: {}", e);
                        continue;
                    }
                };

                for action in actions {
                    let action_type_str = match action.r#type {
                        1 => "terminate_process",
                        2 => "quarantine_file",
                        3 => "restore_quarantine",
                        4 => "delete_quarantine",
                        5 => "isolate_endpoint",
                        6 => "release_isolation",
                        7 => "restart_agent",
                        8 => "trigger_quick_scan",
                        9 => "trigger_full_scan",
                        10 => "collect_diagnostics",
                        11 => "update_policy",
                        12 => "scan_process_memory",
                        13 => "shred_file",
                        _ => "unknown",
                    };
                    tracing::info!(
                        "executing action: id={} type={}",
                        action.id,
                        action_type_str
                    );
                    let params: serde_json::Value =
                        serde_json::from_slice(&action.parameters).unwrap_or_default();
                    let handler = monolith_agent::response::ResponseHandler::new();
                    match handler.execute_action(action_type_str, &params).await {
                        Ok(result) => {
                            metrics.actions_executed.fetch_add(1, Ordering::Relaxed);
                            let status = if result.success {
                                "completed"
                            } else {
                                "failed"
                            };
                            let _ = client.report_action_status(&action.id, status).await;
                        }
                        Err(e) => {
                            tracing::error!("action {} failed: {}", action.id, e);
                            let _ = client.report_action_status(&action.id, "failed").await;
                        }
                    }
                }
            }
        }));
    }

    // Worker 8: Scanner event listener
    {
        let buffer = event_buffer.clone();
        let listen = format!("127.0.0.1:{}", config.scanner.event_listener_port);
        handles.push(tokio::spawn(async move {
            monolith_agent::scanner_events::start(buffer, &listen).await;
        }));
    }

    // Worker 9: ETW manager
    {
        let buffer = event_buffer.clone();
        let scan_url = config.scanner.api_url.clone();
        handles.push(tokio::spawn(async move {
            let manager = monolith_agent::etw_manager::EtwManager::new(buffer, scan_url);
            manager.start().await;
            std::future::pending::<()>().await;
        }));
    }

    // Shared profile parameters
    let profile_params = Arc::new(tokio::sync::RwLock::new(
        monolith_agent::profile::TunableParameters::default(),
    ));

    // Worker 10: System state monitor
    {
        let profile_params = profile_params.clone();
        let running = running.clone();

        handles.push(tokio::spawn(async move {
            let mut monitor = monolith_agent::system_state::SystemStateMonitor::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let pc_profile = monitor.poll();
                {
                    let mut params = profile_params.write().await;
                    params.last_pc_profile = Some(pc_profile as i32);
                }
                tracing::trace!(
                    target: "agent.profile", worker = "system_state",
                    pc_profile = ?pc_profile,
                    "system state polled",
                );
            }
        }));
    }

    // Worker 11: Profile engine
    {
        let profile_params = profile_params.clone();
        let running = running.clone();
        let edr_profile_str = config.performance.edr_profile.clone();

        handles.push(tokio::spawn(async move {
            let edr_profile = match edr_profile_str.as_str() {
                "max_protection" | "max" => v1::EdrProfile::MaxProtection,
                "balanced" => v1::EdrProfile::Balanced,
                "minimal_impact" | "minimal" => v1::EdrProfile::MinimalImpact,
                "stealth" => v1::EdrProfile::Stealth,
                _ => v1::EdrProfile::Balanced,
            };

            let mut engine = monolith_agent::profile::ProfileEngine::new(edr_profile);
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let pc_profile = {
                    let params = profile_params.read().await;
                    params
                        .last_pc_profile
                        .and_then(|v| v1::PcProfile::try_from(v).ok())
                        .unwrap_or(v1::PcProfile::Unspecified)
                };

                let changed = engine.update(pc_profile, None);
                if changed {
                    let p = engine.parameters();
                    tracing::info!(
                        target: "agent.profile", worker = "profile_engine",
                        pc_profile = ?engine.pc_profile(),
                        edr_profile = ?engine.edr_profile(),
                        poll_ms = p.driver_poll_interval_ms,
                        batch = p.event_batch_size,
                        upload_ms = p.upload_interval_ms,
                        hb_secs = p.heartbeat_interval_secs,
                        sensitivity = p.detection_sensitivity,
                        "profile parameters updated",
                    );
                }

                // Update shared params
                {
                    let mut params = profile_params.write().await;
                    params.driver_poll_interval_ms = engine.parameters().driver_poll_interval_ms;
                    params.event_batch_size = engine.parameters().event_batch_size;
                    params.upload_interval_ms = engine.parameters().upload_interval_ms;
                    params.heartbeat_interval_secs = engine.parameters().heartbeat_interval_secs;
                    params.detection_sensitivity = engine.parameters().detection_sensitivity;
                    params.current_pc_profile = Some(engine.pc_profile() as i32);
                    params.current_edr_profile = Some(engine.edr_profile() as i32);
                }
            }
        }));
    }

    // Worker 11: Metrics logger (every 5 minutes)
    {
        let running = running.clone();
        let metrics = metrics.clone();

        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let snap = metrics.snapshot();
                tracing::info!(
                    target: "agent.metrics", worker = "metrics_logger",
                    created = snap.events_created,
                    uploaded = snap.events_uploaded,
                    upload_failed = snap.events_upload_failed,
                    dropped = snap.events_dropped,
                    detections = snap.detections,
                    actions = snap.actions_executed,
                    drop_rate = snap.drop_rate(),
                    upload_success_rate = snap.upload_success_rate(),
                    "metrics snapshot",
                );
            }
        }));
    }

    // Wait for any worker to exit
    tokio::select! {
        result = futures::future::select_all(handles) => {
            let (res, _idx, _remaining) = result;
            if let Err(e) = res {
                tracing::error!(target: "agent", "worker exited with error: {}", e);
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    tracing::info!(target: "agent", "agent shutting down");
    Ok(())
}

fn set_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing::error!(
            target: "panic",
            "agent panicked: {} at {:?}",
            panic_info.to_string(),
            std::time::SystemTime::now(),
        );
        prev(panic_info);
    }));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "service")]
    {
        windows_service::service_dispatcher::start("MonolithAgent", ffi_service_main)?;
    }

    #[cfg(not(feature = "service"))]
    {
        AgentService::run()?;
    }

    Ok(())
}

#[cfg(feature = "service")]
fn ffi_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = AgentService::run() {
        tracing::error!(target: "agent", "service failed: {}", e);
    }
}
