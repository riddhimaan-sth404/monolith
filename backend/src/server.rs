use rustls::{
    ServerConfig as TlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{Item, certs};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::Arc as StdArc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::info;

use crate::config::AppConfig;
use crate::engine::detection::DetectionEngine;
use crate::engine::response_rules;
use crate::router::build_router;
use crate::services::detection_service::DetectionService;
use crate::services::service_registry::ServiceRegistry;
use monolith_shared::db::DatabaseConnection;
use std::sync::atomic::AtomicI64;

pub struct AppMetrics {
    pub events_ingested: AtomicI64,
    pub alerts_generated: AtomicI64,
    pub requests_total: AtomicI64,
    pub errors_total: AtomicI64,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            events_ingested: AtomicI64::new(0),
            alerts_generated: AtomicI64::new(0),
            requests_total: AtomicI64::new(0),
            errors_total: AtomicI64::new(0),
        }
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub db: Box<dyn DatabaseConnection>,
    pub services: ServiceRegistry,
    pub shutdown_flag: StdArc<AtomicBool>,
    pub detection_engine: DetectionEngine,
    pub detection_service: OnceLock<Arc<DetectionService>>,
    pub event_bus: tokio::sync::broadcast::Sender<serde_json::Value>,
    pub metrics: AppMetrics,
    pub toast_script_path: Option<Arc<str>>,
}

impl AppState {
    pub fn new(config: AppConfig, db: Box<dyn DatabaseConnection>) -> Self {
        let services = ServiceRegistry::new(&config);
        let (event_bus, _) = tokio::sync::broadcast::channel(10000);
        let toast_script_path = if config.notifications.enabled {
            Some(Arc::from(config.notifications.toast_script_path.as_str()))
        } else {
            None
        };
        Self {
            config,
            db,
            services,
            shutdown_flag: StdArc::new(AtomicBool::new(false)),
            detection_engine: DetectionEngine::new(),
            detection_service: OnceLock::new(),
            event_bus,
            metrics: AppMetrics::new(),
            toast_script_path,
        }
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_flag.load(Ordering::Relaxed)
    }

    pub fn signal_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
    }
}

pub type SharedAppState = Arc<AppState>;

pub struct Server {
    config: AppConfig,
    state: SharedAppState,
}

impl Server {
    pub fn new(config: AppConfig, state: SharedAppState) -> Self {
        Self { config, state }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let app = build_router(self.state.clone());

        // Load TLS configuration
        let tls_config = self.load_tls_config()?;

        let addr = format!("{}:{}", self.config.server.host, self.config.server.port);
        info!("listening on {}", addr);

        let listener = TcpListener::bind(&addr).await?;
        let acceptor = TlsAcceptor::from(StdArc::new(tls_config));

        // Start gRPC server
        let grpc_state = self.state.clone();
        let grpc_config = self.config.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::grpc::start_grpc_server(grpc_config, grpc_state).await {
                tracing::error!("gRPC server error: {}", e);
            }
        });

        // Serve with TLS using hyper's http1 builder with axum service
        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("TLS accept error from {}: {}", peer_addr, e);
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut app = app.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let bytes = http_body_util::BodyExt::collect(body)
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            let body = axum::body::Body::from(bytes);
                            let req = hyper::Request::from_parts(parts, body);
                            app.call(req).await
                        }
                    },
                );
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::error!("connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }

    fn load_tls_config(&self) -> anyhow::Result<TlsServerConfig> {
        let cert_file = &mut BufReader::new(File::open(&self.config.tls.cert_path)?);
        let key_file = &mut BufReader::new(File::open(&self.config.tls.key_path)?);

        let cert_chain: Vec<CertificateDer> = certs(cert_file).collect::<Result<Vec<_>, _>>()?;

        let mut keys: Vec<PrivateKeyDer<'static>> = Vec::new();
        loop {
            match rustls_pemfile::read_one(key_file)? {
                Some(Item::Pkcs8Key(k)) => keys.push(k.into()),
                Some(Item::Pkcs1Key(k)) => keys.push(k.into()),
                Some(Item::Sec1Key(k)) => keys.push(k.into()),
                Some(_) => continue,
                None => break,
            }
        }

        if keys.is_empty() {
            anyhow::bail!("no private keys found in {}", self.config.tls.key_path);
        }

        let config = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys.remove(0))?;

        Ok(config)
    }
}

pub fn initialize_detection_service(
    state: &SharedAppState,
    config: &AppConfig,
) -> Arc<DetectionService> {
    let rules = load_response_rules(config);

    let toast_script_path = if config.notifications.enabled {
        Some(Arc::from(config.notifications.toast_script_path.as_str()))
    } else {
        None
    };

    let service = Arc::new(DetectionService::new(rules, toast_script_path));

    // Store reference in AppState (OnceLock allows single write)
    if state.detection_service.set(service.clone()).is_err() {
        tracing::warn!("detection service already initialized");
    }

    tracing::info!(
        "detection service initialized with {} response rules",
        service.rule_count()
    );

    service
}

fn load_response_rules(config: &AppConfig) -> Vec<response_rules::ResponseRule> {
    if !config.response_rules.enabled {
        return response_rules::default_rules();
    }

    let path = &config.response_rules.path;
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let parsed: toml::Value = match toml::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("failed to parse response rules config: {}", e);
                    return response_rules::default_rules();
                }
            };
            let rules_list = parsed
                .get("rules")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| {
                            let id = v.get("id").and_then(|s| s.as_str())?.to_string();
                            let name = v.get("name").and_then(|s| s.as_str())?.to_string();
                            let cooldown_secs =
                                v.get("cooldown_secs")
                                    .and_then(|s| s.as_integer())
                                    .unwrap_or(60) as u64;
                            let enabled =
                                v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true);

                            let action_str = v.get("action").and_then(|s| s.as_str())?;
                            let action = match action_str {
                                "isolate_endpoint" => response_rules::RuleAction::IsolateEndpoint,
                                "quarantine_file" => response_rules::RuleAction::QuarantineFile,
                                "terminate_process" => response_rules::RuleAction::TerminateProcess,
                                "run_sandbox" => response_rules::RuleAction::RunSandbox,
                                "kill_and_quarantine" => {
                                    response_rules::RuleAction::KillAndQuarantine
                                }
                                _ => response_rules::RuleAction::AlertOnly,
                            };

                            let condition_val = v.get("condition")?;
                            let condition = parse_condition(condition_val)?;

                            Some(response_rules::ResponseRule {
                                id,
                                name,
                                condition,
                                action,
                                cooldown_secs,
                                enabled,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if rules_list.is_empty() {
                tracing::warn!("no valid rules found in {}, using defaults", path);
                response_rules::default_rules()
            } else {
                tracing::info!("loaded {} response rules from {}", rules_list.len(), path);
                rules_list
            }
        }
        Err(e) => {
            tracing::warn!(
                "failed to read response rules config ({}), using defaults: {}",
                path,
                e
            );
            response_rules::default_rules()
        }
    }
}

fn parse_condition(v: &toml::Value) -> Option<response_rules::RuleCondition> {
    let type_str = v.get("type")?.as_str()?;
    match type_str {
        "min_severity" => {
            let value = v.get("value")?.as_integer()? as u32;
            Some(response_rules::RuleCondition::MinSeverity { value })
        }
        "source" => {
            let sources = v
                .get("sources")?
                .as_array()?
                .iter()
                .filter_map(|s| s.as_str()?.parse::<response_rules::DetectionSource>().ok())
                .collect();
            Some(response_rules::RuleCondition::Source { sources })
        }
        "correlation" => {
            let correlation_types = v
                .get("correlation_types")?
                .as_array()?
                .iter()
                .filter_map(|s| s.as_str()?.parse::<response_rules::CorrelationType>().ok())
                .collect();
            Some(response_rules::RuleCondition::Correlation { correlation_types })
        }
        "min_score" => {
            let value = v.get("value")?.as_float()?;
            Some(response_rules::RuleCondition::MinScore { value })
        }
        "max_score" => {
            let value = v.get("value")?.as_float()?;
            Some(response_rules::RuleCondition::MaxScore { value })
        }
        "composite" => {
            let op = v.get("op")?.as_str()?.to_string();
            let conditions = v
                .get("conditions")?
                .as_array()?
                .iter()
                .filter_map(|c| parse_condition(c))
                .collect();
            Some(response_rules::RuleCondition::Composite { op, conditions })
        }
        _ => None,
    }
}
