use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::config::AppConfig;

pub struct ServiceRegistry {
    pub auth_service: Arc<super::auth_service::AuthService>,
    pub endpoint_service: Arc<super::endpoint_service::EndpointService>,
    pub event_service: Arc<super::event_service::EventService>,
    pub alert_service: Arc<super::alert_service::AlertService>,
    pub ioc_service: Arc<super::ioc_service::IocService>,
    pub policy_service: Arc<super::policy_service::PolicyService>,
    pub scan_service: Arc<super::scan_service::ScanService>,
    pub rule_service: Arc<super::rule_service::RuleService>,
    pub report_service: Arc<super::report_service::ReportService>,
    pub allowlist_service: Arc<super::allowlist_service::AllowlistService>,
    pub detection_service: Option<Arc<super::detection_service::DetectionService>>,
    rate_limit_buckets: Arc<Mutex<HashMap<String, super::super::middleware::rate_limit::TokenBucket>>>,
}

impl ServiceRegistry {
    pub fn new(_config: &AppConfig) -> Self {
        Self {
            auth_service: Arc::new(super::auth_service::AuthService::new()),
            endpoint_service: Arc::new(super::endpoint_service::EndpointService::new()),
            event_service: Arc::new(super::event_service::EventService::new()),
            alert_service: Arc::new(super::alert_service::AlertService::new()),
            ioc_service: Arc::new(super::ioc_service::IocService::new()),
            policy_service: Arc::new(super::policy_service::PolicyService::new()),
            scan_service: Arc::new(super::scan_service::ScanService::new()),
            rule_service: Arc::new(super::rule_service::RuleService::new()),
            report_service: Arc::new(super::report_service::ReportService::new()),
            allowlist_service: Arc::new(super::allowlist_service::AllowlistService::new()),
            detection_service: None,
            rate_limit_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_rate_limiter(&self) -> Arc<Mutex<HashMap<String, super::super::middleware::rate_limit::TokenBucket>>> {
        self.rate_limit_buckets.clone()
    }

    pub async fn shutdown(&self) {
        tracing::info!("shutting down all services...");
    }
}
