use std::collections::VecDeque;
use std::sync::Arc;
use axum::{Json, extract::State, http::StatusCode, routing::post, Router};
use chrono::Utc;
use prost_types::Timestamp;
use serde::Deserialize;
use tokio::sync::Mutex;

use monolith_protobuf::proto::v1::{self, FileHashes, ScannerResultEvent};

#[derive(Debug, Deserialize)]
pub struct ScanResultEvent {
    pub file_path: String,
    pub verdict: String,
    pub score: f64,
    pub matched_rules: Vec<String>,
    pub sha256: Option<String>,
    pub quarantined: Option<bool>,
}

struct AppState {
    buffer: Arc<Mutex<VecDeque<v1::Event>>>,
}

pub async fn start(
    buffer: Arc<Mutex<VecDeque<v1::Event>>>,
    listen_addr: &str,
) {
    let state = Arc::new(AppState { buffer });

    let app = Router::new()
        .route("/api/v1/scanner-result", post(handle_scanner_result))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await;
    match listener {
        Ok(l) => {
            tracing::info!("scanner event listener started on {}", listen_addr);
            if let Err(e) = axum::serve(l, app).await {
                tracing::error!("scanner event listener failed: {}", e);
            }
        }
        Err(e) => {
            tracing::error!("failed to bind scanner event listener on {}: {}", listen_addr, e);
        }
    }
}

async fn handle_scanner_result(
    State(state): State<Arc<AppState>>,
    Json(event): Json<ScanResultEvent>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let proto_event = v1::Event {
        id: Some(v1::Uuid {
            value: uuid::Uuid::new_v4().as_bytes().to_vec(),
        }),
        endpoint_id: Some(v1::Uuid {
            value: uuid::Uuid::new_v4().as_bytes().to_vec(),
        }),
        event_type: v1::EventType::ScannerResult as i32,
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(v1::event::Payload::ScannerResult(ScannerResultEvent {
            file_path: event.file_path.clone(),
            hashes: event.sha256.map(|s| FileHashes {
                sha256: s,
                ..Default::default()
            }),
            malicious: event.verdict == "malicious" || event.verdict == "suspicious",
            score: event.score,
            matched_rules: event.matched_rules,
            quarantined: event.quarantined.unwrap_or(false),
            scanner_message: event.verdict,
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".into(),
            value: "scanner".into(),
        }],
    };

    let mut buf = state.buffer.lock().await;
    if buf.len() < 10000 {
        buf.push_back(proto_event);
    } else {
        tracing::warn!("event buffer full, dropping scanner result");
    }

    Ok(Json(serde_json::json!({"received": true})))
}
