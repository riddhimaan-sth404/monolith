use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{info, warn};
use walkdir::WalkDir;
use yara_x::{Compiler, Rules, Scanner};

#[derive(Parser)]
#[command(name = "matcher", about = "YARA rule matcher sidecar")]
struct Args {
    #[arg(short, long, default_value = "scanner/yara/rules/malware_db.yar")]
    rules: PathBuf,

    #[arg(short, long, default_value = "127.0.0.1:50074")]
    listen: String,
}

#[derive(Clone)]
struct AppState {
    rules: Arc<Rules>,
}

#[derive(Deserialize)]
struct MatchRequest {
    path: String,
    data: Option<String>,
}

#[derive(Serialize)]
struct MatchResponse {
    matches: Vec<RuleMatch>,
    error: Option<String>,
}

#[derive(Serialize)]
struct RuleMatch {
    rule_name: String,
    metadata: Vec<MetaEntry>,
}

#[derive(Serialize)]
struct MetaEntry {
    identifier: String,
    value: String,
}

fn load_rules(path: &Path) -> Result<Rules> {
    let mut compiler = Compiler::new();

    let mut files_found = 0u32;
    let mut files_loaded = 0u32;

    let source_paths: Vec<PathBuf> = if path.is_dir() {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![path.to_path_buf()]
    };

    for file_path in &source_paths {
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yar" && ext != "yara" {
            continue;
        }

        files_found += 1;
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("failed to read rule file: {}: {}", file_path.display(), e);
                continue;
            }
        };

        match compiler.add_source(content.as_str()) {
            Ok(_) => {
                files_loaded += 1;
            }
            Err(e) => {
                warn!("failed to compile rule file: {}: {}", file_path.display(), e);
            }
        }
    }

    info!(
        "YARA rules loaded: {files_loaded}/{files_found} files compiled successfully",
    );

    let rules = compiler.build();
    let mut count = 0;
    for _ in rules.iter() {
        count += 1;
    }
    info!("YARA rules compiled: {count} rules total");

    Ok(rules)
}

fn is_path_safe(path: &Path) -> bool {
    let abs_path = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };
    
    let path_str = abs_path.to_string_lossy().to_lowercase();
    
    // Block reading sensitive configurations, certs, databases, or signatures
    if path_str.contains("certs")
        || path_str.contains("configs")
        || path_str.contains("data")
        || path_str.ends_with(".db")
        || path_str.ends_with(".db-wal")
        || path_str.ends_with(".db-shm")
        || path_str.ends_with(".sig")
        || path_str.ends_with(".toml")
    {
        return false;
    }
    
    true
}

async fn handle_match(
    State(state): State<AppState>,
    Json(req): Json<MatchRequest>,
) -> (StatusCode, Json<MatchResponse>) {
    let data = if let Some(encoded) = &req.data {
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(MatchResponse {
                        matches: vec![],
                        error: Some(format!("invalid base64 data: {e}")),
                    }),
                );
            }
        }
    } else {
        let path = Path::new(&req.path);
        if !path.exists() {
            return (
                StatusCode::NOT_FOUND,
                Json(MatchResponse {
                    matches: vec![],
                    error: Some(format!("path not found: {}", req.path)),
                }),
            );
        }
        if !is_path_safe(path) {
            return (
                StatusCode::FORBIDDEN,
                Json(MatchResponse {
                    matches: vec![],
                    error: Some(format!("access to path is restricted: {}", req.path)),
                }),
            );
        }
        match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(MatchResponse {
                        matches: vec![],
                        error: Some(format!("failed to read file: {e}")),
                    }),
                );
            }
        }
    };

    let mut scanner = Scanner::new(&state.rules);
    let results = match scanner.scan(&data) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MatchResponse {
                    matches: vec![],
                    error: Some(format!("scan failed: {e}")),
                }),
            );
        }
    };
    let mut matches: Vec<RuleMatch> = vec![];

    for rule_match in results.matching_rules() {
        let metadata: Vec<MetaEntry> = rule_match
            .metadata()
            .map(|(key, val)| MetaEntry {
                identifier: key.to_string(),
                value: format!("{val:?}"),
            })
            .collect();

        matches.push(RuleMatch {
            rule_name: rule_match.identifier().to_string(),
            metadata,
        });
    }

    (StatusCode::OK, Json(MatchResponse { matches, error: None }))
}

async fn handle_health() -> StatusCode {
    StatusCode::OK
}

fn main() -> Result<()> {
    // Increase stack size to 8MB to handle deeply nested YARA rules (thor-webshells etc.)
    let builder = std::thread::Builder::new()
        .name("matcher-main".into())
        .stack_size(8 * 1024 * 1024);
    let handle = builder.spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        rt.block_on(async_main())
    })?;
    handle.join().expect("matcher thread panicked")?;
    Ok(())
}

async fn async_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let args = Args::parse();

    let rules_path = if args.rules.is_relative() {
        let cwd = std::env::current_dir().context("failed to get CWD")?;
        cwd.join(&args.rules)
    } else {
        args.rules.clone()
    };

    info!("loading YARA rules from: {}", rules_path.display());
    let rules = load_rules(&rules_path)?;

    let state = AppState {
        rules: Arc::new(rules),
    };

    let app = Router::new()
        .route("/match", post(handle_match))
        .route("/health", get(handle_health))
        .with_state(state);

    let listener = TcpListener::bind(&args.listen)
        .await
        .context("failed to bind listener")?;

    info!("YARA matcher listening on {}", args.listen);
    axum::serve(listener, app)
        .await
        .context("server error")?;

    Ok(())
}
