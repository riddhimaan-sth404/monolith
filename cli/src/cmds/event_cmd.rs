use crate::client::MonolithClient;
use crate::output::{self, OutputFormat};
use clap::Args;
use colored::Colorize;
use futures_util::StreamExt;

#[derive(Args)]
pub struct EventArgs {
    #[command(subcommand)]
    pub command: EventCommand,
}

#[derive(clap::Subcommand)]
pub enum EventCommand {
    List(ListArgs),
    Get(GetArgs),
    Follow(FollowArgs),
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub event_type: Option<String>,
    #[arg(long, default_value = "100")]
    pub limit: usize,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct GetArgs {
    pub id: String,
}

#[derive(Args)]
pub struct FollowArgs {
    #[arg(short, long)]
    pub event_type: Option<String>,
}

pub async fn execute(
    client: &MonolithClient,
    cmd: &EventCommand,
    global_output: &str,
) -> anyhow::Result<()> {
    match cmd {
        EventCommand::List(args) => list(client, args, global_output).await,
        EventCommand::Get(args) => get(client, args).await,
        EventCommand::Follow(args) => follow(client, args).await,
    }
}

async fn list(client: &MonolithClient, args: &ListArgs, global_output: &str) -> anyhow::Result<()> {
    let fmt = OutputFormat::from(args.output.as_deref().unwrap_or(global_output));
    let mut path = "/api/v1/events".to_string();
    let mut params = vec![format!("limit={}", args.limit)];
    if let Some(ref t) = args.event_type {
        params.push(format!("event_type={}", t));
    }
    if let Some(ref s) = args.since {
        params.push(format!("since={}", s));
    }
    if let Some(ref u) = args.until {
        params.push(format!("until={}", u));
    }
    path.push('?');
    path.push_str(&params.join("&"));

    let v = client.get_raw(&path).await?;
    let items = v.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let summary = summarize_event(item);
            vec![
                item["id"].as_str().unwrap_or("").to_string(),
                item["event_type"].as_str().unwrap_or("").to_string(),
                item["timestamp"].as_str().unwrap_or("").to_string(),
                summary,
            ]
        })
        .collect();

    output::print_table(&["ID", "Type", "Timestamp", "Summary"], &rows, fmt);
    Ok(())
}

async fn get(client: &MonolithClient, args: &GetArgs) -> anyhow::Result<()> {
    let v = client
        .get_raw(&format!("/api/v1/events/{}", args.id))
        .await?;
    output::print_value(&v);
    Ok(())
}

async fn follow(client: &MonolithClient, args: &FollowArgs) -> anyhow::Result<()> {
    let ws_url = client.ws_url().await;
    let mut req = http::Request::builder()
        .uri(&ws_url)
        .method("GET")
        .body(())?;
    if let Some(ref token) = client.token {
        req.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token.access_token).parse().unwrap(),
        );
    }

    let (ws_stream, _) = tokio_tungstenite::connect_async(req).await?;
    let (_, mut read) = ws_stream.split();

    println!(
        "{}",
        "Listening for live events... (Ctrl+C to stop)".dimmed()
    );
    while let Some(msg) = read.next().await {
        match msg {
            Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(ref filter_type) = args.event_type {
                        if v["event_type"].as_str() != Some(filter_type) {
                            continue;
                        }
                    }
                    let event_type = v["event_type"].as_str().unwrap_or("?");
                    let summary = summarize_event(&v);
                    let _ts = v["timestamp"].as_str().unwrap_or("");
                    println!(
                        "{} {} {}",
                        chrono::Local::now().format("%H:%M:%S"),
                        format!("[{:20}]", event_type).dimmed(),
                        summary
                    );
                }
            }
            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

fn summarize_event(v: &serde_json::Value) -> String {
    if let Some(data) = v.get("data") {
        if let Some(cmd) = data.get("command_line").and_then(|c| c.as_str()) {
            if cmd.len() > 80 {
                return format!("{}...", &cmd[..77]);
            }
            return cmd.to_string();
        }
        if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
            return path.to_string();
        }
        if let Some(name) = data.get("name").and_then(|n| n.as_str()) {
            return name.to_string();
        }
        if let Some(remote) = data.get("remote_address").and_then(|r| r.as_str()) {
            return format!("connection to {}", remote);
        }
        if let Some(user) = data.get("username").and_then(|u| u.as_str()) {
            return format!("user: {}", user);
        }
    }
    String::new()
}
