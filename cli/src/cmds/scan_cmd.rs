use crate::client::MonolithClient;
use crate::output::{self, OutputFormat};
use clap::Args;

#[derive(Args)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub command: ScanCommand,
}

#[derive(clap::Subcommand)]
pub enum ScanCommand {
    List(ListArgs),
    Trigger(TriggerArgs),
    Cancel(CancelArgs),
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long, default_value = "50")]
    pub limit: usize,
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct TriggerArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, default_value = "quick")]
    pub scan_type: String,
}

#[derive(Args)]
pub struct CancelArgs {
    pub id: String,
}

pub async fn execute(client: &MonolithClient, cmd: &ScanCommand, global_output: &str) -> anyhow::Result<()> {
    match cmd {
        ScanCommand::List(args) => list(client, args, global_output).await,
        ScanCommand::Trigger(args) => trigger(client, args).await,
        ScanCommand::Cancel(args) => cancel(client, args).await,
    }
}

async fn list(client: &MonolithClient, args: &ListArgs, global_output: &str) -> anyhow::Result<()> {
    let fmt = OutputFormat::from(args.output.as_deref().unwrap_or(global_output));
    let mut path = format!("/api/v1/scans?limit={}", args.limit);
    if let Some(ref s) = args.status {
        path.push_str(&format!("&status={}", s));
    }
    let v = client.get_raw(&path).await?;
    let items = v.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                item["id"].as_str().unwrap_or("").to_string(),
                item["scan_type"].as_str().unwrap_or("").to_string(),
                item["status"].as_str().unwrap_or("").to_string(),
                item["started_at"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    output::print_table(&["ID", "Type", "Status", "Started"], &rows, fmt);
    Ok(())
}

async fn trigger(client: &MonolithClient, args: &TriggerArgs) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "scan_type": args.scan_type,
        "path": args.path,
    });
    let resp = client.post_raw("/api/v1/scans", &body).await?;
    let id = resp["id"].as_str().unwrap_or("?");
    output::ok(&format!("Scan triggered: {}", id));
    Ok(())
}

async fn cancel(client: &MonolithClient, args: &CancelArgs) -> anyhow::Result<()> {
    client
        .post_raw(
            &format!("/api/v1/scans/{}/cancel", args.id),
            &serde_json::json!({}),
        )
        .await?;
    output::ok("Scan cancelled");
    Ok(())
}
