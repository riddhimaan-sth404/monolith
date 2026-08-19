use crate::client::MonolithClient;
use crate::output::{self, OutputFormat};
use clap::Args;

#[derive(Args)]
pub struct AlertArgs {
    #[command(subcommand)]
    pub command: AlertCommand,
}

#[derive(clap::Subcommand)]
pub enum AlertCommand {
    List(ListArgs),
    Get(GetArgs),
    Update(UpdateArgs),
    Suppress(SuppressArgs),
    Unsuppress(UnsuppressArgs),
    Summary,
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub severity: Option<String>,
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long, default_value = "50")]
    pub limit: usize,
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct GetArgs {
    pub id: String,
}

#[derive(Args)]
pub struct UpdateArgs {
    pub id: String,
    #[arg(long)]
    pub status: String,
}

#[derive(Args)]
pub struct SuppressArgs {
    pub id: String,
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Args)]
pub struct UnsuppressArgs {
    pub id: String,
}

pub async fn execute(
    client: &MonolithClient,
    cmd: &AlertCommand,
    global_output: &str,
) -> anyhow::Result<()> {
    match cmd {
        AlertCommand::List(args) => list(client, args, global_output).await,
        AlertCommand::Get(args) => get(client, args).await,
        AlertCommand::Update(args) => update(client, args).await,
        AlertCommand::Suppress(args) => suppress(client, args).await,
        AlertCommand::Unsuppress(args) => unsuppress(client, args).await,
        AlertCommand::Summary => summary(client).await,
    }
}

async fn list(client: &MonolithClient, args: &ListArgs, global_output: &str) -> anyhow::Result<()> {
    let fmt = OutputFormat::from(args.output.as_deref().unwrap_or(global_output));
    let mut path = "/api/v1/alerts".to_string();
    let mut params = vec![format!("limit={}", args.limit)];
    if let Some(ref s) = args.severity {
        params.push(format!("severity={}", s));
    }
    if let Some(ref s) = args.status {
        params.push(format!("status={}", s));
    }
    path.push('?');
    path.push_str(&params.join("&"));

    let v = client.get_raw(&path).await?;
    let items = v.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                item["id"].as_str().unwrap_or("").to_string(),
                format_severity(item["severity"].as_str().unwrap_or("")),
                item["title"].as_str().unwrap_or("").to_string(),
                format_score(item["score"].as_f64().unwrap_or(0.0)),
                format_status(item["status"].as_str().unwrap_or("")),
                item["created_at"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();

    output::print_table(
        &["ID", "Severity", "Title", "Score", "Status", "Created"],
        &rows,
        fmt,
    );
    Ok(())
}

async fn get(client: &MonolithClient, args: &GetArgs) -> anyhow::Result<()> {
    let v = client
        .get_raw(&format!("/api/v1/alerts/{}", args.id))
        .await?;
    output::print_value(&v);
    Ok(())
}

async fn update(client: &MonolithClient, args: &UpdateArgs) -> anyhow::Result<()> {
    let body = serde_json::json!({ "status": args.status });
    client
        .put_raw(&format!("/api/v1/alerts/{}", args.id), &body)
        .await?;
    output::ok("Alert updated");
    Ok(())
}

async fn suppress(client: &MonolithClient, args: &SuppressArgs) -> anyhow::Result<()> {
    let body = serde_json::json!({ "reason": args.reason });
    client
        .post_raw(&format!("/api/v1/alerts/{}/suppress", args.id), &body)
        .await?;
    output::ok("Alert suppressed");
    Ok(())
}

async fn unsuppress(client: &MonolithClient, args: &UnsuppressArgs) -> anyhow::Result<()> {
    client
        .post_raw(
            &format!("/api/v1/alerts/{}/unsuppress", args.id),
            &serde_json::json!({}),
        )
        .await?;
    output::ok("Alert unsuppressed");
    Ok(())
}

async fn summary(client: &MonolithClient) -> anyhow::Result<()> {
    let v = client.get_raw("/api/v1/alerts/summary").await?;
    output::print_value(&v);
    Ok(())
}

fn format_severity(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "critical" => format!("\x1b[91m{}\x1b[0m", s),
        "high" => format!("\x1b[91m{}\x1b[0m", s),
        "medium" => format!("\x1b[93m{}\x1b[0m", s),
        "low" => format!("\x1b[94m{}\x1b[0m", s),
        _ => s.to_string(),
    }
}

fn format_status(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "new" => format!("\x1b[93m{}\x1b[0m", s),
        "investigating" => format!("\x1b[96m{}\x1b[0m", s),
        "resolved" => format!("\x1b[92m{}\x1b[0m", s),
        "false_positive" => format!("\x1b[90m{}\x1b[0m", s),
        _ => s.to_string(),
    }
}

fn format_score(s: f64) -> String {
    format!("{:.1}", s)
}
