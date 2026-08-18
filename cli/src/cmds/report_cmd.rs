use crate::client::MonolithClient;
use crate::output::{self, OutputFormat};
use clap::Args;

#[derive(Args)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub command: ReportCommand,
}

#[derive(clap::Subcommand)]
pub enum ReportCommand {
    List(ListArgs),
    Generate(GenerateArgs),
    Download(DownloadArgs),
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long, default_value = "20")]
    pub limit: usize,
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct GenerateArgs {
    #[arg(long, default_value = "pdf")]
    pub format: String,
    #[arg(long, default_value = "7")]
    pub days: u64,
}

#[derive(Args)]
pub struct DownloadArgs {
    pub id: String,
    #[arg(long)]
    pub output: Option<String>,
}

pub async fn execute(client: &MonolithClient, cmd: &ReportCommand, global_output: &str) -> anyhow::Result<()> {
    match cmd {
        ReportCommand::List(args) => list(client, args, global_output).await,
        ReportCommand::Generate(args) => generate(client, args).await,
        ReportCommand::Download(args) => download(client, args).await,
    }
}

async fn list(client: &MonolithClient, args: &ListArgs, global_output: &str) -> anyhow::Result<()> {
    let fmt = OutputFormat::from(args.output.as_deref().unwrap_or(global_output));
    let v = client.get_raw(&format!("/api/v1/reports?limit={}", args.limit)).await?;
    let items = v.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                item["id"].as_str().unwrap_or("").to_string(),
                item["format"].as_str().unwrap_or("").to_string(),
                item["status"].as_str().unwrap_or("").to_string(),
                item["created_at"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    output::print_table(&["ID", "Format", "Status", "Created"], &rows, fmt);
    Ok(())
}

async fn generate(client: &MonolithClient, args: &GenerateArgs) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "format": args.format,
        "days": args.days,
    });
    let resp = client.post_raw("/api/v1/reports", &body).await?;
    let id = resp["id"].as_str().unwrap_or("?");
    output::ok(&format!("Report generated: {}", id));
    Ok(())
}

async fn download(client: &MonolithClient, args: &DownloadArgs) -> anyhow::Result<()> {
    let path = format!("/api/v1/reports/{}/download", args.id);
    let url = format!("{}{}", client.base_url, path);
    let mut req = client.client.get(&url);
    if let Some(ref token) = client.token {
        req = req.header("Authorization", format!("Bearer {}", token.access_token));
    }
    let resp = req.send().await?;
    let bytes = resp.bytes().await?;

    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| format!("report-{}.pdf", args.id));
    std::fs::write(&out_path, &bytes)?;
    output::ok(&format!("Downloaded to {}", out_path));
    Ok(())
}
