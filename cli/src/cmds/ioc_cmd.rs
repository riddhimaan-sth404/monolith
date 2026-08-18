use crate::client::MonolithClient;
use crate::output::{self, OutputFormat};
use clap::Args;

#[derive(Args)]
pub struct IocArgs {
    #[command(subcommand)]
    pub command: IocCommand,
}

#[derive(clap::Subcommand)]
pub enum IocCommand {
    List(ListArgs),
    Create(CreateArgs),
    Import(ImportArgs),
    Get(GetArgs),
    Update(UpdateArgs),
    Delete(DeleteArgs),
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub ioc_type: Option<String>,
    #[arg(long, default_value = "100")]
    pub limit: usize,
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub ioc_type: String,
    #[arg(long)]
    pub value: String,
    #[arg(long, default_value = "high")]
    pub severity: String,
    #[arg(long)]
    pub description: Option<String>,
}

#[derive(Args)]
pub struct ImportArgs {
    pub file: String,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct GetArgs {
    pub id: String,
}

#[derive(Args)]
pub struct UpdateArgs {
    pub id: String,
    #[arg(long)]
    pub severity: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
}

#[derive(Args)]
pub struct DeleteArgs {
    pub id: String,
}

pub async fn execute(client: &MonolithClient, cmd: &IocCommand, global_output: &str) -> anyhow::Result<()> {
    match cmd {
        IocCommand::List(args) => list(client, args, global_output).await,
        IocCommand::Create(args) => create(client, args).await,
        IocCommand::Import(args) => import_(client, args).await,
        IocCommand::Get(args) => get(client, args).await,
        IocCommand::Update(args) => update(client, args).await,
        IocCommand::Delete(args) => delete(client, args).await,
    }
}

async fn list(client: &MonolithClient, args: &ListArgs, global_output: &str) -> anyhow::Result<()> {
    let fmt = OutputFormat::from(args.output.as_deref().unwrap_or(global_output));
    let mut path = "/api/v1/iocs".to_string();
    let mut params = vec![format!("limit={}", args.limit)];
    if let Some(ref t) = args.ioc_type {
        params.push(format!("type={}", t));
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
                item["ioc_type"].as_str().unwrap_or("").to_string(),
                truncate(item["value"].as_str().unwrap_or(""), 50),
                item["severity"].as_str().unwrap_or("").to_string(),
                item["created_at"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();

    output::print_table(&["ID", "Type", "Value", "Severity", "Created"], &rows, fmt);
    Ok(())
}

async fn create(client: &MonolithClient, args: &CreateArgs) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "ioc_type": args.ioc_type,
        "value": args.value,
        "severity": args.severity,
        "description": args.description,
    });
    let resp = client.post_raw("/api/v1/iocs", &body).await?;
    let id = resp["id"].as_str().unwrap_or("?");
    output::ok(&format!("IOC created: {}", id));
    Ok(())
}

async fn import_(client: &MonolithClient, args: &ImportArgs) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(&args.file)?;
    let records: Vec<serde_json::Value> = if args.file.ends_with(".csv") {
        let mut rdr = csv::Reader::from_reader(content.as_bytes());
        let mut items = vec![];
        for result in rdr.records() {
            let rec = result?;
            items.push(serde_json::json!({
                "ioc_type": rec.get(0).unwrap_or(""),
                "value": rec.get(1).unwrap_or(""),
                "severity": rec.get(2).unwrap_or("high"),
                "description": rec.get(3).unwrap_or(""),
            }));
        }
        items
    } else {
        serde_json::from_str(&content)?
    };

    if args.dry_run {
        println!("Would import {} IOC(s)", records.len());
        return Ok(());
    }

    let body = serde_json::json!({ "iocs": records });
    let resp = client.post_raw("/api/v1/iocs/import", &body).await?;
    let count = resp["imported"].as_u64().unwrap_or(0);
    output::ok(&format!("Imported {} IOC(s)", count));
    Ok(())
}

async fn get(client: &MonolithClient, args: &GetArgs) -> anyhow::Result<()> {
    let v = client.get_raw(&format!("/api/v1/iocs/{}", args.id)).await?;
    output::print_value(&v);
    Ok(())
}

async fn update(client: &MonolithClient, args: &UpdateArgs) -> anyhow::Result<()> {
    let mut body = serde_json::json!({});
    if let Some(ref s) = args.severity {
        body["severity"] = serde_json::Value::String(s.clone());
    }
    if let Some(ref d) = args.description {
        body["description"] = serde_json::Value::String(d.clone());
    }
    client
        .put_raw(&format!("/api/v1/iocs/{}", args.id), &body)
        .await?;
    output::ok("IOC updated");
    Ok(())
}

async fn delete(client: &MonolithClient, args: &DeleteArgs) -> anyhow::Result<()> {
    client
        .delete_raw(&format!("/api/v1/iocs/{}", args.id))
        .await?;
    output::ok("IOC deleted");
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}
