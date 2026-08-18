use crate::client::MonolithClient;
use crate::output;
use clap::Args;

#[derive(Args)]
pub struct HealthArgs {
    #[command(subcommand)]
    pub command: Option<HealthCommand>,
}

#[derive(clap::Subcommand)]
pub enum HealthCommand {
    Ready,
    Metrics,
}

pub async fn execute(client: &MonolithClient, cmd: &Option<HealthCommand>) -> anyhow::Result<()> {
    match cmd {
        Some(HealthCommand::Ready) => ready(client).await,
        Some(HealthCommand::Metrics) => metrics(client).await,
        None => health(client).await,
    }
}

async fn health(client: &MonolithClient) -> anyhow::Result<()> {
    let v = client.get_raw("/api/v1/health").await?;
    output::print_value(&v);
    Ok(())
}

async fn ready(client: &MonolithClient) -> anyhow::Result<()> {
    let v = client.get_raw("/api/v1/health/ready").await?;
    output::print_value(&v);
    Ok(())
}

async fn metrics(client: &MonolithClient) -> anyhow::Result<()> {
    let v = client.get_raw("/api/v1/metrics").await?;
    output::print_value(&v);
    Ok(())
}
