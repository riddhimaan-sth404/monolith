mod auth;
mod client;
mod cmds;
mod config;
mod output;

use clap::Parser;
use client::MonolithClient;
use config::Config;

#[derive(Parser)]
#[command(name = "mono", about = "Monolith EDR CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    #[command(name = "self", about = "Activate product key and manage CLI config")]
    Me(cmds::self_cmd::SelfArgs),
    #[command(about = "List, get, update, suppress, and unsuppress alerts")]
    Alert(cmds::alert_cmd::AlertArgs),
    #[command(about = "List, get, and follow events")]
    Event(cmds::event_cmd::EventArgs),
    #[command(about = "List, create, import, get, update, and delete IOCs")]
    Ioc(cmds::ioc_cmd::IocArgs),
    #[command(about = "List, trigger, and cancel scans")]
    Scan(cmds::scan_cmd::ScanArgs),
    #[command(about = "List, generate, and download reports")]
    Report(cmds::report_cmd::ReportArgs),
    #[command(about = "Check health, readiness, and metrics")]
    Health(cmds::health_cmd::HealthArgs),
    #[command(about = "Manage system restore snapshots")]
    Restore(cmds::restore_cmd::RestoreArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = Config::load();
    let token = auth::TokenStore::load();
    let global_output = config.output.clone();

    match cli.command {
        Command::Me(cmd) => {
            cmds::self_cmd::execute(&MonolithClient::new(&config, token)?, &cmd.command).await
        }
        Command::Alert(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::alert_cmd::execute(&client, &cmd.command, &global_output).await
        }
        Command::Event(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::event_cmd::execute(&client, &cmd.command, &global_output).await
        }
        Command::Ioc(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::ioc_cmd::execute(&client, &cmd.command, &global_output).await
        }
        Command::Scan(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::scan_cmd::execute(&client, &cmd.command, &global_output).await
        }
        Command::Report(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::report_cmd::execute(&client, &cmd.command, &global_output).await
        }
        Command::Health(cmd) => {
            let token = auth::TokenStore::load().filter(|t| !t.is_expired());
            let client = MonolithClient::new(&config, token)?;
            cmds::health_cmd::execute(&client, &cmd.command).await
        }
        Command::Restore(cmd) => cmds::restore_cmd::execute(&cmd.command).await,
    }
}
