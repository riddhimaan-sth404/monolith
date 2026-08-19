use crate::auth::TokenStore;
use crate::client::MonolithClient;
use crate::config::Config;
use crate::output;
use anyhow::bail;
use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Args)]
pub struct SelfArgs {
    #[command(subcommand)]
    pub command: Option<SelfCommand>,
}

#[derive(clap::Subcommand)]
pub enum SelfCommand {
    Activate(ActivateArgs),
}

#[derive(Args)]
pub struct ActivateArgs {
    pub product_key: String,
    #[arg(short, long)]
    pub server: Option<String>,
    #[arg(long)]
    pub insecure: bool,
}

pub async fn execute(_client: &MonolithClient, cmd: &Option<SelfCommand>) -> anyhow::Result<()> {
    match cmd {
        Some(SelfCommand::Activate(args)) => activate(args).await,
        None => {
            println!("mono - Monolith EDR CLI");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn activate(args: &ActivateArgs) -> anyhow::Result<()> {
    let mut config = Config::load();
    if let Some(ref server) = args.server {
        config.server = server.clone();
    }
    if args.insecure {
        config.insecure = true;
    }

    // Validate product key format locally before hitting the server
    if !args.product_key.contains('.') {
        bail!("Invalid product key format — expected base64.payload.signature (contains a dot)");
    }

    let fingerprint = get_machine_fingerprint()?;

    let client = MonolithClient::new(&config, None)?;
    let response = match client.activate(&args.product_key, &fingerprint).await {
        Ok(r) => r,
        Err(e) => {
            // Detect connection-level failures and give a friendly message
            let msg = format!("{}", e);
            if msg.contains("Failed to connect to server")
                || msg.contains("connection refused")
                || msg.contains("Connection refused")
                || msg.contains("dns")
                || msg.contains("DNS")
                || msg.contains("timed out")
            {
                bail!(
                    "Could not reach the activation server at {}.\n\
                     Make sure the backend is running and reachable, then try again.\n\
                     Options:\n  \
                       --insecure if the server uses a self-signed certificate\n  \
                       Set ca_cert = \"path/to/ca.pem\" in {} to trust a specific CA.",
                    config.server,
                    Config::path().display()
                );
            }
            return Err(e);
        }
    };

    let token = TokenStore {
        access_token: response.token.clone(),
        refresh_token: None,
        expires_at: response.expires_at,
    };
    token.save()?;
    config.save()?;

    output::ok("Activated!");
    Ok(())
}

fn get_machine_fingerprint() -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm
            .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
            .map_err(|e| anyhow::anyhow!("Failed to read MachineGuid: {}", e))?;
        let guid: String = key
            .get_value("MachineGuid")
            .map_err(|e| anyhow::anyhow!("Failed to read MachineGuid: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(guid.as_bytes());
        return Ok(format!("{:x}", hasher.finalize()));
    }
    #[cfg(not(windows))]
    {
        Err(anyhow::anyhow!(
            "Hardware fingerprint not supported on this platform"
        ))
    }
}
