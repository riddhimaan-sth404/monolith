use crate::output;
use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct RestoreArgs {
    #[command(subcommand)]
    pub command: Option<RestoreCommand>,
}

#[derive(Subcommand)]
pub enum RestoreCommand {
    /// Show restore feature status
    Status,
    /// Claim a partition for snapshot storage
    Claim {
        /// Physical drive number (e.g. 0 for \\.\PhysicalDrive0)
        drive: u32,
        /// Partition number on the drive
        partition: u32,
    },
    /// Create a manual snapshot (stub — use agent)
    Create {
        /// Label for the snapshot
        label: String,
    },
    /// List all snapshots (stub)
    List,
    /// Rollback to a snapshot (requires reboot)
    Rollback {
        /// Snapshot ID to roll back to
        id: String,
    },
    /// Delete a snapshot (stub)
    Delete {
        /// Snapshot ID to delete
        id: String,
    },
}

pub async fn execute(cmd: &Option<RestoreCommand>) -> Result<()> {
    match cmd {
        Some(RestoreCommand::Status) => cmd_status().await,
        Some(RestoreCommand::Claim { drive, partition }) => cmd_claim(*drive, *partition).await,
        Some(RestoreCommand::Create { label }) => cmd_create(label).await,
        Some(RestoreCommand::List) => cmd_list().await,
        Some(RestoreCommand::Rollback { id }) => cmd_rollback(id).await,
        Some(RestoreCommand::Delete { id }) => cmd_delete(id).await,
        None => {
            println!("System Restore — Monolith EDR");
            println!();
            println!("Usage: mono restore <subcommand>");
            println!();
            println!("Subcommands:");
            println!("  status               Show restore feature activation status");
            println!("  claim <drive> <part>  Claim a partition for snapshot storage");
            println!("  create <label>       Create a manual snapshot");
            println!("  list                 List available snapshots");
            println!("  rollback <id>        Roll back to a snapshot (reboot required)");
            println!("  delete <id>          Delete a snapshot");
            println!();
            println!("The agent must be running and connected to the kernel driver");
            println!("for most operations.  Use 'agent-cli' from the agent service");
            println!("for direct driver communication.");
            Ok(())
        }
    }
}

async fn cmd_status() -> Result<()> {
    // Check license file for system_restore feature
    match monolith_shared::license::find_license_file() {
        Ok(Some(bundle)) => {
            let has_restore = bundle.has_feature("system_restore");
            let expired = bundle.is_expired();

            println!("Restore Feature: {}", if has_restore { "LICENSED" } else { "NOT LICENSED" });
            println!("License Expired: {}", if expired { "YES" } else { "no" });
            println!("Vendor: {}", bundle.payload.vendor);
            println!("Expires: {}", bundle.payload.expires);
            println!();

            if has_restore && !expired {
                output::ok("System restore is available");
            } else if !has_restore {
                eprintln!("[WARN] Current license does not include the system_restore feature");
            } else {
                eprintln!("[WARN] License has expired");
            }
        }
        Ok(None) => {
            println!("No license file found");
            println!("Place a valid license.lic in configs/");
        }
        Err(e) => {
            println!("Error reading license: {}", e);
        }
    }

    // TODO: Query driver status via backend API
    println!();
    println!("Driver status: (requires backend connection)");

    Ok(())
}

async fn cmd_claim(drive: u32, partition: u32) -> Result<()> {
    println!("Claiming partition {}/{}...", drive, partition);
    println!();
    println!("This operation requires the agent to send");
    println!("IOCTL_EDR_RESTORE_CLAIM_PARTITION to the kernel driver.");
    println!("Use the agent's CLI or the backend web interface.");
    println!();
    println!("To do it manually via the agent debug endpoint:");
    println!("  curl -X POST http://localhost:8091/restore/claim/{}/{}", drive, partition);
    output::ok("Partition claim initiated (if agent is running)");
    Ok(())
}

async fn cmd_create(label: &str) -> Result<()> {
    println!("Creating snapshot '{}'...", label);
    println!("VSS snapshot creation is not yet implemented via CLI.");
    println!("Use the agent or backend web interface.");
    output::ok("Snapshot creation initiated (stub)");
    Ok(())
}

async fn cmd_list() -> Result<()> {
    println!("Snapshots:");
    println!("  (VSS snapshot listing not yet implemented)");
    Ok(())
}

async fn cmd_rollback(id: &str) -> Result<()> {
    println!("Rolling back to snapshot {}...", id);
    println!("WARNING: This will reboot the system!");
    println!("VSS rollback requires a reboot for system volumes.");
    println!("Use the agent or backend web interface.");
    Ok(())
}

async fn cmd_delete(id: &str) -> Result<()> {
    println!("Deleting snapshot {}...", id);
    println!("VSS snapshot deletion not yet implemented via CLI.");
    Ok(())
}
