//! Scheduled and automatic snapshot management.
//!
//! Phase 1a: stubs for scheduled snapshots and installer detection.
//! The scheduler will run as Worker 13 in main.rs.

use std::time::Duration;

/// Configuration for the restore scheduler.
pub struct RestoreSchedulerConfig {
    pub enabled: bool,
    pub auto_install_snapshots: bool,
    pub schedule: String,
    pub max_snapshots: u32,
    pub volume: String,
}

impl Default for RestoreSchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_install_snapshots: true,
            schedule: "daily".to_string(),
            max_snapshots: 14,
            volume: "C:".to_string(),
        }
    }
}

/// Run the scheduler loop.  Called as a background task.
pub async fn run_scheduler(config: RestoreSchedulerConfig) {
    if !config.enabled {
        tracing::info!("restore scheduler: disabled");
        return;
    }

    tracing::info!("restore scheduler: starting (interval={})", config.schedule);

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;

        // TODO: implement scheduling logic
        // - Check if it's time for a scheduled snapshot
        // - Prune old snapshots beyond max_snapshots
        // - Detect installer processes from driver events
    }
}
