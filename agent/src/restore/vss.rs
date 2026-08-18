//! Volume Shadow Copy Service (VSS) snapshot management.
//!
//! Phase 1a: stubs for snapshot creation, listing, and revert.
//! Full implementation will use the `windows` crate's VSS COM bindings
//! or shell out to `vssadmin.exe`.

pub struct SnapshotInfo {
    pub id: String,
    pub volume: String,
    pub created_at: String,
    pub label: String,
    pub is_auto: bool,
}

impl SnapshotInfo {
    pub fn dummy(id: &str, label: &str) -> Self {
        Self {
            id: id.to_string(),
            volume: "C:".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            label: label.to_string(),
            is_auto: false,
        }
    }
}

/// Create a VSS snapshot of the given volume.
/// The diff area is stored on the hidden partition.
pub fn create_snapshot(volume: &str, label: &str, _diff_area_path: &str) -> Result<SnapshotInfo, String> {
    tracing::info!("VSS snapshot requested: volume={}, label={}", volume, label);
    Err("VSS snapshot creation not yet implemented (Phase 1a)".to_string())
}

/// List all VSS snapshots on the given volume.
pub fn list_snapshots(volume: &str) -> Result<Vec<SnapshotInfo>, String> {
    tracing::info!("VSS snapshot list requested: volume={}", volume);
    Err("VSS snapshot listing not yet implemented (Phase 1a)".to_string())
}

/// Revert a volume to a specific snapshot.
pub fn revert_snapshot(snapshot_id: &str) -> Result<(), String> {
    tracing::info!("VSS snapshot revert requested: id={}", snapshot_id);
    Err("VSS snapshot revert not yet implemented (Phase 1a)".to_string())
}

/// Delete a VSS snapshot.
pub fn delete_snapshot(snapshot_id: &str) -> Result<(), String> {
    tracing::info!("VSS snapshot delete requested: id={}", snapshot_id);
    Err("VSS snapshot deletion not yet implemented (Phase 1a)".to_string())
}
