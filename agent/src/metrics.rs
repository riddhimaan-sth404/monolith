use std::sync::atomic::{AtomicU64, Ordering};

pub struct AgentMetrics {
    pub events_created: AtomicU64,
    pub events_uploaded: AtomicU64,
    pub events_upload_failed: AtomicU64,
    pub events_dropped: AtomicU64,
    pub detections: AtomicU64,
    pub actions_executed: AtomicU64,
    pub last_telemetry_event_time: AtomicU64,
    pub driver_disconnected: std::sync::atomic::AtomicBool,
}

impl Default for AgentMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentMetrics {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            events_created: AtomicU64::new(0),
            events_uploaded: AtomicU64::new(0),
            events_upload_failed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            detections: AtomicU64::new(0),
            actions_executed: AtomicU64::new(0),
            last_telemetry_event_time: AtomicU64::new(now),
            driver_disconnected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_created: self.events_created.load(Ordering::Relaxed),
            events_uploaded: self.events_uploaded.load(Ordering::Relaxed),
            events_upload_failed: self.events_upload_failed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            detections: self.detections.load(Ordering::Relaxed),
            actions_executed: self.actions_executed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub events_created: u64,
    pub events_uploaded: u64,
    pub events_upload_failed: u64,
    pub events_dropped: u64,
    pub detections: u64,
    pub actions_executed: u64,
}

impl MetricsSnapshot {
    pub fn drop_rate(&self) -> f64 {
        let total = self.events_created.max(1);
        self.events_dropped as f64 / total as f64
    }

    pub fn upload_success_rate(&self) -> f64 {
        let total = self.events_uploaded + self.events_upload_failed;
        if total == 0 {
            return 1.0;
        }
        self.events_uploaded as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_all_zero() {
        let m = AgentMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.events_created, 0);
        assert_eq!(snap.events_uploaded, 0);
        assert_eq!(snap.events_upload_failed, 0);
        assert_eq!(snap.events_dropped, 0);
        assert_eq!(snap.detections, 0);
        assert_eq!(snap.actions_executed, 0);
    }

    #[test]
    fn test_increment_counters() {
        let m = AgentMetrics::new();
        m.events_created.fetch_add(100, Ordering::Relaxed);
        m.events_uploaded.fetch_add(80, Ordering::Relaxed);
        m.events_upload_failed.fetch_add(5, Ordering::Relaxed);
        m.events_dropped.fetch_add(15, Ordering::Relaxed);
        m.detections.fetch_add(10, Ordering::Relaxed);
        m.actions_executed.fetch_add(7, Ordering::Relaxed);
        let snap = m.snapshot();
        assert_eq!(snap.events_created, 100);
        assert_eq!(snap.events_uploaded, 80);
        assert_eq!(snap.events_upload_failed, 5);
        assert_eq!(snap.events_dropped, 15);
        assert_eq!(snap.detections, 10);
        assert_eq!(snap.actions_executed, 7);
    }

    #[test]
    fn test_snapshot_independent_of_live_changes() {
        let m = AgentMetrics::new();
        m.events_created.fetch_add(50, Ordering::Relaxed);
        let snap = m.snapshot();
        m.events_created.fetch_add(50, Ordering::Relaxed);
        assert_eq!(snap.events_created, 50);
    }

    #[test]
    fn test_drop_rate() {
        let snap = MetricsSnapshot {
            events_created: 100,
            events_dropped: 10,
            ..Default::default()
        };
        assert!((snap.drop_rate() - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_drop_rate_zero_when_no_events() {
        let snap = MetricsSnapshot::default();
        assert!((snap.drop_rate() - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_drop_rate_can_exceed_one() {
        let snap = MetricsSnapshot {
            events_created: 50,
            events_dropped: 100,
            ..Default::default()
        };
        assert!((snap.drop_rate() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_upload_success_rate() {
        let snap = MetricsSnapshot {
            events_uploaded: 90,
            events_upload_failed: 10,
            ..Default::default()
        };
        assert!((snap.upload_success_rate() - 0.9).abs() < 1e-10);
    }

    #[test]
    fn test_upload_success_rate_no_uploads() {
        let snap = MetricsSnapshot::default();
        assert!((snap.upload_success_rate() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_upload_success_rate_all_failed() {
        let snap = MetricsSnapshot {
            events_uploaded: 0,
            events_upload_failed: 100,
            ..Default::default()
        };
        assert!((snap.upload_success_rate() - 0.0).abs() < 1e-10);
    }
}
