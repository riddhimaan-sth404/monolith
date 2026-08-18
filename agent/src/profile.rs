#![allow(missing_docs)]

use monolith_protobuf::proto::v1::{EdrProfile, PcProfile};

#[derive(Debug, Clone)]
pub struct TunableParameters {
    pub driver_poll_interval_ms: u64,
    pub event_batch_size: usize,
    pub upload_interval_ms: u64,
    pub heartbeat_interval_secs: u64,
    pub detection_sensitivity: f64,
    pub scanner_cooldown_secs: u64,
    pub scanner_max_region_mb: u64,
    pub scanner_periodic_sweep_secs: u64,
    pub event_buffer_capacity: usize,
    pub driver_buffer_size: u32,
    pub last_pc_profile: Option<i32>,
    pub current_pc_profile: Option<i32>,
    pub current_edr_profile: Option<i32>,
}

impl Default for TunableParameters {
    fn default() -> Self {
        Self {
            driver_poll_interval_ms: 100,
            event_batch_size: 100,
            upload_interval_ms: 500,
            heartbeat_interval_secs: 30,
            detection_sensitivity: 1.0,
            scanner_cooldown_secs: 60,
            scanner_max_region_mb: 8,
            scanner_periodic_sweep_secs: 300,
            event_buffer_capacity: 10000,
            driver_buffer_size: 65536,
            last_pc_profile: None,
            current_pc_profile: None,
            current_edr_profile: None,
        }
    }
}

pub struct ProfileEngine {
    current_pc: PcProfile,
    current_edr: EdrProfile,
    current_params: TunableParameters,
}

impl ProfileEngine {
    pub fn new(edr_profile: EdrProfile) -> Self {
        let params = TunableParameters::default();
        Self {
            current_pc: PcProfile::Balanced,
            current_edr: edr_profile,
            current_params: params,
        }
    }

    pub fn parameters(&self) -> &TunableParameters {
        &self.current_params
    }

    pub fn update(&mut self, pc: PcProfile, edr: Option<EdrProfile>) -> bool {
        let old_params = self.current_params.clone();
        self.current_pc = pc;
        if let Some(e) = edr {
            self.current_edr = e;
        }
        self.current_params = compute_parameters(self.current_pc, self.current_edr);

        self.current_params.driver_poll_interval_ms != old_params.driver_poll_interval_ms
            || self.current_params.upload_interval_ms != old_params.upload_interval_ms
            || self.current_params.heartbeat_interval_secs != old_params.heartbeat_interval_secs
            || self.current_params.detection_sensitivity != old_params.detection_sensitivity
    }

    pub fn pc_profile(&self) -> PcProfile {
        self.current_pc
    }

    pub fn edr_profile(&self) -> EdrProfile {
        self.current_edr
    }
}

fn compute_parameters(pc: PcProfile, edr: EdrProfile) -> TunableParameters {
    let base = TunableParameters::default();

    let (pc_poll, pc_batch, pc_upload, pc_hb, pc_sensitivity, pc_cooldown, pc_max_region, pc_sweep, pc_buffer_cap, pc_driver_buf) = match pc {
        PcProfile::Performance => (50, 200, 250, 15, 0.8, 30, 16, 180, 20000, 131072u32),
        PcProfile::Gaming => (200, 50, 1000, 60, 0.7, 120, 4, 600, 5000, 65536),
        PcProfile::Presentation => (250, 30, 1500, 120, 0.5, 300, 2, 900, 3000, 32768),
        PcProfile::Battery => (300, 20, 2000, 180, 0.6, 300, 2, 900, 2000, 16384),
        PcProfile::Idle => (500, 10, 5000, 300, 0.4, 600, 1, 1800, 1000, 8192),
        _ => (base.driver_poll_interval_ms, base.event_batch_size, base.upload_interval_ms, base.heartbeat_interval_secs, base.detection_sensitivity, base.scanner_cooldown_secs, base.scanner_max_region_mb, base.scanner_periodic_sweep_secs, base.event_buffer_capacity, base.driver_buffer_size),
    };

    let (edr_poll, edr_batch, edr_upload, edr_hb, edr_sensitivity, edr_cooldown, edr_max_region, edr_sweep, edr_buffer_cap, edr_driver_buf) = match edr {
        EdrProfile::MaxProtection => (25, 300, 100, 5, 1.5, 10, 32, 60, 50000, 262144u32),
        EdrProfile::Balanced => (base.driver_poll_interval_ms, base.event_batch_size, base.upload_interval_ms, base.heartbeat_interval_secs, base.detection_sensitivity, base.scanner_cooldown_secs, base.scanner_max_region_mb, base.scanner_periodic_sweep_secs, base.event_buffer_capacity, base.driver_buffer_size),
        EdrProfile::MinimalImpact => (500, 20, 2000, 120, 0.5, 300, 2, 900, 2000, 16384),
        EdrProfile::Stealth => (1000, 5, 5000, 300, 1.2, 60, 8, 600, 10000, 65536),
        _ => (base.driver_poll_interval_ms, base.event_batch_size, base.upload_interval_ms, base.heartbeat_interval_secs, base.detection_sensitivity, base.scanner_cooldown_secs, base.scanner_max_region_mb, base.scanner_periodic_sweep_secs, base.event_buffer_capacity, base.driver_buffer_size),
    };

    TunableParameters {
        driver_poll_interval_ms: edr_poll.min(pc_poll),
        event_batch_size: edr_batch.max(pc_batch),
        upload_interval_ms: edr_upload.min(pc_upload),
        heartbeat_interval_secs: edr_hb.min(pc_hb),
        detection_sensitivity: (edr_sensitivity + pc_sensitivity) / 2.0,
        scanner_cooldown_secs: edr_cooldown.min(pc_cooldown),
        scanner_max_region_mb: edr_max_region.max(pc_max_region),
        scanner_periodic_sweep_secs: edr_sweep.min(pc_sweep),
        event_buffer_capacity: edr_buffer_cap.max(pc_buffer_cap),
        driver_buffer_size: edr_driver_buf.max(pc_driver_buf),
        last_pc_profile: base.last_pc_profile,
        current_pc_profile: base.current_pc_profile,
        current_edr_profile: base.current_edr_profile,
    }
}
