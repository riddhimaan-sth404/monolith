use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessExit {
    pub pid: u32,
    pub name: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxReport {
    pub process_count: usize,
    pub exits: Vec<ProcessExit>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub terminated_by: String,
    pub suspicious_indicators: Vec<String>,
    pub file_operations: Vec<String>,
    pub registry_operations: Vec<String>,
    pub network_connections: Vec<String>,
}

impl SandboxReport {
    pub fn new() -> Self {
        Self {
            process_count: 0,
            exits: Vec::new(),
            timed_out: false,
            duration_ms: 0,
            terminated_by: String::new(),
            suspicious_indicators: Vec::new(),
            file_operations: Vec::new(),
            registry_operations: Vec::new(),
            network_connections: Vec::new(),
        }
    }

    pub fn record_exit(&mut self, pid: u32, name: String, exit_code: i32) {
        self.exits.push(ProcessExit { pid, name, exit_code });
        self.process_count = self.exits.len();
    }

    pub fn add_suspicious_indicator(&mut self, indicator: &str) {
        self.suspicious_indicators.push(indicator.to_string());
    }

    pub fn add_file_operation(&mut self, op: &str) {
        self.file_operations.push(op.to_string());
    }

    pub fn add_registry_operation(&mut self, op: &str) {
        self.registry_operations.push(op.to_string());
    }

    pub fn add_network_connection(&mut self, conn: &str) {
        self.network_connections.push(conn.to_string());
    }

    pub fn score(&self) -> f64 {
        let mut score = 0.0f64;
        for indicator in &self.suspicious_indicators {
            if indicator.contains("create_process") { score += 0.3; }
            if indicator.contains("modify_file") { score += 0.2; }
            if indicator.contains("network") { score += 0.3; }
            if indicator.contains("registry") { score += 0.2; }
            if indicator.contains("injection") { score += 0.5; }
            if indicator.contains("persistence") { score += 0.4; }
        }
        if self.timed_out { score += 0.1; }
        if self.exits.iter().any(|e| e.exit_code != 0) { score += 0.1; }
        score.min(1.0)
    }

    pub fn verdict(&self) -> &str {
        let s = self.score();
        if s >= 0.7 { "malicious" }
        else if s >= 0.3 { "suspicious" }
        else { "clean" }
    }
}
