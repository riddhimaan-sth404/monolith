use serde_json::Value;

pub mod system;

pub struct SystemInfoCollector {
    collector: system::SystemCollector,
}

impl SystemInfoCollector {
    pub fn new() -> Self {
        Self {
            collector: system::SystemCollector::new(),
        }
    }

    pub fn collect(&self) -> Vec<Value> {
        self.collector.collect()
    }
}
