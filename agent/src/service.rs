#![allow(missing_docs)]

use tokio::sync::watch;

#[cfg(feature = "service")]
use windows_service::service_control_handler::ServiceControlHandler;

pub struct AgentServiceManager {
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl AgentServiceManager {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            shutdown_tx: tx,
            shutdown_rx: rx,
        }
    }

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    pub fn initiate_shutdown(&self) {
        tracing::info!("initiating agent shutdown");
        let _ = self.shutdown_tx.send(true);
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_rx.borrow()
    }

    pub async fn wait_for_shutdown(&mut self) {
        loop {
            if *self.shutdown_rx.borrow() {
                break;
            }
            self.shutdown_rx.changed().await.ok();
        }
    }
}

pub enum ServiceCommand {
    Stop,
    Pause,
    Resume,
    Shutdown,
    Custom(u32),
}
