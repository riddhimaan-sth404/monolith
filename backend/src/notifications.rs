use std::process::Stdio;
use std::sync::Arc;
use tracing::warn;

/// Sends a Windows toast notification via PowerShell.
/// If the PowerShell script path is None, the notification is silently skipped.
pub async fn send_alert_notification(
    script_path: Option<Arc<str>>,
    title: &str,
    message: &str,
) {
    let Some(script) = script_path else {
        return;
    };

    let title = title.to_string();
    let message = message.to_string();

    tokio::task::spawn_blocking(move || {
        let result = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script.as_ref(),
                "-Title",
                &title,
                "-Message",
                &message,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match result {
            Ok(status) if !status.success() => {
                warn!("toast notification exited with code {:?}", status.code());
            }
            Err(e) => {
                warn!("failed to run toast notification: {}", e);
            }
            _ => {}
        }
    });
}
