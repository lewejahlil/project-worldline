use anyhow::Result;
use serde::Serialize;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use worldline_registry::RegistrySnapshot;

/// Spawns an Anvil process using the provided port. The caller is responsible for
/// terminating the process (for example when the returned child handle is dropped).
pub fn spawn_anvil(port: u16) -> Result<std::process::Child> {
    let child = Command::new("npx")
        .arg("anvil")
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

/// Wait for the devnet to stabilise before attempting deployments.
pub async fn wait_for_ready() {
    sleep(Duration::from_secs(2)).await;
}

/// Serialises the registry snapshot to a JSON string that can be served by the
/// driver during integration tests.
pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_ready() {
        wait_for_ready().await;
    }

    #[test]
    fn serialises_snapshot() {
        let snapshot = RegistrySnapshot::default();
        let json = to_json(&snapshot).unwrap();
        assert!(json.contains("circuits"));
    }
}
