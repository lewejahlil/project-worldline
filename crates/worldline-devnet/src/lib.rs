use std::process::{Child, Command};

use anyhow::{Context, Result};
use serde::Serialize;

/// Spawn an Anvil process listening on the given port.
///
/// The caller is responsible for managing the returned [`Child`] handle
/// (e.g. killing it when the devnet is no longer needed).
pub fn spawn_anvil(port: u16) -> Result<Child> {
    Command::new("anvil")
        .arg("--port")
        .arg(port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn anvil — is it installed?")
}

/// Wait for the devnet to become ready.
///
/// This is a simple async delay to give Anvil time to start listening.
pub async fn wait_for_ready(seconds: u64) {
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
}

/// Pretty-print any serializable value to a JSON string.
pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).context("failed to serialize value to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        name: String,
        count: u32,
    }

    #[test]
    fn to_json_roundtrip() {
        let sample = Sample {
            name: "test".to_string(),
            count: 42,
        };
        let json = to_json(&sample).unwrap();
        let parsed: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, parsed);
    }

    #[test]
    fn to_json_pretty_formatted() {
        let sample = Sample {
            name: "test".to_string(),
            count: 1,
        };
        let json = to_json(&sample).unwrap();
        assert!(json.contains('\n'), "expected pretty-printed output");
    }

    #[test]
    fn spawn_anvil_missing_binary() {
        // If anvil is not installed, spawn should return an error rather than panic.
        // We don't assert success since anvil may not be available in CI.
        let result = spawn_anvil(0);
        // Either it spawns (and we kill it) or it errors — both are valid.
        if let Ok(mut child) = result {
            let _ = child.kill();
        }
    }

    #[tokio::test]
    async fn wait_for_ready_completes() {
        // Verify the function completes without panicking.
        wait_for_ready(0).await;
    }
}
