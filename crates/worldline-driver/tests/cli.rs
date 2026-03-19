/// Integration tests for the `worldline-driver` CLI binary.
///
/// These tests invoke the compiled binary as a subprocess using `assert_cmd`,
/// which mirrors exactly how end-users interact with the tool.
use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::tempdir;
use worldline_registry::{BackendMeta, CircuitMeta, PluginMeta, RegistrySnapshot};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal registry JSON file and return its path inside `dir`.
fn write_registry(dir: &Path, plugin_id: &str) -> std::path::PathBuf {
    let mut snap = RegistrySnapshot::default();
    snap.register_backend(BackendMeta {
        id: "b1".to_string(),
        kind: "groth16".to_string(),
        versions: vec!["0.6.0".to_string()],
    })
    .unwrap();
    snap.register_circuit(CircuitMeta {
        id: "c1".to_string(),
        version: "1.0.0".to_string(),
        public_inputs: vec![],
    })
    .unwrap();
    snap.register_plugin(PluginMeta {
        id: plugin_id.to_string(),
        version: "1.0.0".to_string(),
        backend: "b1".to_string(),
    })
    .unwrap();
    let path = dir.join("registry.json");
    worldline_registry::save(&path, &snap).unwrap();
    path
}

fn cmd() -> Command {
    Command::cargo_bin("worldline-driver").expect("binary not found — run `cargo build` first")
}

// ─── export subcommand ────────────────────────────────────────────────────────

#[test]
fn export_prints_valid_json_to_stdout() {
    let dir = tempdir().unwrap();
    let registry_path = write_registry(dir.path(), "my-plugin");

    cmd()
        .args(["export", "--input", registry_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"circuits\""))
        .stdout(predicate::str::contains("\"plugins\""))
        .stdout(predicate::str::contains("my-plugin"));
}

#[test]
fn export_succeeds_on_empty_missing_registry() {
    let dir = tempdir().unwrap();
    // Point to a non-existent file — load() returns an empty default snapshot.
    let missing = dir.path().join("nonexistent.json");

    cmd()
        .args(["export", "--input", missing.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"circuits\""));
}

// ─── check subcommand ─────────────────────────────────────────────────────────

#[test]
fn check_exits_success_for_known_plugin() {
    let dir = tempdir().unwrap();
    let registry_path = write_registry(dir.path(), "known-plugin");

    cmd()
        .args([
            "check",
            "--input",
            registry_path.to_str().unwrap(),
            "--plugin",
            "known-plugin",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("found in registry"));
}

#[test]
fn check_exits_failure_for_unknown_plugin() {
    let dir = tempdir().unwrap();
    let registry_path = write_registry(dir.path(), "real-plugin");

    cmd()
        .args([
            "check",
            "--input",
            registry_path.to_str().unwrap(),
            "--plugin",
            "ghost-plugin",
        ])
        .assert()
        .failure();
}

// ─── sync subcommand ──────────────────────────────────────────────────────────

#[test]
fn sync_fails_with_unreachable_url() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("out.json");

    cmd()
        .args([
            "sync",
            "--url",
            "http://127.0.0.1:19999/no-such-server",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

// ─── General CLI behaviour ────────────────────────────────────────────────────

#[test]
fn no_subcommand_prints_help() {
    cmd()
        .assert()
        .failure() // clap exits non-zero when no subcommand is given
        .stderr(predicate::str::contains("worldline-driver"));
}

#[test]
fn help_flag_prints_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("worldline-driver"));
}
