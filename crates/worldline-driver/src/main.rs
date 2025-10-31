use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use worldline_compat::{build_compat_snapshot, ensure_plugin_exists};
use worldline_registry::{RegistrySnapshot, RegistryError};

#[derive(Parser, Debug)]
#[command(name = "worldline")]
#[command(about = "Worldline registry driver", version)]
struct Cli {
    /// Path to the local registry snapshot
    #[arg(short, long, default_value = "registry.json")]
    snapshot: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Synchronise the registry from a remote HTTP endpoint
    Sync { #[arg(long)] endpoint: String },
    /// Export a compatibility snapshot for the SDKs
    Export { #[arg(long)] output: PathBuf },
    /// Assert that a plugin exists in the registry
    Check { #[arg(long)] plugin: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut snapshot = RegistrySnapshot::load(&cli.snapshot)?;

    match cli.command {
        Commands::Sync { endpoint } => {
            let response = reqwest::get(endpoint).await?;
            let body = response.text().await?;
            snapshot = serde_json::from_str(&body)?;
            snapshot.save(&cli.snapshot)?;
            println!("Synced {} circuits", snapshot.circuits.len());
        }
        Commands::Export { output } => {
            let compat = build_compat_snapshot(&snapshot)?;
            std::fs::write(output, serde_json::to_vec_pretty(&compat)?)?;
            println!("Exported {} plugins", compat.plugins.len());
        }
        Commands::Check { plugin } => match ensure_plugin_exists(&snapshot, &plugin) {
            Ok(_) => println!("Plugin {plugin} present"),
            Err(err) => match err.downcast_ref::<RegistryError>() {
                Some(RegistryError::MissingEntity(_)) => {
                    eprintln!("Plugin {plugin} missing");
                    std::process::exit(1);
                }
                _ => return Err(err),
            },
        },
    }

    Ok(())
}
