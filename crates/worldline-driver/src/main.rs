use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "worldline-driver", about = "Worldline aggregator driver CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch a registry snapshot from a remote URL and save it locally.
    Sync {
        /// URL of the remote registry JSON.
        #[arg(long)]
        url: String,
        /// Local file path to write the snapshot to.
        #[arg(long)]
        output: PathBuf,
    },
    /// Export the registry as an SDK-compatible JSON snapshot.
    Export {
        /// Path to a local registry JSON file.
        #[arg(long)]
        input: PathBuf,
    },
    /// Check that a plugin exists in the local registry.
    Check {
        /// Path to a local registry JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Plugin ID to look up.
        #[arg(long)]
        plugin: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync { url, output } => {
            worldline_driver::sync_registry(&url, &output).await?;
            println!("Registry synced to {}", output.display());
        }
        Commands::Export { input } => {
            let json = worldline_driver::export_compat(&input)?;
            println!("{json}");
        }
        Commands::Check { input, plugin } => {
            worldline_driver::check_plugin(&input, &plugin)?;
            println!("Plugin '{plugin}' found in registry.");
        }
    }

    Ok(())
}
