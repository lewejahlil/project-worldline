use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Sync { url, output } => {
            info!(url = %url, output = %output.display(), "syncing registry");
            worldline_driver::sync_registry(&url, &output).await?;
            info!(output = %output.display(), "registry synced successfully");
        }
        Commands::Export { input } => {
            info!(input = %input.display(), "exporting compat snapshot");
            let json = worldline_driver::export_compat(&input)?;
            println!("{json}");
        }
        Commands::Check { input, plugin } => {
            info!(input = %input.display(), plugin = %plugin, "checking plugin");
            worldline_driver::check_plugin(&input, &plugin)?;
            info!(plugin = %plugin, "plugin found in registry");
        }
    }

    Ok(())
}
