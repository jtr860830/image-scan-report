//! Command-line arguments and supported report operations.
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Command-line arguments parsed for a report operation.
#[derive(Parser)]
pub struct Cli {
    /// Operation selected on the command line.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported report operations exposed by the executable.
#[derive(Subcommand)]
pub enum Command {
    /// Fetch scan results and generate the configured artifacts.
    Run {
        /// Path to the YAML configuration file. Defaults to the <NAME>_CONFIG variable, the XDG configuration directory, then /etc.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Validate configuration and summarize scan availability.
    Check {
        /// Path to the YAML configuration file. Defaults to the <NAME>_CONFIG variable, the XDG configuration directory, then /etc.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Write serialized template inputs for diagnostic inspection.
    RenderData {
        /// Path to the YAML configuration file. Defaults to the <NAME>_CONFIG variable, the XDG configuration directory, then /etc.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Destination path for serialized rendering data.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the application version and exit.
    Version,
}
