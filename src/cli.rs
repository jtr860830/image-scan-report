use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Run {
        #[arg(long, default_value = "/etc/report/config.yaml")]
        config: PathBuf,
    },
    Check {
        #[arg(long, default_value = "/etc/report/config.yaml")]
        config: PathBuf,
    },
    RenderData {
        #[arg(long, default_value = "/etc/report/config.yaml")]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Version,
}
