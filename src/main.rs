use clap::Parser;
use judex::cli::{self, Cli};
use tracing_subscriber::EnvFilter;

const PRODUCT_NAME: &str = "judex";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        cli::Command::Version => println!("{PRODUCT_NAME} {PRODUCT_VERSION}"),
        cli::Command::Run { .. } | cli::Command::Check { .. } => {
            eprintln!("not implemented");
            std::process::exit(1);
        }
    }
}
