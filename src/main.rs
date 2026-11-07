use clap::Parser;
use scanreport::cli::{self, Cli};
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
        cli::Command::Run { config } => {
            let result = scanreport::config::load(&config)
                .map_err(scanreport::pipeline::RunError::from)
                .and_then(|cfg| scanreport::pipeline::run(&cfg, chrono::Utc::now()));
            match result {
                Ok(summary) => {
                    println!(
                        "Report: {} images, {} findings",
                        summary.images, summary.findings
                    );
                    for stored in summary.stored {
                        println!("{stored}");
                    }
                    for failed in summary.failed_sinks {
                        eprintln!("failed sink: {failed}");
                    }
                }
                Err(e) => fail(e),
            }
        }
        cli::Command::Check { config } => {
            let result = scanreport::config::load(&config)
                .map_err(scanreport::pipeline::RunError::from)
                .and_then(|cfg| scanreport::pipeline::check(&cfg));
            match result {
                Ok(summary) => println!("{summary}"),
                Err(e) => fail(e),
            }
        }
    }
}

fn fail(e: scanreport::pipeline::RunError) -> ! {
    eprintln!("error: {e}");
    std::process::exit(e.exit_code());
}
