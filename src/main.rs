use clap::Parser;
use image_scan_report::cli::{self, Cli};
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

    if let Err(e) = dispatch(Cli::parse().command) {
        fail(e);
    }
}

fn dispatch(command: cli::Command) -> Result<(), image_scan_report::pipeline::RunError> {
    use image_scan_report::{config, pipeline};
    let product = pipeline::ProductInfo {
        name: PRODUCT_NAME.into(),
        version: PRODUCT_VERSION.into(),
    };
    match command {
        cli::Command::RenderData { config, out } => {
            let cfg = config::load(&config)?;
            pipeline::write_render_data(&cfg, chrono::Utc::now(), &product, &out)?;
        }
        cli::Command::Version => println!("{PRODUCT_NAME} {PRODUCT_VERSION}"),
        cli::Command::Run { config } => {
            let cfg = config::load(&config)?;
            let summary = pipeline::run(&cfg, chrono::Utc::now(), &product)?;
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
        cli::Command::Check { config } => {
            let cfg = config::load(&config)?;
            println!("{}", pipeline::check(&cfg, &product)?);
        }
    }
    Ok(())
}

fn fail(e: image_scan_report::pipeline::RunError) -> ! {
    eprintln!("error: {e}");
    std::process::exit(e.exit_code());
}
