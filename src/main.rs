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

    let product = image_scan_report::pipeline::ProductInfo {
        name: PRODUCT_NAME.into(),
        version: PRODUCT_VERSION.into(),
    };
    match Cli::parse().command {
        cli::Command::RenderData { config, out } => {
            let result = image_scan_report::config::load(&config)
                .map_err(image_scan_report::pipeline::RunError::from)
                .and_then(|cfg| {
                    image_scan_report::pipeline::render_data(&cfg, chrono::Utc::now(), &product)
                })
                .and_then(|data| {
                    let bytes = serde_json::to_vec_pretty(&data).map_err(|e| {
                        image_scan_report::pipeline::RunError::Render(e.to_string())
                    })?;
                    std::fs::write(&out, bytes).map_err(|e| {
                        image_scan_report::pipeline::RunError::Render(format!(
                            "cannot write {}: {e}",
                            out.display()
                        ))
                    })
                });
            if let Err(e) = result {
                fail(e);
            }
        }
        cli::Command::Version => println!("{PRODUCT_NAME} {PRODUCT_VERSION}"),
        cli::Command::Run { config } => {
            let result = image_scan_report::config::load(&config)
                .map_err(image_scan_report::pipeline::RunError::from)
                .and_then(|cfg| {
                    image_scan_report::pipeline::run(&cfg, chrono::Utc::now(), &product)
                });
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
            let result = image_scan_report::config::load(&config)
                .map_err(image_scan_report::pipeline::RunError::from)
                .and_then(|cfg| image_scan_report::pipeline::check(&cfg, &product));
            match result {
                Ok(summary) => println!("{summary}"),
                Err(e) => fail(e),
            }
        }
    }
}

fn fail(e: image_scan_report::pipeline::RunError) -> ! {
    eprintln!("error: {e}");
    std::process::exit(e.exit_code());
}
