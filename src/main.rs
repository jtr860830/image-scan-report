//! Command-line entry point for scan report generation.
use image_scan_report::cli::{self, Cli};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

const PRODUCT_NAME: &str = "judex";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    use clap::{CommandFactory, FromArgMatches};
    tracing_subscriber::fmt()
        .with_env_filter(log_filter(std::env::var("RUST_LOG").ok().as_deref()))
        .with_writer(std::io::stderr)
        .init();

    // Not `fn main() -> Result<..>`: that form always exits with status 1 and
    // prints the error with `Debug`, while this program promises distinct exit
    // codes (2 config, 3 source, 4 render, 5 sinks) and a `Display` message.
    let matches = Cli::command()
        .name(PRODUCT_NAME)
        .version(PRODUCT_VERSION)
        .get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

fn dispatch(command: cli::Command) -> Result<(), image_scan_report::pipeline::RunError> {
    use image_scan_report::{config, pipeline};
    let theme_dir_env = format!("{}_THEME_DIR", PRODUCT_NAME.to_uppercase());
    let product = pipeline::Runtime {
        theme_dir: std::env::var_os(&theme_dir_env).map(std::path::PathBuf::from),
        theme_dir_env,
        upstream: PRODUCT_NAME.into(),
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

fn log_filter(env: Option<&str>) -> EnvFilter {
    // ureq_proto's trace output dumps request heads and bodies, including
    // credentials and login tokens, so it stays off whatever RUST_LOG says.
    // ureq itself is capped at debug (its debug log is allow-listed), but
    // only when the operator asked for trace: a directive always raises as
    // well as lowers, and the default run must stay quiet.
    let env = env.unwrap_or("info");
    let filter = EnvFilter::try_new(env)
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("ureq_proto=off".parse().expect("static directive"));
    if env.contains("trace") {
        filter.add_directive("ureq=debug".parse().expect("static directive"))
    } else {
        filter
    }
}

#[cfg(test)]
mod logging_tests {
    #[test]
    fn trace_keeps_transport_credentials_private() {
        let filter = super::log_filter(Some("trace")).to_string();
        assert!(filter.contains("ureq_proto=off"));
        assert!(filter.contains("ureq=debug"));
    }

    #[test]
    fn default_level_does_not_raise_ureq_to_debug() {
        for env in [None, Some("info"), Some("image_scan_report=debug")] {
            let filter = super::log_filter(env).to_string();
            assert!(filter.contains("ureq_proto=off"), "{env:?}");
            assert!(!filter.contains("ureq=debug"), "{env:?}");
        }
    }
}
