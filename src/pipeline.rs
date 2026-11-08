//! Fetch scan results, assemble reports, and store artifacts.
use crate::config::{Config, ConfigError, ReportConfig, SourceConfig};
use crate::model::{Report, ScanSet};

use crate::sink::{Artifact, ReportSink};
use crate::source::neuvector_file::NeuvectorFileSource;
use crate::source::trivy_file::TrivyFileSource;
use crate::source::{ScanSource, SourceError};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Construct the configured scanner source and its transport.
///
/// # Errors
///
/// Fails if connection settings or certificate roots cannot initialize the selected source.
pub fn build_source(cfg: &SourceConfig) -> Result<Box<dyn ScanSource>, ConfigError> {
    match cfg {
        SourceConfig::TrivyFiles { path } => Ok(Box::new(TrivyFileSource { dir: path.clone() })),
        SourceConfig::NeuvectorFiles { path } => {
            Ok(Box::new(NeuvectorFileSource { dir: path.clone() }))
        }
        SourceConfig::Harbor {
            url,
            project,
            username,
            password_env,
            ca_file,
            timeout_secs,
            insecure_skip_verify,
        } => {
            let password = crate::config::secret_from_env(password_env)?;
            let client = crate::source::http::tls_client(
                "source",
                url,
                ca_file.as_deref(),
                *timeout_secs,
                *insecure_skip_verify,
            )?;
            Ok(Box::new(crate::source::harbor::HarborSource::from_config(
                &crate::source::harbor::HarborParams {
                    url: url.clone(),
                    project: project.clone(),
                    username: username.clone(),
                },
                client,
                password,
            )))
        }
        SourceConfig::Neuvector {
            url,
            registry,
            username,
            password_env,
            ca_file,
            timeout_secs,
            insecure_skip_verify,
        } => {
            let password = crate::config::secret_from_env(password_env)?;
            let client = crate::source::http::tls_client(
                "source",
                url,
                ca_file.as_deref(),
                *timeout_secs,
                *insecure_skip_verify,
            )?;
            Ok(Box::new(
                crate::source::neuvector_api::NeuvectorSource::from_config(
                    &crate::source::neuvector_api::NeuvectorParams {
                        url: url.clone(),
                        registry: registry.clone(),
                        username: username.clone(),
                    },
                    client,
                    password,
                ),
            ))
        }
    }
}

/// Combine scan results with report settings and a UTC generation time.
pub fn assemble_report(set: ScanSet, cfg: &ReportConfig, now: DateTime<Utc>) -> Report {
    Report {
        generated_at: now,
        language: cfg.language.clone(),
        organisation: cfg.organization.clone(),
        source: set.source,
        scope: set.scope,
        images: set.images,
        findings: set.findings,
    }
}

/// Descriptions of stored artifacts and any failed output destinations.
#[derive(Debug)]
pub struct RunSummary {
    /// Images included in this scan or vulnerability group.
    pub images: usize,
    /// Normalized vulnerabilities associated with scanned images.
    pub findings: usize,
    /// Artifact and destination descriptions for successful writes. An empty list indicates no entries.
    pub stored: Vec<String>,
    /// Destination descriptions paired with their storage errors. An empty list indicates no entries.
    pub failed_sinks: Vec<String>,
}

/// Configuration, source, rendering, or complete output failure during a run.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum RunError {
    /// Configuration loading or validation failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Scan data collection failed.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Report rendering failed.
    #[error("rendering failed: {0}")]
    Render(String),
    /// Every configured output destination rejected the generated artifacts.
    #[error("every output failed: {0:?}")]
    AllSinksFailed(Vec<String>),
}

impl RunError {
    /// Map a pipeline failure to its command-line exit status.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => 2,
            Self::Source(_) => 3,
            Self::Render(_) => 4,
            Self::AllSinksFailed(_) => 5,
        }
    }
}

/// Product identity supplied by the application.
#[derive(Clone, Debug)]
pub struct ProductInfo {
    /// Display name supplied by the scanner or theme.
    pub name: String,
    /// Schema or component version supplied by the producer.
    pub version: String,
}

fn render_options(
    cfg: &ReportConfig,
    product: &ProductInfo,
) -> crate::render::model::RenderOptions {
    crate::render::model::RenderOptions {
        describe_severities: cfg.describe_severities.clone(),
        description_chars: cfg.description_chars,
        remediation_cards: cfg.remediation_cards,
        customer_logo: None,
        language: cfg.language.clone(),
        stale_after_days: cfg.stale_after_days,
        product_name: product.name.clone(),
        product_version: product.version.clone(),
        top_images: 10,
        top_findings: 15,
    }
}

struct Inputs {
    theme: crate::render::theme::Theme,
    customer_logo: Option<crate::render::theme::Logo>,
    source_description: String,
    report: Report,
    sinks: Vec<Box<dyn ReportSink>>,
}

/// Configuration has already been validated by the loader. Preserve the
/// theme -> sinks -> source error order for every pipeline entry point.
fn load_inputs(cfg: &Config, now: DateTime<Utc>) -> Result<Inputs, RunError> {
    let theme = crate::render::theme::load(cfg.theme.path.as_deref()).map_err(ConfigError::from)?;
    let customer_logo = cfg
        .report
        .logo
        .as_deref()
        .map(crate::render::theme::Logo::load)
        .transpose()
        .map_err(|err| ConfigError::Invalid(format!("report.logo: {err}")))?;
    let sinks = crate::sink::build_sinks(&cfg.output)?;
    let source = build_source(&cfg.source)?;
    let source_description = source.describe();
    let report = assemble_report(source.fetch()?, &cfg.report, now);
    Ok(Inputs {
        customer_logo,
        theme,
        source_description,
        report,
        sinks,
    })
}

/// Descriptions of the serialized template input produced for inspection.
#[derive(Debug)]
pub struct RenderDataSummary {
    /// Filesystem location of the configured resource.
    pub path: PathBuf,
    /// Images included in this scan or vulnerability group.
    pub images: usize,
    /// Normalized vulnerabilities associated with scanned images.
    pub findings: usize,
}

/// Write display-ready JSON for template iteration.
///
/// # Errors
///
/// Fails if scan collection, theme loading, serialization, or writing the destination fails.
pub fn write_render_data(
    cfg: &Config,
    now: DateTime<Utc>,
    product: &ProductInfo,
    out: &Path,
) -> Result<RenderDataSummary, RunError> {
    let data = render_data(cfg, now, product)?;
    let bytes = serde_json::to_vec_pretty(&data).map_err(|e| RunError::Render(e.to_string()))?;
    std::fs::write(out, bytes)
        .map_err(|e| RunError::Render(format!("cannot write {}: {e}", out.display())))?;
    Ok(RenderDataSummary {
        path: out.to_owned(),
        images: data.summary.images_total,
        findings: data.summary.findings_total,
    })
}

/// Build display-ready JSON using the same inputs and options as PDF rendering.
///
/// # Errors
///
/// Fails if scan collection, theme loading, or template-data serialization fails.
pub fn render_data(
    cfg: &Config,
    now: DateTime<Utc>,
    product: &ProductInfo,
) -> Result<crate::render::model::RenderData, RunError> {
    let Inputs {
        theme,
        report,
        customer_logo,
        ..
    } = load_inputs(cfg, now)?;
    let mut opts = render_options(&cfg.report, product);
    opts.customer_logo = customer_logo;
    Ok(crate::render::model::build(
        &report,
        &opts,
        crate::render::strings::load(opts.language.clone()),
        theme.to_render_value(),
    ))
}

/// Fetch scan results, render enabled artifacts, and store them in each destination.
///
/// # Errors
///
/// Fails if inputs or themes cannot be loaded, rendering fails, or every output destination fails.
pub fn run(
    cfg: &Config,
    now: DateTime<Utc>,
    product: &ProductInfo,
) -> Result<RunSummary, RunError> {
    let Inputs {
        customer_logo,
        theme,
        report,
        sinks,
        ..
    } = load_inputs(cfg, now)?;
    let mut artifacts = Vec::new();
    if cfg.report.json {
        artifacts.push(Artifact {
            file_name: format!(
                "{}.json",
                crate::naming::artifact_base_name(
                    &report.scope,
                    report.source.kind,
                    now.date_naive()
                )
            ),
            media_type: "application/json",
            bytes: serde_json::to_vec_pretty(&report)
                .map_err(|e| RunError::Render(e.to_string()))?,
        });
    }
    if cfg.report.pdf {
        let mut opts = render_options(&cfg.report, product);
        opts.customer_logo = customer_logo;
        let bytes = crate::render::render_pdf(&report, &opts, &theme)
            .map_err(|err| RunError::Render(err.to_string()))?;
        artifacts.push(Artifact {
            file_name: format!(
                "{}.pdf",
                crate::naming::artifact_base_name(
                    &report.scope,
                    report.source.kind,
                    now.date_naive()
                )
            ),
            media_type: "application/pdf",
            bytes,
        });
    }
    let mut summary = RunSummary {
        images: report.images.len(),
        findings: report.findings.len(),
        stored: vec![],
        failed_sinks: vec![],
    };
    for sink in sinks {
        let description = sink.describe();
        for artifact in &artifacts {
            match sink.store(artifact) {
                Ok(()) => summary
                    .stored
                    .push(format!("{description}: {}", artifact.file_name)),
                Err(error) => {
                    tracing::warn!(sink = %description, %error, "artifact storage failed");
                    if !summary.failed_sinks.contains(&description) {
                        summary.failed_sinks.push(description.clone());
                    }
                }
            }
        }
    }
    if !artifacts.is_empty() && summary.stored.is_empty() {
        return Err(RunError::AllSinksFailed(summary.failed_sinks));
    }
    Ok(summary)
}

/// Validate inputs and summarize scan availability without storing a report.
///
/// # Errors
///
/// Fails if configuration, theme assets, or scan data cannot be loaded or validated.
pub fn check(cfg: &Config, product: &ProductInfo) -> Result<String, RunError> {
    let inputs = load_inputs(cfg, Utc::now())?;
    let mut scanned = 0usize;
    let mut failed = 0usize;
    let mut not_scanned = 0usize;
    for image in &inputs.report.images {
        match image.scan.state {
            crate::model::ScanState::Ok => scanned += 1,
            crate::model::ScanState::Failed => failed += 1,
            crate::model::ScanState::NotScanned => not_scanned += 1,
        }
    }
    Ok(format!(
        "{}: {} images ({} scanned, {} failed, {} not scanned), {} findings; theme: {}; product: {} {}",
        inputs.source_description,
        inputs.report.images.len(),
        scanned,
        failed,
        not_scanned,
        inputs.report.findings.len(),
        inputs.theme.product.name,
        product.name,
        product.version
    ))
}
