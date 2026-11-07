//! Fetch scan results, assemble reports, and store artifacts.
use crate::{
    config::{Config, ConfigError, ReportConfig, SourceConfig},
    model::{Report, ScanSet},
    naming::artifact_base_name,
    sink::{Artifact, build_sinks},
    source::{
        ScanSource, SourceError, neuvector_file::NeuvectorFileSource, trivy_file::TrivyFileSource,
    },
};
use chrono::{DateTime, Utc};

pub fn build_source(cfg: &SourceConfig) -> Result<Box<dyn ScanSource>, ConfigError> {
    match cfg {
        SourceConfig::TrivyFiles { path } => Ok(Box::new(TrivyFileSource { dir: path.clone() })),
        SourceConfig::NeuvectorFiles { path } => {
            Ok(Box::new(NeuvectorFileSource { dir: path.clone() }))
        }
        SourceConfig::Harbor { .. } => Err(ConfigError::Invalid(
            "harbor source arrives in a later release".into(),
        )),
        SourceConfig::Neuvector { .. } => Err(ConfigError::Invalid(
            "neuvector source arrives in a later release".into(),
        )),
    }
}

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

#[derive(Debug)]
pub struct RunSummary {
    pub images: usize,
    pub findings: usize,
    pub stored: Vec<String>,
    pub failed_sinks: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum RunError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error("rendering failed: {0}")]
    Render(String),
    #[error("every output failed: {0:?}")]
    AllSinksFailed(Vec<String>),
}

impl RunError {
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
    pub name: String,
    pub version: String,
}

fn render_options(
    cfg: &ReportConfig,
    product: &ProductInfo,
) -> crate::render::model::RenderOptions {
    crate::render::model::RenderOptions {
        language: cfg.language.clone(),
        stale_after_days: cfg.stale_after_days,
        product_name: product.name.clone(),
        product_version: product.version.clone(),
        top_images: 10,
        top_findings: 15,
    }
}

/// Build display-ready JSON using the same inputs and options as PDF rendering.
pub fn render_data(
    cfg: &Config,
    now: DateTime<Utc>,
    product: &ProductInfo,
) -> Result<crate::render::model::RenderData, RunError> {
    let theme = crate::render::theme::load(cfg.theme.path.as_deref()).map_err(ConfigError::from)?;
    let set = build_source(&cfg.source)?.fetch()?;
    let report = assemble_report(set, &cfg.report, now);
    let opts = render_options(&cfg.report, product);
    Ok(crate::render::model::build(
        &report,
        &opts,
        crate::render::strings::load(opts.language.clone()),
        theme.to_render_value(),
    ))
}

pub fn run(
    cfg: &Config,
    now: DateTime<Utc>,
    product: &ProductInfo,
) -> Result<RunSummary, RunError> {
    let sinks = build_sinks(&cfg.output)?;
    let theme = crate::render::theme::load(cfg.theme.path.as_deref()).map_err(ConfigError::from)?;
    let set = build_source(&cfg.source)?.fetch()?;
    let report = assemble_report(set, &cfg.report, now);
    let mut artifacts = Vec::new();
    if cfg.report.json {
        artifacts.push(Artifact {
            file_name: format!(
                "{}.json",
                artifact_base_name(&report.scope, report.source.kind, now.date_naive())
            ),
            media_type: "application/json",
            bytes: serde_json::to_vec_pretty(&report)
                .map_err(|e| RunError::Render(e.to_string()))?,
        });
    }
    if cfg.report.pdf {
        let opts = render_options(&cfg.report, product);
        let bytes = crate::render::render_pdf(&report, &opts, &theme)
            .map_err(|err| RunError::Render(err.to_string()))?;
        artifacts.push(Artifact {
            file_name: format!(
                "{}.pdf",
                artifact_base_name(&report.scope, report.source.kind, now.date_naive())
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

pub fn check(cfg: &Config, _product: &ProductInfo) -> Result<String, RunError> {
    build_sinks(&cfg.output)?;
    let theme = crate::render::theme::load(cfg.theme.path.as_deref()).map_err(ConfigError::from)?;
    let source = build_source(&cfg.source)?;
    let set = source.fetch()?;
    Ok(format!(
        "{}: {} images, {} findings; theme: {}",
        source.describe(),
        set.images.len(),
        set.findings.len(),
        theme.product.name
    ))
}
