//! Fetch scan results, assemble reports, and store artifacts.
use crate::config::{Config, ConfigError, ReportConfig, SourceConfig};
use crate::model::{Report, ScanSet};
use crate::sink::{Artifact, ReportSink};
use crate::source::neuvector_file::NeuvectorFileSource;
use crate::source::trivy_file::TrivyFileSource;
use crate::source::{ScanSource, SourceError};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Construct the configured scan source, reading its password and building its transport.
///
/// # Errors
///
/// Fails if a Harbor or NeuVector password variable is unset, or the TLS options conflict or
/// name an unusable CA file.
pub fn build_source(
    cfg: &SourceConfig,
    user_agent: &str,
) -> Result<Box<dyn ScanSource>, ConfigError> {
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
                user_agent,
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
                user_agent,
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

/// Outcome of [`run`]: report totals plus the successful and failed writes.
#[derive(Debug)]
pub struct RunSummary {
    /// Number of images in the report.
    pub images: usize,
    /// Number of findings in the report.
    pub findings: usize,
    /// One `<sink description>: <file name>` entry per artifact written.
    pub stored: Vec<String>,
    /// Descriptions of sinks that rejected at least one artifact; the errors are only logged.
    pub failed_sinks: Vec<String>,
}

/// Configuration, source, rendering, or complete output failure during a run.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum RunError {
    /// Configuration, theme, logo, credential or TLS setup failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Scan data collection failed.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Serialisation, PDF rendering, or writing the render-data file failed.
    #[error("rendering failed: {0}")]
    Render(String),
    /// No artifact was stored anywhere; carries the failed sink descriptions.
    #[error("every output failed: {0:?}")]
    AllSinksFailed(Vec<String>),
}

impl RunError {
    /// Map a failure to its exit status: 2 config, 3 source, 4 render, 5 all sinks failed.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => 2,
            Self::Source(_) => 3,
            Self::Render(_) => 4,
            Self::AllSinksFailed(_) => 5,
        }
    }
}

/// What the binary knows and the library must not spell: upstream identity and environment.
#[derive(Clone, Debug)]
pub struct Runtime {
    /// Upstream product name, `PRODUCT_NAME` in `main.rs`.
    pub upstream: String,
    /// Crate version.
    pub version: String,
    /// Value of `<NAME>_THEME_DIR`, already read from the environment; `None` when unset.
    pub theme_dir: Option<PathBuf>,
    /// Name of that variable, for messages only.
    pub theme_dir_env: String,
}

/// Name and version of the application producing the report.
#[derive(Clone, Debug)]
pub struct ProductInfo {
    /// Name presented by the resolved theme.
    pub name: String,
    /// Upstream application name.
    pub upstream: String,
    /// Crate version.
    pub version: String,
}

impl ProductInfo {
    /// Derive the edition identity from the resolved theme.
    pub fn new(runtime: &Runtime, theme: &crate::render::theme::Theme) -> Self {
        Self {
            name: theme.product.name.clone(),
            upstream: runtime.upstream.clone(),
            version: runtime.version.clone(),
        }
    }
    /// Format the edition and version, including upstream when different.
    pub fn display(&self) -> String {
        let mut value = format!("{} {}", self.name, self.version);
        if self.name != self.upstream {
            value.push_str(&format!(" ({})", self.upstream));
        }
        value
    }
    /// Format HTTP identification, replacing non-RFC 9110 token characters in product names.
    pub fn user_agent(&self) -> String {
        let token = |s: &str| {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c) {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
        };
        let mut value = format!("{}/{}", token(&self.name), self.version);
        if self.name != self.upstream {
            value.push_str(&format!(" {}/{}", token(&self.upstream), self.version));
        }
        value
    }
}

fn render_options(
    cfg: &ReportConfig,
    product: &ProductInfo,
) -> crate::render::model::RenderOptions {
    crate::render::model::RenderOptions {
        min_severity: cfg.min_severity,
        image_detail: cfg.image_detail,
        max_table_rows: cfg.max_table_rows,
        json_artifact: cfg.json,
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
    product: ProductInfo,
    theme: crate::render::theme::Theme,
    theme_source: crate::render::theme::ThemeSource,
    customer_logo: Option<crate::render::theme::Logo>,
    source_description: String,
    report: Report,
    sinks: Vec<Box<dyn ReportSink>>,
}

/// Configuration has already been validated by the loader. Preserve the
/// theme -> sinks -> source error order for every pipeline entry point.
fn load_inputs(cfg: &Config, runtime: &Runtime, now: DateTime<Utc>) -> Result<Inputs, RunError> {
    let (theme, theme_source) =
        crate::render::theme::resolve(cfg.theme.path.as_deref(), runtime.theme_dir.as_deref())
            .map_err(|err| {
                if cfg.theme.path.is_none() && runtime.theme_dir.is_some() {
                    ConfigError::Invalid(format!("{}: {err}", runtime.theme_dir_env))
                } else {
                    ConfigError::from(err)
                }
            })?;
    let product = ProductInfo::new(runtime, &theme);
    let customer_logo = cfg
        .report
        .logo
        .as_deref()
        .map(crate::render::theme::Logo::load)
        .transpose()
        .map_err(|err| ConfigError::Invalid(format!("report.logo: {err}")))?;
    let sinks = crate::sink::build_sinks(&cfg.output, &product.user_agent())?;
    let source = build_source(&cfg.source, &product.user_agent())?;
    let source_description = source.describe();
    let report = assemble_report(source.fetch()?, &cfg.report, now);
    Ok(Inputs {
        product,
        customer_logo,
        theme,
        theme_source,
        source_description,
        report,
        sinks,
    })
}

/// Outcome of [`write_render_data`]: the output file and the report totals.
#[derive(Debug)]
pub struct RenderDataSummary {
    /// File the render data was written to.
    pub path: PathBuf,
    /// Number of images in the render data.
    pub images: usize,
    /// Number of findings in the render data.
    pub findings: usize,
}

/// Write the template input as pretty-printed JSON to `out`, for template iteration.
///
/// # Errors
///
/// Fails for the reasons [`render_data`] does, or if serialising or writing `out` fails.
pub fn write_render_data(
    cfg: &Config,
    now: DateTime<Utc>,
    runtime: &Runtime,
    out: &Path,
) -> Result<RenderDataSummary, RunError> {
    let data = render_data(cfg, now, runtime)?;
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
/// Fails if the theme, customer logo, sinks or source cannot be set up, or collection fails.
pub fn render_data(
    cfg: &Config,
    now: DateTime<Utc>,
    runtime: &Runtime,
) -> Result<crate::render::model::RenderData, RunError> {
    let Inputs {
        product,
        theme,
        report,
        customer_logo,
        ..
    } = load_inputs(cfg, runtime, now)?;
    let mut opts = render_options(&cfg.report, &product);
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
/// Fails if the theme, customer logo, sinks or source cannot be set up, collection fails,
/// JSON serialisation or PDF rendering fails, or no artifact could be stored anywhere.
pub fn run(cfg: &Config, now: DateTime<Utc>, runtime: &Runtime) -> Result<RunSummary, RunError> {
    let Inputs {
        product,
        customer_logo,
        theme,
        report,
        sinks,
        ..
    } = load_inputs(cfg, runtime, now)?;
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
        let mut opts = render_options(&cfg.report, &product);
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

/// Load every input as [`run`] does and summarise scan states, without rendering or storing.
///
/// # Errors
///
/// Fails if the theme, customer logo, sinks or source cannot be set up, or collection fails.
pub fn check(cfg: &Config, runtime: &Runtime) -> Result<String, RunError> {
    let inputs = load_inputs(cfg, runtime, Utc::now())?;
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
        "{}: {} images ({} scanned, {} failed, {} not scanned), {} findings; product: {}; theme: {}",
        inputs.source_description,
        inputs.report.images.len(),
        scanned,
        failed,
        not_scanned,
        inputs.report.findings.len(),
        inputs.product.display(),
        inputs.theme_source
    ))
}

#[cfg(test)]
mod product_tests {
    use super::ProductInfo;
    #[test]
    fn user_agent_uses_only_http_token_characters() {
        for (name, token) in [("A/B (C)", "A-B--C-"), ("中文", "--")] {
            let product = ProductInfo {
                name: name.into(),
                upstream: "upstream".into(),
                version: "0.2.0".into(),
            };
            assert_eq!(
                product.user_agent(),
                format!("{token}/0.2.0 upstream/0.2.0")
            );
        }
    }

    #[test]
    fn edition_user_agent_replaces_whitespace() {
        let runtime = super::Runtime {
            upstream: "upstream".into(),
            version: "0.2.0".into(),
            theme_dir: None,
            theme_dir_env: "UPSTREAM_THEME_DIR".into(),
        };
        let mut theme = crate::render::theme::default_theme();
        theme.product.name = "Arishem Edition".into();
        let product = ProductInfo::new(&runtime, &theme);
        assert_eq!(product.display(), "Arishem Edition 0.2.0 (upstream)");
        assert_eq!(product.user_agent(), "Arishem-Edition/0.2.0 upstream/0.2.0");
    }

    #[test]
    fn product_display_and_user_agent_for_default_theme() {
        let p = ProductInfo {
            name: "upstream".into(),
            upstream: "upstream".into(),
            version: "0.2.0".into(),
        };
        assert_eq!(p.display(), "upstream 0.2.0");
        assert_eq!(p.user_agent(), "upstream/0.2.0");
    }
    #[test]
    fn product_display_and_user_agent_for_edition_theme() {
        let p = ProductInfo {
            name: "Arishem".into(),
            upstream: "upstream".into(),
            version: "0.2.0".into(),
        };
        assert_eq!(p.display(), "Arishem 0.2.0 (upstream)");
        assert_eq!(p.user_agent(), "Arishem/0.2.0 upstream/0.2.0");
    }
}
