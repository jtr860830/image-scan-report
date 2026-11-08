//! YAML configuration and explicit environment-variable resolution.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{Language, Severity};

/// Validated settings for input collection, report generation, and output storage.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Colors, fonts, and product branding supplied to report templates.
    #[serde(default)]
    pub theme: ThemeConfig,
    /// Scanner identity and origin of the input data.
    pub source: SourceConfig,
    /// Report content or generation settings for this operation.
    pub report: ReportConfig,
    /// Destinations to which generated artifacts are written. An empty list indicates no entries.
    pub output: Vec<OutputConfig>,
}

/// Connection or filesystem settings for the selected input source.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceConfig {
    /// Read Trivy scan reports from a directory.
    TrivyFiles {
        /// Filesystem location of the configured resource.
        path: PathBuf,
    },
    /// Read NeuVector scan results from a directory.
    NeuvectorFiles {
        /// Filesystem location of the configured resource.
        path: PathBuf,
    },
    /// Collect scan data through the Harbor v2 API.
    Harbor {
        /// Endpoint or external product URL used by this configuration.
        url: String,
        /// Harbor project filter; None includes all accessible projects.
        project: Option<String>,
        /// Account name used for API authentication.
        username: String,
        /// Environment variable containing the API password.
        password_env: String,
        /// Optional PEM root certificate bundle; None uses the built-in roots.
        ca_file: Option<PathBuf>,
        /// Maximum HTTP request duration in seconds.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// Whether to disable TLS certificate verification.
        #[serde(default)]
        insecure_skip_verify: bool,
    },
    /// Collect scan data through the NeuVector API.
    Neuvector {
        /// Endpoint or external product URL used by this configuration.
        url: String,
        /// Registry name used to scope NeuVector API requests.
        registry: String,
        /// Account name used for API authentication.
        username: String,
        /// Environment variable containing the API password.
        password_env: String,
        /// Optional PEM root certificate bundle; None uses the built-in roots.
        ca_file: Option<PathBuf>,
        /// Maximum HTTP request duration in seconds.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// Whether to disable TLS certificate verification.
        #[serde(default)]
        insecure_skip_verify: bool,
    },
}

/// Content limits, localization, and artifact formats for report generation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    /// Severity bands whose findings include descriptions in the report. An empty list indicates no entries.
    #[serde(default = "default_describe_severities")]
    pub describe_severities: Vec<Severity>,
    /// Maximum number of characters shown in each finding description.
    #[serde(default = "default_description_chars")]
    pub description_chars: usize,
    /// Maximum number of remediation groups displayed as cards.
    #[serde(default = "default_remediation_cards")]
    pub remediation_cards: usize,
    /// Language selected for report labels and explanatory text.
    pub language: Language,
    /// Organization name displayed on the report cover.
    pub organization: String,
    /// Optional branding asset to embed in the report. None indicates that the value is unavailable.
    pub logo: Option<PathBuf>,
    /// Scan age threshold in days used to flag stale images.
    #[serde(default = "default_stale")]
    pub stale_after_days: u32,
    /// Whether to emit the normalized report as JSON.
    #[serde(default)]
    pub json: bool,
    /// Whether to produce a PDF report.
    #[serde(default = "default_pdf")]
    pub pdf: bool,
}

/// Settings for a filesystem or HTTP artifact destination.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OutputConfig {
    /// Store artifacts in a local directory.
    Filesystem {
        /// Filesystem location of the configured resource.
        path: PathBuf,
    },
    /// Upload artifacts to an HTTP endpoint.
    Http {
        /// Endpoint or external product URL used by this configuration.
        url: String,
        /// HTTP upload method, restricted to PUT or POST.
        #[serde(default = "default_put")]
        method: String,
        /// Additional HTTP header names and values attached to uploads.
        #[serde(default)]
        headers: BTreeMap<String, String>,
        /// Encoding used to upload each artifact.
        #[serde(default)]
        mode: HttpMode,
        /// Optional PEM root certificate bundle; None uses the built-in roots.
        ca_file: Option<PathBuf>,
        /// Whether to disable TLS certificate verification.
        #[serde(default)]
        insecure_skip_verify: bool,
        /// Maximum HTTP request duration in seconds.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

/// HTTP artifact encoding, either raw bytes or multipart form data.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMode {
    /// Send artifact bytes directly as the request body.
    #[default]
    Raw,
    /// Wrap the artifact in a multipart form upload.
    Multipart,
}

/// Failure to read, decode, or validate configuration settings.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum ConfigError {
    /// A required resource could not be read.
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// A resource could not be decoded into the expected format.
    #[error("invalid configuration: {0}")]
    Parse(String),
    /// A required environment variable is absent.
    #[error("environment variable {0} is not set")]
    MissingEnv(String),
    /// A decoded configuration value violates a validation constraint.
    #[error("{0}")]
    Invalid(String),
}

fn default_describe_severities() -> Vec<Severity> {
    vec![Severity::Critical, Severity::High]
}

fn default_description_chars() -> usize {
    600
}

fn default_remediation_cards() -> usize {
    30
}

fn default_stale() -> u32 {
    30
}

fn default_pdf() -> bool {
    true
}

fn default_put() -> String {
    "PUT".into()
}

fn default_timeout() -> u64 {
    30
}

/// Read and validate YAML, then expand environment references in HTTP headers.
///
/// Source passwords are read only when a source connects.
///
/// # Errors
///
/// Fails if the file cannot be read or decoded, settings fail validation, or a header references a missing environment variable.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let yaml =
        std::fs::read_to_string(path).map_err(|error| ConfigError::Read(path.to_owned(), error))?;
    let mut config: Config =
        serde_yaml_ng::from_str(&yaml).map_err(|error| ConfigError::Parse(error.to_string()))?;
    config.validate()?;
    for output in &mut config.output {
        if let OutputConfig::Http {
            headers, method, ..
        } = output
        {
            *method = method.to_ascii_uppercase();
            for value in headers.values_mut() {
                *value = resolve_env(value)?;
            }
        }
    }
    Ok(config)
}

/// Replace valid ASCII environment placeholders in one pass.
///
/// Malformed placeholders and replacement values remain literal.
///
/// # Errors
///
/// Fails if a valid placeholder references an absent environment variable.
pub fn resolve_env(value: &str) -> Result<String, ConfigError> {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        if let Some(end) = rest.find('}') {
            let name = &rest[2..end];
            let mut bytes = name.bytes();
            let valid = bytes
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_');
            if valid {
                result.push_str(&secret_from_env(name)?);
                rest = &rest[end + 1..];
                continue;
            }
        }
        result.push_str("${");
        rest = &rest[2..];
    }
    result.push_str(rest);
    Ok(result)
}

/// Read a named secret without expanding its contents.
///
/// # Errors
///
/// Fails if the environment variable is absent or its value is not Unicode.
pub fn secret_from_env(name: &str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::MissingEnv(name.to_owned()))
}

impl Config {
    /// Check that configuration values satisfy the pipeline constraints.
    ///
    /// # Errors
    ///
    /// Fails when configuration cannot be read, decoded, or validated, or a required environment variable is missing.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let SourceConfig::Harbor {
            url,
            ca_file,
            timeout_secs,
            insecure_skip_verify,
            ..
        }
        | SourceConfig::Neuvector {
            url,
            ca_file,
            timeout_secs,
            insecure_skip_verify,
            ..
        } = &self.source
        {
            let parsed = url::Url::parse(url)
                .map_err(|e| ConfigError::Invalid(format!("source.url: {e}")))?;
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(ConfigError::Invalid(
                    "source.url must not embed credentials; use username/password_env".into(),
                ));
            }
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(ConfigError::Invalid(
                    "source.url: scheme must be http or https".into(),
                ));
            }
            if ca_file.is_some() && *insecure_skip_verify {
                return Err(ConfigError::Invalid(
                    "source.ca_file and source.insecure_skip_verify cannot be combined".into(),
                ));
            }
            if *timeout_secs == 0 {
                return Err(ConfigError::Invalid(
                    "source.timeout_secs must be greater than zero".into(),
                ));
            }
        }
        if self.report.description_chars < 50 {
            return Err(ConfigError::Invalid(
                "report.description_chars must be at least 50".into(),
            ));
        }
        if self.output.is_empty() {
            return Err(ConfigError::Invalid("output must not be empty".into()));
        }
        if !self.report.pdf && !self.report.json {
            return Err(ConfigError::Invalid(
                "at least one of report.pdf or report.json must be true".into(),
            ));
        }
        for output in &self.output {
            if let OutputConfig::Http {
                method,
                url,
                ca_file,
                insecure_skip_verify,
                timeout_secs,
                ..
            } = output
            {
                if !method.eq_ignore_ascii_case("PUT") && !method.eq_ignore_ascii_case("POST") {
                    return Err(ConfigError::Invalid(
                        "output.method must be PUT or POST".into(),
                    ));
                }
                if method.eq_ignore_ascii_case("PUT")
                    && self.report.json
                    && !url.contains("{filename}")
                {
                    return Err(ConfigError::Invalid(
                        "output.url: PUT with report.json needs a {filename} placeholder, or every artifact overwrites the same resource".into(),
                    ));
                }
                let parsed = url::Url::parse(url)
                    .map_err(|e| ConfigError::Invalid(format!("output.url: {e}")))?;
                if !matches!(parsed.scheme(), "http" | "https")
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    return Err(ConfigError::Invalid(
                        "output.url: expected HTTP(S) URL without userinfo".into(),
                    ));
                }
                if ca_file.is_some() && *insecure_skip_verify {
                    return Err(ConfigError::Invalid(
                        "output.ca_file and output.insecure_skip_verify cannot be combined".into(),
                    ));
                }
                if *timeout_secs == 0 {
                    return Err(ConfigError::Invalid(
                        "output.timeout_secs must be greater than zero".into(),
                    ));
                }
            }
        }
        if self.report.organization.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "report.organization must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Optional directory override for the embedded report theme.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ThemeConfig {
    /// Filesystem location of the configured resource. None indicates that the value is unavailable.
    pub path: Option<PathBuf>,
}
