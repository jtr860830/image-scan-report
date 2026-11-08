//! YAML configuration and explicit environment-variable resolution.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{Language, Severity};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub theme: ThemeConfig,
    pub source: SourceConfig,
    pub report: ReportConfig,
    pub output: Vec<OutputConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceConfig {
    TrivyFiles {
        path: PathBuf,
    },
    NeuvectorFiles {
        path: PathBuf,
    },
    Harbor {
        url: String,
        project: Option<String>,
        username: String,
        password_env: String,
        ca_file: Option<PathBuf>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        #[serde(default)]
        insecure_skip_verify: bool,
    },
    Neuvector {
        url: String,
        registry: String,
        username: String,
        password_env: String,
        ca_file: Option<PathBuf>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        #[serde(default)]
        insecure_skip_verify: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    #[serde(default = "default_describe_severities")]
    pub describe_severities: Vec<Severity>,
    #[serde(default = "default_description_chars")]
    pub description_chars: usize,
    #[serde(default = "default_remediation_cards")]
    pub remediation_cards: usize,
    pub language: Language,
    pub organization: String,
    pub logo: Option<PathBuf>,
    #[serde(default = "default_stale")]
    pub stale_after_days: u32,
    #[serde(default)]
    pub json: bool,
    #[serde(default = "default_pdf")]
    pub pdf: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OutputConfig {
    Filesystem {
        path: PathBuf,
    },
    Http {
        url: String,
        #[serde(default = "default_put")]
        method: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        mode: HttpMode,
        ca_file: Option<PathBuf>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMode {
    #[default]
    Raw,
    Multipart,
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("invalid configuration: {0}")]
    Parse(String),
    #[error("environment variable {0} is not set")]
    MissingEnv(String),
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

/// Read and validate YAML, then expand HTTP header values.
/// Source passwords are read only when a source connects.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let yaml =
        std::fs::read_to_string(path).map_err(|error| ConfigError::Read(path.to_owned(), error))?;
    let mut config: Config =
        serde_yaml_ng::from_str(&yaml).map_err(|error| ConfigError::Parse(error.to_string()))?;
    config.validate()?;
    for output in &mut config.output {
        if let OutputConfig::Http { headers, .. } = output {
            for value in headers.values_mut() {
                *value = resolve_env(value)?;
            }
        }
    }
    Ok(config)
}

/// Replace valid ASCII environment placeholders in one pass.
/// Malformed placeholders and replacement values remain literal.
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
pub fn secret_from_env(name: &str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::MissingEnv(name.to_owned()))
}

impl Config {
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
            if let OutputConfig::Http { method, .. } = output
                && !method.eq_ignore_ascii_case("PUT")
                && !method.eq_ignore_ascii_case("POST")
            {
                return Err(ConfigError::Invalid(
                    "HTTP method must be PUT or POST".into(),
                ));
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

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ThemeConfig {
    pub path: Option<PathBuf>,
}
