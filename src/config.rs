//! YAML configuration and explicit environment-variable resolution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{Language, Severity};

/// Parsed configuration file; [`load`] validates it before returning it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Theme override; when omitted, the embedded default theme is used.
    #[serde(default)]
    pub theme: ThemeConfig,
    /// Scan source to collect from.
    pub source: SourceConfig,
    /// Report content, language and enabled formats.
    pub report: ReportConfig,
    /// Artifact destinations, each receiving every artifact; `validate` rejects an empty list.
    pub output: Vec<OutputConfig>,
}

/// Scan source selected by the YAML `type` key (`trivy-files`, `neuvector-files`, `harbor`,
/// `neuvector`).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceConfig {
    /// Read Trivy JSON reports from a directory tree.
    TrivyFiles {
        /// Directory searched recursively for Trivy `*.json` reports.
        path: PathBuf,
    },
    /// Read NeuVector scanner JSON results from a directory tree.
    NeuvectorFiles {
        /// Directory searched recursively for NeuVector scanner `*.json` results.
        path: PathBuf,
    },
    /// Collect scan data through the Harbor v2 API.
    Harbor {
        /// Harbor base URL; `validate` requires `http` or `https` without embedded credentials.
        url: String,
        /// Harbor project to report on; `None` walks every project the account can list.
        project: Option<String>,
        /// Harbor account name, sent with HTTP Basic authentication.
        username: String,
        /// Name of the environment variable holding the Harbor password, read when connecting.
        password_env: String,
        /// PEM bundle that replaces the built-in roots; cannot be combined with
        /// `insecure_skip_verify`.
        ca_file: Option<PathBuf>,
        /// Timeout for each HTTP request in seconds; defaults to 30 and must be greater than zero.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// Whether to skip TLS certificate verification, with a warning; defaults to `false`.
        #[serde(default)]
        insecure_skip_verify: bool,
    },
    /// Collect scan data through the NeuVector controller REST API.
    Neuvector {
        /// NeuVector controller API base URL; `validate` requires `http` or `https` without
        /// embedded credentials.
        url: String,
        /// Name of the NeuVector registry configuration to report on.
        registry: String,
        /// NeuVector account name, sent in the login request.
        username: String,
        /// Name of the environment variable holding the NeuVector password, read when connecting.
        password_env: String,
        /// PEM bundle that replaces the built-in roots; cannot be combined with
        /// `insecure_skip_verify`.
        ca_file: Option<PathBuf>,
        /// Timeout for each HTTP request in seconds; defaults to 30 and must be greater than zero.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// Whether to skip TLS certificate verification, with a warning; defaults to `false`.
        #[serde(default)]
        insecure_skip_verify: bool,
    },
}

/// Content limits, language, branding and artifact formats of the report.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    /// Bands whose findings show their description in the image tables; defaults to critical
    /// and high.
    #[serde(default = "default_describe_severities")]
    pub describe_severities: Vec<Severity>,
    /// Characters kept from each description before `…` is appended; defaults to 600, minimum 50.
    #[serde(default = "default_description_chars")]
    pub description_chars: usize,
    /// Remediation groups shown as cards before the rest move to a table; defaults to 30.
    #[serde(default = "default_remediation_cards")]
    pub remediation_cards: usize,
    /// Report language, `en` or `zh-TW`, selecting the bundled strings.
    pub language: Language,
    /// Organisation name printed on the cover; must not be blank.
    pub organization: String,
    /// Customer logo (`.png` or `.svg`) printed on the cover; `None` prints no customer logo.
    pub logo: Option<PathBuf>,
    /// Successful scans older than this many days are listed as stale; defaults to 30.
    #[serde(default = "default_stale")]
    pub stale_after_days: u32,
    /// Whether to also store the normalised report as a JSON artifact; defaults to `false`.
    #[serde(default)]
    pub json: bool,
    /// Whether to render the PDF artifact; defaults to `true`.
    #[serde(default = "default_pdf")]
    pub pdf: bool,
}

/// Artifact destination selected by the YAML `type` key (`filesystem` or `http`).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OutputConfig {
    /// Write artifacts atomically into a local directory.
    Filesystem {
        /// Directory that receives the artifacts, created if missing.
        path: PathBuf,
    },
    /// Upload each artifact to an HTTP endpoint.
    Http {
        /// Upload URL; `{filename}` is replaced by the encoded artifact name. `validate` requires
        /// `http` or `https` with a host and no credentials.
        url: String,
        /// Upload method, `PUT` (default) or `POST` in any case; `load` uppercases it.
        #[serde(default = "default_put")]
        method: String,
        /// Extra request headers; `load` expands `${VAR}` references in their values.
        #[serde(default)]
        headers: BTreeMap<String, String>,
        /// Body encoding of each upload; defaults to `raw`.
        #[serde(default)]
        mode: HttpMode,
        /// PEM bundle that replaces the built-in roots; cannot be combined with
        /// `insecure_skip_verify`.
        ca_file: Option<PathBuf>,
        /// Whether to skip TLS certificate verification, with a warning; defaults to `false`.
        #[serde(default)]
        insecure_skip_verify: bool,
        /// Timeout for each HTTP request in seconds; defaults to 30 and must be greater than zero.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

/// HTTP artifact encoding, either raw bytes or multipart form data.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMode {
    /// Send the artifact bytes as the body, with a `Content-Disposition` header.
    #[default]
    Raw,
    /// Send a `multipart/form-data` body carrying the artifact in the `file` field.
    Multipart,
}

/// Failure to read, decode, or validate the configuration or the inputs it names.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum ConfigError {
    /// No candidate configuration file exists.
    #[error("{}", lookup_error_message(.candidates, .moved_from))]
    NotFound {
        /// Configuration paths searched in lookup order.
        candidates: Vec<PathBuf>,
        /// Historical configuration path, when it still exists.
        moved_from: Option<PathBuf>,
    },
    /// The configuration file could not be read.
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// The YAML could not be decoded into [`Config`].
    #[error("invalid configuration: {0}")]
    Parse(String),
    /// A referenced environment variable is unset or not valid Unicode.
    #[error("environment variable {0} is not set")]
    MissingEnv(String),
    /// A value failed validation, or the theme, logo or TLS setup it names is unusable.
    #[error("{0}")]
    Invalid(String),
}

/// Candidate configuration files in lookup order for a product called `name`:
/// `$<NAME>_CONFIG`, `$XDG_CONFIG_HOME/<name>/config.yaml` (or `$HOME/.config/<name>/config.yaml`), `/etc/<name>/config.yaml`.
/// `env` returns the value of a variable; it is a parameter so tests need not touch the process environment.
pub fn candidate_paths(name: &str, env: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env(&format!("{}_CONFIG", name.to_uppercase())) {
        candidates.push(PathBuf::from(path));
    }
    let xdg = env("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        });
    if let Some(base) = xdg {
        candidates.push(base.join(name).join("config.yaml"));
    }
    candidates.push(Path::new("/etc").join(name).join("config.yaml"));
    candidates
}

/// First existing candidate, or `ConfigError::NotFound { candidates, moved_from: Option<PathBuf> }`.
///
/// # Errors
///
/// Returns [`ConfigError::NotFound`] if no candidate is a file.
pub fn default_path(
    name: &str,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    let candidates = candidate_paths(name, env);
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        return Ok(path.clone());
    }
    let old = Path::new("/etc/report/config.yaml");
    Err(ConfigError::NotFound {
        candidates,
        moved_from: old.is_file().then(|| old.to_owned()),
    })
}

fn lookup_error_message(candidates: &[PathBuf], moved_from: &Option<PathBuf>) -> String {
    let mut message = String::from("configuration not found; searched:");
    for path in candidates {
        message.push_str(&format!("\n{}", path.display()));
    }
    if moved_from.is_some()
        && let Some(destination) = candidates.last()
    {
        message.push_str(&format!(
            "\nconfiguration moved to {} in 0.2.0",
            destination.display()
        ));
    }
    message
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
/// Fails if the file cannot be read or decoded, [`Config::validate`] rejects it, or a header
/// references an unset environment variable.
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
    /// Check the constraints that deserialisation cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if a source or HTTP output URL is not a credential-free
    /// `http` or `https` URL, `ca_file` is combined with `insecure_skip_verify`, a timeout is
    /// zero, `description_chars` is below 50, `output` is empty, neither `pdf` nor `json` is
    /// enabled, an output method is not PUT or POST, a PUT output lacks `{filename}` while
    /// `json` is enabled, or `organization` is blank.
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

/// Optional theme directory that replaces the embedded report theme.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ThemeConfig {
    /// Directory holding `theme.toml` and an optional `logo.png` or `logo.svg`; `None` uses the
    /// embedded default theme.
    pub path: Option<PathBuf>,
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    #[test]
    fn candidates_follow_xdg_then_etc() {
        let env = |k: &str| match k {
            "XDG_CONFIG_HOME" => Some("/xdg".into()),
            "HOME" => Some("/home/u".into()),
            _ => None,
        };
        assert_eq!(
            candidate_paths("prod", &env),
            [
                PathBuf::from("/xdg/prod/config.yaml"),
                "/etc/prod/config.yaml".into()
            ]
        );
    }

    #[test]
    fn explicit_env_variable_comes_first() {
        let env = |k: &str| (k == "PROD_CONFIG").then(|| "/x/c.yaml".into());
        assert_eq!(candidate_paths("prod", &env)[0], Path::new("/x/c.yaml"));
    }

    #[test]
    fn relative_or_empty_xdg_config_home_is_ignored() {
        for value in ["rel", ""] {
            let env = |k: &str| match k {
                "XDG_CONFIG_HOME" => Some(value.into()),
                "HOME" => Some("/home/u".into()),
                _ => None,
            };
            assert_eq!(
                candidate_paths("prod", &env)[0],
                Path::new("/home/u/.config/prod/config.yaml")
            );
        }
    }

    #[test]
    fn missing_home_skips_the_xdg_candidate() {
        for home in [None, Some("")] {
            let env = |k: &str| {
                if k == "HOME" {
                    home.map(Into::into)
                } else {
                    None
                }
            };
            assert_eq!(
                candidate_paths("prod", &env),
                [PathBuf::from("/etc/prod/config.yaml")]
            );
        }
    }

    #[test]
    fn default_path_returns_first_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prod/config.yaml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        let explicit = dir.path().join("explicit.yaml");
        let env = |k: &str| match k {
            "XDG_CONFIG_HOME" => Some(dir.path().as_os_str().to_owned()),
            "PROD_CONFIG" => Some(explicit.as_os_str().to_owned()),
            _ => None,
        };
        assert_eq!(default_path("prod", &env).unwrap(), path);
        std::fs::write(&explicit, "").unwrap();
        assert_eq!(default_path("prod", &env).unwrap(), explicit);
    }

    #[test]
    fn default_path_error_lists_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let env = |k: &str| (k == "XDG_CONFIG_HOME").then(|| dir.path().as_os_str().to_owned());
        let error = default_path("prod", &env).unwrap_err();
        let ConfigError::NotFound { candidates, .. } = &error else {
            panic!("unexpected error")
        };
        for candidate in candidates {
            assert!(
                error
                    .to_string()
                    .lines()
                    .any(|line| line == candidate.display().to_string())
            );
        }
    }
}
