//! Report artifacts and output destinations.
pub mod filesystem;
pub mod http;

use crate::config::{ConfigError, OutputConfig};

/// One encoded report file, handed to every configured sink.
pub struct Artifact {
    /// Basename such as `<scope>-<kind>-<date>.pdf`, built with [`crate::naming`].
    pub file_name: String,
    /// MIME type: `application/pdf` or `application/json`.
    pub media_type: &'static str,
    /// Encoded file contents.
    pub bytes: Vec<u8>,
}

/// Failure to store an encoded report artifact.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum SinkError {
    /// Creating, writing or renaming a file in a filesystem sink failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Free-form message, such as a failed HTTP upload or an unusable system clock.
    #[error("{0}")]
    Other(String),
}

/// Destination capable of storing encoded report artifacts.
pub trait ReportSink {
    /// One-line label for logs and the run summary, such as `Filesystem: /out`.
    fn describe(&self) -> String;
    /// Write one artifact; a filesystem sink replaces any file of the same name.
    ///
    /// # Errors
    ///
    /// Filesystem sinks fail if the directory cannot be created or the temporary file cannot be
    /// written or renamed into place. HTTP sinks fail if the request cannot be built or sent,
    /// or the server answers with a status of 300 or more.
    ///
    /// # Panics
    ///
    /// In debug builds, the HTTP sink panics if `file_name` contains a quote or a line break.
    fn store(&self, artifact: &Artifact) -> Result<(), SinkError>;
}

/// Construct output destinations after validating their configuration.
///
/// # Errors
///
/// Fails if an HTTP destination has conflicting TLS options or an unreadable or invalid CA bundle.
pub fn build_sinks(cfg: &[OutputConfig]) -> Result<Vec<Box<dyn ReportSink>>, ConfigError> {
    cfg.iter()
        .map(|output| match output {
            OutputConfig::Filesystem { path } => {
                Ok(Box::new(filesystem::FilesystemSink { dir: path.clone() })
                    as Box<dyn ReportSink>)
            }
            OutputConfig::Http {
                url,
                method,
                headers,
                mode,
                ca_file,
                insecure_skip_verify,
                timeout_secs,
            } => {
                let client = crate::source::http::tls_client(
                    "output",
                    url,
                    ca_file.as_deref(),
                    *timeout_secs,
                    *insecure_skip_verify,
                )?;
                Ok(Box::new(http::HttpSink::new(
                    url.clone(),
                    method.clone(),
                    headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    *mode,
                    client,
                )) as Box<dyn ReportSink>)
            }
        })
        .collect()
}
