//! Report artifacts and output destinations.
/// Atomic filesystem artifact storage.
pub mod filesystem;
/// HTTP artifact uploads.
pub mod http;

use crate::config::{ConfigError, OutputConfig};

/// Encoded report bytes with a destination filename and media type.
pub struct Artifact {
    /// Artifact basename, including its format extension.
    pub file_name: String,
    /// MIME type describing the encoded artifact.
    pub media_type: &'static str,
    /// Raw bytes of the encoded artifact or branding asset. An empty list indicates no entries.
    pub bytes: Vec<u8>,
}

/// Failure to store an encoded report artifact.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum SinkError {
    /// A filesystem operation failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Preserve an unrecognized value or an additional diagnostic.
    #[error("{0}")]
    Other(String),
}

/// Destination capable of storing encoded report artifacts.
pub trait ReportSink {
    /// Describe the configured endpoint or directory for diagnostics.
    fn describe(&self) -> String;
    /// Write an artifact to the configured destination.
    ///
    /// # Panics
    ///
    /// In debug builds, HTTP destinations panic if a filename contains quotes or line breaks.
    ///
    /// # Errors
    ///
    /// Fails when input cannot be read or decoded, configuration is invalid, or a downstream operation fails.
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
