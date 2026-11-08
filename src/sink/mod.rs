//! Report artifacts and output destinations.
pub mod filesystem;
pub mod http;

use crate::config::{ConfigError, OutputConfig};

pub struct Artifact {
    pub file_name: String,
    pub media_type: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum SinkError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub trait ReportSink {
    fn describe(&self) -> String;
    fn store(&self, artifact: &Artifact) -> Result<(), SinkError>;
}

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
                let client = crate::pipeline::tls_client(
                    "output",
                    url,
                    ca_file.as_deref(),
                    *timeout_secs,
                    *insecure_skip_verify,
                )?;
                Ok(Box::new(http::HttpSink::new(
                    url.clone(),
                    method.to_ascii_uppercase(),
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
