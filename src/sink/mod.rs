//! Report artifacts and output destinations.
pub mod filesystem;

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
            OutputConfig::Http { .. } => Err(ConfigError::Invalid(
                "http output arrives in a later release".into(),
            )),
        })
        .collect()
}
