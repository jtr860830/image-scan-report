//! Scanner input sources and shared file parsing errors.
pub mod files;
pub mod harbor;
pub mod http;
pub mod neuvector;
pub mod neuvector_api;
pub mod neuvector_file;
pub mod trivy_file;

use crate::model::ScanSet;
use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum SourceError {
    #[error("input directory {0} is not readable: {1}")]
    Unreadable(PathBuf, std::io::Error),
    #[error("no scan results found in {0}")]
    Empty(PathBuf),
    #[error("no images found in {0}")]
    NoImages(String),
    #[error("{0}")]
    Other(String),
}
pub trait ScanSource {
    fn describe(&self) -> String;
    fn fetch(&self) -> Result<ScanSet, SourceError>;
}
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Shape(String),
}
