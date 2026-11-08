//! Scanner input sources and shared file parsing errors.
/// Shared discovery, timestamps, and stable deduplication.
pub mod files;
/// Harbor v2 API source.
pub mod harbor;
/// Shared synchronous HTTP transport for API scan sources.
pub mod http;
/// NeuVector report types shared by file and controller API sources.
pub mod neuvector;
/// Provide neuvector api types and operations.
pub mod neuvector_api;
/// Provide neuvector file types and operations.
pub mod neuvector_file;
/// Provide trivy file types and operations.
pub mod trivy_file;

use crate::model::ScanSet;
use std::path::PathBuf;

/// Failure to collect scan data from a configured input.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum SourceError {
    /// The input directory cannot be read.
    #[error("input directory {0} is not readable: {1}")]
    Unreadable(PathBuf, std::io::Error),
    /// No supported scan result files were found in the directory.
    #[error("no scan results found in {0}")]
    Empty(PathBuf),
    /// The source returned no usable image records.
    #[error("no images found in {0}")]
    NoImages(String),
    /// Preserve an unrecognized value or an additional diagnostic.
    #[error("{0}")]
    Other(String),
}
/// Provider of normalized image and vulnerability records.
pub trait ScanSource {
    /// Describe the configured endpoint or directory for diagnostics.
    fn describe(&self) -> String;
    /// Collect normalized images and findings from the configured source.
    ///
    /// # Errors
    ///
    /// Fails when input cannot be read or decoded, configuration is invalid, or a downstream operation fails.
    fn fetch(&self) -> Result<ScanSet, SourceError>;
}
/// Failure to decode JSON or recognize the expected scanner document shape.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum ParseError {
    /// The input is not valid JSON for the expected representation.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON document does not have the required scanner structure.
    #[error("{0}")]
    Shape(String),
}
