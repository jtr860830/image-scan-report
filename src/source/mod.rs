//! Scan sources (Harbor, NeuVector, Trivy files, NeuVector files) behind [`ScanSource`].
pub mod files;
pub mod harbor;
pub mod http;
pub mod neuvector;
pub mod neuvector_api;
pub mod neuvector_file;
pub mod trivy_file;

use crate::model::ScanSet;
use std::path::PathBuf;

/// Failure to collect scan data from a configured input.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum SourceError {
    /// The input directory is missing, is not a directory, or cannot be traversed.
    #[error("input directory {0} is not readable: {1}")]
    Unreadable(PathBuf, std::io::Error),
    /// No file in the directory was a recognised, parseable scan report.
    #[error("no scan results found in {0}")]
    Empty(PathBuf),
    /// An API source found no images in its scope, which the message names.
    #[error("no images found in {0}")]
    NoImages(String),
    /// Free-form message, such as an HTTP failure, a missing project, or a NeuVector login problem.
    #[error("{0}")]
    Other(String),
}
/// Source of normalised images and findings for one configured scope.
pub trait ScanSource {
    /// One-line label for logs and `check` output, such as `Harbor host: project`.
    fn describe(&self) -> String;
    /// Collect, normalise and deduplicate every image and finding in scope.
    ///
    /// # Errors
    ///
    /// File sources fail if the directory is unreadable or holds no usable report. API sources
    /// fail on transport errors (including a TLS handshake the configured roots reject),
    /// authentication or any failed listing request (including a missing
    /// Harbor project or NeuVector registry), on NeuVector login problems, or when the scope
    /// has no images; other per-image request failures mark that image as failed instead.
    fn fetch(&self) -> Result<ScanSet, SourceError>;
}
/// Failure to decode one scan report file; the directory walk logs it and skips the file.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum ParseError {
    /// The file is not valid JSON or does not match the expected field types.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON lacks a required value, such as Trivy's `ArtifactName`.
    #[error("{0}")]
    Shape(String),
}
