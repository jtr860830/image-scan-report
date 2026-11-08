//! Core library for the image scan reporting tool.

/// Command-line arguments and supported report operations.
pub mod cli;
/// YAML configuration and explicit environment-variable resolution.
pub mod config;
/// Normalised scanner data shared by the report pipeline.
pub mod model;
/// Unified severity classification from cleaned CVSS scores and scanner labels.
pub mod severity;

/// Scanner input sources and shared file parsing errors.
pub mod source;

/// Derived report views over normalised findings and images.
pub mod views;

/// Stable report artifact names.
pub mod naming;
/// Fetch scan results, assemble reports, and store artifacts.
pub mod pipeline;
/// Report artifacts and output destinations.
pub mod sink;

/// Report rendering with embedded templates and fonts.
pub mod render;
