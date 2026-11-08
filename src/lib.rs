//! Library behind the report binary: it collects container-image vulnerability scans from
//! Harbor, NeuVector or Trivy files, classifies severity on one CVSS v3 scale, renders a
//! bilingual audit PDF with Typst and stores the artifacts in filesystem or HTTP sinks.

pub mod cli;
pub mod config;
pub mod model;
pub mod severity;

pub mod source;

pub mod views;

pub mod naming;
pub mod pipeline;
pub mod sink;

pub mod render;
