//! Library behind the report binary: it collects container-image vulnerability scans from
//! Harbor, NeuVector or Trivy files, classifies severity on one scale (CVSS v3 bands, with
//! v2 and scanner labels as fallbacks), renders an audit PDF in English or Traditional
//! Chinese with Typst and stores the artifacts in filesystem or HTTP sinks.

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
