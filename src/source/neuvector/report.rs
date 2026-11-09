//! Vulnerability mapping shared by NeuVector scanner and controller reports.
use crate::model::Finding;
use crate::severity::{CvssScores, ScoreInput};
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// NeuVector vulnerability record, shared by scanner files and controller reports.
#[derive(Deserialize)]
pub struct NvVulnerability {
    /// CVE identifier, which becomes `Finding::id`.
    pub name: String,
    /// NeuVector's raw severity label, passed to `classify` and kept as `scanner_severity`.
    pub severity: String,
    /// NeuVector's CVSS v2 score, used when `score_v3` is missing or unusable.
    pub score: Option<f64>,
    /// NeuVector's CVSS v3 score, preferred by `classify`.
    pub score_v3: Option<f64>,
    /// Name of the affected package.
    pub package_name: String,
    /// Installed package version.
    pub package_version: String,
    /// Fixed version; `None` or empty when NeuVector lists no fix.
    pub fixed_version: Option<String>,
    /// Advisory URL; an empty string is dropped.
    pub link: Option<String>,
    /// Advisory text; `None` becomes an empty description.
    pub description: Option<String>,
    /// Advisory publication time in Unix seconds; zero means unknown.
    pub published_timestamp: Option<i64>,
    /// Path of the file that holds the package, when NeuVector reports it; not read.
    pub file_name: Option<String>,
}

/// Convert Unix seconds to UTC, treating `None`, zero and out-of-range values as unknown.
pub fn nv_timestamp(secs: Option<i64>) -> Option<DateTime<Utc>> {
    secs.filter(|s| *s != 0)
        .and_then(|s| DateTime::from_timestamp(s, 0))
}

/// Normalise a NeuVector vulnerability for `image_reference`, under the `neuvector` source.
pub fn finding_from_nv(v: &NvVulnerability, image_reference: &str) -> Finding {
    let cvss = [(
        "neuvector".into(),
        CvssScores {
            v3: crate::severity::clean_score(v.score_v3),
            v2: crate::severity::clean_score(v.score),
        },
    )];
    let c = crate::severity::classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: Some(&v.severity),
    });
    Finding {
        id: v.name.clone(),
        image: image_reference.into(),
        severity: c.severity,
        severity_basis: c.basis,
        score_v3: c.score_v3,
        score_v2: c.score_v2,
        score_source: c.score_source,
        scanner_severity: Some(v.severity.clone()),
        package: v.package_name.clone(),
        installed_version: v.package_version.clone(),
        fixed_version: v.fixed_version.clone().filter(|s| !s.is_empty()),
        fix_status: None,
        description: v.description.clone().unwrap_or_default(),
        links: v.link.iter().filter(|s| !s.is_empty()).cloned().collect(),
        published_at: nv_timestamp(v.published_timestamp),
    }
}

/// Build `registry/repository[:tag]`, without the registry's scheme or trailing slashes, so
/// file and API sources produce the same reference.
pub fn compose_reference(registry: &str, repository: &str, tag: &str) -> String {
    let registry = registry
        .strip_prefix("https://")
        .or_else(|| registry.strip_prefix("http://"))
        .unwrap_or(registry)
        .trim_end_matches('/');
    let mut reference = if registry.is_empty() {
        repository.to_owned()
    } else {
        format!("{registry}/{repository}")
    };
    if !tag.is_empty() {
        reference.push(':');
        reference.push_str(tag);
    }
    reference
}
