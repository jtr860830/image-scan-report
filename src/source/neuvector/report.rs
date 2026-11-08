//! Vulnerability mapping shared by NeuVector scanner and controller reports.
use crate::model::Finding;
use crate::severity::{CvssScores, ScoreInput};
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// NeuVector vulnerability fields preserved for normalization.
#[derive(Deserialize)]
pub struct NvVulnerability {
    /// Display name supplied by the scanner or theme.
    pub name: String,
    /// Normalized vulnerability severity band.
    pub severity: String,
    /// Effective CVSS score selected for severity classification. None indicates that the value is unavailable.
    pub score: Option<f64>,
    /// CVSS v3 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v3: Option<f64>,
    /// Affected software package identifier supplied by NeuVector.
    pub package_name: String,
    /// Installed software version supplied by NeuVector.
    pub package_version: String,
    /// Package version containing the fix, when the scanner supplies one. None indicates that the value is unavailable.
    pub fixed_version: Option<String>,
    /// External advisory URL supplied by the scanner. None indicates that the value is unavailable.
    pub link: Option<String>,
    /// Human-readable explanation of the vulnerability. None indicates that the value is unavailable.
    pub description: Option<String>,
    /// Advisory publication time in Unix seconds. None indicates that the value is unavailable.
    pub published_timestamp: Option<i64>,
    /// File path identifying the affected package, or None when the scanner omits it.
    pub file_name: Option<String>,
}

/// Convert optional Unix seconds to UTC, using None for missing or invalid timestamps.
pub fn nv_timestamp(secs: Option<i64>) -> Option<DateTime<Utc>> {
    secs.filter(|s| *s != 0)
        .and_then(|s| DateTime::from_timestamp(s, 0))
}

/// Normalize a NeuVector vulnerability for the supplied image reference.
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

/// Compose the same image reference for scanner files and controller results.
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
