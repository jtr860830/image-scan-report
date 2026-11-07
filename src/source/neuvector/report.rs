//! Vulnerability mapping shared by NeuVector scanner and controller reports.
use crate::{
    model::Finding,
    severity::{CvssScores, ScoreInput, classify, clean_score},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct NvVulnerability {
    pub name: String,
    pub severity: String,
    pub score: Option<f64>,
    pub score_v3: Option<f64>,
    pub package_name: String,
    pub package_version: String,
    pub fixed_version: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub published_timestamp: Option<i64>,
    pub file_name: Option<String>,
}

pub fn nv_timestamp(secs: Option<i64>) -> Option<DateTime<Utc>> {
    secs.filter(|s| *s != 0)
        .and_then(|s| DateTime::from_timestamp(s, 0))
}

pub fn finding_from_nv(v: &NvVulnerability, image_reference: &str) -> Finding {
    let cvss = [(
        "neuvector".into(),
        CvssScores {
            v3: clean_score(v.score_v3),
            v2: clean_score(v.score),
        },
    )];
    let c = classify(&ScoreInput {
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
