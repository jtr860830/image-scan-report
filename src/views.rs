//! Derived report views over normalised findings and images.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::model::{Finding, Image, ScanState, Severity};

/// Finding totals for each normalized severity band.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    /// Number of findings in the critical severity band.
    pub critical: usize,
    /// Number of findings in the high severity band.
    pub high: usize,
    /// Number of findings in the medium severity band.
    pub medium: usize,
    /// Number of findings in the low severity band.
    pub low: usize,
    /// Number of findings in the unrated severity band.
    pub unrated: usize,
}

impl SeverityCounts {
    /// Sum the counts across all severity bands.
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unrated
    }

    /// Increment the count for a normalized severity band.
    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unrated => self.unrated += 1,
        }
    }

    /// Sum the critical and high severity counts.
    pub fn high_or_worse(&self) -> usize {
        self.critical + self.high
    }

    fn rank(&self) -> (usize, usize, usize, usize) {
        (self.critical, self.high, self.medium, self.low)
    }
}

/// Deduplicated vulnerability with its affected packages and image references.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UniqueVulnerability {
    /// Scanner-provided vulnerability identifier.
    pub id: String,
    /// Normalized vulnerability severity band.
    pub severity: Severity,
    /// CVSS v3 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v3: Option<f32>,
    /// Effective CVSS score selected for severity classification. None indicates that the value is unavailable.
    pub score: Option<f32>,
    /// Affected package names in this vulnerability group. An empty list indicates no entries.
    pub packages: Vec<String>,
    /// Package versions that resolve the grouped vulnerabilities. An empty list indicates no entries.
    pub fixed_versions: Vec<String>,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<String>,
}

/// Findings resolved by upgrading one package to a target version.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemediationGroup {
    /// Affected software package identifier.
    pub package: String,
    /// Package version containing the fix, when the scanner supplies one.
    pub fixed_version: String,
    /// Severity counts for findings resolved by this upgrade.
    pub resolves: SeverityCounts,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<String>,
}

/// Severity totals for one image reference.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageSummary {
    /// Canonical image reference used to associate findings with an image.
    pub reference: String,
    /// Finding totals grouped by normalized severity.
    pub counts: SeverityCounts,
}

/// Count findings in each normalized severity band.
#[must_use]
pub fn counts(findings: &[Finding]) -> SeverityCounts {
    let mut result = SeverityCounts::default();
    for finding in findings {
        result.add(finding.severity);
    }
    result
}

/// Count findings that provide a nonempty fixed version.
#[must_use]
pub fn fixable(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|f| f.fixed_version.is_some())
        .count()
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

/// Group findings by vulnerability identifier with affected packages and images.
#[must_use]
pub fn unique_vulnerabilities(findings: &[Finding]) -> Vec<UniqueVulnerability> {
    let mut groups = BTreeMap::new();
    for f in findings {
        let group = groups.entry(&f.id).or_insert_with(|| UniqueVulnerability {
            id: f.id.clone(),
            severity: f.severity,
            score_v3: f.score_v3,
            score: f.score_v3.or(f.score_v2),
            packages: vec![],
            fixed_versions: vec![],
            images: vec![],
        });
        group.severity = group.severity.max(f.severity);
        if let Some(score) = f.score_v3 {
            group.score_v3 = Some(group.score_v3.map_or(score, |old| old.max(score)));
        }
        if let Some(score) = f.score_v3.or(f.score_v2) {
            group.score = Some(group.score.map_or(score, |old| old.max(score)));
        }
        group.packages.push(f.package.clone());
        if let Some(version) = &f.fixed_version {
            group.fixed_versions.push(version.clone());
        }
        group.images.push(f.image.clone());
    }
    let mut result: Vec<_> = groups.into_values().collect();
    for group in &mut result {
        sort_dedup(&mut group.packages);
        sort_dedup(&mut group.fixed_versions);
        sort_dedup(&mut group.images);
    }
    result.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| match (a.score, b.score) {
                (Some(a), Some(b)) => b.total_cmp(&a),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    result
}

/// Group fixable findings by package and target version.
#[must_use]
pub fn remediation_groups(findings: &[Finding]) -> Vec<RemediationGroup> {
    let mut groups = BTreeMap::new();
    for f in findings {
        let Some(version) = &f.fixed_version else {
            continue;
        };
        let group = groups
            .entry((&f.package, version))
            .or_insert_with(|| RemediationGroup {
                package: f.package.clone(),
                fixed_version: version.clone(),
                resolves: SeverityCounts::default(),
                images: vec![],
            });
        group.resolves.add(f.severity);
        group.images.push(f.image.clone());
    }
    let mut result: Vec<_> = groups.into_values().collect();
    for group in &mut result {
        sort_dedup(&mut group.images);
    }
    result.sort_by(|a, b| {
        b.resolves
            .rank()
            .cmp(&a.resolves.rank())
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.fixed_version.cmp(&b.fixed_version))
    });
    result
}

/// Count findings by severity for each image reference.
#[must_use]
pub fn image_summaries(images: &[Image], findings: &[Finding]) -> Vec<ImageSummary> {
    let mut by_image = BTreeMap::new();
    for f in findings {
        by_image
            .entry(f.image.as_str())
            .or_insert_with(SeverityCounts::default)
            .add(f.severity);
    }
    let mut result: Vec<_> = images
        .iter()
        .map(|image| ImageSummary {
            reference: image.reference.clone(),
            counts: by_image
                .get(image.reference.as_str())
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    result.sort_by(|a, b| {
        b.counts
            .rank()
            .cmp(&a.counts.rank())
            .then_with(|| a.reference.cmp(&b.reference))
    });
    result
}

/// Count images with at least one high or critical finding.
#[must_use]
pub fn images_with_high_or_worse(summaries: &[ImageSummary]) -> usize {
    summaries
        .iter()
        .filter(|s| s.counts.high_or_worse() > 0)
        .count()
}

/// Select images whose scan age exceeds the configured number of days.
#[must_use]
pub fn stale_images(images: &[Image], now: DateTime<Utc>, stale_after_days: u32) -> Vec<&Image> {
    // An unrepresentable threshold precedes every representable scan timestamp.
    let threshold = now.checked_sub_signed(Duration::days(i64::from(stale_after_days)));
    images
        .iter()
        .filter(|image| {
            image.scan.state == ScanState::Ok
                && image
                    .scan
                    .scanned_at
                    .is_none_or(|time| threshold.is_some_and(|limit| time < limit))
        })
        .collect()
}
