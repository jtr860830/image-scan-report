//! Derived report views over normalised findings and images.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::model::{Finding, Image, ScanState, Severity};

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unrated: usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unrated
    }

    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unrated => self.unrated += 1,
        }
    }

    pub fn high_or_worse(&self) -> usize {
        self.critical + self.high
    }

    fn rank(&self) -> (usize, usize, usize, usize) {
        (self.critical, self.high, self.medium, self.low)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UniqueVulnerability {
    pub id: String,
    pub severity: Severity,
    pub score_v3: Option<f32>,
    pub packages: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub images: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemediationGroup {
    pub package: String,
    pub fixed_version: String,
    pub resolves: SeverityCounts,
    pub images: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageSummary {
    pub reference: String,
    pub counts: SeverityCounts,
}

pub fn counts(findings: &[Finding]) -> SeverityCounts {
    let mut result = SeverityCounts::default();
    for finding in findings {
        result.add(finding.severity);
    }
    result
}

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

pub fn unique_vulnerabilities(findings: &[Finding]) -> Vec<UniqueVulnerability> {
    let mut groups = BTreeMap::new();
    for f in findings {
        let group = groups.entry(&f.id).or_insert_with(|| UniqueVulnerability {
            id: f.id.clone(),
            severity: f.severity,
            score_v3: f.score_v3,
            packages: vec![],
            fixed_versions: vec![],
            images: vec![],
        });
        group.severity = group.severity.max(f.severity);
        if let Some(score) = f.score_v3 {
            group.score_v3 = Some(group.score_v3.map_or(score, |old| old.max(score)));
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
            .then_with(|| match (a.score_v3, b.score_v3) {
                (Some(a), Some(b)) => b.total_cmp(&a),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    result
}

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

pub fn images_with_high_or_worse(summaries: &[ImageSummary]) -> usize {
    summaries
        .iter()
        .filter(|s| s.counts.high_or_worse() > 0)
        .count()
}

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
