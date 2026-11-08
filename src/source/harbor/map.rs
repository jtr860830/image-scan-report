//! Conversion of Harbor responses into scanner-independent rows.
use super::api::*;
use crate::{
    model::*,
    severity::{ScoreInput, classify, cvss_from_map},
};
use std::fmt::Write;

pub fn platform_string(p: &Platform) -> String {
    let mut value = format!("{}/{}", p.os, p.architecture);
    if let Some(v) = p.variant.as_ref().filter(|s| !s.is_empty()) {
        value.push('/');
        value.push_str(v);
    }
    value
}
pub fn image_reference(
    repository: &str,
    tags: &[String],
    digest: &str,
    platform: Option<&str>,
) -> String {
    let mut value = if let Some(tag) = tags.iter().min() {
        format!("{repository}:{tag}")
    } else {
        format!("{repository}@{}", digest12(digest))
    };
    if let Some(p) = platform {
        write!(value, " ({p})").expect("writing to String");
    }
    value
}
pub fn scan_status(overview: Option<&ScanOverview>) -> ScanStatus {
    let status = overview.map(|o| o.scan_status.as_str()).unwrap_or("");
    let (state, error) = match status.to_ascii_lowercase().as_str() {
        "success" => (ScanState::Ok, None),
        "error" => (ScanState::Failed, Some(status.into())),
        "running" | "pending" | "scheduled" => {
            (ScanState::NotScanned, Some("scan in progress".into()))
        }
        "" => (ScanState::NotScanned, None),
        _ => (ScanState::Failed, Some(status.into())),
    };
    ScanStatus {
        state,
        error,
        scanned_at: overview.and_then(|o| o.end_time),
        scanner_version: overview
            .and_then(|o| o.scanner.as_ref())
            .and_then(|s| s.version.clone()),
    }
}
pub fn finding(v: &Vuln, image_reference: &str) -> Finding {
    let cvss = v
        .vendor_attributes
        .as_ref()
        .map(|a| cvss_from_map(&a.cvss))
        .unwrap_or_default();
    let c = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: Some(&v.severity),
    });
    Finding {
        id: v.id.clone(),
        image: image_reference.into(),
        severity: c.severity,
        severity_basis: c.basis,
        score_v3: c.score_v3,
        score_v2: c.score_v2,
        score_source: c.score_source,
        scanner_severity: Some(v.severity.clone()),
        package: v.package.clone(),
        installed_version: v.version.clone(),
        fixed_version: v.fix_version.clone().filter(|s| !s.is_empty()),
        fix_status: v.status.as_deref().map(FixStatus::parse),
        description: v.description.clone().unwrap_or_default(),
        links: v.links.clone(),
        published_at: None,
    }
}

/// Infer a usable platform from child or single-manifest metadata.
pub fn platform_from_attrs(attrs: &ExtraAttrs) -> Option<String> {
    let os = attrs
        .os
        .as_ref()
        .filter(|s| !s.is_empty() && *s != "unknown")?;
    let architecture = attrs
        .architecture
        .as_ref()
        .filter(|s| !s.is_empty() && *s != "unknown")?;
    Some(platform_string(&Platform {
        os: os.clone(),
        architecture: architecture.clone(),
        variant: attrs.variant.clone(),
    }))
}

pub(super) fn digest12(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .chars()
        .take(12)
        .collect()
}
