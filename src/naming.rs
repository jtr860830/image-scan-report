//! Deterministic file names for report artifacts.
use crate::model::SourceKind;
use chrono::NaiveDate;

/// Reduce text to lowercase ASCII letters and digits joined by single hyphens, or `report`.
#[must_use]
pub fn slug(s: &str) -> String {
    let mut result = String::new();
    let mut separator = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if separator && !result.is_empty() {
                result.push('-');
            }
            result.push(c.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    if result.is_empty() {
        "report".into()
    } else {
        result
    }
}

/// Compose the artifact basename `<slug(scope)>-<source kind>-<YYYY-MM-DD>`, without extension.
#[must_use]
pub fn artifact_base_name(scope: &str, kind: SourceKind, date: NaiveDate) -> String {
    let kind = match kind {
        SourceKind::TrivyFiles => "trivy-files",
        SourceKind::NeuvectorFiles => "neuvector-files",
        SourceKind::Harbor => "harbor",
        SourceKind::Neuvector => "neuvector",
    };
    format!("{}-{kind}-{date}", slug(scope))
}
