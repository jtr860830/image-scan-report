//! Stable report artifact names.
use crate::model::SourceKind;
use chrono::NaiveDate;

/// Normalize text into a safe filename component.
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

/// Compose a deterministic artifact basename from scope, source kind, and date.
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
