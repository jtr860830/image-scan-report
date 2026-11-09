//! Normalised vulnerability severity bands.
use serde::{Deserialize, Serialize};

/// Normalised severity band, ordered `Unrated < Low < Medium < High < Critical`.
///
/// The derived `Ord` follows declaration order, so the views sort descending to list the
/// worst findings first and use `max` to keep the worst band of a group.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No usable CVSS score and no recognised scanner label.
    Unrated,
    /// CVSS score from 0.1 to 3.9, or the scanner label `low`.
    Low,
    /// CVSS score from 4.0 to 6.9, or the scanner label `medium`.
    Medium,
    /// CVSS v3 score from 7.0 to 8.9, any CVSS v2 score from 7.0, or the label `high`.
    High,
    /// CVSS v3 score of 9.0 or more, or the scanner label `critical`.
    Critical,
}

impl Severity {
    /// Return the English label, such as `Critical`; lowercased, it is the template severity key.
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Unrated => "Unrated",
        }
    }
}
