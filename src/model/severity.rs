//! Normalized vulnerability severity bands.
use serde::{Deserialize, Serialize};

/// Normalized vulnerability risk bands ordered from critical to unrated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No recognized severity evidence is available.
    Unrated,
    /// The vulnerability has low impact.
    Low,
    /// The vulnerability has moderate impact.
    Medium,
    /// The vulnerability has high impact.
    High,
    /// The vulnerability has critical impact.
    Critical,
}

impl Severity {
    /// Select the English display label for a severity band.
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
