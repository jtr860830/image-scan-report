//! Unified severity classification from cleaned CVSS scores and scanner labels.

use crate::model::{Severity, SeverityBasis};

/// Validated CVSS v3 and v2 measurements from one vendor source.
pub struct CvssScores {
    /// CVSS v3 score in the inclusive range zero to ten. None indicates that the value is unavailable.
    pub v3: Option<f32>,
    /// CVSS v2 score in the inclusive range zero to ten. None indicates that the value is unavailable.
    pub v2: Option<f32>,
}

/// Vendor CVSS measurements and an optional scanner severity label.
pub struct ScoreInput<'a> {
    /// CVSS measurements indexed by their vendor source names.
    pub cvss: &'a [(String, CvssScores)],
    /// Raw severity label supplied by the scanner. None indicates that the value is unavailable.
    pub scanner_label: Option<&'a str>,
}

/// Selected severity and the score evidence that determined it.
pub struct Classification {
    /// Normalized vulnerability severity band.
    pub severity: Severity,
    /// Rule that determined the effective severity.
    pub basis: SeverityBasis,
    /// CVSS v3 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v3: Option<f32>,
    /// CVSS v2 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v2: Option<f32>,
    /// Vendor source selected for the effective CVSS score. None indicates that the value is unavailable.
    pub score_source: Option<String>,
}

/// Keep finite CVSS scores in the inclusive range from zero to ten.
#[must_use]
pub fn clean_score(raw: Option<f64>) -> Option<f32> {
    raw.map(|score| ((score * 10.0).round() / 10.0) as f32)
        .filter(|score| score.is_finite() && *score > 0.0)
}

/// Classify a validated CVSS v3 score by its severity thresholds.
#[must_use]
pub fn band_v3(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else {
        band_v2(score)
    }
}

/// Classify a validated CVSS v2 score by its severity thresholds.
#[must_use]
pub fn band_v2(score: f32) -> Severity {
    if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unrated
    }
}

/// Recognize scanner severity labels, ignoring letter case.
#[must_use]
pub fn label_to_severity(label: &str) -> Option<Severity> {
    match label.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

fn source_priority(source: &str) -> (u8, &str) {
    match source {
        "nvd" => (0, source),
        "redhat" => (1, source),
        _ => (2, source),
    }
}

/// Choose a severity using CVSS v3, CVSS v2, then the scanner label.
#[must_use]
pub fn classify(input: &ScoreInput) -> Classification {
    // Select across v3 sources first, regardless of any v2 source's priority.
    if let Some((source, scores)) = input
        .cvss
        .iter()
        .filter(|(_, scores)| scores.v3.is_some())
        .min_by_key(|(source, _)| source_priority(source))
    {
        return Classification {
            severity: band_v3(scores.v3.expect("selected source has a v3 score")),
            basis: SeverityBasis::Cvss3,
            score_v3: scores.v3,
            score_v2: scores.v2,
            score_source: Some(source.clone()),
        };
    }

    if let Some((source, scores)) = input
        .cvss
        .iter()
        .filter(|(_, scores)| scores.v2.is_some())
        .min_by_key(|(source, _)| source_priority(source))
    {
        return Classification {
            severity: band_v2(scores.v2.expect("selected source has a v2 score")),
            basis: SeverityBasis::Cvss2,
            score_v3: None,
            score_v2: scores.v2,
            score_source: Some(source.clone()),
        };
    }

    let label_severity = input.scanner_label.and_then(label_to_severity);
    Classification {
        severity: label_severity.unwrap_or(Severity::Unrated),
        basis: if label_severity.is_some() {
            SeverityBasis::ScannerLabel
        } else {
            SeverityBasis::None
        },
        score_v3: None,
        score_v2: None,
        score_source: None,
    }
}

/// CVSS fields shared by Trivy and Harbor reports.
#[derive(Default, Clone, serde::Deserialize)]
pub struct CvssSourceScores {
    /// Raw CVSS v3 measurement supplied by the scanner. None indicates that the value is unavailable.
    #[serde(rename = "V3Score")]
    pub v3_score: Option<f64>,
    /// Raw CVSS v2 measurement supplied by the scanner. None indicates that the value is unavailable.
    #[serde(rename = "V2Score")]
    pub v2_score: Option<f64>,
}

/// Collect vendor CVSS scores in deterministic source order.
#[must_use]
pub fn cvss_from_map(
    map: &std::collections::BTreeMap<String, CvssSourceScores>,
) -> Vec<(String, CvssScores)> {
    map.iter()
        .map(|(name, scores)| {
            (
                name.clone(),
                CvssScores {
                    v3: clean_score(scores.v3_score),
                    v2: clean_score(scores.v2_score),
                },
            )
        })
        .collect()
}
