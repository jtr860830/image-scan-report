//! Unified severity classification from cleaned CVSS scores and scanner labels.

use crate::model::{Severity, SeverityBasis};

/// CVSS v3 and v2 scores from one vendor source, already passed through [`clean_score`].
pub struct CvssScores {
    /// CVSS v3 score, rounded to one decimal and greater than zero, as reported.
    pub v3: Option<f32>,
    /// CVSS v2 score, rounded to one decimal and greater than zero, as reported.
    pub v2: Option<f32>,
}

/// Vendor CVSS scores and the scanner's severity label for one vulnerability.
pub struct ScoreInput<'a> {
    /// `(vendor, scores)` pairs; `nvd` is preferred, then `redhat`, then others by name.
    pub cvss: &'a [(String, CvssScores)],
    /// Scanner's raw severity label, used when no source has a usable score.
    pub scanner_label: Option<&'a str>,
}

/// Selected severity and the score evidence that determined it.
pub struct Classification {
    /// Selected severity band.
    pub severity: Severity,
    /// Evidence that selected the band.
    pub basis: SeverityBasis,
    /// CVSS v3 score of the selected source as cleaned; `None` unless v3 decided.
    pub score_v3: Option<f32>,
    /// CVSS v2 score of the selected source as cleaned; `None` when the label decided.
    pub score_v2: Option<f32>,
    /// Vendor key of the selected source; `None` when the label decided or nothing did.
    pub score_source: Option<String>,
}

/// Round a raw CVSS score to one decimal, dropping missing, non-finite and non-positive
/// values.
///
/// Scores are not capped, so a value above 10 passes through as reported.
#[must_use]
pub fn clean_score(raw: Option<f64>) -> Option<f32> {
    raw.map(|score| ((score * 10.0).round() / 10.0) as f32)
        .filter(|score| score.is_finite() && *score > 0.0)
}

/// Band a CVSS v3 score: 9.0 or more is critical, anything lower as [`band_v2`].
#[must_use]
pub fn band_v3(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else {
        band_v2(score)
    }
}

/// Band a CVSS v2 score: high from 7.0, medium from 4.0, low above zero, else unrated.
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

/// Map `critical`, `high`, `medium` or `low` in any case to a band; other labels give `None`.
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

/// Choose a severity from the preferred v3 score, else the preferred v2 score, else the label.
///
/// Sources are preferred in the order `nvd`, `redhat`, then the others by name.
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

/// Per-vendor `V3Score` and `V2Score` as found in Trivy and Harbor `CVSS` maps.
#[derive(Default, Clone, serde::Deserialize)]
pub struct CvssSourceScores {
    /// Raw `V3Score`, before [`clean_score`].
    #[serde(rename = "V3Score")]
    pub v3_score: Option<f64>,
    /// Raw `V2Score`, before [`clean_score`].
    #[serde(rename = "V2Score")]
    pub v2_score: Option<f64>,
}

/// Clean each vendor's scores with [`clean_score`], in vendor-name order.
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
