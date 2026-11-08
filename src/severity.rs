//! Unified severity classification from cleaned CVSS scores and scanner labels.

use crate::model::{Severity, SeverityBasis};

pub struct CvssScores {
    pub v3: Option<f32>,
    pub v2: Option<f32>,
}

pub struct ScoreInput<'a> {
    pub cvss: &'a [(String, CvssScores)],
    pub scanner_label: Option<&'a str>,
}

pub struct Classification {
    pub severity: Severity,
    pub basis: SeverityBasis,
    pub score_v3: Option<f32>,
    pub score_v2: Option<f32>,
    pub score_source: Option<String>,
}

pub fn clean_score(raw: Option<f64>) -> Option<f32> {
    raw.map(|score| ((score * 10.0).round() / 10.0) as f32)
        .filter(|score| score.is_finite() && *score > 0.0)
}

pub fn band_v3(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else {
        band_v2(score)
    }
}

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
    #[serde(rename = "V3Score")]
    pub v3_score: Option<f64>,
    #[serde(rename = "V2Score")]
    pub v2_score: Option<f64>,
}

pub fn cvss_from_map(
    map: std::collections::BTreeMap<String, CvssSourceScores>,
) -> Vec<(String, CvssScores)> {
    map.into_iter()
        .map(|(name, scores)| {
            (
                name,
                CvssScores {
                    v3: clean_score(scores.v3_score),
                    v2: clean_score(scores.v2_score),
                },
            )
        })
        .collect()
}
