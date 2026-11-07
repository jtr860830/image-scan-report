//! Normalised scanner data shared by the report pipeline.

mod severity;

pub use severity::Severity;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Report {
    pub generated_at: DateTime<Utc>,
    pub language: Language,
    pub organisation: String,
    pub source: SourceInfo,
    pub scope: String,
    pub images: Vec<Image>,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    #[serde(rename = "zh-TW")]
    ZhTw,
    En,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SourceInfo {
    pub kind: SourceKind,
    pub display_name: String,
    pub scanner_name: Option<String>,
    pub scanner_version: Option<String>,
    pub db_version: Option<String>,
    pub db_updated_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Harbor,
    Neuvector,
    NeuvectorFiles,
    TrivyFiles,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Image {
    pub reference: String,
    pub tags: Vec<String>,
    pub digest: Option<String>,
    pub platform: Option<String>,
    pub os: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: Option<DateTime<Utc>>,
    pub scan: ScanStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanStatus {
    pub state: ScanState,
    pub scanned_at: Option<DateTime<Utc>>,
    pub scanner_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Ok,
    Failed,
    NotScanned,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: String,
    pub image: String,
    pub severity: Severity,
    pub severity_basis: SeverityBasis,
    pub score_v3: Option<f32>,
    pub score_v2: Option<f32>,
    pub score_source: Option<String>,
    pub scanner_severity: Option<String>,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub fix_status: Option<FixStatus>,
    pub description: String,
    pub links: Vec<String>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBasis {
    Cvss3,
    Cvss2,
    ScannerLabel,
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FixStatus {
    Fixed,
    Affected,
    WillNotFix,
    EndOfLife,
    FixDeferred,
    UnderInvestigation,
    #[serde(untagged)]
    Other(String),
}

impl FixStatus {
    pub fn parse(s: &str) -> FixStatus {
        match s.to_lowercase().replace(['-', ' '], "_").as_str() {
            "fixed" => Self::Fixed,
            "affected" => Self::Affected,
            "will_not_fix" => Self::WillNotFix,
            "end_of_life" => Self::EndOfLife,
            "fix_deferred" => Self::FixDeferred,
            "under_investigation" => Self::UnderInvestigation,
            _ => Self::Other(s.to_owned()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanSet {
    pub source: SourceInfo,
    pub scope: String,
    pub images: Vec<Image>,
    pub findings: Vec<Finding>,
}
