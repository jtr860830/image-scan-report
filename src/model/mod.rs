//! Normalised scanner data shared by the report pipeline.

mod severity;

pub use severity::Severity;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Normalized scan snapshot and metadata used to generate artifacts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Report {
    /// UTC instant at which the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Language selected for report labels and explanatory text.
    pub language: Language,
    /// Organization name displayed on the report cover.
    pub organisation: String,
    /// Scanner identity and origin of the input data.
    pub source: SourceInfo,
    /// Human-readable registry, project, or directory scope of the scan.
    pub scope: String,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<Image>,
    /// Normalized vulnerabilities associated with scanned images. An empty list indicates no entries.
    pub findings: Vec<Finding>,
}

/// Supported languages for report text.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    /// Use Traditional Chinese report text for Taiwan.
    #[serde(rename = "zh-TW")]
    ZhTw,
    /// Use English report text.
    En,
}

/// Scanner identity and vulnerability database provenance.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SourceInfo {
    /// Scanner family and input transport represented by this source.
    pub kind: SourceKind,
    /// Human-readable source label displayed in the report.
    pub display_name: String,
    /// Name of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner_name: Option<String>,
    /// Version of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner_version: Option<String>,
    /// Version of the vulnerability database used by the scanner. None indicates that the value is unavailable.
    pub db_version: Option<String>,
    /// Timestamp of the scanner vulnerability database update. None indicates that the value is unavailable.
    pub db_updated_at: Option<DateTime<Utc>>,
}

/// Input scanner family and transport.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Collect scan data through the Harbor v2 API.
    Harbor,
    /// Collect scan data through the NeuVector API.
    Neuvector,
    /// Read NeuVector scan results from a directory.
    NeuvectorFiles,
    /// Read Trivy scan reports from a directory.
    TrivyFiles,
}

/// Container image identity, metadata, and latest scan outcome.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Image {
    /// Canonical image reference used to associate findings with an image.
    pub reference: String,
    /// Alternative tags identifying the same image content. An empty list indicates no entries.
    pub tags: Vec<String>,
    /// Content digest reported by the registry. None indicates that the value is unavailable.
    pub digest: Option<String>,
    /// Operating system and architecture label for the image. None indicates that the value is unavailable.
    pub platform: Option<String>,
    /// Operating system identified by the scanner. None indicates that the value is unavailable.
    pub os: Option<String>,
    /// Image size in bytes, or None when the scanner omits it.
    pub size_bytes: Option<u64>,
    /// Creation time of the scanned image. None indicates that the value is unavailable.
    pub created_at: Option<DateTime<Utc>>,
    /// Outcome and metadata of the most recent scan.
    pub scan: ScanStatus,
}

/// Scan outcome with optional timing and failure diagnostics.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanStatus {
    /// Normalized scan outcome used to distinguish success, failure, and unscanned images.
    pub state: ScanState,
    /// Time of the most recent vulnerability scan. None indicates that the value is unavailable.
    pub scanned_at: Option<DateTime<Utc>>,
    /// Version of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner_version: Option<String>,
    /// Diagnostic explaining an unsuccessful scan or operation. None indicates that the value is unavailable.
    pub error: Option<String>,
}

/// Outcome of the latest scan attempt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    /// The scanner completed successfully.
    Ok,
    /// The scanner reported a failure.
    Failed,
    /// No completed scan is available for this image.
    NotScanned,
}

/// One vulnerability affecting a package in a particular image.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Finding {
    /// Scanner-provided vulnerability identifier.
    pub id: String,
    /// Image reference linking the finding to its scanned image.
    pub image: String,
    /// Normalized vulnerability severity band.
    pub severity: Severity,
    /// Rule used to choose the normalized severity.
    pub severity_basis: SeverityBasis,
    /// CVSS v3 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v3: Option<f32>,
    /// CVSS v2 score in the inclusive range zero to ten, or None when unavailable.
    pub score_v2: Option<f32>,
    /// Vendor source selected for the effective CVSS score. None indicates that the value is unavailable.
    pub score_source: Option<String>,
    /// Original severity label retained alongside the normalized severity. None indicates that the value is unavailable.
    pub scanner_severity: Option<String>,
    /// Affected software package identifier.
    pub package: String,
    /// Package version detected in the scanned image.
    pub installed_version: String,
    /// Package version containing the fix, when the scanner supplies one. None indicates that the value is unavailable.
    pub fixed_version: Option<String>,
    /// Scanner assessment of whether a package fix is available. None indicates that the value is unavailable.
    pub fix_status: Option<FixStatus>,
    /// Human-readable explanation of the vulnerability.
    pub description: String,
    /// External advisory URLs supplied by the scanner. An empty list indicates no entries.
    pub links: Vec<String>,
    /// Publication time of the vulnerability advisory. None indicates that the value is unavailable.
    pub published_at: Option<DateTime<Utc>>,
}

/// Evidence used to select a normalized severity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBasis {
    /// A CVSS v3 score determined the severity.
    Cvss3,
    /// A CVSS v2 score determined the severity.
    Cvss2,
    /// The scanner severity label determined the severity.
    ScannerLabel,
    /// No value or additional policy is supplied.
    None,
}

/// Scanner assessment of package remediation availability.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FixStatus {
    /// The scanner reports that the vulnerability is fixed.
    Fixed,
    /// The installed package is affected by the vulnerability.
    Affected,
    /// The vendor does not plan to provide a fix.
    WillNotFix,
    /// The package has reached the end of its supported lifetime.
    EndOfLife,
    /// The vendor has deferred providing a fix.
    FixDeferred,
    /// The vendor is still investigating the vulnerability.
    UnderInvestigation,
    /// Preserve an unrecognized value or an additional diagnostic.
    #[serde(untagged)]
    Other(String),
}

impl FixStatus {
    /// Interpret a scanner fix status while preserving unrecognized values.
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

/// Normalized images and findings collected from one source scope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanSet {
    /// Scanner identity and origin of the input data.
    pub source: SourceInfo,
    /// Human-readable registry, project, or directory scope of the scan.
    pub scope: String,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<Image>,
    /// Normalized vulnerabilities associated with scanned images. An empty list indicates no entries.
    pub findings: Vec<Finding>,
}
