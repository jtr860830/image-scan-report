//! Normalised scanner data shared by the report pipeline.

mod severity;

pub use severity::Severity;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Normalised report: one scan set plus generation time, language and organisation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Report {
    /// Generation time, also used as the PDF timestamp and the stale-scan reference point.
    pub generated_at: DateTime<Utc>,
    /// Report language, copied from `report.language`.
    pub language: Language,
    /// Organisation printed on the cover, copied from `report.organization`.
    pub organisation: String,
    /// Scanner and vulnerability-database provenance.
    pub source: SourceInfo,
    /// Scope label, such as `host/project` or the input directory name; slugged into artifact
    /// names.
    pub scope: String,
    /// Images in scope, including failed and unscanned ones.
    pub images: Vec<Image>,
    /// Findings across all images, linked to them by [`Finding::image`].
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
    /// Source that produced the data; also part of the artifact names.
    pub kind: SourceKind,
    /// Label printed on the cover, such as `Harbor <host>` or `Trivy (files)`.
    pub display_name: String,
    /// Scanner name; `None` when Harbor returned no vulnerability report to name it.
    pub scanner_name: Option<String>,
    /// Scanner version from Harbor's report or the most common NeuVector controller value;
    /// file sources leave it `None`.
    pub scanner_version: Option<String>,
    /// Vulnerability database version; only NeuVector sources report it.
    pub db_version: Option<String>,
    /// Vulnerability database build time; only NeuVector sources report it.
    pub db_updated_at: Option<DateTime<Utc>>,
}

/// Input scanner family and transport.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Harbor v2 API.
    Harbor,
    /// NeuVector controller REST API.
    Neuvector,
    /// NeuVector scanner JSON files in a directory.
    NeuvectorFiles,
    /// Trivy JSON files in a directory.
    TrivyFiles,
}

/// Container image identity, metadata, and latest scan outcome.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Image {
    /// Reference that findings point at. Harbor image-index children get ` (platform)`, or
    /// the first 12 digest hex digits when the platform is unknown or the reference collides.
    pub reference: String,
    /// Tags of the image content; Trivy and NeuVector sources give at most one.
    pub tags: Vec<String>,
    /// Manifest digest, such as `sha256:…`; the deduplication key for file sources.
    pub digest: Option<String>,
    /// Platform label `os/arch[/variant]`; NeuVector sources never set it.
    pub platform: Option<String>,
    /// Base operating system reported by the scanner.
    pub os: Option<String>,
    /// Image size in bytes from Harbor or NeuVector; Trivy reports leave it `None`.
    pub size_bytes: Option<u64>,
    /// Image creation time from the image config or scanner metadata.
    pub created_at: Option<DateTime<Utc>>,
    /// Outcome of the latest scan.
    pub scan: ScanStatus,
}

/// Scan outcome with optional timing and failure diagnostics.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanStatus {
    /// Whether the scan succeeded, failed, or has not completed.
    pub state: ScanState,
    /// Scan completion time; file sources fall back to the report file's modification time.
    pub scanned_at: Option<DateTime<Utc>>,
    /// Version of the scanner that scanned this image, when reported.
    pub scanner_version: Option<String>,
    /// Failure or in-progress note shown in the report; `None` for successful scans.
    pub error: Option<String>,
}

/// Outcome of the latest scan attempt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    /// The scan finished and its findings were retrieved.
    Ok,
    /// The scan, or retrieving its findings, failed.
    Failed,
    /// The image has no scan yet or its scan is still running.
    NotScanned,
}

/// One vulnerability in one package of one image.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Finding {
    /// Vulnerability identifier, such as a CVE id.
    pub id: String,
    /// Reference of the affected image, equal to an [`Image::reference`].
    pub image: String,
    /// Severity band chosen by [`crate::severity::classify`].
    pub severity: Severity,
    /// Evidence that chose `severity`.
    pub severity_basis: SeverityBasis,
    /// CVSS v3 score of the selected source, rounded to one decimal and greater than zero.
    pub score_v3: Option<f32>,
    /// CVSS v2 score of the selected source, rounded to one decimal and greater than zero.
    pub score_v2: Option<f32>,
    /// Vendor key of the selected CVSS entry, such as `nvd` or `neuvector`; `None` when no
    /// score was used.
    pub score_source: Option<String>,
    /// Scanner's raw severity label as reported; `None` only when a Trivy entry omits it.
    pub scanner_severity: Option<String>,
    /// Name of the affected package.
    pub package: String,
    /// Installed package version.
    pub installed_version: String,
    /// Version that fixes the vulnerability; `None` when the scanner lists no fix.
    pub fixed_version: Option<String>,
    /// Parsed fix status; `None` when the scanner gives none, as NeuVector never does.
    pub fix_status: Option<FixStatus>,
    /// Advisory text, empty when none; Trivy falls back to the title.
    pub description: String,
    /// Advisory URLs; for Trivy, the primary URL comes first.
    pub links: Vec<String>,
    /// Advisory publication time; Harbor never provides it.
    pub published_at: Option<DateTime<Utc>>,
}

/// Evidence used to select a normalised severity.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBasis {
    /// A CVSS v3 score determined the severity.
    Cvss3,
    /// A CVSS v2 score determined the severity.
    Cvss2,
    /// The scanner severity label determined the severity.
    ScannerLabel,
    /// No usable score and no recognised label, so the severity is `Unrated`.
    None,
}

/// Scanner assessment of whether a fix is available.
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
    /// Any other status, kept verbatim.
    #[serde(untagged)]
    Other(String),
}

impl FixStatus {
    /// Parse a status case-insensitively, reading `-` and spaces as `_`; unknown values become
    /// `Other`.
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

/// Normalised images and findings collected from one source scope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ScanSet {
    /// Scanner and vulnerability-database provenance.
    pub source: SourceInfo,
    /// Scope label, such as `host/project` or the input directory name.
    pub scope: String,
    /// Deduplicated images in scope.
    pub images: Vec<Image>,
    /// Findings of those images.
    pub findings: Vec<Finding>,
}
