//! Serde mirrors of Harbor API responses; unrelated fields are ignored.
use crate::severity::CvssSourceScores;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Harbor project identity used to enumerate repositories.
#[derive(Clone, Deserialize)]
pub struct Project {
    /// Display name supplied by the scanner or theme.
    pub name: String,
}

/// Harbor repository identity used to enumerate artifacts.
#[derive(Clone, Deserialize)]
pub struct Repository {
    /// Display name supplied by the scanner or theme.
    pub name: String,
}

/// Encoded report bytes with a destination filename and media type.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Artifact {
    /// Content digest reported by the registry.
    pub digest: String,
    /// Harbor artifact kind; IMAGE records are eligible for report collection.
    pub r#type: String,
    /// Media type identifying the manifest format.
    pub manifest_media_type: String,
    /// Alternative tags identifying the same image content. An empty list indicates no entries.
    #[serde(deserialize_with = "null_default")]
    pub tags: Vec<Tag>,
    /// Child manifests referenced by an image index. An empty list indicates no entries.
    #[serde(deserialize_with = "null_default")]
    pub references: Vec<Reference>,
    /// Scanner summaries indexed by report media type.
    #[serde(deserialize_with = "null_default")]
    pub scan_overview: BTreeMap<String, ScanOverview>,
    /// Manifest metadata containing operating system and architecture details. None indicates that the value is unavailable.
    pub extra_attrs: Option<ExtraAttrs>,
    /// Image size reported by the scanner, in bytes before display formatting. None indicates that the value is unavailable.
    pub size: Option<u64>,
    /// Time at which the artifact was pushed to the registry. None indicates that the value is unavailable.
    pub push_time: Option<DateTime<Utc>>,
}

/// Harbor tag identifying an artifact within a repository.
#[derive(Clone, Deserialize)]
pub struct Tag {
    /// Display name supplied by the scanner or theme.
    pub name: String,
}

/// Child manifest digest and platform metadata from a Harbor image index.
#[derive(Clone, Deserialize)]
pub struct Reference {
    /// Content digest of a referenced child manifest.
    pub child_digest: String,
    /// Operating system and architecture label for the image. None indicates that the value is unavailable.
    pub platform: Option<Platform>,
}

/// Operating system, CPU architecture, and optional architecture variant.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Platform {
    /// Operating system identified by the scanner.
    pub os: String,
    /// CPU architecture reported by the registry.
    pub architecture: String,
    /// Architecture variant, such as an ARM revision. None indicates that the value is unavailable.
    pub variant: Option<String>,
}

/// Optional platform and creation metadata returned for a Harbor artifact.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraAttrs {
    /// Operating system identified by the scanner. None indicates that the value is unavailable.
    pub os: Option<String>,
    /// CPU architecture reported by the registry. None indicates that the value is unavailable.
    pub architecture: Option<String>,
    /// Architecture variant, such as an ARM revision. None indicates that the value is unavailable.
    pub variant: Option<String>,
    /// Creation time supplied by the scanner. None indicates that the value is unavailable.
    pub created: Option<DateTime<Utc>>,
}

/// Harbor scan outcome, timing, scanner identity, and report details.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ScanOverview {
    /// Raw status label supplied by the scanner.
    pub scan_status: String,
    /// Time at which the scanner began processing the image. None indicates that the value is unavailable.
    pub start_time: Option<DateTime<Utc>>,
    /// Time at which the scanner finished processing the image. None indicates that the value is unavailable.
    pub end_time: Option<DateTime<Utc>>,
    /// Identity and version of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner: Option<Scanner>,
    /// Scanner report identifier for the artifact. None indicates that the value is unavailable.
    pub report_id: Option<String>,
}

/// Scanner identity and optional version returned by Harbor.
#[derive(Clone, Deserialize)]
pub struct Scanner {
    /// Display name supplied by the scanner or theme.
    pub name: String,
    /// Schema or component version supplied by the producer. None indicates that the value is unavailable.
    pub version: Option<String>,
}

/// Harbor vulnerability report with optional scanner identity and findings.
#[derive(Clone, Deserialize)]
pub struct VulnReport {
    /// Identity and version of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner: Option<Scanner>,
    /// Vulnerability records included in this scanner response. None indicates that the value is unavailable. An empty list indicates no entries.
    pub vulnerabilities: Option<Vec<Vuln>>,
}

/// Harbor vulnerability fields preserved for severity and remediation normalization.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Vuln {
    /// Scanner-provided vulnerability identifier.
    pub id: String,
    /// Affected software package identifier.
    pub package: String,
    /// Schema or component version supplied by the producer.
    pub version: String,
    /// Package version that resolves the vulnerability. None indicates that the value is unavailable.
    pub fix_version: Option<String>,
    /// Normalized vulnerability severity band.
    pub severity: String,
    /// Raw status label supplied by the API. None indicates that the value is unavailable.
    pub status: Option<String>,
    /// Human-readable explanation of the vulnerability. None indicates that the value is unavailable.
    pub description: Option<String>,
    /// External advisory URLs supplied by the scanner. An empty list indicates no entries.
    #[serde(deserialize_with = "null_default")]
    pub links: Vec<String>,
    /// Vendor-specific CVSS measurements attached to the vulnerability. None indicates that the value is unavailable.
    pub vendor_attributes: Option<VendorAttributes>,
}

/// Vendor-indexed CVSS scores attached to a Harbor vulnerability.
#[derive(Clone, Default, Deserialize)]
pub struct VendorAttributes {
    /// CVSS measurements indexed by their vendor source names.
    #[serde(default, rename = "CVSS")]
    pub cvss: BTreeMap<String, CvssSourceScores>,
}
