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
    /// Harbor project name.
    pub name: String,
}

/// Harbor repository identity used to enumerate artifacts.
#[derive(Clone, Deserialize)]
pub struct Repository {
    /// Repository name including its project prefix, such as `library/nginx`.
    pub name: String,
}

/// Harbor registry artifact record from an artifact listing or a child-digest lookup.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Artifact {
    /// Manifest digest, such as `sha256:…`.
    pub digest: String,
    /// Harbor artifact type; only `IMAGE` artifacts are reported.
    pub r#type: String,
    /// Manifest media type; deserialised but not read.
    pub manifest_media_type: String,
    /// Tags pointing at the artifact; `null` is read as empty.
    #[serde(deserialize_with = "null_default")]
    pub tags: Vec<Tag>,
    /// Child manifests of an image index; empty for a single-platform image.
    #[serde(deserialize_with = "null_default")]
    pub references: Vec<Reference>,
    /// Scan summaries keyed by report MIME type; only the first entry is read.
    #[serde(deserialize_with = "null_default")]
    pub scan_overview: BTreeMap<String, ScanOverview>,
    /// Image config attributes that supply the OS, architecture and creation time.
    pub extra_attrs: Option<ExtraAttrs>,
    /// Artifact size in bytes.
    pub size: Option<u64>,
    /// Push time; deserialised but not read.
    pub push_time: Option<DateTime<Utc>>,
}

/// Harbor tag identifying an artifact within a repository.
#[derive(Clone, Deserialize)]
pub struct Tag {
    /// Tag name.
    pub name: String,
}

/// Child manifest digest and platform metadata from a Harbor image index.
#[derive(Clone, Deserialize)]
pub struct Reference {
    /// Content digest of a referenced child manifest.
    pub child_digest: String,
    /// Platform from the index; `unknown/unknown` entries are skipped.
    pub platform: Option<Platform>,
}

/// Operating system, CPU architecture, and optional architecture variant.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Platform {
    /// Operating system, such as `linux`.
    pub os: String,
    /// CPU architecture, such as `amd64`.
    pub architecture: String,
    /// Architecture variant, such as `v8`; an empty string is ignored.
    pub variant: Option<String>,
}

/// Optional platform and creation metadata returned for a Harbor artifact.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraAttrs {
    /// Image operating system; empty or `unknown` yields no platform.
    pub os: Option<String>,
    /// Image CPU architecture; empty or `unknown` yields no platform.
    pub architecture: Option<String>,
    /// Architecture variant, such as `v8`.
    pub variant: Option<String>,
    /// Image creation time.
    pub created: Option<DateTime<Utc>>,
}

/// Harbor scan outcome, timing, scanner identity, and report details.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ScanOverview {
    /// Scan status, such as `Success`, `Error` or `Running`, compared case-insensitively.
    pub scan_status: String,
    /// Scan start time; not read.
    pub start_time: Option<DateTime<Utc>>,
    /// Scan end time, used as the image's scan time.
    pub end_time: Option<DateTime<Utc>>,
    /// Scanner that ran, supplying the per-image scanner version.
    pub scanner: Option<Scanner>,
    /// Harbor report id; not read.
    pub report_id: Option<String>,
}

/// Scanner identity and optional version returned by Harbor.
#[derive(Clone, Deserialize)]
pub struct Scanner {
    /// Scanner name, such as `Trivy`.
    pub name: String,
    /// Scanner version.
    pub version: Option<String>,
}

/// Harbor vulnerability report with optional scanner identity and findings.
#[derive(Clone, Deserialize)]
pub struct VulnReport {
    /// Scanner of this report; the first one seen names the report's scanner.
    pub scanner: Option<Scanner>,
    /// Vulnerabilities found; `None` marks the image as failed, while an empty list means none.
    pub vulnerabilities: Option<Vec<Vuln>>,
}

/// Harbor vulnerability fields read for severity classification and remediation.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Vuln {
    /// Vulnerability identifier, such as a CVE id.
    pub id: String,
    /// Name of the affected package.
    pub package: String,
    /// Installed package version.
    pub version: String,
    /// Fixed version; `None` or empty when no fix is listed.
    pub fix_version: Option<String>,
    /// Scanner's raw severity label, passed to `classify`.
    pub severity: String,
    /// Fix status, parsed by `FixStatus::parse`.
    pub status: Option<String>,
    /// Advisory text.
    pub description: Option<String>,
    /// Advisory URLs; `null` is read as empty.
    #[serde(deserialize_with = "null_default")]
    pub links: Vec<String>,
    /// Vendor attributes that carry the per-source CVSS scores.
    pub vendor_attributes: Option<VendorAttributes>,
}

/// Vendor-indexed CVSS scores attached to a Harbor vulnerability.
#[derive(Clone, Default, Deserialize)]
pub struct VendorAttributes {
    /// CVSS scores keyed by vendor, such as `nvd` or `redhat`.
    #[serde(default, rename = "CVSS")]
    pub cvss: BTreeMap<String, CvssSourceScores>,
}
