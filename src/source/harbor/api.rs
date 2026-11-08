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

#[derive(Clone, Deserialize)]
pub struct Project {
    pub name: String,
}

#[derive(Clone, Deserialize)]
pub struct Repository {
    pub name: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Artifact {
    pub digest: String,
    pub r#type: String,
    pub manifest_media_type: String,
    #[serde(deserialize_with = "null_default")]
    pub tags: Vec<Tag>,
    #[serde(deserialize_with = "null_default")]
    pub references: Vec<Reference>,
    #[serde(deserialize_with = "null_default")]
    pub scan_overview: BTreeMap<String, ScanOverview>,
    pub extra_attrs: Option<ExtraAttrs>,
    pub size: Option<u64>,
    pub push_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Deserialize)]
pub struct Tag {
    pub name: String,
}

#[derive(Clone, Deserialize)]
pub struct Reference {
    pub child_digest: String,
    pub platform: Option<Platform>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraAttrs {
    pub os: Option<String>,
    pub architecture: Option<String>,
    pub variant: Option<String>,
    pub created: Option<DateTime<Utc>>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ScanOverview {
    pub scan_status: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub scanner: Option<Scanner>,
    pub report_id: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct Scanner {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct VulnReport {
    pub scanner: Option<Scanner>,
    pub vulnerabilities: Option<Vec<Vuln>>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Vuln {
    pub id: String,
    pub package: String,
    pub version: String,
    pub fix_version: Option<String>,
    pub severity: String,
    pub status: Option<String>,
    pub description: Option<String>,
    #[serde(deserialize_with = "null_default")]
    pub links: Vec<String>,
    pub vendor_attributes: Option<VendorAttributes>,
}

#[derive(Clone, Default, Deserialize)]
pub struct VendorAttributes {
    #[serde(default, rename = "CVSS")]
    pub cvss: BTreeMap<String, CvssSourceScores>,
}
