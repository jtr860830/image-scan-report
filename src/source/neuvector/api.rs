//! Permissive mirrors of NeuVector controller API payloads.
use super::report::NvVulnerability;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
#[derive(Serialize)]
pub struct AuthRequest {
    pub password: Credentials,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct TokenInfo {
    pub token: String,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct AuthResponse {
    pub token: Option<TokenInfo>,
    pub need_to_reset_password: Option<bool>,
    pub code: Option<i64>,
    pub message: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistrySummary {
    pub summary: RegistryConfigSummary,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryConfigSummary {
    pub name: String,
    pub registry: String,
    pub status: String,
    pub cvedb_version: Option<String>,
    pub cvedb_create_time: Option<String>,
    pub started_at: Option<String>,
    pub scanned: u64,
    pub failed: u64,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryImages {
    pub images: Vec<ImageSummary>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageSummary {
    pub repository: String,
    pub tag: String,
    pub image_id: String,
    pub digest: Option<String>,
    pub base_os: Option<String>,
    pub size: Option<u64>,
    pub created_at: Option<String>,
    pub scanned_at: Option<String>,
    pub scanned_timestamp: Option<i64>,
    pub status: Option<String>,
    pub result: Option<String>,
    pub scanner_version: Option<String>,
    pub os_scan_status: Option<String>,
    pub critical: Option<u64>,
    pub high: Option<u64>,
    pub medium: Option<u64>,
    pub low: Option<u64>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageReport {
    pub report: Option<ReportBody>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ReportBody {
    pub vulnerabilities: Option<Vec<NvVulnerability>>,
}
