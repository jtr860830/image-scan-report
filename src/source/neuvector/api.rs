//! Permissive mirrors of NeuVector controller API payloads.
use super::report::NvVulnerability;
use serde::{Deserialize, Serialize};

/// Account name and password encoded in a NeuVector login request.
#[derive(Serialize)]
pub struct Credentials<'a> {
    /// NeuVector account name.
    pub username: &'a str,
    /// NeuVector account password.
    pub password: &'a str,
}
/// Body of `POST /v1/auth`.
#[derive(Serialize)]
pub struct AuthRequest<'a> {
    /// Account credentials, sent under NeuVector's `password` key.
    pub password: Credentials<'a>,
}
/// Session token issued after a successful NeuVector login.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct TokenInfo {
    /// Token sent as `X-Auth-Token` on later requests.
    pub token: String,
}
/// NeuVector login response containing a token or reset-password diagnostic.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct AuthResponse {
    /// Issued session; `None` or an empty token fails the fetch.
    pub token: Option<TokenInfo>,
    /// `Some(true)` when the account must change its password first, which fails the fetch.
    pub need_to_reset_password: Option<bool>,
    /// NeuVector error code; deserialised but not read.
    pub code: Option<i64>,
    /// NeuVector error message; deserialised but not read.
    pub message: Option<String>,
}
/// Response of `GET /v1/scan/registry/{name}`.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistrySummary {
    /// Registry configuration, supplying the registry URL and the database facts.
    pub summary: RegistryConfigSummary,
}
/// Registry identity and scan progress reported by NeuVector.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryConfigSummary {
    /// Name of the registry configuration.
    pub name: String,
    /// Registry URL whose host prefixes every image reference.
    pub registry: String,
    /// Registry scan status label; not read.
    pub status: String,
    /// Vulnerability database version, copied to `SourceInfo::db_version`.
    pub cvedb_version: Option<String>,
    /// RFC 3339 database build time, copied to `SourceInfo::db_updated_at`.
    pub cvedb_create_time: Option<String>,
    /// RFC 3339 time at which the registry scan began; not read.
    pub started_at: Option<String>,
    /// Number of images scanned, as NeuVector counts them; not read.
    pub scanned: u64,
    /// Number of images whose scan failed, as NeuVector counts them; not read.
    pub failed: u64,
}
/// Response of `GET /v1/scan/registry/{name}/images`.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryImages {
    /// One summary per scanned repository tag.
    pub images: Vec<ImageSummary>,
}
/// NeuVector's scan summary of one image in the registry.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageSummary {
    /// Repository path, joined to the registry host to form the image reference.
    pub repository: String,
    /// Image tag; empty when the image is untagged.
    pub tag: String,
    /// NeuVector image id used to fetch the vulnerability report.
    pub image_id: String,
    /// Manifest digest; an empty string is treated as missing.
    pub digest: Option<String>,
    /// Base operating system detected by NeuVector.
    pub base_os: Option<String>,
    /// Image size in bytes.
    pub size: Option<u64>,
    /// RFC 3339 image creation time.
    pub created_at: Option<String>,
    /// RFC 3339 scan time, preferred over `scanned_timestamp`.
    pub scanned_at: Option<String>,
    /// Scan time in Unix seconds; zero means unknown.
    pub scanned_timestamp: Option<i64>,
    /// Scan status label, such as `finished`, `scheduled` or `scanning`.
    pub status: Option<String>,
    /// Scan result label; with a `finished` status, only `succeeded` counts as success.
    pub result: Option<String>,
    /// Scanner version; the most common value becomes the report's scanner version.
    pub scanner_version: Option<String>,
    /// Status of the operating-system scan; not read.
    pub os_scan_status: Option<String>,
    /// Critical finding count as NeuVector reports it; the report recounts from findings.
    pub critical: Option<u64>,
    /// High finding count as NeuVector reports it; the report recounts from findings.
    pub high: Option<u64>,
    /// Medium finding count as NeuVector reports it; the report recounts from findings.
    pub medium: Option<u64>,
    /// Low finding count as NeuVector reports it; the report recounts from findings.
    pub low: Option<u64>,
}
/// Response of `GET /v1/scan/registry/{name}/image/{id}`.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageReport {
    /// Vulnerability report; `None` marks the image as failed.
    pub report: Option<ReportBody>,
}
/// NeuVector vulnerability records contained in an image report.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ReportBody {
    /// Vulnerabilities found; `None` marks the image as failed, while an empty list means none.
    pub vulnerabilities: Option<Vec<NvVulnerability>>,
}
