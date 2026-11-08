//! Permissive mirrors of NeuVector controller API payloads.
use super::report::NvVulnerability;
use serde::{Deserialize, Serialize};

/// Account name and password encoded in a NeuVector login request.
#[derive(Serialize)]
pub struct Credentials<'a> {
    /// Account name used to authenticate API requests.
    pub username: &'a str,
    /// Secret credential used to authenticate the request.
    pub password: &'a str,
}
/// NeuVector login payload wrapping account credentials.
#[derive(Serialize)]
pub struct AuthRequest<'a> {
    /// Secret credential used to authenticate the request.
    pub password: Credentials<'a>,
}
/// Session token issued after a successful NeuVector login.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct TokenInfo {
    /// Session credential issued by the NeuVector authentication endpoint.
    pub token: String,
}
/// NeuVector login response containing a token or reset-password diagnostic.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct AuthResponse {
    /// Session credential issued by the NeuVector authentication endpoint. None indicates that the value is unavailable.
    pub token: Option<TokenInfo>,
    /// Whether the API requires a password reset before further requests. None indicates that the value is unavailable.
    pub need_to_reset_password: Option<bool>,
    /// Numeric error code supplied by the API. None indicates that the value is unavailable.
    pub code: Option<i64>,
    /// Diagnostic message supplied by the API. None indicates that the value is unavailable.
    pub message: Option<String>,
}
/// NeuVector response wrapper around registry scan metadata.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistrySummary {
    /// Aggregate scan counts and ranked findings for the report overview.
    pub summary: RegistryConfigSummary,
}
/// Registry identity and scan progress reported by NeuVector.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryConfigSummary {
    /// Display name supplied by the scanner or theme.
    pub name: String,
    /// Registry name used to scope NeuVector API requests.
    pub registry: String,
    /// Raw status label supplied by the API.
    pub status: String,
    /// Version of the scanner vulnerability database. None indicates that the value is unavailable.
    pub cvedb_version: Option<String>,
    /// Creation timestamp of the scanner vulnerability database. None indicates that the value is unavailable.
    pub cvedb_create_time: Option<String>,
    /// Time at which the registry scan began. None indicates that the value is unavailable.
    pub started_at: Option<String>,
    /// Number of successfully scanned images.
    pub scanned: u64,
    /// Number of images whose scans failed.
    pub failed: u64,
}
/// NeuVector response containing image summary records.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RegistryImages {
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<ImageSummary>,
}
/// Severity totals for one image reference.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageSummary {
    /// Repository path within the registry.
    pub repository: String,
    /// Tag used to identify the repository image.
    pub tag: String,
    /// Scanner identifier used to retrieve image details.
    pub image_id: String,
    /// Content digest reported by the registry. None indicates that the value is unavailable.
    pub digest: Option<String>,
    /// Operating system identified in the image layers. None indicates that the value is unavailable.
    pub base_os: Option<String>,
    /// Image size reported by the scanner, in bytes before display formatting. None indicates that the value is unavailable.
    pub size: Option<u64>,
    /// Creation time of the scanned image. None indicates that the value is unavailable.
    pub created_at: Option<String>,
    /// Time of the most recent vulnerability scan. None indicates that the value is unavailable.
    pub scanned_at: Option<String>,
    /// Time of the most recent scan in Unix seconds. None indicates that the value is unavailable.
    pub scanned_timestamp: Option<i64>,
    /// Raw status label supplied by the API. None indicates that the value is unavailable.
    pub status: Option<String>,
    /// Raw scanner result label retained for status normalization. None indicates that the value is unavailable.
    pub result: Option<String>,
    /// Version of the scanner that generated this result. None indicates that the value is unavailable.
    pub scanner_version: Option<String>,
    /// Scanner state for the image operating-system scan. None indicates that the value is unavailable.
    pub os_scan_status: Option<String>,
    /// Number of findings in the critical severity band. None indicates that the value is unavailable.
    pub critical: Option<u64>,
    /// Number of findings in the high severity band. None indicates that the value is unavailable.
    pub high: Option<u64>,
    /// Number of findings in the medium severity band. None indicates that the value is unavailable.
    pub medium: Option<u64>,
    /// Number of findings in the low severity band. None indicates that the value is unavailable.
    pub low: Option<u64>,
}
/// NeuVector response wrapper around an optional vulnerability report.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageReport {
    /// Report content or generation settings for this operation. None indicates that the value is unavailable.
    pub report: Option<ReportBody>,
}
/// NeuVector vulnerability records contained in an image report.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ReportBody {
    /// Vulnerability records included in this scanner response. None indicates that the value is unavailable. An empty list indicates no entries.
    pub vulnerabilities: Option<Vec<NvVulnerability>>,
}
