//! NeuVector controller registry scan source.
use super::{
    ScanSource, SourceError,
    files::dedupe_images,
    http::{Auth, HttpClient, HttpError, encode_segment, url_authority},
    neuvector::{
        api::*,
        report::{compose_reference, finding_from_nv, nv_timestamp},
    },
};
use crate::model::*;
use chrono::{DateTime, Utc};

pub struct NeuvectorParams {
    pub url: String,
    pub registry: String,
    pub username: String,
}
pub struct NeuvectorSource {
    pub base_url: String,
    pub registry: String,
    pub username: String,
    pub password: String,
    pub client: HttpClient,
    host: String,
}
struct Session<'a> {
    source: &'a NeuvectorSource,
    token: String,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.source.client.delete(
            &format!("{}/v1/auth", self.source.base_url),
            &Auth::None,
            &[("X-Auth-Token", &self.token)],
        ) {
            tracing::debug!(%error, "NeuVector logout failed");
        }
    }
}
fn timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}
pub fn scan_status(image: &ImageSummary) -> ScanStatus {
    let status = image.status.as_deref().unwrap_or_default();
    let result = image.result.as_deref().unwrap_or_default();
    let (state, error) = match status.to_ascii_lowercase().as_str() {
        "finished" if result.eq_ignore_ascii_case("succeeded") => (ScanState::Ok, None),
        "finished" => (
            ScanState::Failed,
            Some(
                if result.is_empty() {
                    "scan failed"
                } else {
                    result
                }
                .into(),
            ),
        ),
        "scheduled" | "scanning" => (ScanState::NotScanned, Some("scan in progress".into())),
        "" => (ScanState::NotScanned, None),
        _ => (ScanState::Failed, Some(status.into())),
    };
    ScanStatus {
        state,
        error,
        scanned_at: timestamp(image.scanned_at.as_deref())
            .or_else(|| nv_timestamp(image.scanned_timestamp)),
        scanner_version: image.scanner_version.clone(),
    }
}
impl NeuvectorSource {
    pub fn from_config(cfg: &NeuvectorParams, client: HttpClient, password: String) -> Self {
        Self {
            host: url_authority(&cfg.url),
            base_url: cfg.url.trim_end_matches('/').into(),
            registry: cfg.registry.clone(),
            username: cfg.username.clone(),
            password,
            client,
        }
    }
}
impl ScanSource for NeuvectorSource {
    fn describe(&self) -> String {
        format!("NeuVector {}: {}", self.host, self.registry)
    }
    fn fetch(&self) -> Result<ScanSet, SourceError> {
        // Login retries may create extra sessions; controller sessions expire automatically.
        let auth = self
            .client
            .post_json::<_, AuthResponse>(
                &format!("{}/v1/auth", self.base_url),
                &Auth::None,
                &AuthRequest {
                    password: Credentials {
                        username: &self.username,
                        password: &self.password,
                    },
                },
                &[],
            )?
            .body;
        let session = auth.token.filter(|t| !t.token.is_empty()).map(|t| Session {
            source: self,
            token: t.token,
        });
        if auth.need_to_reset_password == Some(true) {
            return Err(SourceError::Other(
                "NeuVector requires an admin password reset before API use".into(),
            ));
        }
        let session = session.ok_or_else(|| {
            SourceError::Other("NeuVector authentication response missing token".into())
        })?;
        let headers = [("X-Auth-Token", session.token.as_str())];
        let path = format!(
            "{}/v1/scan/registry/{}",
            self.base_url,
            encode_segment(&self.registry)
        );
        let summary = match self
            .client
            .get_json::<RegistrySummary>(&path, &Auth::None, &headers)
        {
            Ok(r) => r.body.summary,
            Err(HttpError::Status(_, 404)) => {
                return Err(SourceError::Other(format!(
                    "registry configuration {} not found",
                    self.registry
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let list = self
            .client
            .get_json::<RegistryImages>(&format!("{path}/images"), &Auth::None, &headers)?
            .body;
        let mut versions = std::collections::BTreeMap::<String, usize>::new();
        let mut rows = Vec::new();
        for entry in list.images {
            if let Some(v) = &entry.scanner_version {
                *versions.entry(v.clone()).or_default() += 1;
            }
            let reference = compose_reference(&summary.registry, &entry.repository, &entry.tag);
            let mut scan = scan_status(&entry);
            let mut findings = Vec::new();
            if scan.state == ScanState::Ok {
                match self.client.get_json::<ImageReport>(
                    &format!("{path}/image/{}", encode_segment(&entry.image_id)),
                    &Auth::None,
                    &headers,
                ) {
                    Ok(r) => match r.body.report.and_then(|r| r.vulnerabilities) {
                        Some(v) => {
                            findings = v.iter().map(|v| finding_from_nv(v, &reference)).collect()
                        }
                        None => {
                            scan.state = ScanState::Failed;
                            scan.error = Some("vulnerabilities missing".into());
                            tracing::warn!(image = reference, "NeuVector vulnerabilities missing");
                        }
                    },
                    Err(e @ HttpError::Unauthorized(_)) => return Err(e.into()),
                    Err(e) => {
                        tracing::warn!(image=reference,%e,"NeuVector image report failed");
                        scan.state = ScanState::Failed;
                        scan.error = Some(e.to_string());
                    }
                }
            }
            rows.push((
                Image {
                    reference,
                    tags: if entry.tag.is_empty() {
                        vec![]
                    } else {
                        vec![entry.tag]
                    },
                    digest: entry.digest,
                    platform: None,
                    os: entry.base_os,
                    size_bytes: entry.size,
                    created_at: timestamp(entry.created_at.as_deref()),
                    scan,
                },
                findings,
            ));
        }
        let scope = format!("{}/{}", self.host, self.registry);
        let (images, findings) = dedupe_images(rows);
        if images.is_empty() {
            return Err(SourceError::NoImages(scope));
        }
        Ok(ScanSet {
            source: SourceInfo {
                kind: SourceKind::Neuvector,
                display_name: format!("NeuVector {}", self.host),
                scanner_name: Some("NeuVector".into()),
                scanner_version: versions.into_iter().max_by_key(|(_, n)| *n).map(|(v, _)| v),
                db_version: summary.cvedb_version,
                db_updated_at: timestamp(summary.cvedb_create_time.as_deref()),
            },
            scope,
            images,
            findings,
        })
    }
}
