//! Harbor v2 API source.
pub mod api;
pub mod map;
use super::{
    ScanSource, SourceError,
    files::dedupe_images,
    http::{Auth, HttpClient},
};
use crate::model::*;
use api::*;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

/// Connection fields kept independent of pipeline configuration.
pub struct HarborParams {
    pub url: String,
    pub project: Option<String>,
    pub username: String,
}
pub struct HarborSource {
    pub base_url: String,
    pub project: Option<String>,
    pub auth: Auth,
    pub client: HttpClient,
}
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
impl HarborSource {
    pub fn from_config(cfg: &HarborParams, client: HttpClient, password: String) -> Self {
        Self {
            base_url: cfg.url.trim_end_matches('/').into(),
            project: cfg.project.clone(),
            auth: Auth::Basic {
                username: cfg.username.clone(),
                password,
            },
            client,
        }
    }
    fn host(&self) -> String {
        self.base_url
            .parse::<ureq::http::Uri>()
            .ok()
            .and_then(|u| u.authority().map(|a| a.as_str().to_owned()))
            .unwrap_or_default()
    }
    fn scope(&self) -> String {
        format!(
            "{}/{}",
            self.host(),
            self.project.as_deref().unwrap_or("all projects")
        )
    }
    fn pages<T: DeserializeOwned>(&self, path: &str, query: &str) -> Result<Vec<T>, SourceError> {
        let mut result = Vec::new();
        for page in 1.. {
            let url = format!("{}{path}?page_size=100&page={page}{query}", self.base_url);
            let response = self.client.get_json::<Vec<T>>(&url, &self.auth, &[])?;
            let count = response.body.len();
            result.extend(response.body);
            let total = response
                .headers
                .get("x-total-count")
                .and_then(|s| s.parse::<usize>().ok());
            if count == 0 || total.map(|t| result.len() >= t).unwrap_or(count < 100) {
                break;
            }
        }
        Ok(result)
    }
    fn row(
        &self,
        repository: &str,
        path: &str,
        artifact: Artifact,
        mut tags: Vec<String>,
        platform: (Option<String>, bool),
        scanner: &mut Option<Scanner>,
    ) -> Result<(Image, Vec<Finding>), SourceError> {
        let (platform, child) = platform;
        tags.sort();
        tags.dedup();
        let reference = map::image_reference(
            repository,
            &tags,
            &artifact.digest,
            if child { platform.as_deref() } else { None },
        );
        let scan = map::scan_status(artifact.scan_overview.values().next());
        let mut findings = Vec::new();
        if scan.state == ScanState::Ok {
            let reports = self
                .client
                .get_json::<BTreeMap<String, VulnReport>>(
                    &format!(
                        "{}{path}/{}/additions/vulnerabilities",
                        self.base_url, artifact.digest
                    ),
                    &self.auth,
                    &[(
                        "X-Accept-Vulnerabilities",
                        "application/vnd.security.vulnerability.report; version=1.1",
                    )],
                )?
                .body;
            if let Some(report) = reports.into_values().next() {
                if scanner.is_none() {
                    *scanner = report.scanner;
                }
                findings = report
                    .vulnerabilities
                    .unwrap_or_default()
                    .iter()
                    .map(|v| map::finding(v, &reference))
                    .collect();
            }
        }
        let attrs = artifact.extra_attrs;
        Ok((
            Image {
                reference,
                tags,
                digest: Some(artifact.digest),
                platform,
                os: attrs.as_ref().and_then(|a| a.os.clone()),
                created_at: attrs.and_then(|a| a.created),
                size_bytes: artifact.size,
                scan,
            },
            findings,
        ))
    }
}
impl ScanSource for HarborSource {
    fn describe(&self) -> String {
        format!(
            "Harbor {}: {}",
            self.host(),
            self.project.as_deref().unwrap_or("all projects")
        )
    }
    fn fetch(&self) -> Result<ScanSet, SourceError> {
        let projects = match &self.project {
            Some(p) => vec![Project { name: p.clone() }],
            None => self.pages("/api/v2.0/projects", "")?,
        };
        let mut rows = Vec::new();
        let mut scanner = None;
        for project in projects {
            let path = format!("/api/v2.0/projects/{}/repositories", encode(&project.name));
            for repo in self.pages::<Repository>(&path, "")? {
                let name = repo
                    .name
                    .strip_prefix(&format!("{}/", project.name))
                    .unwrap_or(&repo.name);
                let path = format!("{path}/{}/artifacts", encode(name));
                let artifacts =
                    self.pages::<Artifact>(&path, "&with_tag=true&with_scan_overview=true")?;
                tracing::info!("repository {}: {} artifacts", repo.name, artifacts.len());
                for artifact in artifacts {
                    if artifact.r#type != "IMAGE" {
                        continue;
                    }
                    let tags: Vec<_> = artifact.tags.iter().map(|t| t.name.clone()).collect();
                    if artifact.references.is_empty() {
                        let platform = artifact.extra_attrs.as_ref().and_then(|a| {
                            Some(map::platform_string(&Platform {
                                os: a.os.clone()?,
                                architecture: a.architecture.clone()?,
                                variant: a.variant.clone(),
                            }))
                        });
                        rows.push(self.row(
                            &repo.name,
                            &path,
                            artifact,
                            tags,
                            (platform, false),
                            &mut scanner,
                        )?);
                    } else {
                        for reference in artifact.references {
                            if reference
                                .platform
                                .as_ref()
                                .is_some_and(|p| p.os == "unknown" && p.architecture == "unknown")
                            {
                                continue;
                            }
                            let child = self
                                .client
                                .get_json::<Artifact>(
                                    &format!(
                                        "{}{path}/{}?with_scan_overview=true&with_tag=true",
                                        self.base_url, reference.child_digest
                                    ),
                                    &self.auth,
                                    &[],
                                )?
                                .body;
                            if child.r#type != "IMAGE" {
                                continue;
                            }
                            rows.push(self.row(
                                &repo.name,
                                &path,
                                child,
                                tags.clone(),
                                (reference.platform.as_ref().map(map::platform_string), true),
                                &mut scanner,
                            )?);
                        }
                    }
                }
            }
        }
        let (images, findings) = dedupe_images(rows);
        if images.is_empty() {
            return Err(SourceError::NoImages(self.scope()));
        }
        Ok(ScanSet {
            source: SourceInfo {
                kind: SourceKind::Harbor,
                display_name: format!("Harbor {}", self.host()),
                scanner_name: scanner.as_ref().map(|s| s.name.clone()),
                scanner_version: scanner.and_then(|s| s.version),
                db_version: None,
                db_updated_at: None,
            },
            scope: self.scope(),
            images,
            findings,
        })
    }
}
