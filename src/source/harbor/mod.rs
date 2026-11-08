//! Harbor v2 API source.
pub mod api;
pub mod map;
use super::{
    ScanSource, SourceError,
    files::dedupe_images_by_reference,
    http::{Auth, HttpClient, HttpError, encode_segment, row_failure, url_authority},
};
use crate::model::*;
use api::*;
use map::digest12;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};

/// Connection fields kept independent of pipeline configuration.
pub struct HarborParams {
    pub url: String,
    pub project: Option<String>,
    pub username: String,
}
pub struct HarborSource {
    pub base_url: String,
    pub project: Option<String>,
    auth: Auth,
    pub client: HttpClient,
    host: String,
}
impl HarborSource {
    pub fn from_config(cfg: &HarborParams, client: HttpClient, password: String) -> Self {
        Self {
            host: url_authority(&cfg.url),
            base_url: cfg.url.trim_end_matches('/').into(),
            project: cfg.project.clone(),
            auth: Auth::Basic {
                username: cfg.username.clone(),
                password,
            },
            client,
        }
    }
    fn host(&self) -> &str {
        &self.host
    }
    fn scope(&self) -> String {
        match &self.project {
            Some(project) => format!("{}/{project}", self.host),
            None => format!("{} (all projects)", self.host),
        }
    }
    fn pages<T: DeserializeOwned + PageItem>(
        &self,
        path: &str,
        query: &str,
    ) -> Result<Vec<T>, SourceError> {
        collect_pages(|page| {
            let url = format!("{}{path}?page_size=100&page={page}{query}", self.base_url);
            match self.client.get_json::<Vec<T>>(&url, &self.auth, &[]) {
                Err(HttpError::Status(_, 404)) if page == 1 && path.ends_with("/repositories") => {
                    Err(SourceError::Other(format!(
                        "project {} not found",
                        path.split('/').nth(4).unwrap_or_default()
                    )))
                }
                result => Ok(result?),
            }
        })
    }
    fn artifact_rows(
        &self,
        repo_path: &str,
        repository: &str,
        artifact: &Artifact,
        scanner: &mut Option<Scanner>,
    ) -> Result<Vec<(Image, Vec<Finding>)>, SourceError> {
        if artifact.r#type != "IMAGE" {
            return Ok(Vec::new());
        }
        let mut tags: Vec<_> = artifact.tags.iter().map(|t| t.name.clone()).collect();
        tags.sort();
        tags.dedup();
        let mut candidates = Vec::new();
        if artifact.references.is_empty() {
            candidates.push((artifact.clone(), RowKind::Single, None));
        } else {
            for reference in &artifact.references {
                if reference
                    .platform
                    .as_ref()
                    .is_some_and(|p| p.os == "unknown" && p.architecture == "unknown")
                {
                    continue;
                }
                let platform = reference.platform.as_ref().map(map::platform_string);
                match self.client.get_json::<Artifact>(
                    &format!(
                        "{}{repo_path}/{}?with_scan_overview=true&with_tag=true",
                        self.base_url, reference.child_digest
                    ),
                    &self.auth,
                    &[],
                ) {
                    Ok(response) => {
                        if response.body.r#type == "IMAGE" {
                            candidates.push((response.body, RowKind::Child(platform), None));
                        }
                    }
                    Err(error) => candidates.push((
                        Artifact {
                            digest: reference.child_digest.clone(),
                            ..Artifact::default()
                        },
                        RowKind::Child(platform),
                        Some(row_failure(error)?),
                    )),
                }
            }
        }
        let mut rows = Vec::new();
        let mut references = BTreeSet::new();
        for (artifact, kind, mut failure) in candidates {
            let platform = match &kind {
                RowKind::Single => artifact
                    .extra_attrs
                    .as_ref()
                    .and_then(map::platform_from_attrs),
                RowKind::Child(platform) => platform.clone().or_else(|| {
                    artifact
                        .extra_attrs
                        .as_ref()
                        .and_then(map::platform_from_attrs)
                }),
            };
            let suffix = match &kind {
                RowKind::Single => None,
                RowKind::Child(_) => Some(
                    platform
                        .clone()
                        .unwrap_or_else(|| digest12(&artifact.digest)),
                ),
            };
            let mut reference =
                map::image_reference(repository, &tags, &artifact.digest, suffix.as_deref());
            if !references.insert(reference.clone()) {
                let suffix = format!(
                    "{}, {}",
                    suffix.unwrap_or_default(),
                    digest12(&artifact.digest)
                );
                reference =
                    map::image_reference(repository, &tags, &artifact.digest, Some(&suffix));
                references.insert(reference.clone());
            }
            let mut scan = map::scan_status(artifact.scan_overview.values().next());
            let mut findings = Vec::new();
            if failure.is_none() && scan.state == ScanState::Ok {
                match self.client.get_json::<BTreeMap<String, VulnReport>>(
                    &format!(
                        "{}{repo_path}/{}/additions/vulnerabilities",
                        self.base_url, artifact.digest
                    ),
                    &self.auth,
                    &[(
                        "X-Accept-Vulnerabilities",
                        "application/vnd.security.vulnerability.report; version=1.1",
                    )],
                ) {
                    Ok(response) => {
                        let vulnerabilities =
                            response.body.into_values().next().and_then(|report| {
                                if scanner.is_none() {
                                    *scanner = report.scanner;
                                }
                                report.vulnerabilities
                            });
                        match vulnerabilities {
                            Some(vulnerabilities) => {
                                findings = vulnerabilities
                                    .iter()
                                    .map(|v| map::finding(v, &reference))
                                    .collect();
                            }
                            None => {
                                scan.state = ScanState::Failed;
                                scan.error = Some("vulnerability report missing".into());
                                tracing::warn!(image = reference, "Harbor vulnerabilities missing");
                            }
                        }
                    }
                    Err(error) => failure = Some(row_failure(error)?),
                }
            }
            if let Some(error) = failure {
                tracing::warn!(image = reference, %error, "artifact request failed");
                scan.state = ScanState::Failed;
                scan.error = Some(error.to_string());
            }
            rows.push((
                Image {
                    reference,
                    tags: tags.clone(),
                    digest: Some(artifact.digest),
                    platform,
                    os: artifact.extra_attrs.as_ref().and_then(|a| a.os.clone()),
                    created_at: artifact.extra_attrs.and_then(|a| a.created),
                    size_bytes: artifact.size,
                    scan,
                },
                findings,
            ));
        }
        Ok(rows)
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
            let path = format!(
                "/api/v2.0/projects/{}/repositories",
                encode_segment(&project.name)
            );
            for repo in self.pages::<Repository>(&path, "")? {
                let name = repo
                    .name
                    .strip_prefix(&format!("{}/", project.name))
                    .unwrap_or(&repo.name);
                let path = format!("{path}/{}/artifacts", encode_segment(&encode_segment(name)));
                let artifacts =
                    self.pages::<Artifact>(&path, "&with_tag=true&with_scan_overview=true")?;
                tracing::info!("repository {}: {} artifacts", repo.name, artifacts.len());
                for artifact in artifacts {
                    rows.extend(self.artifact_rows(&path, &repo.name, &artifact, &mut scanner)?);
                }
            }
        }
        let (images, findings) = dedupe_images_by_reference(rows);
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

enum RowKind {
    Single,
    Child(Option<String>),
}
const MAX_PAGES: usize = 10_000;

trait PageItem {
    fn key(&self) -> &str;
}
impl PageItem for Artifact {
    fn key(&self) -> &str {
        &self.digest
    }
}
impl PageItem for Repository {
    fn key(&self) -> &str {
        &self.name
    }
}
impl PageItem for Project {
    fn key(&self) -> &str {
        &self.name
    }
}

fn collect_pages<T: PageItem>(
    mut request: impl FnMut(usize) -> Result<super::http::Response<Vec<T>>, SourceError>,
) -> Result<Vec<T>, SourceError> {
    let mut result = Vec::new();
    let mut previous = None;
    for page in 1..=MAX_PAGES {
        let response = request(page)?;
        let count = response.body.len();
        if repeated_page(&mut previous, response.body.first().map(PageItem::key)) {
            break;
        }
        result.extend(response.body);
        let total = response
            .headers
            .get("x-total-count")
            .and_then(|s| s.parse::<usize>().ok());
        if count == 0 || total.map(|t| result.len() >= t).unwrap_or(count < 100) {
            break;
        }
        if page == MAX_PAGES {
            tracing::warn!(MAX_PAGES, "pagination limit reached; results truncated");
        }
    }
    Ok(result)
}

fn repeated_page(previous: &mut Option<String>, first: Option<&str>) -> bool {
    let repeated = first.is_some() && previous.as_deref() == first;
    *previous = first.map(str::to_owned);
    repeated
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagination_stops_repeated_page_and_caps_requests() {
        let mut calls = 0;
        let rows = collect_pages(|_| {
            calls += 1;
            Ok(super::super::http::Response {
                body: vec![Repository {
                    name: "same".into(),
                }],
                headers: BTreeMap::from([("x-total-count".into(), "20000".into())]),
            })
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(rows.len(), 1);
        calls = 0;
        let rows = collect_pages(|page| {
            calls += 1;
            Ok(super::super::http::Response {
                body: vec![Repository {
                    name: page.to_string(),
                }],
                headers: BTreeMap::from([("x-total-count".into(), "20000".into())]),
            })
        })
        .unwrap();
        assert_eq!(calls, MAX_PAGES);
        assert_eq!(rows.len(), MAX_PAGES);
    }
    #[test]
    fn pagination_guard() {
        let mut previous = None;
        assert!(!repeated_page(&mut previous, Some("a")));
        assert!(!repeated_page(&mut previous, Some("b")));
        assert!(repeated_page(&mut previous, Some("b")));
        assert!(!repeated_page(&mut previous, None));
    }
}
