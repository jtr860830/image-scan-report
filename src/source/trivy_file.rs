//! Trivy JSON reports loaded from a directory.
use super::{ParseError, ScanSource, SourceError, files::fetch_directory};
use crate::{
    model::*,
    severity::{CvssSourceScores, ScoreInput, classify, cvss_from_map},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Default, Deserialize)]
struct Report {
    #[serde(default, rename = "SchemaVersion")]
    schema_version: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "ArtifactName")]
    artifact_name: String,
    #[serde(default, rename = "CreatedAt")]
    created_at: Option<DateTime<Utc>>,
    #[serde(default, rename = "Metadata")]
    metadata: Metadata,
    #[serde(default, rename = "Results")]
    results: Option<Vec<ResultEntry>>,
}
#[derive(Default, Deserialize)]
struct Metadata {
    #[serde(default, rename = "OS")]
    os: Option<Os>,
    #[serde(default, rename = "RepoDigests")]
    repo_digests: Vec<String>,
    #[serde(default, rename = "ImageConfig")]
    image_config: Option<ImageConfig>,
}
#[derive(Default, Deserialize)]
struct Os {
    #[serde(default, rename = "Family")]
    family: String,
    #[serde(default, rename = "Name")]
    name: String,
}
#[derive(Default, Deserialize)]
struct ImageConfig {
    #[serde(default)]
    created: Option<DateTime<Utc>>,
    #[serde(default, rename = "architecture")]
    architecture: Option<String>,
    #[serde(default, rename = "os")]
    os: Option<String>,
    #[serde(default, rename = "variant")]
    variant: Option<String>,
}
#[derive(Default, Deserialize)]
struct ResultEntry {
    #[serde(default, rename = "Class")]
    class: String,
    #[serde(default, rename = "Vulnerabilities")]
    vulnerabilities: Option<Vec<Vulnerability>>,
}
#[derive(Default, Deserialize)]
struct Vulnerability {
    #[serde(default, rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(default, rename = "PkgName")]
    pkg_name: String,
    #[serde(default, rename = "InstalledVersion")]
    installed_version: String,
    #[serde(default, rename = "FixedVersion")]
    fixed_version: Option<String>,
    #[serde(default, rename = "Status")]
    status: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "CVSS")]
    cvss: BTreeMap<String, CvssSourceScores>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "PrimaryURL")]
    primary_url: Option<String>,
    #[serde(default, rename = "References")]
    references: Vec<String>,
    #[serde(default, rename = "PublishedDate")]
    published_date: Option<DateTime<Utc>>,
}
pub struct TrivyFileSource {
    pub dir: PathBuf,
}
impl ScanSource for TrivyFileSource {
    fn describe(&self) -> String {
        format!("Trivy (files): {}", self.dir.display())
    }
    fn fetch(&self) -> Result<ScanSet, SourceError> {
        let fetched = fetch_directory(&self.dir, |_, bytes, scanned_at| {
            parse_trivy_report(bytes, scanned_at)
        })?;
        Ok(fetched.into_scan_set(SourceInfo {
            kind: SourceKind::TrivyFiles,
            display_name: "Trivy (files)".into(),
            scanner_name: Some("Trivy".into()),
            scanner_version: None,
            db_version: None,
            db_updated_at: None,
        }))
    }
}
pub fn parse_trivy_report(
    bytes: &[u8],
    scanned_at: Option<DateTime<Utc>>,
) -> Result<Option<(Image, Vec<Finding>)>, ParseError> {
    let report: Report = serde_json::from_slice(bytes)?;
    if report.schema_version.is_none() {
        return Ok(None);
    }
    if report.artifact_name.is_empty() {
        return Err(ParseError::Shape("missing ArtifactName".into()));
    }
    let reference = report.artifact_name;
    let tags = reference
        .rsplit_once(':')
        .filter(|(_, tag)| !tag.contains('/') && !tag.is_empty() && !reference.contains('@'))
        .map(|(_, tag)| vec![tag.to_owned()])
        .unwrap_or_default();
    let image = Image {
        reference: reference.clone(),
        tags,
        digest: report
            .metadata
            .repo_digests
            .first()
            .and_then(|s| s.split_once('@'))
            .map(|(_, d)| d.to_owned()),
        os: report
            .metadata
            .os
            .map(|os| format!("{} {}", os.family, os.name).trim().to_owned()),
        created_at: report
            .metadata
            .image_config
            .as_ref()
            .and_then(|c| c.created),
        platform: report.metadata.image_config.and_then(|c| {
            c.architecture.map(|arch| {
                let mut p = format!("{}/{}", c.os.as_deref().unwrap_or("linux"), arch);
                if let Some(v) = c.variant.filter(|v| !v.is_empty()) {
                    p.push('/');
                    p.push_str(&v);
                }
                p
            })
        }),
        size_bytes: None,
        scan: ScanStatus {
            state: ScanState::Ok,
            scanned_at: report.created_at.or(scanned_at),
            scanner_version: None,
            error: None,
        },
    };
    let mut findings = Vec::new();
    for result in report.results.unwrap_or_default() {
        if !matches!(result.class.as_str(), "os-pkgs" | "lang-pkgs") {
            continue;
        }
        for v in result.vulnerabilities.unwrap_or_default() {
            let cvss = cvss_from_map(v.cvss);
            let c = classify(&ScoreInput {
                cvss: &cvss,
                scanner_label: v.severity.as_deref(),
            });
            let mut links: Vec<_> = v
                .primary_url
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();
            links.extend(v.references);
            findings.push(Finding {
                id: v.vulnerability_id,
                image: reference.clone(),
                severity: c.severity,
                severity_basis: c.basis,
                score_v3: c.score_v3,
                score_v2: c.score_v2,
                score_source: c.score_source,
                scanner_severity: v.severity,
                package: v.pkg_name,
                installed_version: v.installed_version,
                fixed_version: v.fixed_version.filter(|s| !s.is_empty()),
                fix_status: v.status.as_deref().map(FixStatus::parse),
                description: v
                    .description
                    .filter(|s| !s.is_empty())
                    .or(v.title)
                    .unwrap_or_default(),
                links,
                published_at: v.published_date,
            });
        }
    }
    Ok(Some((image, findings)))
}
