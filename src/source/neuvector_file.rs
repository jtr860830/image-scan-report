//! NeuVector scanner JSON reports loaded from a directory.
use super::{
    ParseError, ScanSource, SourceError,
    files::{dedupe_images, file_modified_at, walk_json_files},
    neuvector::report::{NvVulnerability, finding_from_nv, nv_timestamp},
};
use crate::model::*;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Default, Deserialize)]
#[serde(default)]
struct NvReport {
    registry: String,
    repository: String,
    tag: String,
    digest: Option<String>,
    base_os: Option<String>,
    size: Option<u64>,
    created_at: Option<DateTime<Utc>>,
    cvedb_version: Option<String>,
    cvedb_create_time: Option<DateTime<Utc>>,
    scanner_version: Option<String>,
    result: Option<String>,
    error: Option<String>,
    scanned_timestamp: Option<i64>,
    scanned_at: Option<DateTime<Utc>>,
    vulnerabilities: Option<Vec<NvVulnerability>>,
}

fn read_report(bytes: &[u8]) -> Result<Option<NvReport>, ParseError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    match value.get("report").filter(|v| v.is_object()) {
        Some(report) => Ok(Some(serde_json::from_value(report.clone())?)),
        None => Ok(None),
    }
}

fn map_report(report: NvReport, scanned_at: Option<DateTime<Utc>>) -> (Image, Vec<Finding>) {
    let registry = report
        .registry
        .strip_prefix("https://")
        .or_else(|| report.registry.strip_prefix("http://"))
        .unwrap_or(&report.registry)
        .trim_end_matches('/');
    let mut reference = if registry.is_empty() {
        report.repository.clone()
    } else {
        format!("{registry}/{}", report.repository)
    };
    if !report.tag.is_empty() {
        reference.push(':');
        reference.push_str(&report.tag);
    }
    let succeeded = report
        .result
        .as_deref()
        .is_none_or(|s| s.eq_ignore_ascii_case("succeeded"));
    let ok = succeeded && report.vulnerabilities.is_some();
    let error = if ok {
        None
    } else {
        Some(
            report
                .error
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    report
                        .result
                        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("succeeded"))
                })
                .unwrap_or_else(|| "vulnerabilities missing".into()),
        )
    };
    let findings = report
        .vulnerabilities
        .unwrap_or_default()
        .iter()
        .map(|v| finding_from_nv(v, &reference))
        .collect();
    let image = Image {
        reference,
        tags: if report.tag.is_empty() {
            vec![]
        } else {
            vec![report.tag]
        },
        digest: report.digest.filter(|s| !s.is_empty()),
        platform: None,
        os: report.base_os,
        size_bytes: report.size,
        created_at: report.created_at,
        scan: ScanStatus {
            state: if ok { ScanState::Ok } else { ScanState::Failed },
            scanned_at: nv_timestamp(report.scanned_timestamp)
                .or(report.scanned_at)
                .or(scanned_at),
            scanner_version: report.scanner_version,
            error,
        },
    };
    (image, findings)
}

pub fn parse_neuvector_result(
    bytes: &[u8],
    scanned_at: Option<DateTime<Utc>>,
) -> Result<Option<(Image, Vec<Finding>)>, ParseError> {
    Ok(read_report(bytes)?.map(|report| map_report(report, scanned_at)))
}

pub struct NeuvectorFileSource {
    pub dir: PathBuf,
}

impl ScanSource for NeuvectorFileSource {
    fn describe(&self) -> String {
        format!("NeuVector scanner (files): {}", self.dir.display())
    }
    fn fetch(&self) -> Result<ScanSet, SourceError> {
        let mut items = Vec::new();
        let mut db_version = None;
        let mut db_updated_at = None;
        for path in walk_json_files(&self.dir)? {
            let parsed = std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|bytes| read_report(&bytes).map_err(|e| e.to_string()));
            match parsed {
                Ok(Some(report)) => {
                    if db_version.is_none() {
                        db_version = report.cvedb_version.clone();
                    }
                    if db_updated_at.is_none() {
                        db_updated_at = report.cvedb_create_time;
                    }
                    items.push(map_report(report, file_modified_at(&path)));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(file = %path.display(), %error, "skipping unreadable or invalid scan report")
                }
            }
        }
        if items.is_empty() {
            return Err(SourceError::Empty(self.dir.clone()));
        }
        let (images, findings) = dedupe_images(items);
        Ok(ScanSet {
            source: SourceInfo {
                kind: SourceKind::NeuvectorFiles,
                display_name: "NeuVector scanner (files)".into(),
                scanner_name: Some("NeuVector".into()),
                scanner_version: None,
                db_version,
                db_updated_at,
            },
            scope: self
                .dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            images,
            findings,
        })
    }
}
