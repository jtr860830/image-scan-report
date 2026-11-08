//! NeuVector scanner JSON reports loaded from a directory.
use super::{
    ParseError, ScanSource, SourceError,
    files::fetch_directory,
    neuvector::report::{NvVulnerability, compose_reference, finding_from_nv, nv_timestamp},
};
use crate::model::*;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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

#[derive(Deserialize)]
struct NvFile {
    #[serde(default)]
    error_message: String,
    report: Option<NvReport>,
}

fn read_report(
    bytes: &[u8],
    path: Option<&Path>,
    source_dir: Option<&Path>,
) -> Result<Option<NvReport>, ParseError> {
    let file: NvFile = serde_json::from_slice(bytes)?;
    if file.error_message.is_empty() {
        return Ok(file.report);
    }
    let mut report = file.report.unwrap_or_else(|| NvReport {
        repository: path
            .zip(source_dir)
            .and_then(|(path, dir)| path.strip_prefix(dir).ok())
            .map(|path| {
                let mut reference = path.with_extension("");
                if path
                    .file_name()
                    .is_some_and(|name| name == "scan_result.json")
                    && reference
                        .parent()
                        .is_some_and(|parent| !parent.as_os_str().is_empty())
                {
                    reference.pop();
                }
                reference.to_string_lossy().into_owned()
            })
            .unwrap_or_default(),
        ..NvReport::default()
    });
    report.result = Some("failed".into());
    report.error = Some(file.error_message);
    report.vulnerabilities = None;
    Ok(Some(report))
}

fn map_report(report: NvReport, scanned_at: Option<DateTime<Utc>>) -> (Image, Vec<Finding>) {
    let reference = compose_reference(&report.registry, &report.repository, &report.tag);
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
    Ok(read_report(bytes, None, None)?.map(|report| map_report(report, scanned_at)))
}

pub struct NeuvectorFileSource {
    pub dir: PathBuf,
}

impl ScanSource for NeuvectorFileSource {
    fn describe(&self) -> String {
        format!("NeuVector scanner (files): {}", self.dir.display())
    }
    fn fetch(&self) -> Result<ScanSet, SourceError> {
        let mut db_version = None;
        let mut db_updated_at = None;
        let fetched = fetch_directory(&self.dir, |path, bytes, scanned_at| {
            Ok(
                read_report(bytes, Some(path), Some(&self.dir))?.map(|report| {
                    if db_version.is_none() {
                        db_version = report.cvedb_version.clone();
                    }
                    if db_updated_at.is_none() {
                        db_updated_at = report.cvedb_create_time;
                    }
                    map_report(report, scanned_at)
                }),
            )
        })?;
        Ok(fetched.into_scan_set(SourceInfo {
            kind: SourceKind::NeuvectorFiles,
            display_name: "NeuVector scanner (files)".into(),
            scanner_name: Some("NeuVector".into()),
            scanner_version: None,
            db_version,
            db_updated_at,
        }))
    }
}
