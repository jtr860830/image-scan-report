//! Integration checks for neuvector file behavior.
use image_scan_report::model::{ScanState, Severity, SeverityBasis};
use image_scan_report::source::{
    ScanSource,
    neuvector::report::{NvVulnerability, finding_from_nv},
    neuvector_file::{NeuvectorFileSource, parse_neuvector_result},
};

#[test]
fn parses_scanner_fixture() {
    let (image, findings) = parse_neuvector_result(
        &std::fs::read("tests/fixtures/neuvector-scanner/nginx-1.21.0/scan_result.json").unwrap(),
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        image.reference, "registry-1.docker.io/library/nginx:1.21.0",
        "neuvector_file: image.reference mismatch"
    );
    assert!(findings.len() > 100);
    assert!(
        findings
            .iter()
            .all(|f| f.score_source.as_deref() == Some("neuvector"))
    );
}
#[test]
fn finding_from_nv_uses_v3_then_v2() {
    let mut v: NvVulnerability = serde_json::from_str(r#"{"name":"CVE-1","severity":"High","package_name":"p","package_version":"1","score_v3":9.8,"score":6.8}"#).unwrap();
    for (v3, v2, severity, basis) in [
        (9.8, 6.8, Severity::Critical, SeverityBasis::Cvss3),
        (0.0, 6.8, Severity::Medium, SeverityBasis::Cvss2),
        (0.0, 0.0, Severity::High, SeverityBasis::ScannerLabel),
    ] {
        v.score_v3 = Some(v3);
        v.score = Some(v2);
        let f = finding_from_nv(&v, "image");
        assert_eq!(f.severity, severity, "neuvector_file: f.severity mismatch");
        assert_eq!(
            f.severity_basis, basis,
            "neuvector_file: f.severity_basis mismatch"
        );
    }
}
fn edge(
    name: &str,
) -> (
    image_scan_report::model::Image,
    Vec<image_scan_report::model::Finding>,
) {
    parse_neuvector_result(
        &std::fs::read(format!("tests/data/neuvector/{name}.json")).unwrap(),
        None,
    )
    .unwrap()
    .unwrap()
}
#[test]
fn failed_scan_is_kept_as_failed() {
    let set = NeuvectorFileSource {
        dir: "tests/data/neuvector/failed".into(),
    }
    .fetch()
    .unwrap();
    assert_eq!(
        set.images.len(),
        1,
        "neuvector_file: set.images.len() mismatch"
    );
    let i = &set.images[0];
    assert_eq!(
        i.scan.state,
        ScanState::Failed,
        "neuvector_file: i.scan.state mismatch"
    );
    assert_eq!(
        i.scan.error.as_deref(),
        Some("manifest unknown"),
        "neuvector_file: i.scan.error.as_deref() mismatch"
    );
    assert_eq!(
        i.reference, "nginx-9.9.9",
        "neuvector_file: i.reference mismatch"
    );
    assert!(set.findings.is_empty());
}
#[test]
fn empty_vulnerabilities_is_ok() {
    let (i, f) = edge("empty");
    assert_eq!(
        i.scan.state,
        ScanState::Ok,
        "neuvector_file: i.scan.state mismatch"
    );
    assert!(f.is_empty());
}
#[test]
fn not_neuvector_returns_none() {
    assert!(
        parse_neuvector_result(br#"{"SchemaVersion":2}"#, None)
            .unwrap()
            .is_none()
    );
}
#[test]
fn fetch_fixture_directory() {
    let s = NeuvectorFileSource {
        dir: "tests/fixtures/neuvector-scanner".into(),
    }
    .fetch()
    .unwrap();
    assert_eq!(
        s.images.len(),
        11,
        "neuvector_file: s.images.len() mismatch"
    );
    assert!(s.source.db_version.is_some());
}

#[test]
fn maps_optional_fields_and_timestamp_precedence() {
    let fallback = Some("2026-01-01T00:00:00Z".parse().unwrap());
    let bytes = br#"{"report":{
        "registry":"https://registry.example/","repository":"library/test","tag":"1",
        "digest":"sha256:abc","base_os":"alpine","size":123,
        "created_at":"2024-01-01T00:00:00Z","scanner_version":"5",
        "result":"SUCCEEDED","scanned_timestamp":1704067200,
        "scanned_at":"2025-01-01T00:00:00Z",
        "vulnerabilities":[{"name":"CVE-1","severity":"High","score":6.8,
        "package_name":"pkg","package_version":"1","fixed_version":"",
        "link":"https://example.com/CVE-1","published_timestamp":1704067200}]
    }}"#;
    let (i, f) = parse_neuvector_result(bytes, fallback).unwrap().unwrap();
    assert_eq!(
        i.reference, "registry.example/library/test:1",
        "neuvector_file: i.reference mismatch"
    );
    assert_eq!(i.tags, ["1"], "neuvector_file: i.tags mismatch");
    assert_eq!(
        i.digest.as_deref(),
        Some("sha256:abc"),
        "neuvector_file: i.digest.as_deref() mismatch"
    );
    assert_eq!(
        i.os.as_deref(),
        Some("alpine"),
        "neuvector_file: i.os.as_deref() mismatch"
    );
    assert_eq!(
        i.size_bytes,
        Some(123),
        "neuvector_file: i.size_bytes mismatch"
    );
    assert_eq!(
        i.scan.scanned_at, i.created_at,
        "neuvector_file: i.scan.scanned_at mismatch"
    );
    assert_eq!(
        i.scan.scanner_version.as_deref(),
        Some("5"),
        "neuvector_file: i.scan.scanner_version.as_deref() mismatch"
    );
    assert_eq!(
        i.scan.state,
        ScanState::Ok,
        "neuvector_file: i.scan.state mismatch"
    );
    assert_eq!(
        f[0].image, i.reference,
        "neuvector_file: f[0].image mismatch"
    );
    assert_eq!(
        f[0].fixed_version, None,
        "neuvector_file: f[0].fixed_version mismatch"
    );
    assert_eq!(
        f[0].fix_status, None,
        "neuvector_file: f[0].fix_status mismatch"
    );
    assert_eq!(
        f[0].description, "",
        "neuvector_file: f[0].description mismatch"
    );
    assert_eq!(
        f[0].links,
        ["https://example.com/CVE-1"],
        "neuvector_file: f[0].links mismatch"
    );
    assert_eq!(
        f[0].published_at, i.created_at,
        "neuvector_file: f[0].published_at mismatch"
    );
    assert_eq!(
        parse_neuvector_result(
            br#"{"report":{"repository":"bare","vulnerabilities":[]}}"#,
            fallback
        )
        .unwrap()
        .unwrap()
        .0
        .scan
        .scanned_at,
        fallback
    );
}

#[test]
fn timestamp_and_shape_edges() {
    use image_scan_report::source::neuvector::report::nv_timestamp;
    assert_eq!(
        nv_timestamp(None),
        None,
        "neuvector_file: nv_timestamp(None) mismatch"
    );
    assert_eq!(
        nv_timestamp(Some(0)),
        None,
        "neuvector_file: nv_timestamp(Some(0)) mismatch"
    );
    assert_eq!(
        nv_timestamp(Some(i64::MAX)),
        None,
        "neuvector_file: nv_timestamp(Some(i64::MAX)) mismatch"
    );
    assert!(parse_neuvector_result(b"{", None).is_err());
    assert!(
        parse_neuvector_result(br#"{"report":null}"#, None)
            .unwrap()
            .is_none()
    );
    assert!(parse_neuvector_result(br#"{"report":{"vulnerabilities":"invalid"}}"#, None).is_err());
    let (i, _) = parse_neuvector_result(br#"{"report":{"repository":"bare"}}"#, None)
        .unwrap()
        .unwrap();
    assert_eq!(i.reference, "bare", "neuvector_file: i.reference mismatch");
    assert_eq!(
        i.scan.state,
        ScanState::Failed,
        "neuvector_file: i.scan.state mismatch"
    );
    assert_eq!(
        i.scan.error.as_deref(),
        Some("vulnerabilities missing"),
        "neuvector_file: i.scan.error.as_deref() mismatch"
    );
}

#[test]
fn fetch_skips_bad_files_and_deduplicates_latest() {
    let d = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        (
            "a.json",
            r#"{"report":{"repository":"old","digest":"same","scanned_timestamp":1,"vulnerabilities":[]}}"#,
        ),
        (
            "b.json",
            r#"{"report":{"registry":"http://host/","repository":"new","digest":"same","scanned_timestamp":2,"cvedb_version":"v1","cvedb_create_time":"2024-01-01T00:00:00Z","vulnerabilities":[]}}"#,
        ),
        (
            "c.json",
            r#"{"report":{"repository":"other","digest":"other","cvedb_version":"v2","vulnerabilities":[]}}"#,
        ),
        ("bad.json", "{"),
        ("unrelated.json", "{}"),
    ] {
        std::fs::write(d.path().join(name), bytes).unwrap();
    }
    let s = NeuvectorFileSource {
        dir: d.path().into(),
    }
    .fetch()
    .unwrap();
    assert_eq!(s.images.len(), 2, "neuvector_file: s.images.len() mismatch");
    assert_eq!(
        s.images[0].reference, "host/new",
        "neuvector_file: s.images[0].reference mismatch"
    );
    assert_eq!(
        s.source.db_version.as_deref(),
        Some("v1"),
        "neuvector_file: s.source.db_version.as_deref() mismatch"
    );
    assert!(s.source.db_updated_at.is_some());
    assert_eq!(
        s.source.kind,
        image_scan_report::model::SourceKind::NeuvectorFiles
    );
    assert_eq!(
        s.source.scanner_name.as_deref(),
        Some("NeuVector"),
        "neuvector_file: s.source.scanner_name.as_deref() mismatch"
    );
    let d = tempfile::tempdir().unwrap();
    assert!(matches!(
        NeuvectorFileSource {
            dir: d.path().into()
        }
        .fetch(),
        Err(image_scan_report::source::SourceError::Empty(_))
    ));
}

#[test]
fn top_level_error_overrides_report_success() {
    let (image, findings) = parse_neuvector_result(
        br#"{"error_message":"scan failed","report":{"repository":"nginx","tag":"9","vulnerabilities":[]}}"#, None
    ).unwrap().unwrap();
    assert_eq!(
        image.reference, "nginx:9",
        "neuvector_file: image.reference mismatch"
    );
    assert_eq!(
        image.scan.state,
        ScanState::Failed,
        "neuvector_file: image.scan.state mismatch"
    );
    assert_eq!(
        image.scan.error.as_deref(),
        Some("scan failed"),
        "neuvector_file: image.scan.error.as_deref() mismatch"
    );
    assert!(findings.is_empty());
}

#[test]
fn renamed_failed_scans_keep_distinct_references() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a.json", "b.json"] {
        std::fs::write(
            dir.path().join(name),
            br#"{"error_message":"manifest unknown","report":null}"#,
        )
        .unwrap();
    }
    let set = NeuvectorFileSource {
        dir: dir.path().into(),
    }
    .fetch()
    .unwrap();
    assert_eq!(
        set.images.len(),
        2,
        "neuvector_file: set.images.len() mismatch"
    );
    assert!(
        set.images
            .iter()
            .all(|image| image.scan.state == ScanState::Failed)
    );
    let mut references: Vec<_> = set
        .images
        .iter()
        .map(|image| image.reference.as_str())
        .collect();
    references.sort_unstable();
    assert_eq!(
        references,
        ["a", "b"],
        "neuvector_file: references mismatch"
    );
}
