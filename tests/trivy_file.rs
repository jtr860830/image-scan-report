//! Integration checks for trivy file behavior.
use chrono::Datelike;
use image_scan_report::model::{ScanState, SeverityBasis};
use image_scan_report::source::{
    ScanSource, SourceError,
    files::{dedupe_images, walk_json_files},
    trivy_file::{TrivyFileSource, parse_trivy_report},
};

#[test]
fn parses_nginx_fixture() {
    let (image, findings) = parse_trivy_report(
        &std::fs::read("fixtures/trivy/nginx-1.21.0.json").unwrap(),
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(image.created_at.unwrap().year(), 2021);
    assert_eq!(
        image.scan.scanned_at,
        Some("2026-11-07T14:32:23.847557344Z".parse().unwrap())
    );
    assert_eq!(image.reference, "nginx:1.21.0");
    assert!(image.digest.as_deref().unwrap().starts_with("sha256:"));
    assert!(image.os.as_deref().unwrap().starts_with("debian"));
    assert!(findings.len() > 100);
    let f = findings
        .iter()
        .find(|f| f.id == "CVE-2023-44487")
        .expect("known CVE present");
    assert_eq!(f.severity_basis, SeverityBasis::Cvss3);
    assert_eq!(f.score_source.as_deref(), Some("nvd"));
}
fn edge(
    name: &str,
) -> (
    image_scan_report::model::Image,
    Vec<image_scan_report::model::Finding>,
) {
    parse_trivy_report(
        &std::fs::read(format!("tests/data/trivy/{name}.json")).unwrap(),
        None,
    )
    .unwrap()
    .unwrap()
}
#[test]
fn results_null_yields_image_without_findings() {
    let (i, f) = edge("results-null");
    assert_eq!(i.reference, "empty");
    assert!(f.is_empty());
}
#[test]
fn secret_and_license_classes_are_ignored() {
    assert!(edge("secret-only").1.is_empty());
}
#[test]
fn duplicate_vulnerability_counted_once_per_image() {
    assert_eq!(dedupe_images(vec![edge("duplicate")]).1.len(), 1);
}
#[test]
fn not_a_trivy_report_returns_none() {
    assert!(parse_trivy_report(br#"{"foo":1}"#, None).unwrap().is_none());
}
#[test]
fn walk_skips_unrelated_files_and_sorts() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("sub")).unwrap();
    for p in ["b.json", "a.JSON", "note.txt", "sub/c.json"] {
        std::fs::write(d.path().join(p), "{}").unwrap();
    }
    assert_eq!(
        walk_json_files(d.path()).unwrap(),
        ["a.JSON", "b.json", "sub/c.json"].map(|p| d.path().join(p))
    );
}
#[test]
fn fetch_fixture_directory() {
    let s = TrivyFileSource {
        dir: "fixtures/trivy".into(),
    }
    .fetch()
    .unwrap();
    assert_eq!(s.images.len(), 11);
    assert_eq!(s.scope, "trivy");
    let b = s
        .images
        .iter()
        .find(|i| i.reference.contains("busybox"))
        .unwrap();
    assert_eq!(b.scan.state, ScanState::Ok);
    assert!(!s.findings.iter().any(|f| f.image == b.reference));
}
#[test]
fn fetch_empty_directory_is_error() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("note.txt"), "").unwrap();
    assert!(matches!(
        TrivyFileSource {
            dir: d.path().into()
        }
        .fetch(),
        Err(SourceError::Empty(_))
    ));
}
#[test]
fn malformed_json_is_skipped_with_warning() {
    let d = tempfile::tempdir().unwrap();
    std::fs::copy(
        "fixtures/trivy/nginx-1.21.0.json",
        d.path().join("valid.json"),
    )
    .unwrap();
    std::fs::write(d.path().join("bad.json"), "{").unwrap();
    assert_eq!(
        TrivyFileSource {
            dir: d.path().into()
        }
        .fetch()
        .unwrap()
        .images
        .len(),
        1
    );
}

#[test]
fn latest_scan_wins_and_missing_timestamp_sorts_first() {
    let (base, findings) = edge("duplicate");
    let mut newer = base.clone();
    newer.scan.scanned_at = Some("2026-01-01T00:00:00Z".parse().unwrap());
    newer.reference = "newer".into();
    let mut older = newer.clone();
    older.scan.scanned_at = Some("2025-01-01T00:00:00Z".parse().unwrap());
    older.reference = "older".into();
    for image in [&mut newer, &mut older] {
        image.digest = Some("sha256:same".into());
    }
    let mut missing = base;
    missing.digest = Some("sha256:same".into());
    let (images, entries) = dedupe_images(vec![
        (missing, findings.clone()),
        (newer.clone(), vec![]),
        (older, findings),
    ]);
    assert_eq!(images, vec![newer]);
    assert!(entries.is_empty());
}

#[test]
fn maps_optional_fields_and_preserves_first_duplicate() {
    let timestamp = Some("2026-01-01T00:00:00Z".parse().unwrap());
    let bytes = br#"{
      "SchemaVersion":2,"ArtifactName":"ghcr.io/x/y:latest",
      "CreatedAt":"2025-01-01T00:00:00Z",
      "Metadata":{"OS":{"Family":"alpine","Name":"3.20"},"RepoDigests":["x@sha256:abc"],"ImageConfig":{"created":"2024-01-01T00:00:00Z","os":"linux","architecture":"arm64","variant":"v8"}},
      "Results":[{"Class":"lang-pkgs","Vulnerabilities":[
        {"VulnerabilityID":"CVE-1","PkgName":"pkg","InstalledVersion":"1","FixedVersion":"","Status":"will_not_fix","Severity":"HIGH","CVSS":{"nvd":{"V3Score":0,"V2Score":7.54}},"Title":"fallback","PrimaryURL":"primary","References":["reference"],"PublishedDate":"2024-01-01T00:00:00Z"},
        {"VulnerabilityID":"CVE-1","PkgName":"pkg","InstalledVersion":"1","Description":"second"}
      ]}]
    }"#;
    let (i, f) = parse_trivy_report(bytes, timestamp).unwrap().unwrap();
    assert_eq!(i.tags, vec!["latest"]);
    assert_eq!(i.platform.as_deref(), Some("linux/arm64/v8"));
    assert_eq!(i.os.as_deref(), Some("alpine 3.20"));
    assert_eq!(i.digest.as_deref(), Some("sha256:abc"));
    assert_eq!(
        i.scan.scanned_at,
        Some("2025-01-01T00:00:00Z".parse().unwrap())
    );
    assert!(i.created_at.is_some());
    let (_, f) = dedupe_images(vec![(i, f)]);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].description, "fallback");
    assert_eq!(f[0].links, vec!["primary", "reference"]);
    assert_eq!(f[0].fixed_version, None);
    assert_eq!(
        f[0].fix_status,
        Some(image_scan_report::model::FixStatus::WillNotFix)
    );
    assert_eq!(f[0].severity_basis, SeverityBasis::Cvss2);
    assert_eq!(f[0].score_v2, Some(7.5));
    assert!(f[0].published_at.is_some());
}
#[test]
fn unreadable_directory_and_invalid_shape_are_errors() {
    let d = tempfile::tempdir().unwrap();
    assert!(matches!(
        walk_json_files(&d.path().join("missing")),
        Err(SourceError::Unreadable(_, _))
    ));
    assert!(parse_trivy_report(br#"{"SchemaVersion":2}"#, None).is_err());
    assert!(parse_trivy_report(b"{", None).is_err());
}
#[test]
fn tags_ignore_registry_ports_and_digest_references() {
    for (reference, tags) in [
        ("localhost:5000/x", vec![]),
        ("bare", vec![]),
        ("nginx:1.21.0", vec!["1.21.0"]),
        ("nginx@sha256:abc", vec![]),
    ] {
        let bytes =
            serde_json::to_vec(&serde_json::json!({"SchemaVersion":2,"ArtifactName":reference}))
                .unwrap();
        assert_eq!(
            parse_trivy_report(&bytes, None).unwrap().unwrap().0.tags,
            tags
        );
    }
}

#[test]
fn missing_report_time_uses_file_mtime() {
    let path = std::path::Path::new("tests/data/trivy/no-report-time.json");
    let mtime = image_scan_report::source::files::file_modified_at(path);
    let (image, _) = parse_trivy_report(&std::fs::read(path).unwrap(), mtime)
        .unwrap()
        .unwrap();
    assert!(mtime.is_some());
    assert_eq!(image.scan.scanned_at, mtime);
    assert_eq!(image.created_at, None);
}
