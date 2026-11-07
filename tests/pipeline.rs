#[path = "support/pdf.rs"]
mod pdf;
#[path = "support/reduced_fixtures.rs"]
mod reduced_fixtures;
use chrono::{DateTime, NaiveDate, Utc};
use image_scan_report::{
    config::Config,
    model::{Report, SourceKind},
    naming::{artifact_base_name, slug},
    pipeline::{ProductInfo, RunError, check, run, write_render_data},
    source::SourceError,
};
use std::path::Path;

fn now() -> DateTime<Utc> {
    "2026-11-07T12:00:00Z".parse().unwrap()
}
fn config(input: &Path, output: &Path) -> Config {
    serde_yaml_ng::from_str(&format!("source:\n  type: trivy-files\n  path: {}\nreport:\n  language: en\n  organization: Test\n  json: true\n  pdf: false\noutput:\n  - type: filesystem\n    path: {}\n", input.display(), output.display())).unwrap()
}
fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trivy")
}
#[test]
fn slug_and_base_name() {
    assert_eq!(slug("Demo Project/x"), "demo-project-x");
    assert_eq!(slug("---"), "report");
    assert_eq!(
        artifact_base_name(
            "trivy",
            SourceKind::TrivyFiles,
            NaiveDate::from_ymd_opt(2026, 11, 7).unwrap()
        ),
        "trivy-trivy-files-2026-11-07"
    );
}
#[test]
fn run_trivy_fixtures_to_json() {
    let dir = tempfile::tempdir().unwrap();
    let summary = run(&config(&fixtures(), dir.path()), now(), &product()).unwrap();
    let report: Report = serde_json::from_slice(
        &std::fs::read(dir.path().join("trivy-trivy-files-2026-11-07.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report.images.len(), 11);
    assert_eq!(report.generated_at, now());
    assert_eq!(report.organisation, "Test");
    assert_eq!(summary.images, 11);
    assert_eq!(summary.findings, report.findings.len());
    assert_eq!(summary.stored.len(), 1);
    assert!(summary.failed_sinks.is_empty());
}
#[test]
fn run_with_empty_input_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let err = run(&config(dir.path(), dir.path()), now(), &product())
        .err()
        .unwrap();
    assert_eq!(err.exit_code(), 3);
    assert!(matches!(err, RunError::Source(SourceError::Empty(_))));
}
#[test]
fn run_with_unwritable_sink_exits_5() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let err = run(&config(&fixtures(), file.path()), now(), &product())
        .err()
        .unwrap();
    assert_eq!(err.exit_code(), 5);
    assert!(matches!(err, RunError::AllSinksFailed(_)));
}
#[test]
fn check_reports_counts() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&fixtures(), dir.path());
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(
        check(&cfg, &product()).unwrap(),
        format!(
            "Trivy (files): {}: 11 images, {} findings; theme: judex; product: judex 0.1.0",
            fixtures().display(),
            summary.findings
        )
    );
}

#[test]
fn partial_sink_failure_preserves_success() {
    let dir = tempfile::tempdir().unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut cfg = config(&fixtures(), dir.path());
    cfg.output
        .push(image_scan_report::config::OutputConfig::Filesystem {
            path: file.path().into(),
        });
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(summary.stored.len(), 1);
    assert_eq!(summary.failed_sinks.len(), 1);
    assert!(summary.failed_sinks[0].contains(&file.path().display().to_string()));
}

fn product() -> ProductInfo {
    ProductInfo {
        name: "judex".into(),
        version: "0.1.0".into(),
    }
}
#[test]
fn run_writes_pdf_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let input = reduced_fixtures::input();
    let mut cfg = config(input.path(), dir.path());
    cfg.report.pdf = true;
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(summary.stored.len(), 2);
    let bytes = std::fs::read(dir.path().join(format!(
        "{}.pdf",
        artifact_base_name(
            input.path().file_name().unwrap().to_str().unwrap(),
            SourceKind::TrivyFiles,
            now().date_naive()
        )
    )))
    .unwrap();
    assert!(pdf::page_count(&bytes) >= 6);
    let _: Report = serde_json::from_slice(
        &std::fs::read(dir.path().join(format!(
            "{}.json",
            artifact_base_name(
                input.path().file_name().unwrap().to_str().unwrap(),
                SourceKind::TrivyFiles,
                now().date_naive()
            )
        )))
        .unwrap(),
    )
    .unwrap();
}
#[test]
fn run_with_zero_findings_renders() {
    let input = tempfile::tempdir().unwrap();
    std::fs::copy(
        fixtures().join("busybox-1.37.json"),
        input.path().join("busybox.json"),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(input.path(), dir.path());
    cfg.report.json = false;
    cfg.report.pdf = true;
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(summary.findings, 0);
    assert_eq!(summary.stored.len(), 1);
    let path = std::fs::read_dir(dir.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(path).unwrap();
    assert!(pdf::page_count(&bytes) >= 4);
    let strings = image_scan_report::render::strings::load(image_scan_report::model::Language::En);
    assert!(pdf::text(&bytes).contains(&strings["no_findings"]));
}
#[test]
fn theme_path_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), dir.path());
    cfg.theme.path =
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/theme/unknown-key"));
    for err in [
        run(&cfg, now(), &product()).unwrap_err(),
        check(&cfg, &product()).unwrap_err(),
    ] {
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("theme.toml"));
        assert!(matches!(err, RunError::Config(_)));
    }
}

#[test]
fn check_rejects_http_output_before_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), dir.path());
    cfg.output = vec![image_scan_report::config::OutputConfig::Http {
        url: "https://example.test/upload".into(),
        method: "POST".into(),
        headers: Default::default(),
        mode: image_scan_report::config::HttpMode::Raw,
        ca_file: None,
        timeout_secs: 30,
    }];
    assert!(matches!(check(&cfg, &product()), Err(RunError::Config(_))));
    assert!(matches!(
        run(&cfg, now(), &product()),
        Err(RunError::Config(_))
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn theme_errors_precede_bad_sinks() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), dir.path());
    cfg.theme.path =
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/theme/unknown-key"));
    cfg.output = vec![image_scan_report::config::OutputConfig::Http {
        url: "https://example.test/upload".into(),
        method: "POST".into(),
        headers: Default::default(),
        mode: image_scan_report::config::HttpMode::Raw,
        ca_file: None,
        timeout_secs: 30,
    }];
    for err in [
        run(&cfg, now(), &product()).unwrap_err(),
        check(&cfg, &product()).unwrap_err(),
    ] {
        assert!(matches!(err, RunError::Config(_)));
        assert!(err.to_string().contains("theme.toml"));
    }
}

#[test]
fn write_render_data_empty_input_exits_3() {
    let input = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let err = write_render_data(
        &config(input.path(), dir.path()),
        now(),
        &product(),
        &dir.path().join("data.json"),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert!(matches!(err, RunError::Source(SourceError::Empty(_))));
}

#[test]
fn write_render_data_missing_parent_exits_4() {
    let input = reduced_fixtures::input();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("missing/data.json");
    let err =
        write_render_data(&config(input.path(), dir.path()), now(), &product(), &out).unwrap_err();
    assert_eq!(err.exit_code(), 4);
    assert!(matches!(err, RunError::Render(_)));
    assert!(err.to_string().contains("missing/data.json"));
}

#[test]
fn write_render_data_returns_summary() {
    let input = reduced_fixtures::input();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("data.json");
    let summary =
        write_render_data(&config(input.path(), dir.path()), now(), &product(), &out).unwrap();
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(summary.path, out);
    assert_eq!(summary.images, 3);
    assert_eq!(data["summary"]["images_total"], summary.images);
    assert_eq!(data["summary"]["findings_total"], summary.findings);
}
