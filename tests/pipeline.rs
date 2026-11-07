use chrono::{DateTime, NaiveDate, Utc};
use judex::{
    config::Config,
    model::{Report, SourceKind},
    naming::{artifact_base_name, slug},
    pipeline::{RunError, check, run},
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
    let summary = run(&config(&fixtures(), dir.path()), now()).unwrap();
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
    let err = run(&config(dir.path(), dir.path()), now()).err().unwrap();
    assert_eq!(err.exit_code(), 3);
    assert!(matches!(err, RunError::Source(SourceError::Empty(_))));
}
#[test]
fn run_with_unwritable_sink_exits_5() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let err = run(&config(&fixtures(), file.path()), now()).err().unwrap();
    assert_eq!(err.exit_code(), 5);
    assert!(matches!(err, RunError::AllSinksFailed(_)));
}
#[test]
fn check_reports_counts() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&fixtures(), dir.path());
    let summary = run(&cfg, now()).unwrap();
    assert_eq!(
        check(&cfg).unwrap(),
        format!(
            "Trivy (files): {}: 11 images, {} findings",
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
    cfg.output.push(judex::config::OutputConfig::Filesystem {
        path: file.path().into(),
    });
    let summary = run(&cfg, now()).unwrap();
    assert_eq!(summary.stored.len(), 1);
    assert_eq!(summary.failed_sinks.len(), 1);
    assert!(summary.failed_sinks[0].contains(&file.path().display().to_string()));
}

#[test]
fn pdf_only_returns_empty_summary() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&fixtures(), dir.path());
    cfg.report.json = false;
    cfg.report.pdf = true;
    let summary = run(&cfg, now()).unwrap();
    assert!(summary.stored.is_empty());
    assert!(summary.failed_sinks.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
