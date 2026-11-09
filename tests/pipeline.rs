//! Integration checks for pipeline behavior.
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
            "Trivy (files): {}: 11 images (11 scanned, 0 failed, 0 not scanned), {} findings; theme: judex; product: judex 0.1.0",
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
fn bad_http_ca_rejected_before_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), dir.path());
    cfg.output = vec![image_scan_report::config::OutputConfig::Http {
        url: "https://example.test/upload".into(),
        method: "POST".into(),
        headers: Default::default(),
        mode: image_scan_report::config::HttpMode::Raw,
        ca_file: Some("tests/data/tls/not-a-cert.pem".into()),
        insecure_skip_verify: false,
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
        insecure_skip_verify: false,
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

#[test]
fn customer_logo_renders_on_cover_and_gif_exits_2() {
    let input = reduced_fixtures::input();
    let output = tempfile::tempdir().unwrap();
    let assets = tempfile::tempdir().unwrap();
    let logo = assets.path().join("customer.png");
    std::fs::write(&logo, pdf::LOGO_PNG).unwrap();
    let mut cfg = config(input.path(), output.path());
    cfg.report.pdf = true;
    cfg.report.json = false;
    cfg.report.logo = Some(logo);
    run(&cfg, now(), &product()).unwrap();
    let path = std::fs::read_dir(output.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(path).unwrap();
    assert!(pdf::image_count(&bytes, 1) > 0);
    let data = image_scan_report::pipeline::render_data(&cfg, now(), &product()).unwrap();
    assert_eq!(data.meta.logo.as_deref(), Some("report-logo.png"));
    let gif = assets.path().join("customer.gif");
    std::fs::write(&gif, b"GIF89a").unwrap();
    cfg.report.logo = Some(gif);
    let err = run(&cfg, now(), &product()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("report.logo:"), "{err}");
    assert!(!err.to_string().contains("theme:"), "{err}");
    assert!(matches!(err, RunError::Config(_)));
}

#[allow(dead_code)]
#[path = "support/harbor_mock.rs"]
mod harbor_mock;
#[allow(dead_code)]
#[path = "support/neuvector_mock.rs"]
mod neuvector_mock;

fn api_config(kind: &str, url: &str, output: &Path) -> Config {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe { std::env::set_var("JUDEX_TASK5_MOCK_PASSWORD", "secret-password") });
    let mut cfg = config(output, output);
    cfg.source = serde_yaml_ng::from_str(&format!(
        "type: {kind}\nurl: {url}\nusername: {}\npassword_env: JUDEX_TASK5_MOCK_PASSWORD\ntimeout_secs: 1\n{}",
        if kind == "harbor" { "robot" } else { "admin" },
        if kind == "harbor" {
            "project: demo"
        } else {
            "registry: harbor-lab"
        }
    ))
    .unwrap();
    cfg
}

#[test]
fn missing_password_env_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    for kind in ["harbor", "neuvector"] {
        let mut cfg = api_config(kind, "https://scanner.test", dir.path());
        match &mut cfg.source {
            image_scan_report::config::SourceConfig::Harbor { password_env, .. }
            | image_scan_report::config::SourceConfig::Neuvector { password_env, .. } => {
                *password_env = "JUDEX_TASK5_UNSET_PASSWORD_49382".into()
            }
            _ => unreachable!(),
        }
        let err = check(&cfg, &product()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("JUDEX_TASK5_UNSET_PASSWORD_49382"));
        assert!(
            matches!(err, RunError::Config(image_scan_report::config::ConfigError::MissingEnv(ref n)) if n == "JUDEX_TASK5_UNSET_PASSWORD_49382")
        );
    }
}

#[test]
fn bad_ca_file_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    for kind in ["harbor", "neuvector"] {
        let mut cfg = api_config(kind, "https://scanner.test", dir.path());
        match &mut cfg.source {
            image_scan_report::config::SourceConfig::Harbor { ca_file, .. }
            | image_scan_report::config::SourceConfig::Neuvector { ca_file, .. } => {
                *ca_file = Some("tests/data/tls/not-a-cert.pem".into())
            }
            _ => unreachable!(),
        }
        let err = check(&cfg, &product()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("ca_file"));
    }
}

#[test]
fn unreachable_scanner_exits_3() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let dir = tempfile::tempdir().unwrap();
    let start = std::time::Instant::now();
    let err = check(&api_config("harbor", &url, dir.path()), &product()).unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert!(err.to_string().contains(url.trim_start_matches("http://")));
    assert!(matches!(err, RunError::Source(_)));
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn run_against_mock_harbor_writes_pdf_and_json() {
    let (server, _) = harbor_mock::harbor_mock_subset();
    run_api_mock("harbor", &server.base_url(), Some(3));
}

#[test]
fn run_against_mock_neuvector_writes_pdf() {
    let (server, _) = neuvector_mock::capture(false);
    run_api_mock("neuvector", &server.base_url(), None);
}

fn run_api_mock(kind: &str, url: &str, images: Option<usize>) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = api_config(kind, url, dir.path());
    match &mut cfg.source {
        image_scan_report::config::SourceConfig::Harbor { password_env, .. }
        | image_scan_report::config::SourceConfig::Neuvector { password_env, .. } => {
            *password_env = "JUDEX_TASK5_MOCK_PASSWORD".into()
        }
        _ => unreachable!(),
    }
    cfg.report.pdf = true;
    let result = run(&cfg, now(), &product());
    let summary = result.unwrap();
    assert_eq!(summary.stored.len(), 2);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        if path.extension().unwrap() == "pdf" {
            assert!(pdf::page_count(&bytes) >= 6);
        } else {
            let report: Report = serde_json::from_slice(&bytes).unwrap();
            if kind == "neuvector" {
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(json["source"]["kind"], "neuvector");
                assert_eq!(
                    report.scope,
                    format!("{}/harbor-lab", url.trim_start_matches("http://"))
                );
            }
            if let Some(n) = images {
                assert_eq!(report.images.len(), n);
            }
            assert_eq!(report.images.len(), summary.images);
        }
    }
}

fn upload_output(url: &str) -> image_scan_report::config::OutputConfig {
    serde_yaml_ng::from_str(&format!(
        "type: http\nurl: {url}\nheaders:\n  Authorization: Bearer pipeline-secret"
    ))
    .unwrap()
}
#[test]
fn one_failed_sink_keeps_exit_zero_and_hides_headers() {
    let server = httpmock::MockServer::start();
    let m = server.mock(|w, t| {
        w.any_request();
        t.status(403);
    });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&fixtures(), dir.path());
    cfg.output.push(upload_output(&server.url("/upload")));
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(summary.failed_sinks.len(), 1);
    assert!(!summary.failed_sinks[0].contains("Bearer"));
    assert_eq!(summary.stored.len(), 1);
    use image_scan_report::sink::ReportSink;
    let direct = image_scan_report::sink::http::HttpSink::new(
        server.url("/upload"),
        "PUT".into(),
        vec![("Authorization".into(), "Bearer pipeline-secret".into())],
        image_scan_report::config::HttpMode::Raw,
        image_scan_report::source::http::client_from_tls(
            None,
            false,
            std::time::Duration::from_secs(1),
        )
        .unwrap(),
    );
    let error = direct
        .store(&image_scan_report::sink::Artifact {
            file_name: "test.pdf".into(),
            media_type: "application/pdf",
            bytes: vec![],
        })
        .unwrap_err();
    assert!(!error.to_string().contains("pipeline-secret"));
    m.assert_calls(2);
}
#[test]
fn all_sinks_failed_exits_5() {
    let server = httpmock::MockServer::start();
    let m = server.mock(|w, t| {
        w.any_request();
        t.status(500);
    });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&fixtures(), dir.path());
    cfg.output = vec![upload_output(&server.url("/upload"))];
    let e = run(&cfg, now(), &product()).unwrap_err();
    assert_eq!(e.exit_code(), 5);
    assert!(matches!(e, RunError::AllSinksFailed(_)));
    assert!(!e.to_string().contains("Bearer"));
    m.assert_calls(3);
}
#[test]
fn unset_header_variable_is_config_error() {
    let server = httpmock::MockServer::start();
    let m = server.mock(|w, t| {
        w.any_request();
        t.status(200);
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, format!("source:\n  type: harbor\n  url: {}\n  username: reader\n  password_env: UNUSED_PASSWORD\nreport:\n  language: en\n  organization: Test\noutput:\n  - type: http\n    url: {}\n    headers:\n      X-Token: \"${{JUDEX_UNSET_UPLOAD_VAR}}\"\n", server.base_url(), server.url("/upload"))).unwrap();
    let result = image_scan_report::config::load(&path).map_err(RunError::from);
    assert!(
        matches!(result, Err(RunError::Config(image_scan_report::config::ConfigError::MissingEnv(n))) if n == "JUDEX_UNSET_UPLOAD_VAR")
    );
    m.assert_calls(0);
}
#[test]
fn json_artifact_goes_to_http_sink_too() {
    let server = httpmock::MockServer::start();
    let input = reduced_fixtures::input();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(input.path(), dir.path());
    cfg.report.pdf = true;
    cfg.output = vec![upload_output(&server.url("/upload/{filename}"))];
    let base = artifact_base_name(
        input.path().file_name().unwrap().to_str().unwrap(),
        SourceKind::TrivyFiles,
        now().date_naive(),
    );
    let mocks: Vec<_> = [("pdf", "application/pdf"), ("json", "application/json")]
        .into_iter()
        .map(|(ext, ct)| {
            server.mock(|w, t| {
                w.method("PUT")
                    .path(format!("/upload/{base}.{ext}"))
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{base}.{ext}\""),
                    )
                    .header("Content-Type", ct);
                t.status(201);
            })
        })
        .collect();
    let summary = run(&cfg, now(), &product()).unwrap();
    assert_eq!(summary.stored.len(), 2);
    for m in mocks {
        m.assert_calls(1);
    }
}
