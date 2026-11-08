#[path = "support/reduced_fixtures.rs"]
mod reduced_fixtures;
use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_product_name_and_semver() {
    let out = cargo_bin_cmd!("judex").arg("version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("judex "));
    // The version is the crate's own; a pre-release such as 1.0.0-rc.1 is fine.
    assert_eq!(
        s.trim().split(' ').nth(1).unwrap(),
        env!("CARGO_PKG_VERSION")
    );
}

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.yaml");
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trivy");
    std::fs::write(&path, format!("source:\n  type: trivy-files\n  path: {}\nreport:\n  language: en\n  organization: Test\n  json: true\n  pdf: false\noutput:\n  - type: filesystem\n    path: {}\n", input.display(), dir.display())).unwrap();
    path
}

#[test]
fn run_subcommand_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let out = cargo_bin_cmd!("judex")
        .args(["run", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let name = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .find(|n| n.ends_with(".json"))
        .unwrap();
    assert!(name.starts_with("trivy-trivy-files-"));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&name));
    let report: image_scan_report::model::Report =
        serde_json::from_slice(&std::fs::read(dir.path().join(&name)).unwrap()).unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!(
        "Report: {} images, {} findings",
        report.images.len(),
        report.findings.len()
    )));
}
#[test]
fn bad_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yaml");
    std::fs::write(&path, "source:\n  type: foo\n").unwrap();
    let out = cargo_bin_cmd!("judex")
        .args(["run", "--config"])
        .arg(path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid configuration"));
}

#[test]
fn partial_failure_is_reported_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, b"file").unwrap();
    let mut yaml = std::fs::read_to_string(&config).unwrap();
    yaml.push_str(&format!(
        "  - type: filesystem\n    path: {}\n",
        blocked.display()
    ));
    std::fs::write(&config, yaml).unwrap();
    let out = cargo_bin_cmd!("judex")
        .args(["run", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("failed sink:"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed sink:"));
}

#[test]
fn scope_for_dot_is_directory_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("input.json"),
        r#"{"SchemaVersion":2,"ArtifactName":"example","Results":[]}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("config.yaml"),
        "source:\n  type: trivy-files\n  path: .\nreport:\n  language: en\n  organization: Test\n  json: true\n  pdf: false\noutput:\n  - type: filesystem\n    path: out\n").unwrap();
    let out = cargo_bin_cmd!("judex")
        .current_dir(dir.path())
        .args(["run", "--config", "config.yaml"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let name = std::fs::read_dir(dir.path().join("out"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let report: image_scan_report::model::Report =
        serde_json::from_slice(&std::fs::read(name).unwrap()).unwrap();
    assert_eq!(
        report.scope,
        dir.path()
            .canonicalize()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
    );
}

#[test]
fn render_data_subcommand_writes_json() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let path = dir.path().join("data.json");
    let out = cargo_bin_cmd!("judex")
        .args(["render-data", "--config"])
        .arg(config)
        .arg("--out")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(data.get("strings").is_some());
    assert!(data.get("theme").is_some());
    assert_eq!(data["meta"]["product_name"], "judex");
}

#[test]
fn run_default_config_produces_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let input = reduced_fixtures::input();
    let original_input = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trivy");
    let yaml = std::fs::read_to_string(&config)
        .unwrap()
        .replace("  json: true\n  pdf: false\n", "")
        .replace(
            original_input.to_str().unwrap(),
            input.path().to_str().unwrap(),
        );
    std::fs::write(&config, yaml).unwrap();
    let out = cargo_bin_cmd!("judex")
        .args(["run", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|s| s == "pdf"))
    );
}

#[allow(dead_code)]
#[path = "support/harbor_mock.rs"]
mod harbor_mock;

#[test]
fn check_prints_scan_state_counts() {
    use image_scan_report::source::ScanSource;
    let (server, source) = harbor_mock::harbor_mock_subset_running();
    let expected = source.fetch().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mut cfg: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    cfg["source"] = serde_yaml_ng::from_str(&format!("type: harbor\nurl: {}\nproject: demo\nusername: robot\npassword_env: JUDEX_CLI_HARBOR_PASSWORD", server.base_url())).unwrap();
    std::fs::write(&path, serde_yaml_ng::to_string(&cfg).unwrap()).unwrap();
    let out = cargo_bin_cmd!("judex")
        .args(["check", "--config"])
        .arg(path)
        .env("JUDEX_CLI_HARBOR_PASSWORD", "secret-password")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!(
        "Harbor {}: demo: {} images (2 scanned, 0 failed, 1 not scanned), {} findings;",
        server.address(),
        expected.images.len(),
        expected.findings.len()
    )));
}

#[test]
fn version_flag_prints_product_and_version() {
    for flag in ["--version", "-V", "version"] {
        let out = cargo_bin_cmd!("judex").arg(flag).output().unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!("judex {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn default_config_path_is_etc_report() {
    assert!(!std::path::Path::new("/etc/report/config.yaml").exists());
    for command in ["run", "check", "render-data"] {
        let mut cmd = cargo_bin_cmd!("judex");
        cmd.env_remove("HOME").arg(command);
        if command == "render-data" {
            cmd.args(["--out", "/tmp/judex-unused.json"]);
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("/etc/report/config.yaml"));
    }
}
