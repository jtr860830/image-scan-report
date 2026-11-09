//! Integration checks for cli behavior.
#[path = "support/reduced_fixtures.rs"]
mod reduced_fixtures;
use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_product_name_and_semver() {
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .arg("version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("judex "));
    // The version is the crate's own, whatever shape it has (0.1.0, 1.0.0-rc.1, ...).
    assert_eq!(
        s.trim().split(' ').nth(1).unwrap(),
        env!("CARGO_PKG_VERSION")
    );
}

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.yaml");
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trivy");
    std::fs::write(&path, format!("source:\n  type: trivy-files\n  path: {}\nreport:\n  language: en\n  organization: Test\n  json: true\n  pdf: false\noutput:\n  - type: filesystem\n    path: {}\n", input.display(), dir.display())).unwrap();
    path
}

#[test]
fn run_subcommand_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
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
        .env_remove("JUDEX_THEME_DIR")
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
        .env_remove("JUDEX_THEME_DIR")
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
        .env_remove("JUDEX_THEME_DIR")
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
    edition_theme(dir.path());
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .env("JUDEX_THEME_DIR", dir.path())
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
    assert_eq!(data["meta"]["product_name"], "Edition");
}

#[test]
fn run_default_config_produces_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let input = reduced_fixtures::input();
    let original_input =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trivy");
    let yaml = std::fs::read_to_string(&config)
        .unwrap()
        .replace("  json: true\n  pdf: false\n", "")
        .replace(
            original_input.to_str().unwrap(),
            input.path().to_str().unwrap(),
        );
    std::fs::write(&config, yaml).unwrap();
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
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
        .env_remove("JUDEX_THEME_DIR")
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
        let out = cargo_bin_cmd!("judex")
            .env_remove("JUDEX_THEME_DIR")
            .arg(flag)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!("judex {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn missing_config_lists_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("unused.json");
    for command in ["run", "check", "render-data"] {
        let mut cmd = cargo_bin_cmd!("judex");
        cmd.env_remove("JUDEX_THEME_DIR");
        cmd.env("HOME", temp.path())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("JUDEX_CONFIG")
            .arg(command);
        if command == "render-data" {
            cmd.arg("--out").arg(&output);
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(
                temp.path()
                    .join(".config/judex/config.yaml")
                    .to_str()
                    .unwrap()
            )
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("/etc/judex/config.yaml"));
    }
}

#[test]
fn check_fails_with_exit_2_when_theme_dir_env_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .args(["check", "--config"])
        .arg(config)
        .env("JUDEX_THEME_DIR", empty.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(empty.path().to_str().unwrap()));
    assert!(stderr.contains("theme.toml"));
}

fn edition_theme(dir: &std::path::Path) {
    let mut theme = image_scan_report::render::theme::default_theme();
    theme.product.name = "Edition".into();
    std::fs::write(dir.join("theme.toml"), toml::to_string(&theme).unwrap()).unwrap();
}

#[test]
fn version_uses_edition_name_from_theme_dir_env() {
    let dir = tempfile::tempdir().unwrap();
    edition_theme(dir.path());
    for command in ["version", "--version"] {
        let out = cargo_bin_cmd!("judex")
            .env("JUDEX_THEME_DIR", dir.path())
            .arg(command)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("Edition {} (judex)\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn version_warns_but_prints_when_theme_dir_env_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    for value in [dir.path().as_os_str(), std::ffi::OsStr::new("")] {
        for command in ["version", "--version"] {
            let out = cargo_bin_cmd!("judex")
                .env("JUDEX_THEME_DIR", value)
                .arg(command)
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("judex {}\n", env!("CARGO_PKG_VERSION"))
            );
            assert!(String::from_utf8_lossy(&out.stderr).contains("JUDEX_THEME_DIR:"));
        }
    }
}

#[test]
fn config_found_under_xdg_config_home() {
    let temp = tempfile::tempdir().unwrap();
    let product = temp.path().join("judex");
    std::fs::create_dir(&product).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let yaml = std::fs::read_to_string(root.join("deploy/examples/config-trivy-files.yaml"))
        .unwrap()
        .replace(
            "./tests/fixtures/trivy",
            root.join("tests/fixtures/trivy").to_str().unwrap(),
        )
        .replace("./out", temp.path().join("out").to_str().unwrap());
    std::fs::write(product.join("config.yaml"), yaml).unwrap();
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .env("HOME", temp.path())
        .env_remove("JUDEX_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CONFIG_HOME", temp.path())
        .arg("check")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn judex_config_env_overrides_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let config = write_config(temp.path());
    let xdg = temp.path().join("judex");
    std::fs::create_dir(&xdg).unwrap();
    std::fs::write(xdg.join("config.yaml"), "invalid: competing-config").unwrap();
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path())
        .env_remove("JUDEX_CONFIG")
        .env("JUDEX_CONFIG", config)
        .arg("check")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn missing_explicit_env_config_is_authoritative() {
    let temp = tempfile::tempdir().unwrap();
    let config = write_config(temp.path());
    let xdg = temp.path().join("judex");
    std::fs::create_dir(&xdg).unwrap();
    std::fs::copy(config, xdg.join("config.yaml")).unwrap();
    let out = cargo_bin_cmd!("judex")
        .env_remove("JUDEX_THEME_DIR")
        .env("XDG_CONFIG_HOME", temp.path())
        .env("JUDEX_CONFIG", "/nonexistent.yaml")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot read"));
    assert!(stderr.contains("/nonexistent.yaml"));
}

#[test]
fn empty_theme_env_never_selects_current_directory() {
    let temp = tempfile::tempdir().unwrap();
    edition_theme(temp.path());
    // A valid 1x1 PNG makes the current directory a complete theme.
    std::fs::write(
        temp.path().join("logo.png"),
        [
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 156, 99, 96, 0, 2,
            0, 0, 5, 0, 1, 169, 245, 214, 200, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
        ],
    )
    .unwrap();
    image_scan_report::render::theme::load(Some(temp.path())).unwrap();
    let config = write_config(temp.path());
    let out = cargo_bin_cmd!("judex")
        .current_dir(temp.path())
        .env("JUDEX_THEME_DIR", "")
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("judex {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("theme directory must not be empty"));
    let out = cargo_bin_cmd!("judex")
        .current_dir(temp.path())
        .env("JUDEX_THEME_DIR", "")
        .arg("check")
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn version_parse_warning_is_one_line() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("theme.toml"), "[broken").unwrap();
    let out = cargo_bin_cmd!("judex")
        .env("JUDEX_THEME_DIR", temp.path())
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("JUDEX_THEME_DIR:"));
    assert_eq!(stderr.lines().count(), 1);
}
