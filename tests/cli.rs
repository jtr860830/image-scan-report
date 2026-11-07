use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_product_name_and_semver() {
    let out = cargo_bin_cmd!("judex").arg("version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("judex "));
    assert_eq!(s.trim().split(' ').nth(1).unwrap().split('.').count(), 3);
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
