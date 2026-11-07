use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_product_name_and_semver() {
    let out = cargo_bin_cmd!("judex").arg("version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("judex "));
    assert_eq!(s.trim().split(' ').nth(1).unwrap().split('.').count(), 3);
}
