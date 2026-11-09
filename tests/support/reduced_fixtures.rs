/// Real scanner captures small enough for PDF integration tests.
pub fn input() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trivy");
    for name in ["alpine-3.12.json", "nginx-1.21.0.json", "busybox-1.37.json"] {
        std::fs::copy(fixtures.join(name), dir.path().join(name)).unwrap();
    }
    dir
}
