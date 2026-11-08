use image_scan_report::{
    model::*,
    source::harbor::{api::*, map::*},
};
#[test]
fn scan_states_map() {
    assert_eq!(scan_status(None).state, ScanState::NotScanned);
    for (status, state, error) in [
        ("Error", ScanState::Failed, Some("Error")),
        ("Running", ScanState::NotScanned, Some("scan in progress")),
        ("Success", ScanState::Ok, None),
    ] {
        let overview: ScanOverview = serde_json::from_value(
            serde_json::json!({"scan_status":status,"end_time":"2026-11-08T12:00:00Z"}),
        )
        .unwrap();
        let result = scan_status(Some(&overview));
        assert_eq!(result.state, state);
        assert_eq!(result.error.as_deref(), error);
        assert_eq!(result.scanned_at, overview.end_time);
    }
}
#[test]
fn cvss_map_feeds_classify() {
    let v: Vuln = serde_json::from_value(serde_json::json!({"id":"CVE-test","vendor_attributes":{"CVSS":{"nvd":{"V3Score":10.0},"redhat":{"V3Score":7.4}}}})).unwrap();
    let f = finding(&v, "repo:tag");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.score_source.as_deref(), Some("nvd"));
}
#[test]
fn references_are_stable() {
    assert_eq!(
        image_reference(
            "repo",
            &["v2".into(), "latest".into()],
            "sha256:123456789012abcd",
            None
        ),
        "repo:latest"
    );
    assert_eq!(
        image_reference("repo", &[], "sha256:123456789012abcd", Some("linux/arm/v7")),
        "repo@123456789012 (linux/arm/v7)"
    );
}

mod support;
use image_scan_report::source::ScanSource;
use support::harbor_mock::*;
#[test]
fn fetches_project_images_and_findings() {
    let (_s, src) = harbor_mock();
    let result = src.fetch().unwrap();
    assert_eq!(result.images.len(), 19);
    assert!(
        result
            .findings
            .iter()
            .filter(|f| f.image == "demo/nginx:1.21.0")
            .count()
            > 300
    );
    assert_eq!(result.source.scanner_name.as_deref(), Some("Trivy"));
    assert!(result.scope.ends_with("/demo"));
}
#[test]
fn index_children_become_platform_rows() {
    let (_s, src) = harbor_mock();
    let result = src.fetch().unwrap();
    let children: Vec<_> = result
        .images
        .iter()
        .filter(|i| i.reference.starts_with("demo/alpine-multi:3.20 ("))
        .collect();
    assert_eq!(children.len(), 8);
    assert!(
        children
            .iter()
            .any(|i| i.reference.ends_with("(linux/amd64)"))
    );
    let digests: std::collections::BTreeSet<_> = children.iter().map(|i| &i.digest).collect();
    assert_eq!(digests.len(), 8);
}
#[test]
fn unauthorized_is_reported_without_secrets() {
    let s = httpmock::MockServer::start();
    s.mock(|w, t| {
        w.any_request();
        t.status(401);
    });
    let message = source(&s).fetch().unwrap_err().to_string();
    assert!(message.contains("authentication failed"));
    assert!(!message.contains("secret-password"));
}
#[test]
fn paginates_repositories_and_artifacts() {
    let s = httpmock::MockServer::start();
    paged(
        &s,
        "/api/v2.0/projects/demo/repositories",
        (0..150)
            .map(|n| serde_json::json!({"name":format!("demo/r{n}")}))
            .collect(),
    );
    for n in 0..150 {
        artifacts(
            &s,
            &format!("r{n}"),
            (0..if n == 0 { 101 } else { 1 })
                .map(
                    |a| serde_json::json!({"type":"IMAGE","digest":format!("sha256:{n:06}{a:06}")}),
                )
                .collect(),
        );
    }
    assert_eq!(source(&s).fetch().unwrap().images.len(), 250);
}
#[test]
fn multiple_tags_one_row() {
    let s = httpmock::MockServer::start();
    paged(
        &s,
        "/api/v2.0/projects/demo/repositories",
        vec![serde_json::json!({"name":"demo/repo"})],
    );
    artifacts(
        &s,
        "repo",
        vec![
            serde_json::json!({"type":"IMAGE","digest":"sha256:abc","tags":[{"name":"v2"},{"name":"latest"}]}),
        ],
    );
    let result = source(&s).fetch().unwrap();
    assert_eq!(result.images.len(), 1);
    assert_eq!(result.images[0].reference, "demo/repo:latest");
    assert_eq!(result.images[0].tags, ["latest", "v2"]);
}
#[test]
fn non_image_artifacts_are_skipped() {
    let (_s, src) = harbor_mock();
    let result = src.fetch().unwrap();
    assert!(
        !result
            .images
            .iter()
            .any(|i| i.reference.contains("junk-artifact")
                || i.platform.as_deref() == Some("unknown/unknown"))
    );
}

#[test]
fn fixture_responses_deserialize_without_sockets() {
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/harbor")).unwrap()
    {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("artifacts-")
        {
            let _: Vec<Artifact> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        }
    }
    for entry in std::fs::read_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/harbor/multiarch"
    ))
    .unwrap()
    {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        let bytes = std::fs::read(&path).unwrap();
        if name.starts_with("child-") {
            let _: Artifact = serde_json::from_slice(&bytes).unwrap();
        } else if name.starts_with("vulns-") {
            let _: std::collections::BTreeMap<String, VulnReport> =
                serde_json::from_slice(&bytes).unwrap();
        } else if name.starts_with("artifacts-") {
            let _: Vec<Artifact> = serde_json::from_slice(&bytes).unwrap();
        }
    }
}
#[test]
fn empty_scope_is_named() {
    let s = httpmock::MockServer::start();
    paged(&s, "/api/v2.0/projects/demo/repositories", vec![]);
    assert!(
        source(&s)
            .fetch()
            .unwrap_err()
            .to_string()
            .ends_with("/demo")
    );
}
