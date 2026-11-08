//! Integration checks for harbor source behavior.
use image_scan_report::{
    model::*,
    source::harbor::{api::*, map::*},
};
#[test]
fn scan_states_map() {
    assert_eq!(
        scan_status(None).state,
        ScanState::NotScanned,
        "harbor_source: scan_status(None).state mismatch"
    );
    let artifact: Artifact =
        serde_json::from_value(serde_json::json!({"scan_overview":{}})).unwrap();
    assert_eq!(
        scan_status(artifact.scan_overview.values().next()).state,
        ScanState::NotScanned
    );
    for (status, state, error) in [
        ("Error", ScanState::Failed, Some("Error")),
        ("Stopped", ScanState::Failed, Some("Stopped")),
        ("Running", ScanState::NotScanned, Some("scan in progress")),
        ("Success", ScanState::Ok, None),
        ("sUcCeSs", ScanState::Ok, None),
    ] {
        let overview: ScanOverview = serde_json::from_value(
            serde_json::json!({"scan_status":status,"end_time":"2026-11-08T12:00:00Z"}),
        )
        .unwrap();
        let result = scan_status(Some(&overview));
        assert_eq!(result.state, state, "harbor_source: result.state mismatch");
        assert_eq!(
            result.error.as_deref(),
            error,
            "harbor_source: result.error.as_deref() mismatch"
        );
        assert_eq!(
            result.scanned_at, overview.end_time,
            "harbor_source: result.scanned_at mismatch"
        );
    }
}
#[test]
fn cvss_map_feeds_classify() {
    let v: Vuln = serde_json::from_value(serde_json::json!({"id":"CVE-test","vendor_attributes":{"CVSS":{"nvd":{"V3Score":10.0},"redhat":{"V3Score":7.4}}}})).unwrap();
    let f = finding(&v, "repo:tag");
    assert_eq!(
        f.severity,
        Severity::Critical,
        "harbor_source: f.severity mismatch"
    );
    assert_eq!(
        f.score_source.as_deref(),
        Some("nvd"),
        "harbor_source: f.score_source.as_deref() mismatch"
    );
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
    assert_eq!(
        result.images.len(),
        19,
        "harbor_source: result.images.len() mismatch"
    );
    assert!(
        result
            .findings
            .iter()
            .filter(|f| f.image == "demo/nginx:1.21.0")
            .count()
            > 300
    );
    assert_eq!(
        result.source.scanner_name.as_deref(),
        Some("Trivy"),
        "harbor_source: result.source.scanner_name.as_deref() mismatch"
    );
    assert_eq!(
        result.scope,
        format!("{}/demo", _s.address()),
        "harbor_source: result.scope mismatch"
    );
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
    assert_eq!(children.len(), 8, "harbor_source: children.len() mismatch");
    assert!(
        children
            .iter()
            .any(|i| i.reference.ends_with("(linux/amd64)"))
    );
    let digests: std::collections::BTreeSet<_> = children.iter().map(|i| &i.digest).collect();
    assert_eq!(digests.len(), 8, "harbor_source: digests.len() mismatch");
    for child in children {
        let digest = child.digest.as_ref().unwrap();
        let report = fixture(&format!("multiarch/vulns-{}.json", &digest[7..19]));
        let expected = report.as_object().unwrap().values().next().unwrap()["vulnerabilities"]
            .as_array()
            .map_or(0, Vec::len);
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|f| f.image == child.reference)
                .count(),
            expected
        );
    }
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
    let mut mocks = paged(
        &s,
        "/api/v2.0/projects/demo/repositories",
        (0..150)
            .map(|n| serde_json::json!({"name":format!("demo/r{n}")}))
            .collect(),
    );
    for n in 0..150 {
        mocks.extend(artifacts(
            &s,
            &format!("r{n}"),
            (0..if n == 0 { 101 } else { 1 })
                .map(
                    |a| serde_json::json!({"type":"IMAGE","digest":format!("sha256:{n:06}{a:06}")}),
                )
                .collect(),
        ));
    }
    assert_eq!(
        source(&s).fetch().unwrap().images.len(),
        250,
        "harbor_source: source(&s).fetch().unwrap().images.len() mismatch"
    );
    for mock in mocks {
        mock.assert_calls(1);
    }
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
    assert_eq!(
        result.images.len(),
        1,
        "harbor_source: result.images.len() mismatch"
    );
    assert_eq!(
        result.images[0].reference, "demo/repo:latest",
        "harbor_source: result.images[0].reference mismatch"
    );
    assert_eq!(
        result.images[0].tags,
        ["latest", "v2"],
        "harbor_source: result.images[0].tags mismatch"
    );
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

#[test]
fn all_projects_scope() {
    let (server, mut src) = harbor_mock();
    src.project = None;
    let result = src.fetch().unwrap();
    assert_eq!(
        result.images.len(),
        19,
        "harbor_source: result.images.len() mismatch"
    );
    assert_eq!(
        result.scope,
        format!("{} (all projects)", server.address()),
        "harbor_source: result.scope mismatch"
    );
}

#[test]
fn failing_child_becomes_failed_row() {
    let parent = fixture("multiarch/artifacts-alpine-multi.json");
    let child = parent[0]["references"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["platform"]["os"] == "linux")
        .unwrap();
    let digest = child["child_digest"].as_str().unwrap();
    let path = format!("/api/v2.0/projects/demo/repositories/alpine-multi/artifacts/{digest}");
    let (_server, src) = harbor_mock_with_failure(Some((&path, 500)));
    let result = src.fetch().unwrap();
    assert_eq!(
        result.images.len(),
        19,
        "harbor_source: result.images.len() mismatch"
    );
    let row = result
        .images
        .iter()
        .find(|i| i.digest.as_deref() == Some(digest))
        .unwrap();
    assert_eq!(
        row.scan.state,
        ScanState::Failed,
        "harbor_source: row.scan.state mismatch"
    );
    assert!(row.scan.error.as_ref().unwrap().contains("500"));
    assert_eq!(
        result
            .images
            .iter()
            .filter(|i| i.scan.state == ScanState::Ok)
            .count(),
        18
    );
    assert!(!result.findings.iter().any(|f| f.image == row.reference));
}

#[test]
fn failing_vulnerability_report_becomes_failed_row() {
    let artifact = fixture("artifacts-nginx.json");
    let digest = artifact[0]["digest"].as_str().unwrap();
    let path = format!(
        "/api/v2.0/projects/demo/repositories/nginx/artifacts/{digest}/additions/vulnerabilities"
    );
    let (_server, src) = harbor_mock_with_failure(Some((&path, 404)));
    let result = src.fetch().unwrap();
    let row = result
        .images
        .iter()
        .find(|i| i.reference == "demo/nginx:1.21.0")
        .unwrap();
    assert_eq!(
        row.scan.state,
        ScanState::Failed,
        "harbor_source: row.scan.state mismatch"
    );
    assert!(row.scan.error.as_ref().unwrap().contains("404"));
    assert!(row.scan.scanned_at.is_some());
    assert!(!result.findings.iter().any(|f| f.image == row.reference));
}

#[test]
fn nested_repository_is_double_encoded() {
    let server = httpmock::MockServer::start();
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        vec![serde_json::json!({"name":"demo/nested/busybox"})],
    );
    let mut values = fixture("artifacts-nested-busybox.json")
        .as_array()
        .unwrap()
        .clone();
    // This test isolates routing from vulnerability retrieval.
    values[0]["scan_overview"] = serde_json::json!({});
    let mocks = artifacts(&server, "nested%252Fbusybox", values);
    let result = source(&server).fetch().unwrap();
    assert_eq!(
        result.images[0].reference, "demo/nested/busybox:1.37",
        "harbor_source: result.images[0].reference mismatch"
    );
    for mock in mocks {
        mock.assert_calls(1);
    }
}

#[test]
fn platform_attrs_fallback() {
    let attrs: ExtraAttrs = serde_json::from_value(
        serde_json::json!({"os":"linux","architecture":"arm","variant":"v7"}),
    )
    .unwrap();
    assert_eq!(
        platform_from_attrs(&attrs).as_deref(),
        Some("linux/arm/v7"),
        "harbor_source: platform_from_attrs(&attrs).as_deref() mismatch"
    );
    assert!(platform_from_attrs(&ExtraAttrs::default()).is_none());
}

#[test]
fn missing_child_platform_uses_attrs_or_digest_suffix() {
    let server = httpmock::MockServer::start();
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        vec![serde_json::json!({"name":"demo/index"})],
    );
    artifacts(
        &server,
        "index",
        vec![
            serde_json::json!({"type":"IMAGE","digest":"sha256:parent","tags":[{"name":"v1"}],"references":[
                {"child_digest":"sha256:111111111111aaaa"}, {"child_digest":"sha256:222222222222bbbb"}, {"child_digest":"sha256:333333333333cccc"}
            ]}),
        ],
    );
    for (digest, attrs) in [
        (
            "sha256:111111111111aaaa",
            serde_json::json!({"os":"linux","architecture":"arm","variant":"v7"}),
        ),
        ("sha256:222222222222bbbb", serde_json::json!({})),
        ("sha256:333333333333cccc", serde_json::json!({})),
    ] {
        server.mock(|w, t| {
            w.path(format!(
                "/api/v2.0/projects/demo/repositories/index/artifacts/{digest}"
            ))
            .query_param("with_tag", "true")
            .query_param("with_scan_overview", "true");
            t.status(200)
                .json_body(serde_json::json!({"type":"IMAGE","digest":digest,"extra_attrs":attrs}));
        });
    }
    let result = source(&server).fetch().unwrap();
    let references: std::collections::BTreeSet<_> =
        result.images.iter().map(|i| i.reference.as_str()).collect();
    assert_eq!(
        references,
        std::collections::BTreeSet::from([
            "demo/index:v1 (linux/arm/v7)",
            "demo/index:v1 (222222222222)",
            "demo/index:v1 (333333333333)"
        ])
    );
}

#[test]
fn shared_digest_in_two_repositories_preserves_both_rows() {
    let server = httpmock::MockServer::start();
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        vec![
            serde_json::json!({"name":"demo/busybox"}),
            serde_json::json!({"name":"demo/nested/busybox"}),
        ],
    );
    for (repo, file) in [
        ("busybox", "artifacts-busybox.json"),
        ("nested%252Fbusybox", "artifacts-nested-busybox.json"),
    ] {
        let values = fixture(file).as_array().unwrap().clone();
        artifacts(&server, repo, values.clone());
        for artifact in values {
            let digest = artifact["digest"].as_str().unwrap();
            server.mock(|w, t| {
                w.path(format!("/api/v2.0/projects/demo/repositories/{repo}/artifacts/{digest}/additions/vulnerabilities"));
                t.json_body(fixture("vulns/nginx.json"));
            });
        }
    }
    let result = source(&server).fetch().unwrap();
    for repo in ["demo/busybox:", "demo/nested/busybox:"] {
        let image = result
            .images
            .iter()
            .find(|i| i.reference.starts_with(repo))
            .unwrap();
        assert!(result.findings.iter().any(|f| f.image == image.reference));
    }
    assert_eq!(
        result.images.len(),
        2,
        "harbor_source: result.images.len() mismatch"
    );
}

#[test]
fn missing_project_on_first_repositories_page_is_named() {
    let server = httpmock::MockServer::start();
    let request = server.mock(|w, t| {
        w.path("/api/v2.0/projects/demo/repositories")
            .query_param("page", "1");
        t.status(404);
    });
    assert_eq!(
        source(&server).fetch().unwrap_err().to_string(),
        "project demo not found"
    );
    request.assert_calls(1);
}

fn fetch_with_additions(body: serde_json::Value) -> ScanSet {
    let server = httpmock::MockServer::start();
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        vec![serde_json::json!({"name":"demo/repo"})],
    );
    artifacts(
        &server,
        "repo",
        vec![
            serde_json::json!({"type":"IMAGE","digest":"sha256:abc","tags":[{"name":"v1"}],"scan_overview":{"report":{"scan_status":"Success"}}}),
        ],
    );
    server.mock(|w, t| {
        w.path("/api/v2.0/projects/demo/repositories/repo/artifacts/sha256:abc/additions/vulnerabilities");
        t.json_body(body);
    });
    source(&server).fetch().unwrap()
}

#[test]
fn empty_additions_body_is_failed() {
    let result = fetch_with_additions(serde_json::json!({}));
    assert_eq!(
        result.images[0].scan.state,
        ScanState::Failed,
        "harbor_source: result.images[0].scan.state mismatch"
    );
    assert_eq!(
        result.images[0].scan.error.as_deref(),
        Some("vulnerability report missing")
    );
    assert!(result.findings.is_empty());
}

#[test]
fn null_vulnerabilities_is_failed() {
    for report in [
        serde_json::json!({"vulnerabilities":null}),
        serde_json::json!({}),
    ] {
        let result = fetch_with_additions(
            serde_json::json!({"application/vnd.security.vulnerability.report; version=1.1":report}),
        );
        assert_eq!(
            result.images[0].scan.state,
            ScanState::Failed,
            "harbor_source: result.images[0].scan.state mismatch"
        );
        assert_eq!(
            result.images[0].scan.error.as_deref(),
            Some("vulnerability report missing")
        );
        assert!(result.findings.is_empty());
    }
}

#[test]
fn empty_vulnerability_list_is_clean() {
    let result = fetch_with_additions(
        serde_json::json!({"application/vnd.security.vulnerability.report; version=1.1":{"vulnerabilities":[]}}),
    );
    assert_eq!(
        result.images[0].scan.state,
        ScanState::Ok,
        "harbor_source: result.images[0].scan.state mismatch"
    );
    assert_eq!(
        result.images[0].scan.error, None,
        "harbor_source: result.images[0].scan.error mismatch"
    );
    assert!(result.findings.is_empty());
}

#[test]
fn sibling_children_with_same_platform_get_distinct_references() {
    let server = httpmock::MockServer::start();
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        vec![serde_json::json!({"name":"demo/index"})],
    );
    let digests = ["sha256:111111111111aaaa", "sha256:222222222222bbbb"];
    artifacts(
        &server,
        "index",
        vec![
            serde_json::json!({"type":"IMAGE","digest":"sha256:parent","tags":[{"name":"v1"}],"references":digests.map(|digest| serde_json::json!({"child_digest":digest,"platform":{"os":"linux","architecture":"amd64"}}))}),
        ],
    );
    for (i, digest) in digests.iter().enumerate() {
        server.mock(|w, t| {
            w.path(format!("/api/v2.0/projects/demo/repositories/index/artifacts/{digest}"));
            t.json_body(serde_json::json!({"type":"IMAGE","digest":digest,"scan_overview":{"report":{"scan_status":"Success"}}}));
        });
        server.mock(|w, t| {
            w.path(format!("/api/v2.0/projects/demo/repositories/index/artifacts/{digest}/additions/vulnerabilities"));
            t.json_body(serde_json::json!({"application/vnd.security.vulnerability.report; version=1.1":{"vulnerabilities":[{"id":format!("CVE-{i}"),"severity":"High"}]}}));
        });
    }
    let result = source(&server).fetch().unwrap();
    assert_eq!(
        result.images.len(),
        2,
        "harbor_source: result.images.len() mismatch"
    );
    assert_eq!(
        result.findings.len(),
        2,
        "harbor_source: result.findings.len() mismatch"
    );
    for (i, expected) in [
        "demo/index:v1 (linux/amd64)",
        "demo/index:v1 (linux/amd64, 222222222222)",
    ]
    .iter()
    .enumerate()
    {
        let row = result
            .images
            .iter()
            .find(|row| row.digest.as_deref() == Some(digests[i]))
            .unwrap();
        assert_eq!(
            &row.reference, expected,
            "harbor_source: &row.reference mismatch"
        );
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.id == format!("CVE-{i}"))
            .unwrap();
        assert_eq!(
            finding.image, row.reference,
            "harbor_source: finding.image mismatch"
        );
    }
    assert_ne!(result.images[0].reference, result.images[1].reference);
}
