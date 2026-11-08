use httpmock::{Mock, MockServer};
use image_scan_report::source::{
    harbor::{HarborParams, HarborSource},
    http::{HttpClient, HttpOptions},
};
use serde_json::Value;
use std::{path::Path, time::Duration};

pub fn source(server: &MockServer) -> HarborSource {
    HarborSource::from_config(
        &HarborParams {
            url: server.base_url(),
            project: Some("demo".into()),
            username: "robot".into(),
        },
        HttpClient::new(&HttpOptions {
            ca_file: None,
            insecure_skip_verify: false,
            timeout: Duration::from_secs(5),
            user_agent: "judex-test".into(),
        })
        .unwrap()
        .with_backoff([Duration::ZERO; 2]),
        "secret-password".into(),
    )
}
pub fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/harbor")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
pub fn paged<'a>(server: &'a MockServer, path: &str, values: Vec<Value>) -> Vec<Mock<'a>> {
    let mut mocks = Vec::new();
    let total = values.len();
    for (i, chunk) in values.chunks(100).enumerate() {
        mocks.push(server.mock(|w, t| {
            let w = w
                .method("GET")
                .path(path)
                .query_param("page", (i + 1).to_string())
                .query_param("page_size", "100");
            if path.ends_with("/artifacts") {
                w.query_param("with_scan_overview", "true")
                    .query_param("with_tag", "true");
            }
            t.status(200)
                .header("X-Total-Count", total.to_string())
                .json_body(chunk);
        }));
    }
    if values.is_empty() {
        mocks.push(server.mock(|w, t| {
            let w = w.method("GET").path(path);
            if path.ends_with("/artifacts") {
                w.query_param("with_scan_overview", "true")
                    .query_param("with_tag", "true");
            }
            t.status(200).json_body(Vec::<Value>::new());
        }));
    }
    mocks
}
pub fn artifacts<'a>(server: &'a MockServer, repo: &str, values: Vec<Value>) -> Vec<Mock<'a>> {
    paged(
        server,
        &format!("/api/v2.0/projects/demo/repositories/{repo}/artifacts"),
        values,
    )
}
pub fn harbor_mock() -> (MockServer, HarborSource) {
    harbor_mock_with_failure(None)
}
pub fn harbor_mock_with_failure(failure: Option<(&str, u16)>) -> (MockServer, HarborSource) {
    harbor_mock_selected(failure, false)
}
#[allow(dead_code)]
pub fn harbor_mock_subset() -> (MockServer, HarborSource) {
    harbor_mock_selected(None, true)
}
fn harbor_mock_selected(failure: Option<(&str, u16)>, subset: bool) -> (MockServer, HarborSource) {
    let server = MockServer::start();
    if let Some((path, status)) = failure {
        server.mock(|w, t| {
            w.path(path);
            t.status(status);
        });
    }
    paged(&server, "/api/v2.0/projects/library/repositories", vec![]);

    server.mock(|w, t| {
        w.path("/api/v2.0/projects");
        t.status(200).json_body(fixture("projects.json"));
    });
    let mut repos = fixture("repositories-after.json")
        .as_array()
        .unwrap()
        .clone();
    if subset {
        repos.retain(|r| {
            matches!(
                r["name"].as_str(),
                Some("demo/alpine" | "demo/nginx" | "demo/busybox")
            )
        });
    }
    paged(
        &server,
        "/api/v2.0/projects/demo/repositories",
        repos.clone(),
    );
    for repo in repos {
        let name = repo["name"]
            .as_str()
            .unwrap()
            .strip_prefix("demo/")
            .unwrap();
        let file = if name == "alpine-multi" {
            "multiarch/artifacts-alpine-multi.json".into()
        } else {
            format!("artifacts-{name}.json")
        };
        let mut values = fixture(&file).as_array().unwrap().clone();
        if subset {
            values.truncate(1);
        }
        artifacts(&server, name, values.clone());
        for a in values {
            if let Some(refs) = a["references"].as_array() {
                for r in refs {
                    let digest = r["child_digest"].as_str().unwrap();
                    let short = &digest[7..19];
                    server.mock(|w, t| {
                        w.path(format!(
                            "/api/v2.0/projects/demo/repositories/{name}/artifacts/{digest}"
                        ))
                        .query_param("with_scan_overview", "true")
                        .query_param("with_tag", "true");
                        t.status(200)
                            .json_body(fixture(&format!("multiarch/child-{short}.json")));
                    });
                    let file = format!("multiarch/vulns-{short}.json");
                    if Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("fixtures/harbor")
                        .join(&file)
                        .exists()
                    {
                        vulnerability(&server, name, digest, fixture(&file));
                    }
                }
            } else if name != "junk-artifact" {
                vulnerability(
                    &server,
                    name,
                    a["digest"].as_str().unwrap(),
                    fixture(&format!("vulns/{name}.json")),
                );
            }
        }
    }
    let src = source(&server);
    (server, src)
}
fn vulnerability(server: &MockServer, repo: &str, digest: &str, value: Value) {
    server.mock(|w,t| { w.path(format!("/api/v2.0/projects/demo/repositories/{repo}/artifacts/{digest}/additions/vulnerabilities")).header("X-Accept-Vulnerabilities","application/vnd.security.vulnerability.report; version=1.1"); t.status(200).json_body(value); });
}
