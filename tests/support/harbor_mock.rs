use httpmock::MockServer;
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
pub fn paged(server: &MockServer, path: &str, values: Vec<Value>) {
    let total = values.len();
    for (i, chunk) in values.chunks(100).enumerate() {
        server.mock(|w, t| {
            w.method("GET")
                .path(path)
                .query_param("page", (i + 1).to_string())
                .query_param("page_size", "100");
            t.status(200)
                .header("X-Total-Count", total.to_string())
                .json_body(chunk);
        });
    }
    if values.is_empty() {
        server.mock(|w, t| {
            w.method("GET").path(path);
            t.status(200).json_body(Vec::<Value>::new());
        });
    }
}
pub fn artifacts(server: &MockServer, repo: &str, values: Vec<Value>) {
    paged(
        server,
        &format!("/api/v2.0/projects/demo/repositories/{repo}/artifacts"),
        values,
    );
}
pub fn harbor_mock() -> (MockServer, HarborSource) {
    let server = MockServer::start();
    server.mock(|w, t| {
        w.path("/api/v2.0/projects");
        t.status(200).json_body(fixture("projects.json"));
    });
    let repos = fixture("repositories-after.json")
        .as_array()
        .unwrap()
        .clone();
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
        let values = fixture(&file).as_array().unwrap().clone();
        artifacts(&server, name, values.clone());
        for a in values {
            if let Some(refs) = a["references"].as_array() {
                for r in refs {
                    let digest = r["child_digest"].as_str().unwrap();
                    let short = &digest[7..19];
                    server.mock(|w, t| {
                        w.path(format!(
                            "/api/v2.0/projects/demo/repositories/{name}/artifacts/{digest}"
                        ));
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
