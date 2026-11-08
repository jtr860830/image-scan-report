use httpmock::{Mock, MockServer};
use image_scan_report::source::{
    http::{HttpClient, HttpOptions},
    neuvector_api::{NeuvectorParams, NeuvectorSource},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub const TOKEN: &str = "test-session-token";
pub const ROOT: &str = "/v1/scan/registry/harbor-lab";
pub fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/neuvector-api")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
pub fn source(server: &MockServer) -> NeuvectorSource {
    NeuvectorSource::from_config(
        &NeuvectorParams {
            url: server.base_url(),
            registry: "harbor-lab".into(),
            username: "admin".into(),
        },
        HttpClient::try_new(&HttpOptions {
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
pub fn auth(server: &MockServer, value: Value, status: u16) -> Mock<'_> {
    server.mock(|w, t| {
        w.method("POST")
            .path("/v1/auth")
            .json_body(json!({"password":{"username":"admin","password":"secret-password"}}));
        t.status(status).json_body(value);
    })
}
pub fn login(server: &MockServer) {
    auth(server, json!({"token":{"token":TOKEN}}), 200);
}
pub fn logout(server: &MockServer) -> Mock<'_> {
    server.mock(|w, t| {
        w.method("DELETE")
            .path("/v1/auth")
            .header("X-Auth-Token", TOKEN);
        t.status(200);
    })
}
pub fn get<'a>(server: &'a MockServer, path: &str, value: Value, status: u16) -> Mock<'a> {
    server.mock(|w, t| {
        w.method("GET").path(path).header("X-Auth-Token", TOKEN);
        t.status(status).json_body(value);
    })
}
pub fn summary(server: &MockServer) {
    get(server, ROOT, fixture("rescan/registry.json"), 200);
}
pub fn capture(rescan: bool) -> (MockServer, NeuvectorSource) {
    let server = MockServer::start();
    login(&server);
    logout(&server);
    summary(&server);
    let list = fixture(if rescan {
        "rescan/registry-images.json"
    } else {
        "registry-images.json"
    });
    for image in list["images"].as_array().unwrap() {
        let id = image["image_id"].as_str().unwrap();
        let path = format!("images/{id}.json");
        // The rescan index has no captured report; an empty successful report suffices.
        let body = if Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/neuvector-api")
            .join(&path)
            .exists()
        {
            fixture(&path)
        } else {
            json!({"report":{"vulnerabilities":[]}})
        };
        get(&server, &format!("{ROOT}/image/{id}"), body, 200);
    }
    get(&server, &format!("{ROOT}/images"), list, 200);
    let src = source(&server);
    (server, src)
}
