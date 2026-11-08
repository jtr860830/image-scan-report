#[path = "support/neuvector_mock.rs"]
mod neuvector_mock;
use httpmock::MockServer;
use image_scan_report::{
    model::ScanState,
    source::{ScanSource, http::url_authority},
};
use neuvector_mock::*;
use serde_json::json;

#[test]
fn fetches_registry_images_and_findings() {
    let (_server, src) = capture(false);
    let result = src.fetch().unwrap();
    assert_eq!(result.images.len(), 11);
    assert!(
        result
            .findings
            .iter()
            .filter(|f| f.image == "harbor.example.test/demo/centos:7")
            .count()
            > 1000
    );
    assert_eq!(result.source.db_version.as_deref(), Some("4.318"));
    assert_eq!(
        result.scope,
        format!("{}/harbor-lab", url_authority(&src.base_url))
    );
}
#[test]
fn rescan_capture_lists_multiarch_as_one_image() {
    let (_server, src) = capture(true);
    let result = src.fetch().unwrap();
    assert_eq!(result.images.len(), 12);
    assert_eq!(
        result
            .images
            .iter()
            .filter(|i| i.reference.ends_with("/demo/alpine-multi:3.20"))
            .count(),
        1
    );
}
fn synthetic(
    status: &str,
    result: &str,
    report_status: u16,
) -> (
    MockServer,
    image_scan_report::source::neuvector_api::NeuvectorSource,
) {
    let server = MockServer::start();
    login(&server);
    logout(&server);
    summary(&server);
    get(
        &server,
        &format!("{ROOT}/images"),
        json!({"images":[{"repository":"demo/test","tag":"latest","image_id":"id","status":status,"result":result}]}),
        200,
    );
    if status == "finished" && result == "succeeded" {
        get(
            &server,
            &format!("{ROOT}/image/id"),
            json!({}),
            report_status,
        );
    }
    let src = source(&server);
    (server, src)
}
#[test]
fn failed_scan_is_failed_not_dropped() {
    let (server, src) = synthetic("finished", "failed", 200);
    let report = server.mock(|w, t| {
        w.path(format!("{ROOT}/image/id"));
        t.status(200);
    });
    let result = src.fetch().unwrap();
    assert_eq!(result.images[0].scan.state, ScanState::Failed);
    assert_eq!(result.images[0].scan.error.as_deref(), Some("failed"));
    report.assert_calls(0);
}
#[test]
fn in_progress_images_are_not_scanned() {
    let (_server, src) = synthetic("scanning", "", 200);
    let result = src.fetch().unwrap();
    assert_eq!(result.images[0].scan.state, ScanState::NotScanned);
    assert_eq!(
        result.images[0].scan.error.as_deref(),
        Some("scan in progress")
    );
}
#[test]
fn logout_runs_on_failure() {
    let server = MockServer::start();
    login(&server);
    let out = logout(&server);
    summary(&server);
    get(
        &server,
        &format!("{ROOT}/images"),
        json!({"images":[{"image_id":"id","status":"finished","result":"succeeded"}]}),
        200,
    );
    let report = get(&server, &format!("{ROOT}/image/id"), json!({}), 500);
    let result = source(&server).fetch().unwrap();
    assert_eq!(result.images[0].scan.state, ScanState::Failed);
    report.assert_calls(3);
    out.assert_calls(1);
}
#[test]
fn password_reset_required_is_reported() {
    let server = MockServer::start();
    auth(
        &server,
        json!({"token":{"token":TOKEN},"need_to_reset_password":true}),
        200,
    );
    let out = logout(&server);
    assert!(
        source(&server)
            .fetch()
            .err()
            .unwrap()
            .to_string()
            .contains("password reset")
    );
    out.assert_calls(1);
}
#[test]
fn unauthorized_is_reported_without_secrets() {
    let server = MockServer::start();
    let out = logout(&server);
    auth(&server, json!({"message":"secret-password"}), 401);
    let error = source(&server).fetch().err().unwrap().to_string();
    assert!(error.contains("authentication failed"));
    assert!(!error.contains("secret-password"));
    assert!(!error.contains(TOKEN));
    out.assert_calls(0);
}
#[test]
fn registry_not_found_is_reported() {
    let server = MockServer::start();
    login(&server);
    let out = logout(&server);
    get(&server, ROOT, json!({}), 404);
    assert!(
        source(&server)
            .fetch()
            .err()
            .unwrap()
            .to_string()
            .contains("registry configuration harbor-lab not found")
    );
    out.assert_calls(1);
}
#[test]
fn auth_header_is_required() {
    let server = MockServer::start();
    let matched = get(&server, ROOT, json!({}), 200);
    auth(&server, json!({"token":{"token":"other"}}), 200);
    assert!(source(&server).fetch().is_err());
    matched.assert_calls(0);
}

#[test]
fn captured_payloads_map_without_sockets() {
    use image_scan_report::source::neuvector::{api::*, report::compose_reference};
    use image_scan_report::source::neuvector_api::scan_status;
    let list: RegistryImages = serde_json::from_value(fixture("registry-images.json")).unwrap();
    assert_eq!(list.images.len(), 11);
    for entry in list.images {
        let scan = scan_status(&entry);
        assert_eq!(scan.state, ScanState::Ok);
        assert!(scan.scanned_at.is_some());
        assert_eq!(scan.scanner_version.as_deref(), Some("4.318"));
        let report: ImageReport =
            serde_json::from_value(fixture(&format!("images/{}.json", entry.image_id))).unwrap();
        assert!(report.report.unwrap().vulnerabilities.is_some());
    }
    assert_eq!(
        compose_reference("http://harbor.example.test/", "demo/alpine", "3.12"),
        "harbor.example.test/demo/alpine:3.12"
    );
    for (status, result, state) in [
        ("finished", "failed", ScanState::Failed),
        ("finished", "unknown", ScanState::Failed),
        ("scanning", "", ScanState::NotScanned),
    ] {
        let entry: ImageSummary =
            serde_json::from_value(json!({"status":status,"result":result,"scanned_timestamp":1}))
                .unwrap();
        let scan = scan_status(&entry);
        assert_eq!(scan.state, state);
        assert!(scan.scanned_at.is_some());
    }
}
#[test]
fn missing_token_is_reported() {
    let server = MockServer::start();
    let out = logout(&server);
    auth(&server, json!({}), 200);
    assert!(
        source(&server)
            .fetch()
            .err()
            .unwrap()
            .to_string()
            .contains("missing token")
    );
    out.assert_calls(0);
}
#[test]
fn empty_registry_logs_out() {
    let server = MockServer::start();
    login(&server);
    let out = logout(&server);
    summary(&server);
    get(
        &server,
        &format!("{ROOT}/images"),
        json!({"images":[]}),
        200,
    );
    assert!(matches!(
        source(&server).fetch(),
        Err(image_scan_report::source::SourceError::NoImages(_))
    ));
    out.assert_calls(1);
}
#[test]
fn unauthorized_report_aborts_and_logs_out() {
    let server = MockServer::start();
    login(&server);
    let out = logout(&server);
    summary(&server);
    get(
        &server,
        &format!("{ROOT}/images"),
        json!({"images":[{"image_id":"id","status":"finished","result":"succeeded"}]}),
        200,
    );
    get(&server, &format!("{ROOT}/image/id"), json!({}), 401);
    let result = source(&server).fetch().err().unwrap().to_string();
    assert!(result.contains("authentication failed"));
    assert!(!result.contains(TOKEN));
    assert!(!result.contains("secret-password"));
    out.assert_calls(1);
}
#[test]
fn status_table_without_sockets() {
    use image_scan_report::source::{neuvector::api::ImageSummary, neuvector_api::scan_status};
    for (status, result, state, error) in [
        (Some("failed"), None, ScanState::Failed, Some("failed")),
        (
            Some("unsupported"),
            None,
            ScanState::Failed,
            Some("unsupported"),
        ),
        (None, None, ScanState::NotScanned, None),
        (Some(""), None, ScanState::NotScanned, None),
        (Some("Finished"), Some("Succeeded"), ScanState::Ok, None),
        (
            Some("finished"),
            Some(""),
            ScanState::Failed,
            Some("scan failed"),
        ),
        (
            Some("scheduled"),
            None,
            ScanState::NotScanned,
            Some("scan in progress"),
        ),
    ] {
        let entry: ImageSummary =
            serde_json::from_value(json!({"status":status,"result":result})).unwrap();
        let scan = scan_status(&entry);
        assert_eq!(scan.state, state);
        assert_eq!(scan.error.as_deref(), error);
    }
}
