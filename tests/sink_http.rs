use image_scan_report::{
    config::HttpMode,
    sink::{
        Artifact, ReportSink,
        http::{HttpSink, boundary, multipart_body},
    },
    source::http::client_from_tls,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn sink(url: String, mode: HttpMode, method: &str) -> HttpSink {
    HttpSink::new(
        url,
        method.into(),
        vec![("Authorization".into(), "Bearer t".into())],
        mode,
        client_from_tls(None, false, Duration::from_secs(5))
            .unwrap()
            .with_backoff([Duration::ZERO; 2]),
    )
}
fn artifact() -> Artifact {
    Artifact {
        file_name: "report.pdf".into(),
        media_type: "application/pdf",
        bytes: b"%PDF-test".to_vec(),
    }
}
#[test]
fn raw_put_sends_bytes_with_content_headers() {
    let s = httpmock::MockServer::start();
    let m = s.mock(|w, t| {
        w.method("PUT")
            .header("Content-Type", "application/pdf")
            .header("Content-Disposition", "attachment; filename=\"report.pdf\"")
            .header("Authorization", "Bearer t")
            .body("%PDF-test");
        t.status(201);
    });
    sink(s.url("/upload"), HttpMode::Raw, "PUT")
        .store(&artifact())
        .unwrap();
    m.assert_calls(1);
}
#[test]
fn multipart_post_has_one_file_part() {
    let s = httpmock::MockServer::start();
    let captured = Arc::new(Mutex::new(None));
    let capture = captured.clone();
    let m = s.mock(|w, t| {
        w.method("POST").is_true(move |r| {
            *capture.lock().unwrap() = Some(r.clone());
            true
        });
        t.status(201);
    });
    sink(s.url("/upload"), HttpMode::Multipart, "POST")
        .store(&artifact())
        .unwrap();
    m.assert_calls(1);
    let captured = captured.lock().unwrap();
    let r = captured.as_ref().unwrap();
    let ct = r
        .headers_vec()
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .unwrap()
        .1
        .as_str();
    let b = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    let body = String::from_utf8(r.body_vec()).unwrap();
    let parts: Vec<_> = body.split(&format!("--{b}")).collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "");
    assert_eq!(
        parts[1],
        "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-test\r\n"
    );
    assert_eq!(parts[2], "--\r\n");
}
#[test]
fn multipart_body_is_well_formed() {
    let b = boundary();
    assert_eq!(b.len(), "image-scan-report-".len() + 32);
    assert!(
        b["image-scan-report-".len()..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    );
    assert_ne!(b, boundary());
    let bytes = vec![0xff; 2 * 1024 * 1024];
    let body = multipart_body(&b, "file", "r.pdf", "application/pdf", &bytes);
    assert!(body.starts_with(format!("--{b}\r\n").as_bytes()));
    let offset = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&body[offset..offset + bytes.len()], bytes);
    assert_eq!(body.windows(4).filter(|w| *w == b"\r\n\r\n").count(), 1);
    assert!(body.ends_with(format!("\r\n--{b}--\r\n").as_bytes()));
}
#[test]
fn retries_on_503_then_succeeds() {
    let s = httpmock::MockServer::start();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let m = s.mock(|w, t| {
        w.method("PUT").body("%PDF-test");
        t.respond_with(move |_| {
            httpmock::HttpMockResponse::builder()
                .status(if c.fetch_add(1, Ordering::SeqCst) < 2 {
                    503
                } else {
                    201
                })
                .build()
        });
    });
    sink(s.url("/upload"), HttpMode::Raw, "PUT")
        .store(&artifact())
        .unwrap();
    m.assert_calls(3);
}
#[test]
fn gives_up_after_three_5xx() {
    let s = httpmock::MockServer::start();
    let m = s.mock(|w, t| {
        w.any_request();
        t.status(500);
    });
    let url = s.url("/upload");
    let e = sink(url.clone(), HttpMode::Raw, "PUT")
        .store(&artifact())
        .unwrap_err()
        .to_string();
    assert!(e.contains("HTTP PUT") && e.contains(&url) && e.contains("500"));
    assert!(!e.contains("Bearer t"));
    m.assert_calls(3);
}
#[test]
fn four_xx_fails_immediately() {
    let s = httpmock::MockServer::start();
    let m = s.mock(|w, t| {
        w.any_request();
        t.status(403);
    });
    let e = sink(s.url("/upload"), HttpMode::Raw, "PUT")
        .store(&artifact())
        .unwrap_err()
        .to_string();
    assert!(e.contains("authentication failed"));
    m.assert_calls(1);
}
#[test]
fn describe_hides_headers() {
    assert_eq!(
        sink("https://example.test/upload".into(), HttpMode::Raw, "PUT").describe(),
        "HTTP PUT https://example.test/upload"
    );
}

#[test]
fn connection_refused_is_transport_after_retries() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/upload", listener.local_addr().unwrap());
    drop(listener);
    let e = sink(url, HttpMode::Raw, "PUT")
        .store(&artifact())
        .unwrap_err()
        .to_string();
    assert!(e.contains("request to"));
    assert!(e.contains("failed:"));
    assert!(!e.contains("authentication failed"));
    assert!(!e.contains("Bearer t"));
}
#[test]
fn upload_query_is_redacted() {
    let s = httpmock::MockServer::start();
    s.mock(|w, t| {
        w.any_request();
        t.status(403);
    });
    let sink = sink(s.url("/upload?token=SECRET"), HttpMode::Raw, "PUT");
    let redacted_url = s.url("/upload");
    let description = sink.describe();
    assert!(description.contains(&redacted_url));
    assert!(!description.contains("SECRET"));
    let error = sink.store(&artifact()).unwrap_err().to_string();
    assert!(error.contains(&redacted_url));
    assert!(!error.contains("SECRET"));
}
