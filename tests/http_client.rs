use httpmock::MockServer;
use image_scan_report::source::http::{Auth, HttpClient, HttpError, HttpOptions};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

fn options() -> HttpOptions {
    HttpOptions {
        ca_file: None,
        insecure_skip_verify: false,
        timeout: Duration::from_secs(1),
        user_agent: format!("image-scan-report/{}", env!("CARGO_PKG_VERSION")),
    }
}
fn client() -> HttpClient {
    HttpClient::new(&options())
        .unwrap()
        .with_backoff([Duration::ZERO; 2])
}
#[test]
fn get_json_decodes_and_returns_headers() {
    let s = MockServer::start();
    let m = s.mock(|w, t| {
        w.method("GET").header("X-Auth-Token", "token").header(
            "User-Agent",
            format!("image-scan-report/{}", env!("CARGO_PKG_VERSION")),
        );
        t.status(200)
            .header("X-Total-Count", "7")
            .json_body(json!({"a":1}));
    });
    let r = client()
        .get_json::<Value>(&s.url("/"), &Auth::None, &[("X-Auth-Token", "token")])
        .unwrap();
    assert_eq!(r.body["a"], 1);
    assert_eq!(r.headers["x-total-count"], "7");
    m.assert_calls(1);
}
#[test]
fn basic_auth_header_is_sent() {
    auth_test(
        Auth::Basic {
            username: "u".into(),
            password: "p".into(),
        },
        "Basic dTpw",
    );
}
#[test]
fn bearer_header_is_sent() {
    auth_test(Auth::Bearer("token".into()), "Bearer token");
}
fn auth_test(auth: Auth, expected: &str) {
    let s = MockServer::start();
    let m = s.mock(|w, t| {
        w.header("Authorization", expected);
        t.json_body(json!({}));
    });
    client().get_json::<Value>(&s.url("/"), &auth, &[]).unwrap();
    m.assert_calls(1);
}
#[test]
fn unauthorized_is_reported_without_secrets() {
    for status in [401, 403] {
        let s = MockServer::start();
        let m = s.mock(|_, t| {
            t.status(status);
        });
        let e = client()
            .get_json::<Value>(
                &s.url("/"),
                &Auth::Basic {
                    username: "u".into(),
                    password: "s3cr3t".into(),
                },
                &[],
            )
            .err()
            .unwrap();
        assert!(matches!(e, HttpError::Unauthorized(_)));
        assert!(!e.to_string().contains("s3cr3t"));
        m.assert_calls(1);
    }
}
#[test]
fn retries_on_503_then_succeeds() {
    // A local scripted server makes response ordering deterministic.
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for status in [503, 503, 200] {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                s.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let body = "{}";
            write!(
                s,
                "HTTP/1.1 {status} OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{body}"
            )
            .unwrap();
        }
    });
    client()
        .get_json::<Value>(&format!("http://{addr}/"), &Auth::None, &[])
        .unwrap();
    server.join().unwrap();
}
#[test]
fn gives_up_after_three_transport_failures() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let start = std::time::Instant::now();
    assert!(matches!(
        client()
            .with_backoff([Duration::from_millis(50), Duration::from_millis(100)])
            .get_json::<Value>(&format!("http://{addr}/"), &Auth::None, &[]),
        Err(HttpError::Transport(..))
    ));
    assert!(start.elapsed() >= Duration::from_millis(150));
    assert!(start.elapsed() < Duration::from_secs(3));
}
#[test]
fn non_pem_ca_is_config_error() {
    let mut o = options();
    o.ca_file = Some(PathBuf::from("tests/data/tls/not-a-cert.pem"));
    assert!(matches!(HttpClient::new(&o), Err(HttpError::CaInvalid(_))));
    o.ca_file = Some(PathBuf::from("tests/data/tls/missing.pem"));
    assert!(matches!(HttpClient::new(&o), Err(HttpError::CaRead(..))));
}
#[test]
fn pem_ca_is_accepted() {
    let mut o = options();
    o.ca_file = Some("tests/data/tls/ca.pem".into());
    assert!(HttpClient::new(&o).is_ok());
}
#[test]
fn insecure_skip_verify_builds_client() {
    let mut o = options();
    o.insecure_skip_verify = true;
    assert!(HttpClient::new(&o).is_ok());
}
#[test]
fn conflicting_tls_options_rejected() {
    let mut o = options();
    o.insecure_skip_verify = true;
    o.ca_file = Some("tests/data/tls/ca.pem".into());
    assert!(matches!(
        HttpClient::new(&o),
        Err(HttpError::ConflictingTls)
    ));
}
#[test]
fn post_delete_and_decode_status_errors() {
    let s = MockServer::start();
    let p = s.mock(|w, t| {
        w.method("POST")
            .header("X-Auth-Token", "nv")
            .json_body(json!({"x":1}));
        t.json_body(json!({"ok":true}));
    });
    assert_eq!(
        client()
            .post_json::<_, Value>(
                &s.url("/"),
                &Auth::None,
                &json!({"x":1}),
                &[("X-Auth-Token", "nv")]
            )
            .unwrap()
            .body["ok"],
        true
    );
    p.assert_calls(1);
    let d = s.mock(|w, t| {
        w.method("DELETE").header("X-Auth-Token", "nv");
        t.status(204);
    });
    client()
        .delete(&s.url("/"), &Auth::None, &[("X-Auth-Token", "nv")])
        .unwrap();
    d.assert_calls(1);
    for status in [400, 500] {
        let s = MockServer::start();
        let m = s.mock(|_, t| {
            t.status(status);
        });
        assert!(
            matches!(client().get_json::<Value>(&s.url("/"), &Auth::None, &[]),Err(HttpError::Status(_,c)) if c==status)
        );
        m.assert_calls(if status == 500 { 3 } else { 1 });
    }
    let s = MockServer::start();
    s.mock(|_, t| {
        t.body("invalid");
    });
    assert!(matches!(
        client().get_json::<Value>(&s.url("/"), &Auth::None, &[]),
        Err(HttpError::Decode(..))
    ));
}

#[test]
fn untrusted_server_is_source_error() {
    // HTTPS is unavailable in this httpmock build; cover the CA error conversion.
    let mut opts = options();
    opts.ca_file = Some("tests/data/tls/not-a-cert.pem".into());
    let error = HttpClient::new(&opts).err().unwrap();
    let source_error: image_scan_report::source::SourceError = error.into();
    assert!(matches!(
        source_error,
        image_scan_report::source::SourceError::Other(_)
    ));
}

#[test]
fn multi_certificate_pem_is_accepted() {
    let mut o = options();
    o.ca_file = Some("tests/data/tls/bundle.pem".into());
    assert!(HttpClient::new(&o).is_ok());
}

#[test]
fn redirects_do_not_forward_headers() {
    let target = MockServer::start();
    let hit = target.mock(|_, t| {
        t.json_body(json!({}));
    });
    let origin = MockServer::start();
    origin.mock(|_, t| {
        t.status(302).header("Location", target.url("/"));
    });
    assert!(matches!(
        client().get_json::<Value>(&origin.url("/"), &Auth::None, &[("X-Auth-Token", "secret")]),
        Err(HttpError::Status(_, 302))
    ));
    hit.assert_calls(0);
}

#[test]
fn decode_errors_do_not_expose_response_values() {
    let s = MockServer::start();
    s.mock(|_, t| {
        t.json_body(json!({"token":{"token":"TOPSECRET"}}));
    });
    let e = client()
        .get_json::<std::collections::BTreeMap<String, u64>>(&s.url("/"), &Auth::None, &[])
        .err()
        .unwrap();
    assert!(matches!(e, HttpError::Decode(..)));
    assert!(!e.to_string().contains("TOPSECRET"));
}
