//! Shared synchronous HTTP transport for API scan sources.
use super::SourceError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use ureq::tls::{PemItem, RootCerts, TlsConfig};

/// Default HTTP client identification including the package version.
pub const USER_AGENT: &str = concat!("image-scan-report/", env!("CARGO_PKG_VERSION"));

/// Maximum accepted response body size in bytes (512 MiB).
pub const MAX_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;

/// TLS trust, timeout, and client identification settings for HTTP requests.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Optional PEM certificate bundle; None uses the built-in trust roots.
    pub ca_file: Option<PathBuf>,
    /// Whether TLS certificate verification is disabled.
    pub insecure_skip_verify: bool,
    /// Maximum duration of a request, including connection and response handling.
    pub timeout: Duration,
    /// HTTP User-Agent value sent with each request.
    pub user_agent: String,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            ca_file: None,
            insecure_skip_verify: false,
            timeout: Duration::from_secs(30),
            user_agent: USER_AGENT.into(),
        }
    }
}

/// Authentication credentials attached to an HTTP request.
pub enum Auth {
    /// No value or additional policy is supplied.
    None,
    /// Authenticate with an account name and password.
    Basic {
        /// Account name used for API authentication.
        username: String,
        /// Secret used to authenticate API requests.
        password: String,
    },
    /// Authenticate with a bearer token.
    Bearer(String),
}

/// Failure in TLS setup, request transport, authentication, or response decoding.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum HttpError {
    /// The configured certificate bundle could not be read.
    #[error("cannot read CA file {0}: {1}")]
    CaRead(PathBuf, std::io::Error),
    /// The configured bundle contains no usable PEM certificate.
    #[error("CA file {0} contains no PEM certificate")]
    CaInvalid(PathBuf),
    /// Custom roots and disabled certificate verification were both requested.
    #[error("ca_file and insecure_skip_verify cannot be combined")]
    ConflictingTls,
    /// The remote service rejected authentication or authorization.
    #[error("authentication failed for {0}")]
    Unauthorized(String),
    /// The server returned an unsuccessful HTTP status.
    #[error("{0} returned HTTP {1}")]
    Status(String, u16),
    /// The URL, headers, method, or request serialization is invalid.
    #[error("invalid request {0}: {1}")]
    InvalidRequest(String, String),
    /// The request failed before a usable response was received.
    #[error("request to {0} failed: {1}")]
    Transport(String, String),
    /// The response could not be decoded or exceeded the size limit.
    #[error("invalid response from {0}: {1}")]
    Decode(String, String),
}

/// Decoded HTTP payload paired with response headers.
pub struct Response<T> {
    /// Decoded response payload, separate from HTTP headers.
    pub body: T,
    /// Response header values indexed by their header names.
    pub headers: BTreeMap<String, String>,
}

/// Synchronous HTTP transport with bounded retries and response size.
pub struct HttpClient {
    agent: ureq::Agent,
    retry_delays: [Duration; 2],
}

/// Build an HTTP transport from optional certificate roots and verification settings.
///
/// # Errors
///
/// Fails if TLS options conflict or a custom certificate file cannot be read or parsed.
pub fn client_from_tls(
    ca_file: Option<&Path>,
    insecure_skip_verify: bool,
    timeout: Duration,
) -> Result<HttpClient, HttpError> {
    HttpClient::try_new(&HttpOptions {
        ca_file: ca_file.map(Path::to_owned),
        insecure_skip_verify,
        timeout,
        user_agent: USER_AGENT.into(),
    })
}

impl HttpClient {
    /// Build an HTTP transport with the requested TLS roots and timeout.
    ///
    /// # Errors
    ///
    /// Fails if TLS options conflict or a custom certificate file cannot be read or parsed.
    pub fn try_new(opts: &HttpOptions) -> Result<Self, HttpError> {
        if opts.ca_file.is_some() && opts.insecure_skip_verify {
            return Err(HttpError::ConflictingTls);
        }
        let roots = if let Some(path) = &opts.ca_file {
            let pem = std::fs::read(path).map_err(|e| HttpError::CaRead(path.clone(), e))?;
            let mut certs = Vec::new();
            for item in ureq::tls::parse_pem(&pem) {
                match item.map_err(|_| HttpError::CaInvalid(path.clone()))? {
                    PemItem::Certificate(cert) => certs.push(cert),
                    _ => continue,
                }
            }
            if certs.is_empty() {
                return Err(HttpError::CaInvalid(path.clone()));
            }
            RootCerts::Specific(Arc::new(certs))
        } else {
            RootCerts::WebPki
        };
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(opts.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(opts.user_agent.clone())
            .tls_config(
                TlsConfig::builder()
                    .root_certs(roots)
                    .disable_verification(opts.insecure_skip_verify)
                    .build(),
            )
            .build();
        Ok(Self {
            agent: config.into(),
            retry_delays: [Duration::from_secs(1), Duration::from_secs(2)],
        })
    }

    /// Override the delays between the three request attempts.
    #[doc(hidden)]
    pub fn with_backoff(mut self, delays: [Duration; 2]) -> Self {
        self.retry_delays = delays;
        self
    }

    /// Send raw bytes, retrying PUT uploads but sending POST uploads only once.
    ///
    /// # Errors
    ///
    /// Fails for unsupported methods, invalid request metadata, transport or authentication errors, unsuccessful HTTP status, or an oversized response.
    pub fn send_bytes(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let method = method.to_ascii_uppercase();
        if !matches!(method.as_str(), "PUT" | "POST") {
            return Err(HttpError::InvalidRequest(
                format!("{method} {}", redact_url(url)),
                "expected PUT or POST".into(),
            ));
        }
        let mut headers: Vec<_> = headers
            .iter()
            .copied()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("content-type"))
            .collect();
        headers.push(("Content-Type", content_type));
        self.request(
            &method,
            url,
            &Auth::None,
            &headers,
            Some(body),
            if method == "POST" { 1 } else { 3 },
        )
    }

    /// Fetch and decode a JSON response, retrying transient failures up to three attempts.
    ///
    /// # Errors
    ///
    /// Fails for invalid request metadata, transport or authentication errors, unsuccessful HTTP status, oversized bodies, or invalid response JSON.
    pub fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
    ) -> Result<Response<T>, HttpError> {
        self.json_response(
            "GET",
            url,
            self.request("GET", url, auth, headers, None, 3)?,
        )
    }

    /// Serialize and post JSON, retrying transient failures up to three attempts.
    ///
    /// # Errors
    ///
    /// Fails if body serialization, request validation, transport, authentication, HTTP status, or response decoding fails.
    pub fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        auth: &Auth,
        body: &B,
        headers: &[(&str, &str)],
    ) -> Result<Response<T>, HttpError> {
        let bytes = serde_json::to_vec(body).map_err(|e| {
            HttpError::InvalidRequest(format!("POST {}", redact_url(url)), e.to_string())
        })?;
        self.json_response(
            "POST",
            url,
            self.request("POST", url, auth, headers, Some(&bytes), 3)?,
        )
    }

    /// Delete a resource, retrying transient failures up to three attempts.
    ///
    /// # Errors
    ///
    /// Fails for invalid request metadata, transport or authentication errors, or unsuccessful HTTP status.
    pub fn delete(
        &self,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
    ) -> Result<(), HttpError> {
        self.request("DELETE", url, auth, headers, None, 3)?;
        Ok(())
    }

    /// Delete a resource with a single request attempt.
    ///
    /// # Errors
    ///
    /// Fails for invalid request metadata, transport or authentication errors, or unsuccessful HTTP status.
    pub fn delete_once(
        &self,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
    ) -> Result<(), HttpError> {
        self.request("DELETE", url, auth, headers, None, 1)?;
        Ok(())
    }

    fn json_response<T: DeserializeOwned>(
        &self,
        method: &str,
        url: &str,
        response: Response<Vec<u8>>,
    ) -> Result<Response<T>, HttpError> {
        let context = format!("{method} {}", redact_url(url));
        let headers = response.headers;
        let body = serde_json::from_slice(&response.body).map_err(|e| {
            HttpError::Decode(
                context,
                format!(
                    "invalid JSON ({}) at line {} column {}",
                    match e.classify() {
                        serde_json::error::Category::Io => "io",
                        serde_json::error::Category::Syntax => "syntax",
                        serde_json::error::Category::Data => "data",
                        serde_json::error::Category::Eof => "eof",
                    },
                    e.line(),
                    e.column()
                ),
            )
        })?;
        Ok(Response { body, headers })
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        attempts: usize,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let uri: ureq::http::Uri = url.parse().map_err(|e: ureq::http::uri::InvalidUri| {
            HttpError::InvalidRequest(format!("{method} {}", redact_url(url)), e.to_string())
        })?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            return Err(HttpError::InvalidRequest(
                format!("{method} {}", redact_url(url)),
                "expected an absolute HTTP(S) URL".into(),
            ));
        }
        let authorization = match auth {
            Auth::None => None,
            Auth::Basic { username, password } => Some(format!(
                "Basic {}",
                base64(format!("{username}:{password}").as_bytes())
            )),
            Auth::Bearer(token) => Some(format!("Bearer {token}")),
        };
        let context = format!("{method} {}", redact_url(url));
        for attempt in 0..attempts {
            tracing::debug!(method, url = redact_url(url));
            let mut request = ureq::http::Request::builder().method(method).uri(url);
            if let Some(value) = &authorization {
                let mut value = ureq::http::HeaderValue::from_str(value)
                    .map_err(|e| HttpError::InvalidRequest(context.clone(), e.to_string()))?;
                value.set_sensitive(true);
                request = request.header("Authorization", value);
            }
            for (key, value) in headers {
                let mut value = ureq::http::HeaderValue::from_str(value)
                    .map_err(|e| HttpError::InvalidRequest(context.clone(), e.to_string()))?;
                if key.eq_ignore_ascii_case("authorization")
                    || key.eq_ignore_ascii_case("x-auth-token")
                {
                    value.set_sensitive(true);
                }
                request = request.header(*key, value);
            }
            if body.is_some()
                && !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                request = request.header("Content-Type", "application/json");
            }
            let request = request
                .body(body.unwrap_or_default())
                .map_err(|e| HttpError::InvalidRequest(context.clone(), e.to_string()))?;
            let result = self
                .agent
                .run(request)
                .map_err(|e| HttpError::Transport(context.clone(), e.to_string()))
                .and_then(|mut response| {
                    let code = response.status().as_u16();
                    match code {
                        401 | 403 => Err(HttpError::Unauthorized(context.clone())),
                        300..=599 => Err(HttpError::Status(context.clone(), code)),
                        _ => {
                            let headers = response
                                .headers()
                                .iter()
                                .filter_map(|(k, v)| {
                                    v.to_str()
                                        .ok()
                                        .map(|v| (k.as_str().to_owned(), v.to_owned()))
                                })
                                .collect();
                            let body = response
                                .body_mut()
                                .with_config()
                                .limit(MAX_RESPONSE_BYTES)
                                .read_to_vec()
                                .map_err(|e| {
                                    if matches!(e, ureq::Error::BodyExceedsLimit(_)) {
                                        HttpError::Decode(
                                            context.clone(),
                                            "response larger than 512 MiB".into(),
                                        )
                                    } else {
                                        HttpError::Transport(context.clone(), e.to_string())
                                    }
                                })?;
                            Ok(Response { body, headers })
                        }
                    }
                });
            let retry = matches!(
                &result,
                Err(HttpError::Transport(..) | HttpError::Status(_, 500..=599))
            );
            if !retry || attempt + 1 == attempts {
                return result;
            }
            std::thread::sleep(self.retry_delays[attempt]);
        }
        unreachable!("request attempts always return a result")
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        encoded.push(TABLE[((n >> 18) & 63) as usize] as char);
        encoded.push(TABLE[((n >> 12) & 63) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

impl From<HttpError> for SourceError {
    fn from(error: HttpError) -> Self {
        Self::Other(error.to_string())
    }
}

/// Encode one URL path segment.
#[must_use]
pub fn encode_segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Extract the URL authority, including an explicit port; invalid URLs yield an empty string.
#[must_use]
pub fn url_authority(url: &str) -> String {
    url.parse::<ureq::http::Uri>()
        .ok()
        .and_then(|u| u.authority().map(|a| a.as_str().to_owned()))
        .unwrap_or_default()
}
/// Authentication errors abort a source; other errors describe a failed row.
///
/// # Errors
///
/// Fails only for authentication or authorization errors; other errors become row diagnostics.
pub fn row_failure(error: HttpError) -> Result<String, HttpError> {
    match error {
        error @ HttpError::Unauthorized(_) => Err(error),
        error => Ok(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_handles_padding_and_utf8() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("u:p", "dTpw"),
            ("ü:p", "w7w6cA=="),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    #[test]
    fn insecure_tls_flag_is_applied() {
        for insecure_skip_verify in [false, true] {
            let client = HttpClient::try_new(&HttpOptions {
                ca_file: None,
                insecure_skip_verify,
                timeout: Duration::from_secs(1),
                user_agent: format!("image-scan-report/{}", env!("CARGO_PKG_VERSION")),
            })
            .expect("valid test TLS options");
            assert_eq!(
                client.retry_delays,
                [Duration::from_secs(1), Duration::from_secs(2)]
            );
            assert_eq!(
                client.agent.config().tls_config().disable_verification(),
                insecure_skip_verify
            );
        }
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;
    #[test]
    fn helpers() {
        assert_eq!(encode_segment("a/b %é"), "a%2Fb%20%25%C3%A9");
        assert_eq!(encode_segment(&encode_segment("a/b")), "a%252Fb");
        assert_eq!(encode_segment("-._~Az09"), "-._~Az09");
        assert_eq!(
            url_authority("https://example.test:8443/path"),
            "example.test:8443"
        );
        assert_eq!(url_authority("https://example.test/"), "example.test");
        assert_eq!(url_authority(""), "");
    }
}

/// Build a transport and emit a warning when certificate verification is disabled.
///
/// # Errors
///
/// Fails if TLS options conflict or a custom certificate file cannot be read or parsed.
pub fn tls_client(
    role: &str,
    url: &str,
    ca_file: Option<&Path>,
    timeout_secs: u64,
    insecure_skip_verify: bool,
) -> Result<crate::source::http::HttpClient, crate::config::ConfigError> {
    let client = crate::source::http::client_from_tls(
        ca_file,
        insecure_skip_verify,
        std::time::Duration::from_secs(timeout_secs),
    )
    .map_err(|e| crate::config::ConfigError::Invalid(format!("{role}.ca_file: {e}")))?;
    if insecure_skip_verify {
        tracing::warn!(
            "{} {}: TLS certificate verification is disabled",
            role,
            redact_url(url)
        );
    }
    Ok(client)
}

/// Strip query and fragment secrets from diagnostic URLs.
#[must_use]
pub fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => url.split(['?', '#']).next().unwrap_or_default().to_owned(),
    }
}
#[cfg(test)]
mod redaction_tests {
    #[test]
    fn redact_url_removes_secrets() {
        assert_eq!(
            super::redact_url("https://h/p?X-Amz-Signature=abc#f"),
            "https://h/p"
        );
        assert_eq!(super::redact_url("invalid?secret#fragment"), "invalid");
    }
}
