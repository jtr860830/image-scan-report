//! Shared synchronous HTTP transport for API scan sources.
use super::SourceError;
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use ureq::tls::{PemItem, RootCerts, TlsConfig, parse_pem};

pub struct HttpOptions {
    pub ca_file: Option<PathBuf>,
    pub insecure_skip_verify: bool,
    pub timeout: Duration,
    pub user_agent: String,
}

pub enum Auth {
    None,
    Basic { username: String, password: String },
    Bearer(String),
}

#[derive(thiserror::Error, Debug)]
pub enum HttpError {
    #[error("cannot read CA file {0}: {1}")]
    CaRead(PathBuf, std::io::Error),
    #[error("CA file {0} contains no PEM certificate")]
    CaInvalid(PathBuf),
    #[error("ca_file and insecure_skip_verify cannot be combined")]
    ConflictingTls,
    #[error("authentication failed for {0}")]
    Unauthorized(String),
    #[error("{0} returned HTTP {1}")]
    Status(String, u16),
    #[error("request to {0} failed: {1}")]
    Transport(String, String),
    #[error("invalid response from {0}: {1}")]
    Decode(String, String),
}

pub struct Response<T> {
    pub body: T,
    pub headers: BTreeMap<String, String>,
}

pub struct HttpClient {
    agent: ureq::Agent,
    retry_delays: [Duration; 2],
}

impl HttpClient {
    pub fn new(opts: &HttpOptions) -> Result<Self, HttpError> {
        if opts.ca_file.is_some() && opts.insecure_skip_verify {
            return Err(HttpError::ConflictingTls);
        }
        let roots = if let Some(path) = &opts.ca_file {
            let pem = std::fs::read(path).map_err(|e| HttpError::CaRead(path.clone(), e))?;
            let mut certs = Vec::new();
            for item in parse_pem(&pem) {
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
    pub fn with_backoff(mut self, delays: [Duration; 2]) -> Self {
        self.retry_delays = delays;
        self
    }

    pub fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
    ) -> Result<Response<T>, HttpError> {
        self.json_response("GET", url, self.request("GET", url, auth, headers, None)?)
    }

    pub fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        auth: &Auth,
        body: &B,
        headers: &[(&str, &str)],
    ) -> Result<Response<T>, HttpError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| HttpError::Decode(format!("POST {url}"), e.to_string()))?;
        self.json_response(
            "POST",
            url,
            self.request("POST", url, auth, headers, Some(&bytes))?,
        )
    }

    pub fn delete(
        &self,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
    ) -> Result<(), HttpError> {
        self.request("DELETE", url, auth, headers, None)?;
        Ok(())
    }

    fn json_response<T: DeserializeOwned>(
        &self,
        method: &str,
        url: &str,
        mut response: ureq::http::Response<ureq::Body>,
    ) -> Result<Response<T>, HttpError> {
        let context = format!("{method} {url}");
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|e| HttpError::Decode(context.clone(), e.to_string()))?;
        let body = serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(context, e.to_string()))?;
        Ok(Response { body, headers })
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        auth: &Auth,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpError> {
        let authorization = match auth {
            Auth::None => None,
            Auth::Basic { username, password } => Some(format!(
                "Basic {}",
                base64(format!("{username}:{password}").as_bytes())
            )),
            Auth::Bearer(token) => Some(format!("Bearer {token}")),
        };
        let context = format!("{method} {url}");
        for attempt in 0..3 {
            tracing::debug!(method, url);
            let mut request = ureq::http::Request::builder().method(method).uri(url);
            if let Some(value) = &authorization {
                request = request.header("Authorization", value);
            }
            for (key, value) in headers {
                request = request.header(*key, *value);
            }
            if body.is_some() {
                request = request.header("Content-Type", "application/json");
            }
            let request = request
                .body(body.unwrap_or_default())
                .map_err(|e| HttpError::Transport(context.clone(), e.to_string()))?;
            let result = self
                .agent
                .run(request)
                .map_err(|e| HttpError::Transport(context.clone(), e.to_string()))
                .and_then(|response| {
                    let code = response.status().as_u16();
                    match code {
                        401 | 403 => Err(HttpError::Unauthorized(context.clone())),
                        400..=599 => Err(HttpError::Status(context.clone(), code)),
                        _ => Ok(response),
                    }
                });
            let retry = matches!(
                &result,
                Err(HttpError::Transport(..) | HttpError::Status(_, 500..=599))
            );
            if !retry || attempt == 2 {
                return result;
            }
            std::thread::sleep(self.retry_delays[attempt]);
        }
        unreachable!("three attempts always return a result")
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
            let client = HttpClient::new(&HttpOptions {
                ca_file: None,
                insecure_skip_verify,
                timeout: Duration::from_secs(1),
                user_agent: format!("image-scan-report/{}", env!("CARGO_PKG_VERSION")),
            })
            .unwrap();
            assert_eq!(
                client.agent.config().tls_config().disable_verification(),
                insecure_skip_verify
            );
        }
    }
}
