//! HTTP artifact uploads.
use super::{Artifact, ReportSink, SinkError};
use crate::{
    config::HttpMode,
    source::http::{HttpClient, encode_segment, redact_url},
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct HttpSink {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    mode: HttpMode,
    client: HttpClient,
}
impl HttpSink {
    pub fn new(
        url: String,
        method: String,
        headers: Vec<(String, String)>,
        mode: HttpMode,
        client: HttpClient,
    ) -> Self {
        Self {
            url,
            method,
            headers,
            mode,
            client,
        }
    }
}
pub fn boundary() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "image-scan-report-{:032x}",
        (nanos << 64) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed))
    )
}
pub fn multipart_body(
    boundary: &str,
    field: &str,
    file_name: &str,
    content_type: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{file_name}\"\r\nContent-Type: {content_type}\r\n\r\n").into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}
impl ReportSink for HttpSink {
    fn describe(&self) -> String {
        format!(
            "HTTP {} {}",
            self.method,
            redact_url(&self.url).replace("%7Bfilename%7D", "{filename}")
        )
    }
    fn store(&self, artifact: &Artifact) -> Result<(), SinkError> {
        let url = self
            .url
            .replace("{filename}", &encode_segment(&artifact.file_name));
        let mut headers: Vec<_> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let disposition = format!("attachment; filename=\"{}\"", artifact.file_name);
        // naming::slug guarantees filenames contain no header delimiters.
        debug_assert!(!artifact.file_name.contains(['"', '\r', '\n']));
        let result = match self.mode {
            HttpMode::Raw => {
                headers.retain(|(key, _)| !key.eq_ignore_ascii_case("Content-Disposition"));
                headers.push(("Content-Disposition", &disposition));
                self.client.send_bytes(
                    &self.method,
                    &url,
                    &headers,
                    artifact.media_type,
                    &artifact.bytes,
                )
            }
            HttpMode::Multipart => {
                let b = boundary();
                let content_type = format!("multipart/form-data; boundary={b}");
                let body = multipart_body(
                    &b,
                    "file",
                    &artifact.file_name,
                    artifact.media_type,
                    &artifact.bytes,
                );
                self.client
                    .send_bytes(&self.method, &url, &headers, &content_type, &body)
            }
        };
        result.map(|_| ()).map_err(|e| {
            SinkError::Other(format!("HTTP {} {}: {e}", self.method, redact_url(&url)))
        })
    }
}
