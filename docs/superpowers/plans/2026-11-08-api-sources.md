# API Sources Implementation Plan (plan 3 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `judex run` pulls the latest scan results straight from a Harbor instance (built-in Trivy) or a NeuVector controller (registry scans) over HTTPS with a custom CA, so a Kubernetes Job needs no files at all.

**Architecture:** One small synchronous HTTP client (`ureq` + rustls, custom roots from `ca_file`, basic/bearer auth, bounded retries) is shared by two new `ScanSource` implementations. The Harbor source walks projects → repositories → artifacts (paged) → per-artifact vulnerability additions and expands image indexes into one row per platform child; the NeuVector source logs in, lists a registry configuration's images, fetches each image report through the parser plan 1 already shares with the file source, and always logs out. Both map scan status to `Ok | Failed | NotScanned` and feed `severity::classify` exactly like the file sources. Tests replay the sanitised lab captures through an in-process mock HTTP server.

**Tech Stack:** `ureq` 3 (default rustls; `tls::RootCerts::Specific` from `tls::Certificate::from_pem`), `serde`/`serde_json`, existing `source::neuvector::report` parser; dev: `httpmock` 0.9, existing `tests/support/*`.

**Spec:** `docs/superpowers/specs/2026-11-07-product-redesign-design.md` §5 (sources), §6 (6.1 Harbor, 6.2 NeuVector, "behaviours to handle everywhere"), §7, §13, §15. Read `docs/superpowers/plans/2026-11-07-core-pipeline-deferred.md` (plan-3 notes: multi-arch references; real failed-scan capture; stricter NeuVector envelope) and `docs/superpowers/plans/2026-11-08-rendering-deferred.md` first.

## Global Constraints

- Everything plans 1–2 established still binds: product name only in `Cargo.toml [package] name`, the binary and `PRODUCT_NAME`; library `image_scan_report`; English code/comments/docs; Apache-2.0; secrets only from the environment, never logged; Codex builds run cargo `--offline` after the controller fetches new crates.
- Network only to the configured scanner URL; no other outbound call. HTTPS with the system roots by default; `ca_file` (PEM, one or more certificates) **replaces** the roots; plain `http://` URLs are allowed (lab Harbor runs on http). No "skip verification" option exists (spec §3: custom CA, not disabled TLS).
- Credentials: Harbor basic auth with `username` + the variable named by `password_env`; NeuVector token from `POST /v1/auth` with the same pair; the token is released with `DELETE /v1/auth` on every exit path. Error messages never contain the password or token; request logs at `debug` print method + URL only.
- HTTP behaviour: timeout from the config (`timeout_secs`, default 30, per request); 3 attempts with 1 s / 2 s backoff on connection errors and 5xx; 4xx fail immediately; a 401/403 is reported as "authentication failed for <url>" → `SourceError` (exit 3). Harbor pagination `page_size=100`, follow `X-Total-Count`.
- Severity: Harbor and Trivy-file findings share the CVSS source map rule (`nvd`, `redhat`, then alphabetical) through `severity::classify`; NeuVector API findings go through `source::neuvector::report::finding_from_nv` unchanged. A score of 0/null/absent is "no score".
- **Multi-arch (spec §6.1 + ruling):** an index artifact is not a row; each platform child is an `Image` with `platform = "<os>/<arch>[/<variant>]"` and `reference = "<repository>:<tag> (<platform>)"` (untagged: `"<repository>@<digest12>"`; single-manifest artifacts keep `"<repository>:<tag>"`), so `Finding.image` keys stay unique. Non-image artifacts (`type` ≠ `IMAGE`, charts, SBOM-only accessories) are skipped. Several tags → one row, `tags` sorted, reference uses the first tag alphabetically.
- Scan status mapping: Harbor `scan_overview` missing → `NotScanned`; `scan_status` `Success` → `Ok`; `Error`/`Stopped` → `Failed` (error = the status text); `Running`/`Pending`/`Scheduled` → `NotScanned` with `error = "scan in progress"`. NeuVector image `status: finished` + `result: succeeded` → `Ok`; `result` ≠ succeeded → `Failed` (error = result text); `status` `scheduled`/`scanning` → `NotScanned` with `"scan in progress"`.
- `SourceInfo`: Harbor `{ kind: Harbor, display_name: "Harbor <host>", scanner_name/version from the first vulnerability report's `scanner`, db_version None }`; NeuVector `{ kind: Neuvector, display_name: "NeuVector <host>", scanner_name: "NeuVector", scanner_version from the images, db_version/db_updated_at from the registry summary `cvedb_version`/`cvedb_create_time` }`. Scope: Harbor `"<host>/<project>"` or `"<host> (all projects)"`; NeuVector `"<host>/<registry config name>"`.
- Exit codes unchanged: 2 configuration (incl. unreadable or non-PEM `ca_file`, missing `password_env`), 3 source unreachable/auth/empty, 4 render, 5 sinks.

## Review Focus

1. A Harbor project with more than 100 repositories or artifacts — every page is fetched and nothing is duplicated (Task 3: `paginates_repositories_and_artifacts`).
2. Wrong credentials (401) — exit 3 with "authentication failed", and the password never appears in the message or logs (Task 2/3/4: `unauthorized_is_reported_without_secrets`).
3. An index artifact with two children — two rows with platforms and distinct references, each with its own findings (Task 3: `index_children_become_platform_rows`).
4. The NeuVector session is always closed — `DELETE /v1/auth` is called even when an image report request fails mid-way (Task 4: `logout_runs_on_failure`).
5. A `ca_file` that is not PEM, or an HTTPS server whose certificate is not signed by it — exit 2 for the file, exit 3 with a TLS message for the handshake (Task 2: `non_pem_ca_is_config_error`, `untrusted_server_is_source_error`).

---

### Task 1: Lab captures — multi-arch artifact and a failed NeuVector scan

The lab VM (see the maintainer's private notes) runs Harbor 2.15.4 at `http://<vm>:30002` (project `demo`, admin password in `~/harbor-admin-password`) and NeuVector 5.6.4 (API on the `neuvector-svc-controller-api` NodePort, admin password in `~/neuvector-admin-password`, registry config `harbor-lab`). The controller performs the lab steps (the implementer sandbox has no network); the implementer sanitises and commits.

**Files:**
- Create: `fixtures/harbor/multiarch/artifacts-alpine-multi.json`, `fixtures/harbor/multiarch/child-<digest12>.json` (one per child, `?with_scan_overview=true`), `fixtures/harbor/multiarch/vulns-<digest12>.json` (one per child), `fixtures/neuvector-api/failed/registry-images.json`, `fixtures/neuvector-api/failed/registry.json`, `fixtures/neuvector-api/failed/images/<id>.json` (if the controller exposes a report for a failed image), `fixtures/harbor/projects.json`, `fixtures/harbor/repositories-paged-p1.json` + headers note
- Modify: `fixtures/README.md`

- [ ] **Step 1 (controller): push a multi-arch image and scan it** — on the VM: `skopeo copy --all --dest-tls-verify=false --dest-creds admin:$PW docker://docker.io/library/alpine:3.20 docker://<vm>:30002/demo/alpine-multi:3.20`; wait for auto-scan of every child (`GET …/artifacts?with_scan_overview=true` until each child's `scan_status` is `Success`).
- [ ] **Step 2 (controller): capture Harbor** — `GET /api/v2.0/projects`, `GET /api/v2.0/projects/demo/repositories/alpine-multi/artifacts?with_tag=true&with_scan_overview=true` (the index with `references`), for each `child_digest`: `GET …/artifacts/<child_digest>?with_scan_overview=true` and `GET …/artifacts/<child_digest>/additions/vulnerabilities` with `X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1`; also one paged repository list with `page_size=2` saving the `X-Total-Count` header value into `fixtures/README.md`.
- [ ] **Step 3 (controller): capture a failed NeuVector scan** — add `demo/does-not-exist` to the `harbor-lab` registry config filters (`PATCH /v1/scan/registry/harbor-lab` or recreate), start a scan, wait until the summary is idle, capture `GET /v1/scan/registry/harbor-lab`, `GET /v1/scan/registry/harbor-lab/images` (expect one entry with a non-succeeded `result`) and the per-image report call's response (status code + body). Restore the filter afterwards.
- [ ] **Step 4 (implementer): sanitise and commit** — replace the VM addresses as plan 1 did (`harbor.example.test` / `neuvector.example.test`), verify no credentials, describe each file and the captured `X-Total-Count` in `fixtures/README.md`.
- [ ] **Step 5: Commit** — `git commit -m "test: capture multi-arch Harbor artifact and failed NeuVector scan fixtures"`

---

### Task 2: HTTP client

**Files:**
- Create: `src/source/http.rs`, `tests/http_client.rs`, `tests/data/tls/` (a self-signed test CA + server cert generated in the test with `rcgen`? — **no**: keep dev-deps small; use a static PEM pair committed under `tests/data/tls/{ca.pem, bad-ca.pem}` generated once by the controller with `openssl`, and test the handshake against `httpmock`'s HTTPS mode only if available — otherwise cover `untrusted_server_is_source_error` against a plain `http://` mock by asserting the error type on a bad PEM, and document the gap)
- Modify: `Cargo.toml` (`ureq = { version = "3", features = ["json"] }`; dev `httpmock = "0.9"`), `src/source/mod.rs` (`pub mod http;`)

**Interfaces:**
- Produces:
```rust
pub struct HttpOptions { pub ca_file: Option<PathBuf>, pub timeout: Duration, pub user_agent: String /* "<lib name>/<version>" */ }
pub enum Auth { None, Basic { username: String, password: String }, Bearer(String) }
pub struct HttpClient { /* ureq::Agent */ }
#[derive(thiserror::Error, Debug)] pub enum HttpError {
    #[error("cannot read CA file {0}: {1}")] CaRead(PathBuf, std::io::Error),
    #[error("CA file {0} contains no PEM certificate")] CaInvalid(PathBuf),
    #[error("authentication failed for {0}")] Unauthorized(String /* method + url */),
    #[error("{0} returned HTTP {1}")] Status(String, u16),
    #[error("request to {0} failed: {1}")] Transport(String, String),
    #[error("invalid response from {0}: {1}")] Decode(String, String) }
impl HttpClient {
    pub fn new(opts: &HttpOptions) -> Result<HttpClient, HttpError>          // CaRead/CaInvalid only
    pub fn get_json<T: DeserializeOwned>(&self, url: &str, auth: &Auth, headers: &[(&str, &str)]) -> Result<Response<T>, HttpError>
    pub fn post_json<B: Serialize, T: DeserializeOwned>(&self, url: &str, auth: &Auth, body: &B) -> Result<Response<T>, HttpError>
    pub fn delete(&self, url: &str, auth: &Auth) -> Result<(), HttpError> }
pub struct Response<T> { pub body: T, pub headers: BTreeMap<String, String> /* lowercase names */ }
impl From<HttpError> for SourceError   // CaRead/CaInvalid → SourceError::Other handled as config by callers (see Task 5), everything else → SourceError::Other(msg)
```
Retries: `Transport` and `Status(5xx)` retried twice more (sleep 1 s, 2 s); the retry log line is `debug!` with method + URL only. `Unauthorized` for 401/403. `Status` for other 4xx. Bodies are read fully then decoded with `serde_json::from_slice`.

- [ ] **Step 1: Write the failing tests** (`httpmock::MockServer::start()`):
```rust
#[test] fn get_json_decodes_and_returns_headers()        // mock returns {"a":1} + X-Total-Count: 7 → body.a == 1, headers["x-total-count"] == "7"
#[test] fn basic_auth_header_is_sent()                   // mock expects Authorization: Basic base64("u:p")
#[test] fn bearer_header_is_sent()
#[test] fn unauthorized_is_reported_without_secrets()    // 401 → HttpError::Unauthorized whose Display does not contain the password "s3cr3t"
#[test] fn retries_on_503_then_succeeds()                // first two calls 503, third 200 → Ok; mock asserts 3 hits
#[test] fn gives_up_after_three_transport_failures()     // unreachable port → Transport within ~3 s
#[test] fn non_pem_ca_is_config_error()                  // tests/data/tls/not-a-cert.pem (garbage) → CaInvalid; missing file → CaRead
#[test] fn pem_ca_is_accepted()                          // tests/data/tls/ca.pem (a real self-signed CA generated by the controller) → Ok(client)
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement** with `ureq::Agent::config_builder().timeout_global(..).tls_config(TlsConfig::builder().root_certs(RootCerts::Specific(Arc::new(certs))).build()).http_status_as_error(false).user_agent(..).build()`; parse PEM with `ureq::tls::parse_pem` / `Certificate::from_pem`. - [ ] **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** — `git commit -am "feat: HTTP client with custom CA, auth and bounded retries"`

---

### Task 3: Harbor source

**Files:**
- Create: `src/source/harbor/mod.rs`, `src/source/harbor/api.rs` (serde mirrors of the Harbor responses), `src/source/harbor/map.rs` (API → model), `tests/harbor_source.rs`, `tests/support/harbor_mock.rs` (serves the fixtures under `fixtures/harbor/**` from an `httpmock` server, rewriting nothing: the fixtures already use `harbor.example.test`, the mock just answers the paths)
- Modify: `src/source/mod.rs`

**Interfaces:**
- Consumes: `HttpClient`, `Auth::Basic`, `severity::{classify, clean_score, CvssScores, ScoreInput}`, `model::*`, `config::SourceConfig::Harbor { url, project, username, password_env, ca_file }` (+ `timeout_secs` is taken from a new optional `timeout_secs: u64` on the Harbor and Neuvector variants, default 30 — add it in `config.rs`).
- Produces:
```rust
pub struct HarborSource { pub base_url: String, pub project: Option<String>, pub auth: Auth, pub client: HttpClient }
impl HarborSource { pub fn from_config(cfg: &HarborConfigFields, client: HttpClient, password: String) -> HarborSource }
impl ScanSource for HarborSource { fn describe(&self) -> String /* "Harbor <host>: <scope>" */; fn fetch(&self) -> Result<ScanSet, SourceError> }
// api.rs
pub struct Project { pub name: String }  pub struct Repository { pub name: String }
pub struct Artifact { pub digest: String, pub r#type: String, pub manifest_media_type: String, pub tags: Vec<Tag>, pub references: Vec<Reference>, pub scan_overview: BTreeMap<String, ScanOverview>, pub extra_attrs: Option<ExtraAttrs> /* os, architecture, created */, pub size: Option<u64>, pub push_time: Option<DateTime<Utc>> }
pub struct Reference { pub child_digest: String, pub platform: Option<Platform { os, architecture, variant: Option<String> }> }
pub struct ScanOverview { pub scan_status: String, pub start_time: Option<DateTime<Utc>>, pub end_time: Option<DateTime<Utc>>, pub scanner: Option<Scanner { name, version }>, pub report_id: Option<String> }
pub struct VulnReport { pub scanner: Option<Scanner>, pub vulnerabilities: Option<Vec<Vuln>> }
pub struct Vuln { pub id, pub package, pub version, pub fix_version: Option<String>, pub severity: String, pub status: Option<String>, pub description: Option<String>, pub links: Vec<String>, pub vendor_attributes: Option<VendorAttributes { #[serde(rename = "CVSS")] cvss: BTreeMap<String, CvssEntry { V3Score: Option<f64>, V2Score: Option<f64> }> }> }
// map.rs
pub fn image_reference(repository: &str, tags: &[String], digest: &str, platform: Option<&str>) -> String   // rules in Global Constraints
pub fn platform_string(p: &Platform) -> String
pub fn scan_status(overview: Option<&ScanOverview>) -> ScanStatus
pub fn finding(v: &Vuln, image_reference: &str) -> Finding       // vendor_attributes.CVSS → cvss input (every source), severity label as scanner_label, status via FixStatus::parse
```
Flow of `fetch`: projects (one or all, paged) → repositories (paged) → artifacts (paged, `with_tag=true&with_scan_overview=true`) → for each `IMAGE` artifact: if `references` non-empty, fetch each child (`GET …/artifacts/{child_digest}?with_scan_overview=true`) and treat it as the row (platform from the reference, tags from the parent); else the artifact itself → `scan_status`; when `Ok`, `GET …/additions/vulnerabilities` with the accept header → findings. Repository names in URLs are percent-encoded (`library/nginx` → `library%2Fnginx`). Dedupe via `source::files::dedupe_images`. Empty result → `SourceError::Empty`-like error naming the scope (add `SourceError::NoImages(String)` variant).

- [ ] **Step 1: Write the failing tests** (all against the fixture-backed mock):
```rust
#[test] fn fetches_project_images_and_findings()          // demo project → 11+ images (incl. the multi-arch children), nginx:1.21.0 has > 300 findings, source.scanner_name == Some("Trivy"), scope "harbor.example.test/demo" (the mock host is substituted in `describe`)
#[test] fn index_children_become_platform_rows()          // alpine-multi:3.20 → ≥ 2 rows, references "demo/alpine-multi:3.20 (linux/amd64)" and "(linux/arm64)" (or whatever the capture has), distinct digests, each with its own finding count
#[test] fn paginates_repositories_and_artifacts()          // mock serves 150 synthetic repositories in pages of 100 with X-Total-Count: 150 → 150 images requested
#[test] fn scan_states_map()                               // hand-built artifacts: no scan_overview → NotScanned; Error → Failed("Error"); Running → NotScanned("scan in progress"); Success → Ok with scanned_at == end_time
#[test] fn unauthorized_is_reported_without_secrets()      // 401 → SourceError whose Display mentions "authentication failed" and not the password
#[test] fn multiple_tags_one_row()                         // artifact with tags ["v2", "latest"] → one Image, tags ["latest", "v2"], reference "repo:latest"
#[test] fn non_image_artifacts_are_skipped()               // type "CHART" → skipped
#[test] fn cvss_map_feeds_classify()                       // vendor_attributes with nvd 10.0 + redhat 7.4 → Critical, score_source "nvd"
```
- [ ] **Step 2–4: fail → implement → pass.** - [ ] **Step 5: Commit** — `git commit -am "feat: Harbor API source"`

---

### Task 4: NeuVector controller source

**Files:**
- Create: `src/source/neuvector_api.rs`, `src/source/neuvector/api.rs` (serde mirrors: auth request/response, registry summary, image list entry), `tests/neuvector_source.rs`, `tests/support/neuvector_mock.rs`
- Modify: `src/source/mod.rs`, `src/source/neuvector/mod.rs`

**Interfaces:**
- Consumes: `HttpClient`, `Auth::Bearer`, `source::neuvector::report::{NvVulnerability, finding_from_nv, nv_timestamp}`, `model::*`.
- Produces:
```rust
pub struct NeuvectorSource { pub base_url: String, pub registry: String, pub username: String, pub password: String, pub client: HttpClient }
impl ScanSource for NeuvectorSource { fn describe(&self) -> String /* "NeuVector <host>: <registry>" */; fn fetch(&self) -> Result<ScanSet, SourceError> }
// api.rs
pub struct AuthRequest { password: Credentials { username, password } }
pub struct AuthResponse { token: Option<TokenInfo { token: String }>, need_to_reset_password: Option<bool>, code: Option<i64>, message: Option<String> }
pub struct RegistrySummary { summary: RegistryConfigSummary { name, registry, status, cvedb_version: Option<String>, cvedb_create_time: Option<String>, started_at: Option<String>, scanned, failed } }
pub struct RegistryImages { images: Vec<ImageSummary> }
pub struct ImageSummary { repository, tag, image_id, digest: Option<String>, base_os: Option<String>, size: Option<u64>, created_at: Option<String>, scanned_at: Option<String>, status: Option<String>, result: Option<String>, scanner_version: Option<String>, os_scan_status: Option<String>, critical/high/medium/low: Option<u64> }
pub struct ImageReport { report: Option<ReportBody { vulnerabilities: Option<Vec<NvVulnerability>> }> }
```
Flow: `POST /v1/auth` (`X-Auth-Token` header for subsequent calls; `need_to_reset_password == Some(true)` → `SourceError::Other("NeuVector requires an admin password reset before API use")`; missing token → auth error) → `GET /v1/scan/registry/{registry}` (404 → `SourceError::Other("registry configuration <name> not found")`) → `GET /v1/scan/registry/{registry}/images` → for every image with `Ok` status `GET /v1/scan/registry/{registry}/image/{image_id}` → `finding_from_nv` for each vulnerability; `Failed`/`NotScanned` images get no report call. Reference = `<registry URL host>/<repository>:<tag>` via the scheme-stripping rule plan 1 used (`source::neuvector_file` has the helper — move it to `source::neuvector::report::compose_reference(registry, repository, tag)` so both share it). Always `DELETE /v1/auth` — implement with a guard struct whose `Drop` performs the logout (errors on logout are `debug!` only). Dedupe via `dedupe_images`.

- [ ] **Step 1: Write the failing tests**:
```rust
#[test] fn fetches_registry_images_and_findings()     // fixtures/neuvector-api → 11 images, centos:7 > 1000 findings, db_version Some("4.318"), scope "neuvector.example.test/harbor-lab"
#[test] fn failed_scan_is_failed_not_dropped()         // fixtures/neuvector-api/failed → the does-not-exist image is ScanState::Failed with the captured result text; no report call was made for it (mock asserts 0 hits on its image path)
#[test] fn logout_runs_on_failure()                    // mock: image report returns 500 three times → fetch Err, DELETE /v1/auth hit exactly once
#[test] fn password_reset_required_is_reported()       // auth response need_to_reset_password true → SourceError message contains "password reset"
#[test] fn unauthorized_is_reported_without_secrets()
#[test] fn registry_not_found_is_reported()            // 404 on the summary → message contains the registry name
#[test] fn in_progress_images_are_not_scanned()        // status "scanning" → NotScanned("scan in progress")
```
- [ ] **Step 2–4: fail → implement → pass.** - [ ] **Step 5: Commit** — `git commit -am "feat: NeuVector controller API source"`

---

### Task 5: Pipeline wiring, configuration and docs

**Files:**
- Modify: `src/pipeline.rs` (`build_source` constructs the two API sources: read `password_env` via `config::secret_from_env` → `ConfigError::MissingEnv`; `HttpClient::new` errors → `ConfigError::Invalid("<source>.ca_file: …")`), `src/config.rs` (`timeout_secs` on both API variants, default 30; validate `url` parses and is http/https), `examples/config.yaml` (Harbor, already), `examples/config-neuvector.yaml` (new), `README.md` (both sources: fields, credentials, CA, what "scope" means, the multi-arch row rule, scan-state mapping; remove "arrives in a later release"), `docs/development.md` (mock-server test pattern; how the fixtures were captured — link)
- Test: `tests/pipeline.rs`, `tests/cli.rs`, `tests/config.rs`

- [ ] **Step 1: Write the failing tests**:
```rust
// tests/config.rs
#[test] fn api_sources_accept_timeout_and_reject_bad_url()      // timeout_secs parses; url "ftp://x" → Invalid; url "not a url" → Invalid
// tests/pipeline.rs (mock-backed)
#[test] fn run_against_mock_harbor_writes_pdf_and_json()          // Harbor source → PDF page_count ≥ 6 (use the 3-image subset by serving only three repositories), JSON has 3 images
#[test] fn run_against_mock_neuvector_writes_pdf()
#[test] fn missing_password_env_exits_2()                         // password_env names an unset variable → RunError::Config (MissingEnv), exit 2, message names the variable
#[test] fn bad_ca_file_exits_2()                                  // ca_file → tests/data/tls/not-a-cert.pem → exit 2, message mentions ca_file
#[test] fn unreachable_scanner_exits_3()                          // url to a closed port → RunError::Source, exit 3, within ~5 s (timeout_secs: 1)
// tests/cli.rs
#[test] fn check_against_mock_harbor_reports_counts()             // "Harbor 127.0.0.1:<port>: demo: N images, M findings; …"
```
- [ ] **Step 2–4: fail → implement → pass**; README updated; `cargo run -- check --config examples/config.yaml` fails fast with exit 2/3 (no server) and the message is readable.
- [ ] **Step 5: Commit** — `git commit -am "feat: wire Harbor and NeuVector API sources into run and check"`

---

### Task 6: Live verification against the lab and fixture refresh

**Files:**
- Modify: `fixtures/README.md`, `docs/development.md` (a "verified against" table: Harbor 2.15.4 / Trivy 0.75.0, NeuVector 5.6.4, date)

- [ ] **Step 1 (controller):** on the lab VM (or from the laptop through the SSH jump with port forwards) run `judex check` and `judex run` against the real Harbor (`http://<vm>:30002`, project `demo`) and the real NeuVector (`https://<vm>:<nodeport>` — NeuVector uses a self-signed certificate: export it with `openssl s_client -showcerts` into a `ca_file` and use it; this is the real custom-CA test), both languages. Record image/finding counts, page counts and wall time in `docs/development.md`; keep the PDFs out of the repo.
- [ ] **Step 2 (implementer):** fix whatever the live run surfaces (schema drift, encoding, pagination) with a regression test backed by a new sanitised capture; commit per fix.
- [ ] **Step 3: Commit** — `git commit -am "docs: record live verification of the API sources"`

---

## Self-review notes

- Spec coverage: §5 pluggable sources (T3, T4 implement `ScanSource`), §6.1 Harbor incl. multi-arch children, tags, non-image artifacts, `vendor_attributes.CVSS` (T3), §6.2 NeuVector incl. password-reset answer, token release, status mapping (T4), "behaviours to handle everywhere" (T3/T4 tests + shared dedupe), §3 custom CA (T2, T5), §13 config/exit codes (T5), §15 fixtures from the lab (T1, T6). Plan-1 parked note "stricter NeuVector envelope" is not touched (file source unchanged) — carried forward.
- Type consistency: `HttpClient`/`Auth`/`HttpError`/`Response` (T2) used by T3/T4; `compose_reference` moved into `neuvector::report` and used by both NeuVector sources; `SourceError::NoImages` added in T3 and used by T4; `timeout_secs` added in T5's config change but consumed by T3/T4 construction in `build_source` — T3/T4 take an `HttpClient` already built, so they do not depend on config.
- Review Focus → tests: 1 `paginates_repositories_and_artifacts`; 2 `unauthorized_is_reported_without_secrets` (×3); 3 `index_children_become_platform_rows`; 4 `logout_runs_on_failure`; 5 `non_pem_ca_is_config_error` + `bad_ca_file_exits_2` (the live self-signed NeuVector certificate in T6 is the handshake test; an in-process HTTPS mock is not required).
- Proportion: interfaces, mappings and tests are fixed; request loops and serde mirrors are the implementer's.
