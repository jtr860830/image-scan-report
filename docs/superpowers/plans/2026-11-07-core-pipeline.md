# Core Pipeline Implementation Plan (plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python prototype with a Rust crate that reads Trivy and NeuVector scanner files from a directory, normalises them into one model with the unified severity rule, and writes the normalised JSON to a filesystem path – the spine that the PDF renderer (plan 2), the API sources (plan 3) and the HTTP sink / container (plan 4) plug into.

**Architecture:** `ScanSource` implementations produce a `ScanSet` (images + findings in the normalised model); `severity::classify` is the single place a severity is decided; derived views (unique vulnerabilities, remediation groups, counts) are pure functions over findings; `ReportSink` implementations store `Artifact`s. `judex run` wires config → source → views → sinks. Everything is synchronous; no async runtime.

**Tech Stack:** Rust (current stable, edition 2024), `serde` + `serde_json`, `serde_yaml_ng` 0.10, `clap` 4 (derive), `chrono` 0.4 (serde feature), `thiserror` 2, `anyhow` 1, `tracing` + `tracing-subscriber`, `walkdir`, `insta` 1 and `rstest` 0.28 for tests. No Typst in this plan.

**Spec:** `docs/superpowers/specs/2026-11-07-product-redesign-design.md` – sections 5 (architecture, model), 6.3–6.4 (file sources), 7 (severity), 12 (filesystem sink), 13 (configuration, exit codes), 14 (layout), 15 (fixtures).

**The four plans:** 1 core pipeline (this) · 2 rendering: Typst engine, template, i18n, theme, fonts, golden and performance tests · 3 API sources: Harbor and NeuVector controller · 4 HTTP sink, container image, Kubernetes/Podman examples, release. Each later plan is written after the previous one is merged.

## Global Constraints

- Product working name `judex` (spec §18; the user may still rename). It appears only in `Cargo.toml [package] name`, the binary name, and `src/main.rs` `const PRODUCT_NAME`. Nothing else may hard-code it.
- Repository documentation, comments, commit messages, identifiers: English (spec §3).
- Licence Apache-2.0; `LICENSE` file present from the first commit (spec §3).
- No network access anywhere in this plan's code paths (spec §3); file sources read only the configured directory.
- Secrets never appear in config files or logs; config references environment variables by name (spec §13).
- Severity thresholds (spec §7): v3 Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9; v2 High 7.0–10.0, Medium 4.0–6.9, Low 0.1–3.9. Score source order: `nvd`, then `redhat`, then remaining sources alphabetically. A score of `0`, `null` or absent means "no score".
- Exit codes (spec §13): 0 report produced; 2 configuration error; 3 source unreachable/unreadable; 4 render failure (unused until plan 2); 5 all sinks failed.
- Output file name `<scope>-<source>-<YYYY-MM-DD>.<ext>`; rerun the same day overwrites (spec §12).
- The Python implementation (`main.py`, `templates/`, `static/`, `requirements.txt`, `Dockerfile`) is deleted in Task 2 (spec §17; nobody is waiting on it).
- Fixtures are sanitised: no credentials, the lab's addresses replaced by `harbor.example.test` / `neuvector.example.test` (spec §15).

## Review Focus

Inputs the spec implies but no task's happy path exercises; each has a pinned test in the owning task:

1. A Trivy report whose `Results` is `null` or whose only results are `Class: secret` / `license` – must yield one image with zero findings, not a crash or phantom findings (Task 5).
2. The same vulnerability listed twice for one image (two `Results` targets, same package and version) – counted once per image (Task 5).
3. A NeuVector `scan_result.json` whose scan failed (`report.result` not `succeeded`, or `report.vulnerabilities` absent) – the image appears with `ScanState::Failed` and the error text, never silently dropped (Task 6).
4. A directory with unrelated or malformed JSON files – skipped with a `warn!` naming the file; the run still succeeds if at least one file parsed, and exits 3 if none did (Tasks 5, 8).
5. `password_env` or `${VAR}` naming an environment variable that is not set – exit 2 with a message naming the variable (Task 7).

---

### Task 1: Capture and commit fixtures

The lab (private; see the maintainer's notes) holds Harbor 2.15.4 / Trivy 0.75.0 and NeuVector 5.6.4 with 11 images in project `demo`: `nginx:1.21.0`, `alpine:3.12`, `alpine:3.22`, `redis:6.0.5`, `python:3.6-slim`, `ubuntu:18.04`, `centos:7`, `postgres:12.4`, `httpd:2.4.49`, `busybox:1.37`, `ghcr.io/christophetd/log4shell-vulnerable-app:latest`. The API captures already exist in `~/samples` on the lab VM; the file-mode captures do not.

**Files:**
- Create: `fixtures/README.md`, `fixtures/harbor/**`, `fixtures/neuvector-api/**`, `fixtures/trivy/<image>.json`, `fixtures/neuvector-scanner/<image>/scan_result.json`

**Interfaces:**
- Produces: the fixture paths above, used by Tasks 5, 6 and by plan 3.

- [ ] **Step 1: On the lab VM, produce Trivy CLI output for every image**

Install the Trivy release matching Harbor's scanner (`trivy_0.75.0_Linux-64bit.tar.gz` from GitHub releases) and run, for each image, pulling from its public registry:

```sh
trivy image --format json --scanners vuln -o ~/fixtures/trivy/<name>.json <image>
```

`<name>` is `<repo>-<tag>` with `/` and `:` replaced by `-` (e.g. `nginx-1.21.0.json`, `log4shell-vulnerable-app-latest.json`).

- [ ] **Step 2: Produce NeuVector standalone-scanner output for every image**

Install `podman` on the VM. For each image run the scanner container per NeuVector's standalone-scanner documentation (environment variables `SCANNER_REGISTRY`, `SCANNER_REPOSITORY`, `SCANNER_TAG`; the result is written to `/var/neuvector/scan_result.json` in the mounted directory). Mount `~/fixtures/neuvector-scanner/<name>/` as `/var/neuvector`. Verify the exact variable names against the current docs before running; record the scanner image tag used in `fixtures/README.md`.

- [ ] **Step 3: Copy everything to the repo and sanitise**

Copy `~/samples/harbor` → `fixtures/harbor`, `~/samples/neuvector` → `fixtures/neuvector-api`, and the two new trees. Then:

```sh
grep -rl '192\.168\.' fixtures | xargs sed -i '' -e 's#192\.168\.1\.[0-9]*:30002#harbor.example.test#g' -e 's#192\.168\.1\.[0-9]*#neuvector.example.test#g'
grep -rn -iE 'password|token|secret' fixtures | grep -v '"description"' | head
```

Expected: the second command prints nothing that is a credential (CVE descriptions mentioning "password" are fine).

- [ ] **Step 4: Write `fixtures/README.md`**

Record: capture date, tool versions (Harbor, Trivy, NeuVector controller and scanner, scanner DB version from `neuvector-api/scanner.json`), the image list, the sanitisation applied, and that every file is real scanner output used as test input, not documentation.

- [ ] **Step 5: Commit**

```bash
git add fixtures
git commit -m "test: add captured scanner fixtures (Harbor, NeuVector API, NeuVector scanner, Trivy CLI)"
```

---

### Task 2: Crate skeleton, licence, `version` command

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `LICENSE`, `README.md` (replace), `.gitignore` (extend), `src/main.rs`, `src/cli.rs`, `tests/cli.rs`, `.github/workflows/ci.yml`
- Delete: `main.py`, `requirements.txt`, `Dockerfile`, `templates/`, `static/`, `CLAUDE.md` (rewrite later in plan 4; delete now because every statement in it is about the Python tool)

**Interfaces:**
- Produces: `const PRODUCT_NAME: &str = "judex"` and `const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION")` in `src/main.rs`; `cli::Cli` (clap derive) with subcommands `Run { config: PathBuf }`, `Check { config: PathBuf }`, `Version`. `run`/`check` bodies are filled in Tasks 8–9; until then they print `not implemented` and exit 1.

- [ ] **Step 1: Write the failing integration test**

```rust
// tests/cli.rs
use assert_cmd::Command;

#[test]
fn version_prints_product_name_and_semver() {
    let out = Command::cargo_bin("judex").unwrap().arg("version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("judex "));
    assert_eq!(s.trim().split(' ').nth(1).unwrap().split('.').count(), 3);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test cli`
Expected: FAIL – no binary / compile error.

- [ ] **Step 3: Create the crate**

`Cargo.toml`: `name = "judex"`, `version = "0.1.0"`, `edition = "2024"`, `license = "Apache-2.0"`, `rust-version` = the installed stable (also pinned in `rust-toolchain.toml` as `channel = "<that version>"`). Dependencies for the whole plan: `clap` (derive), `serde` (derive), `serde_json`, `serde_yaml_ng`, `chrono` (serde), `thiserror`, `anyhow`, `tracing`, `tracing-subscriber` (env-filter), `walkdir`. Dev: `assert_cmd`, `insta` (json), `rstest`, `tempfile`.

`src/cli.rs`: `#[derive(Parser)] pub struct Cli { #[command(subcommand)] pub command: Command }`, `#[derive(Subcommand)] pub enum Command { Run { #[arg(long, default_value = "/etc/report/config.yaml")] config: PathBuf }, Check { #[arg(long, default_value = "/etc/report/config.yaml")] config: PathBuf }, Version }`.

`src/main.rs`: initialise `tracing_subscriber` to stderr with `RUST_LOG` filter defaulting to `info`; `Version` prints `"{PRODUCT_NAME} {PRODUCT_VERSION}"`.

`LICENSE`: the Apache-2.0 text. `README.md`: one paragraph in English stating what the tool is, that it is being rewritten, and pointing at the spec. Delete the Python files.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test cli`
Expected: PASS

- [ ] **Step 5: Add CI**

`.github/workflows/ci.yml`: on push and pull request, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, with `Swatinem/rust-cache`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: replace Python prototype with Rust crate skeleton"
```

---

### Task 3: Normalised model

**Files:**
- Create: `src/model/mod.rs`, `src/model/severity.rs` (the enum only; the rule is Task 4), `tests/model_snapshot.rs`, `tests/snapshots/`

**Interfaces:**
- Produces (all `serde::{Serialize, Deserialize}`, `Debug`, `Clone`, `PartialEq`):

```rust
pub struct Report { pub generated_at: DateTime<Utc>, pub language: Language, pub organisation: String,
                    pub source: SourceInfo, pub scope: String, pub images: Vec<Image>, pub findings: Vec<Finding> }
#[serde(rename_all = "kebab-case")] pub enum Language { #[serde(rename = "zh-TW")] ZhTw, En }
pub struct SourceInfo { pub kind: SourceKind, pub display_name: String, pub scanner_name: Option<String>,
                        pub scanner_version: Option<String>, pub db_version: Option<String>, pub db_updated_at: Option<DateTime<Utc>> }
#[serde(rename_all = "kebab-case")] pub enum SourceKind { Harbor, Neuvector, NeuvectorFiles, TrivyFiles }
pub struct Image { pub reference: String, pub tags: Vec<String>, pub digest: Option<String>, pub platform: Option<String>,
                   pub os: Option<String>, pub size_bytes: Option<u64>, pub created_at: Option<DateTime<Utc>>, pub scan: ScanStatus }
pub struct ScanStatus { pub state: ScanState, pub scanned_at: Option<DateTime<Utc>>, pub scanner_version: Option<String>, pub error: Option<String> }
#[serde(rename_all = "snake_case")] pub enum ScanState { Ok, Failed, NotScanned }
pub struct Finding { pub id: String, pub image: String, pub severity: Severity, pub severity_basis: SeverityBasis,
                     pub score_v3: Option<f32>, pub score_v2: Option<f32>, pub score_source: Option<String>,
                     pub scanner_severity: Option<String>, pub package: String, pub installed_version: String,
                     pub fixed_version: Option<String>, pub fix_status: Option<FixStatus>, pub description: String,
                     pub links: Vec<String>, pub published_at: Option<DateTime<Utc>> }
#[serde(rename_all = "lowercase")] pub enum Severity { Critical, High, Medium, Low, Unrated }   // Ord: Critical > High > Medium > Low > Unrated
#[serde(rename_all = "snake_case")] pub enum SeverityBasis { Cvss3, Cvss2, ScannerLabel, None }
#[serde(rename_all = "snake_case")] pub enum FixStatus { Fixed, Affected, WillNotFix, EndOfLife, FixDeferred, UnderInvestigation, #[serde(untagged)] Other(String) }
pub struct ScanSet { pub source: SourceInfo, pub scope: String, pub images: Vec<Image>, pub findings: Vec<Finding> }
impl Severity { pub fn label(self) -> &'static str }   // "Critical" | "High" | "Medium" | "Low" | "Unrated"
impl FixStatus { pub fn parse(s: &str) -> FixStatus }  // case-insensitive; "will_not_fix"/"will-not-fix" → WillNotFix, etc.; anything else Other(original)
```

- [ ] **Step 1: Write the failing snapshot test**

```rust
// tests/model_snapshot.rs
#[test]
fn report_json_shape_is_stable() {
    let report = judex::model::Report { /* one image, two findings, fixed timestamps, every Option both Some and None across the two findings */ };
    insta::assert_json_snapshot!(report);
}

#[test]
fn severity_orders_critical_first() {
    use judex::model::Severity::*;
    let mut v = vec![Low, Unrated, Critical, Medium, High];
    v.sort_by(|a, b| b.cmp(a));
    assert_eq!(v, vec![Critical, High, Medium, Low, Unrated]);
}

#[test]
fn fix_status_parses_known_and_other() {
    use judex::model::FixStatus;
    assert_eq!(FixStatus::parse("will_not_fix"), FixStatus::WillNotFix);
    assert_eq!(FixStatus::parse("End-Of-Life"), FixStatus::EndOfLife);
    assert_eq!(FixStatus::parse("weird"), FixStatus::Other("weird".into()));
}
```

- [ ] **Step 2: Run to verify it fails** – `cargo test --test model_snapshot` → compile error (no `judex::model`).

- [ ] **Step 3: Implement the types** in `src/model/mod.rs` and `src/model/severity.rs`; expose `pub mod model;` from `src/lib.rs` (create `src/lib.rs`; `main.rs` uses the library).

- [ ] **Step 4: Run, accept the snapshot, run again** – `cargo insta test --accept` then `cargo test --test model_snapshot` → PASS. Review the accepted snapshot: keys are kebab/snake as declared, timestamps are RFC 3339 `Z`, `null` appears for `None`.

- [ ] **Step 5: Commit** – `git add src tests && git commit -m "feat: normalised report model"`

---

### Task 4: Severity rule

**Files:**
- Create: `src/severity.rs`, `tests/severity.rs`

**Interfaces:**
- Consumes: `model::{Severity, SeverityBasis}`.
- Produces:

```rust
pub struct CvssScores { pub v3: Option<f32>, pub v2: Option<f32> }           // already cleaned: 0 → None
pub struct ScoreInput<'a> { pub cvss: &'a [(String, CvssScores)], pub scanner_label: Option<&'a str> }
pub struct Classification { pub severity: Severity, pub basis: SeverityBasis, pub score_v3: Option<f32>,
                            pub score_v2: Option<f32>, pub score_source: Option<String> }
pub fn clean_score(raw: Option<f64>) -> Option<f32>            // None, NaN, ≤ 0 → None; else rounded to one decimal
pub fn band_v3(score: f32) -> Severity
pub fn band_v2(score: f32) -> Severity                          // never Critical
pub fn label_to_severity(label: &str) -> Option<Severity>       // case-insensitive critical/high/medium/low; else None
pub fn classify(input: &ScoreInput) -> Classification
```

`classify` follows spec §7 exactly: choose the source by priority (`nvd`, `redhat`, then alphabetical) **among sources that have a v3 score**; if none has v3, choose the first by the same priority that has a v2; `score_v3`/`score_v2` in the result are taken from the chosen source (when basis is `Cvss3`, `score_v2` is that same source's v2 if present). Basis `ScannerLabel` when no score at all and the label maps; `None` with `Unrated` otherwise.

- [ ] **Step 1: Write the failing tests** (`rstest` cases, names as shown; one assertion per row of the spec's rule)

```rust
#[rstest]
#[case(10.0, Critical)] #[case(9.0, Critical)] #[case(8.9, High)] #[case(7.0, High)]
#[case(6.9, Medium)] #[case(4.0, Medium)] #[case(3.9, Low)] #[case(0.1, Low)]
fn v3_bands(#[case] s: f32, #[case] want: Severity) { assert_eq!(band_v3(s), want); }

#[rstest] #[case(10.0, High)] #[case(7.0, High)] #[case(6.9, Medium)] #[case(3.9, Low)]
fn v2_bands_have_no_critical(#[case] s: f32, #[case] want: Severity) { assert_eq!(band_v2(s), want); }

#[test] fn clean_score_drops_zero_and_rounds() { assert_eq!(clean_score(Some(0.0)), None); assert_eq!(clean_score(Some(7.46)), Some(7.5)); assert_eq!(clean_score(None), None); }

#[test] fn nvd_wins_over_redhat() { /* nvd v3 10.0, redhat v3 7.4 → Critical, source "nvd", score_v3 10.0 */ }
#[test] fn redhat_wins_when_nvd_absent() { /* julia 3.3, redhat 4.4 → Medium, source "redhat" */ }
#[test] fn alphabetical_after_redhat() { /* bitnami 9.1, julia 3.3, no nvd/redhat → "bitnami" */ }
#[test] fn source_without_v3_is_skipped_for_v3() { /* nvd has only v2 5.0, redhat v3 8.0 → Cvss3 from redhat; score_v2 None */ }
#[test] fn falls_back_to_v2() { /* nvd v2 7.5 only → High, basis Cvss2, score_v2 7.5, score_v3 None */ }
#[test] fn falls_back_to_scanner_label() { /* no scores, label "High" → High, basis ScannerLabel, source None */ }
#[test] fn unrated_when_nothing() { /* no scores, label "Unknown" → Unrated, basis None */ }
#[test] fn unrated_when_label_missing() { /* no scores, label None → Unrated */ }
```

- [ ] **Step 2: Run to verify failure** – `cargo test --test severity` → compile error.
- [ ] **Step 3: Implement `src/severity.rs`**; `pub mod severity;` in `lib.rs`.
- [ ] **Step 4: Run** – `cargo test --test severity` → all PASS.
- [ ] **Step 5: Commit** – `git commit -am "feat: unified CVSS v3 severity rule"`

---

### Task 5: Trivy file source

**Files:**
- Create: `src/source/mod.rs`, `src/source/files.rs`, `src/source/trivy_file.rs`, `tests/trivy_file.rs`, `tests/data/trivy/` (hand-written edge cases)

**Interfaces:**
- Consumes: `model::*`, `severity::{classify, clean_score, CvssScores, ScoreInput}`.
- Produces:

```rust
// src/source/mod.rs
#[derive(thiserror::Error, Debug)] pub enum SourceError { #[error("input directory {0} is not readable: {1}")] Unreadable(PathBuf, std::io::Error),
    #[error("no scan results found in {0}")] Empty(PathBuf), #[error("{0}")] Other(String) }
pub trait ScanSource { fn describe(&self) -> String; fn fetch(&self) -> Result<ScanSet, SourceError>; }

// src/source/files.rs
pub fn walk_json_files(dir: &Path) -> Result<Vec<PathBuf>, SourceError>   // recursive, extension .json (case-insensitive), sorted by path
pub fn file_modified_at(path: &Path) -> Option<DateTime<Utc>>
pub fn dedupe_images(items: Vec<(Image, Vec<Finding>)>) -> (Vec<Image>, Vec<Finding>)
    // same digest (or same reference when digest is None) → keep the one with the latest scan.scanned_at; findings deduped per image by (id, package, installed_version)

// src/source/trivy_file.rs
pub struct TrivyFileSource { pub dir: PathBuf }
pub fn parse_trivy_report(bytes: &[u8], scanned_at: Option<DateTime<Utc>>) -> Result<Option<(Image, Vec<Finding>)>, ParseError>
    // Ok(None) when the JSON has no "SchemaVersion" (not a Trivy report)
#[derive(thiserror::Error, Debug)] pub enum ParseError { #[error("invalid JSON: {0}")] Json(#[from] serde_json::Error), #[error("{0}")] Shape(String) }
```

Field mapping (spec §6.4): `ArtifactName` → `reference`; `Metadata.RepoDigests[0]` after `@` → `digest`; `Metadata.OS.Family` + ` ` + `Metadata.OS.Name` → `os`; `Metadata.ImageConfig.architecture` (+`/`+`variant` if present) with `os` prefixed `linux/` → `platform`; `CreatedAt` → `created_at`; `tags` = the tag part of `ArtifactName` if any. `Results[]` with `Class` in `os-pkgs`, `lang-pkgs` only. Per vulnerability: `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion` (empty → None), `Status` → `FixStatus::parse`, `Severity` → `scanner_severity`, `CVSS` map → `cvss` input (`V3Score`, `V2Score` through `clean_score`), `Description` (fallback `Title`, fallback empty), `PrimaryURL` first then `References` → `links`, `PublishedDate` → `published_at`. `scan.state = Ok`, `scan.scanned_at` = the file's modification time (Trivy's JSON carries no scan timestamp), `scan.scanner_version` = None. `SourceInfo { kind: TrivyFiles, display_name: "Trivy (files)", scanner_name: Some("Trivy") }`, `scope` = the directory's file name.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn parses_nginx_fixture() {
    let (image, findings) = parse_trivy_report(&std::fs::read("fixtures/trivy/nginx-1.21.0.json").unwrap(), None).unwrap().unwrap();
    assert_eq!(image.reference, "nginx:1.21.0");
    assert!(image.digest.as_deref().unwrap().starts_with("sha256:"));
    assert!(image.os.as_deref().unwrap().starts_with("debian"));
    assert!(findings.len() > 100);
    let f = findings.iter().find(|f| f.id == "CVE-2023-44487").expect("known CVE present");
    assert_eq!(f.severity_basis, SeverityBasis::Cvss3);
    assert_eq!(f.score_source.as_deref(), Some("nvd"));
}
#[test] fn results_null_yields_image_without_findings()      // tests/data/trivy/results-null.json: SchemaVersion 2, ArtifactName, "Results": null
#[test] fn secret_and_license_classes_are_ignored()           // tests/data/trivy/secret-only.json → 0 findings
#[test] fn duplicate_vulnerability_counted_once_per_image()   // two Results targets with the same (id, pkg, version) → 1 finding after dedupe_images
#[test] fn not_a_trivy_report_returns_none()                  // {"foo": 1} → Ok(None)
#[test] fn walk_skips_unrelated_files_and_sorts()             // tempdir with b.json, a.JSON, note.txt, sub/c.json → [a.JSON, b.json, sub/c.json]
#[test] fn fetch_fixture_directory()                          // TrivyFileSource over fixtures/trivy → 11 images; scope "trivy"; busybox has 0 findings and ScanState::Ok
#[test] fn fetch_empty_directory_is_error()                   // tempdir with only note.txt → Err(SourceError::Empty)
#[test] fn malformed_json_is_skipped_with_warning()           // tempdir with one fixture copy + one "{" file → Ok with 1 image (assert via tracing_test or by result count)
```

- [ ] **Step 2: Run to verify failure** – `cargo test --test trivy_file` → compile error.
- [ ] **Step 3: Implement** `files.rs`, `trivy_file.rs`, `source/mod.rs`; `pub mod source;` in `lib.rs`. Deserialise with a private `#[derive(Deserialize)]` struct set mirroring only the fields above (`#[serde(default)]` everywhere – Trivy omits absent fields).
- [ ] **Step 4: Run** – `cargo test --test trivy_file` → PASS.
- [ ] **Step 5: Commit** – `git add -A && git commit -m "feat: Trivy JSON file source"`

---

### Task 6: NeuVector file source (parser shared with plan 3)

**Files:**
- Create: `src/source/neuvector/mod.rs`, `src/source/neuvector/report.rs`, `src/source/neuvector_file.rs`, `tests/neuvector_file.rs`, `tests/data/neuvector/`

**Interfaces:**
- Consumes: Task 5's `files.rs`, `ScanSource`, `ParseError`.
- Produces:

```rust
// src/source/neuvector/report.rs — the JSON shapes NeuVector emits in both scan_result.json and the controller API
#[derive(Deserialize)] pub struct NvVulnerability { pub name: String, pub severity: String, pub score: Option<f64>, pub score_v3: Option<f64>,
    pub package_name: String, pub package_version: String, pub fixed_version: Option<String>, pub link: Option<String>,
    pub description: Option<String>, pub published_timestamp: Option<i64>, pub file_name: Option<String> }
pub fn finding_from_nv(v: &NvVulnerability, image_reference: &str) -> Finding
    // cvss input: a single source "neuvector" with v3 = clean_score(score_v3), v2 = clean_score(score); score_source "neuvector"; links = [link]
pub fn nv_timestamp(secs: Option<i64>) -> Option<DateTime<Utc>>   // 0 or None → None

// src/source/neuvector_file.rs
pub struct NeuvectorFileSource { pub dir: PathBuf }
pub fn parse_neuvector_result(bytes: &[u8], scanned_at: Option<DateTime<Utc>>) -> Result<Option<(Image, Vec<Finding>)>, ParseError>
    // Ok(None) when there is no top-level "report" object
```

Mapping for `scan_result.json` (`report.*`): `registry` + `repository` + `:` + `tag` → `reference` (omit registry when empty); `digest`; `base_os` → `os`; `size` → `size_bytes`; `created_at` → `created_at`; `cvedb_version`/`cvedb_create_time` → `SourceInfo.db_version`/`db_updated_at` (from the first file that has them); `scanner_version` when present. Scan state: `Ok` when `result` is absent or equals `succeeded` (case-insensitive) and `vulnerabilities` is present (empty list is fine); otherwise `Failed` with `error` = the `result`/`error` text or `"vulnerabilities missing"`. `scanned_at`: `scanned_timestamp`/`scanned_at` if present, else file modification time. `SourceInfo { kind: NeuvectorFiles, display_name: "NeuVector scanner (files)", scanner_name: Some("NeuVector") }`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn parses_scanner_fixture()                     // fixtures/neuvector-scanner/nginx-1.21.0/scan_result.json → reference ends with "nginx:1.21.0", > 100 findings, every finding score_source == Some("neuvector")
#[test] fn finding_from_nv_uses_v3_then_v2()            // score_v3 9.8 → Critical/Cvss3; score_v3 0 + score 6.8 → Medium/Cvss2; both 0 + severity "High" → High/ScannerLabel
#[test] fn failed_scan_is_kept_as_failed()              // tests/data/neuvector/failed.json: report.result "failed", no vulnerabilities → ScanState::Failed, error Some, 0 findings
#[test] fn empty_vulnerabilities_is_ok()                // report.vulnerabilities [] → Ok, 0 findings
#[test] fn not_neuvector_returns_none()                 // {"SchemaVersion": 2} → Ok(None)
#[test] fn fetch_fixture_directory()                    // NeuvectorFileSource over fixtures/neuvector-scanner → 11 images, db_version Some
```

- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement.** - [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** – `git add -A && git commit -m "feat: NeuVector scanner file source with shared report parser"`

---

### Task 7: Configuration

**Files:**
- Create: `src/config.rs`, `tests/config.rs`, `tests/data/config/*.yaml`, `examples/config.yaml`

**Interfaces:**
- Produces:

```rust
pub struct Config { pub source: SourceConfig, pub report: ReportConfig, pub output: Vec<OutputConfig> }
#[serde(tag = "type", rename_all = "kebab-case")] pub enum SourceConfig {
    TrivyFiles { path: PathBuf }, NeuvectorFiles { path: PathBuf },
    Harbor { url: String, project: Option<String>, username: String, password_env: String, ca_file: Option<PathBuf> },   // consumed in plan 3
    Neuvector { url: String, registry: String, username: String, password_env: String, ca_file: Option<PathBuf> } }     // consumed in plan 3
pub struct ReportConfig { pub language: Language, pub organization: String, pub logo: Option<PathBuf>,
                          #[serde(default = "default_stale")] pub stale_after_days: u32 /* 30 */, #[serde(default)] pub json: bool,
                          #[serde(default = "default_pdf")] pub pdf: bool /* true */ }
#[serde(tag = "type", rename_all = "kebab-case")] pub enum OutputConfig { Filesystem { path: PathBuf },
    Http { url: String, #[serde(default = "default_put")] method: String, #[serde(default)] headers: BTreeMap<String, String>,
           #[serde(default)] mode: HttpMode, ca_file: Option<PathBuf>, #[serde(default = "default_timeout")] timeout_secs: u64 } }  // consumed in plan 4
#[serde(rename_all = "lowercase")] pub enum HttpMode { #[default] Raw, Multipart }
#[derive(thiserror::Error, Debug)] pub enum ConfigError { #[error("cannot read {0}: {1}")] Read(PathBuf, std::io::Error),
    #[error("invalid configuration: {0}")] Parse(String), #[error("environment variable {0} is not set")] MissingEnv(String),
    #[error("{0}")] Invalid(String) }
pub fn load(path: &Path) -> Result<Config, ConfigError>
pub fn resolve_env(value: &str) -> Result<String, ConfigError>   // replaces every ${NAME} with the variable's value; MissingEnv on the first unset one
pub fn secret_from_env(name: &str) -> Result<String, ConfigError>
impl Config { pub fn validate(&self) -> Result<(), ConfigError> }   // output non-empty; at least one of report.pdf / report.json true; method PUT or POST
```

`load` reads, parses (`serde_yaml_ng`), calls `validate`, and resolves `${VAR}` in every `headers` value. It does **not** read `password_env` secrets – sources do that when they connect, so `check`/`run` fail with `MissingEnv` only when the secret is actually needed.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn loads_minimal_trivy_files_config()        // tests/data/config/trivy-files.yaml → SourceConfig::TrivyFiles{path "/input"}, stale_after_days 30, pdf true, json false
#[test] fn unknown_type_is_parse_error()              // type: foo → ConfigError::Parse
#[test] fn empty_output_is_invalid()                  // output: [] → ConfigError::Invalid
#[test] fn pdf_and_json_both_false_is_invalid()
#[test] fn header_env_placeholder_is_resolved()       // set JUDEX_TEST_TOKEN=abc; headers Authorization "Bearer ${JUDEX_TEST_TOKEN}" → "Bearer abc"
#[test] fn missing_env_names_the_variable()           // "${JUDEX_UNSET_VAR}" → Err(MissingEnv("JUDEX_UNSET_VAR"))
#[test] fn example_config_in_repo_loads()             // examples/config.yaml parses and validates
```

- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement `src/config.rs`** and write `examples/config.yaml` exactly as spec §13's example (Harbor source, zh-TW, filesystem + http outputs, with comments in English). - [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** – `git add -A && git commit -m "feat: YAML configuration with environment-variable secrets"`

---

### Task 8: Derived views

**Files:**
- Create: `src/views.rs`, `tests/views.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Default, Serialize, PartialEq, Debug)] pub struct SeverityCounts { pub critical: usize, pub high: usize, pub medium: usize, pub low: usize, pub unrated: usize }
impl SeverityCounts { pub fn total(&self) -> usize; pub fn add(&mut self, s: Severity); pub fn high_or_worse(&self) -> usize }
pub struct UniqueVulnerability { pub id: String, pub severity: Severity, pub score_v3: Option<f32>, pub packages: Vec<String>, pub fixed_versions: Vec<String>, pub images: Vec<String> }
pub struct RemediationGroup { pub package: String, pub fixed_version: String, pub resolves: SeverityCounts, pub images: Vec<String> }
pub struct ImageSummary { pub reference: String, pub counts: SeverityCounts }
pub fn counts(findings: &[Finding]) -> SeverityCounts
pub fn fixable(findings: &[Finding]) -> usize                                   // fixed_version.is_some()
pub fn unique_vulnerabilities(findings: &[Finding]) -> Vec<UniqueVulnerability> // severity = max over occurrences; sorted severity desc, score_v3 desc (None last), id asc; images sorted, deduped
pub fn remediation_groups(findings: &[Finding]) -> Vec<RemediationGroup>        // only findings with fixed_version; sorted by resolves (critical, high, medium, low) desc, then package asc
pub fn image_summaries(images: &[Image], findings: &[Finding]) -> Vec<ImageSummary> // one per image incl. zero counts; sorted critical desc, high desc, …, reference asc
pub fn images_with_high_or_worse(summaries: &[ImageSummary]) -> usize
pub fn stale_images(images: &[Image], now: DateTime<Utc>, stale_after_days: u32) -> Vec<&Image>  // scanned_at older than threshold, or None while state Ok
```

- [ ] **Step 1: Write the failing tests** with a small hand-built `Vec<Finding>` (helper `f(id, image, severity, score, pkg, fixed: Option<&str>)`):
```rust
#[test] fn counts_and_fixable()
#[test] fn unique_vulnerabilities_merge_images_and_take_max_severity()   // CVE-1 on img-a High 7.5 and img-b Critical 9.1 → one entry Critical, images [img-a, img-b]
#[test] fn unique_sort_order()                                            // Critical before High; within High, 8.1 before 7.5; None score last; ties by id
#[test] fn remediation_groups_rank_by_what_they_resolve()                 // openssl→3.0.15 resolves 2 Critical; xz→5.6.2 resolves 1 Critical: openssl first
#[test] fn remediation_skips_unfixable()
#[test] fn image_summaries_include_zero_count_images()
#[test] fn stale_images_by_threshold_and_missing_time()
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement `src/views.rs`.** - [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** – `git add -A && git commit -m "feat: derived report views"`

---

### Task 9: Filesystem sink, pipeline, `run` and `check`

**Files:**
- Create: `src/sink/mod.rs`, `src/sink/filesystem.rs`, `src/pipeline.rs`, `src/naming.rs`
- Modify: `src/main.rs`, `src/cli.rs`
- Test: `tests/sink_filesystem.rs`, `tests/pipeline.rs`, `tests/cli.rs` (extend)

**Interfaces:**
- Consumes: everything above.
- Produces:

```rust
// src/sink/mod.rs
pub struct Artifact { pub file_name: String, pub media_type: &'static str, pub bytes: Vec<u8> }
#[derive(thiserror::Error, Debug)] pub enum SinkError { #[error("{0}")] Io(#[from] std::io::Error), #[error("{0}")] Other(String) }
pub trait ReportSink { fn describe(&self) -> String; fn store(&self, artifact: &Artifact) -> Result<(), SinkError>; }
pub fn build_sinks(cfg: &[OutputConfig]) -> Result<Vec<Box<dyn ReportSink>>, ConfigError>   // Http → ConfigError::Invalid("http output arrives in a later release") until plan 4
// src/sink/filesystem.rs
pub struct FilesystemSink { pub dir: PathBuf }   // creates dir if missing; writes to a temp file then renames (atomic overwrite)
// src/naming.rs
pub fn slug(s: &str) -> String                                   // lowercase; runs of non [a-z0-9] → "-"; trimmed; empty → "report"
pub fn artifact_base_name(scope: &str, kind: SourceKind, date: NaiveDate) -> String   // "<slug(scope)>-<kind kebab>-<YYYY-MM-DD>"
// src/pipeline.rs
pub fn build_source(cfg: &SourceConfig) -> Result<Box<dyn ScanSource>, ConfigError>   // Harbor/Neuvector → ConfigError::Invalid("… arrives in a later release") until plan 3
pub fn assemble_report(set: ScanSet, cfg: &ReportConfig, now: DateTime<Utc>) -> Report
pub struct RunSummary { pub images: usize, pub findings: usize, pub stored: Vec<String>, pub failed_sinks: Vec<String> }
#[derive(thiserror::Error, Debug)] pub enum RunError { #[error(transparent)] Config(#[from] ConfigError), #[error(transparent)] Source(#[from] SourceError),
    #[error("rendering failed: {0}")] Render(String), #[error("every output failed: {0:?}")] AllSinksFailed(Vec<String>) }
impl RunError { pub fn exit_code(&self) -> i32 }   // Config 2, Source 3, Render 4, AllSinksFailed 5
pub fn run(cfg: &Config, now: DateTime<Utc>) -> Result<RunSummary, RunError>
pub fn check(cfg: &Config) -> Result<String, RunError>   // builds the source, calls fetch(), returns "<describe>: N images, M findings"
```

`run` in this plan: fetch → `assemble_report` → if `report.json` produce the JSON artifact (`serde_json::to_vec_pretty`, media type `application/json`) → if `report.pdf` log `warn!("PDF rendering is not available in this build yet; set report.json: true")` and produce nothing for it (plan 2 replaces this branch) → store every artifact in every sink, collecting failures → `AllSinksFailed` only when every sink failed for every artifact. `main.rs` maps `Err(e)` to `eprintln!("error: {e}")` + `std::process::exit(e.exit_code())`, and prints the summary on success.

- [ ] **Step 1: Write the failing tests**

```rust
// tests/sink_filesystem.rs
#[test] fn writes_and_overwrites_file()           // store twice with different bytes → second content wins; no leftover temp file
#[test] fn creates_missing_directory()
// tests/pipeline.rs
#[test] fn slug_and_base_name()                   // slug("Demo Project/x") == "demo-project-x"; artifact_base_name("trivy", TrivyFiles, 2026-11-07) == "trivy-trivy-files-2026-11-07"
#[test] fn run_trivy_fixtures_to_json()           // config: trivy-files over fixtures/trivy, json true, pdf false, filesystem tempdir → file "trivy-trivy-files-<today>.json" exists; parses back to Report with 11 images
#[test] fn run_with_empty_input_exits_3()         // tempdir with no json → Err(Source(Empty)), exit_code 3
#[test] fn run_with_unwritable_sink_exits_5()     // filesystem path is a file, not a dir → AllSinksFailed, exit_code 5
#[test] fn check_reports_counts()                 // "Trivy (files): 11 images, N findings"
// tests/cli.rs (extend)
#[test] fn run_subcommand_end_to_end()            // write config yaml into tempdir, run binary `run --config …`, assert exit 0 and output file exists
#[test] fn bad_config_exits_2()                   // config with type: foo → exit code 2, stderr contains "invalid configuration"
```

- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement** the four modules, wire `cli` → `pipeline` in `main.rs`, remove the `not implemented` stubs. - [ ] **Step 4: Run** – `cargo test` → all PASS; `cargo clippy --all-targets -- -D warnings` clean.
- [ ] **Step 5: Commit** – `git add -A && git commit -m "feat: filesystem sink, pipeline, run and check commands"`

---

### Task 10: Developer documentation for this milestone

**Files:**
- Modify: `README.md`
- Create: `docs/development.md`

- [ ] **Step 1: Write `README.md`**: what the tool is (two sentences), status ("file sources and JSON output; PDF, Harbor and NeuVector API sources, HTTP upload are in progress – see the spec"), quick start with `cargo run -- run --config examples/config.yaml` adjusted to a `trivy-files` source over `fixtures/trivy`, the config reference (every key from Task 7 with its default), exit codes, licence.
- [ ] **Step 2: Write `docs/development.md`**: toolchain, `cargo insta`, how fixtures were captured (link to `fixtures/README.md`), module map from spec §14 as it now exists, the "name lives in three places" note for renaming.
- [ ] **Step 3: Verify** – every command in `README.md` runs as written: `cargo run -- version`, `cargo run -- check --config <the trivy example>`, `cargo run -- run --config <the trivy example>`.
- [ ] **Step 4: Commit** – `git add -A && git commit -m "docs: README and development notes for the core pipeline"`

---

## Self-review notes

- Spec coverage for this plan's scope: §5 model (T3), views (T8), source trait (T5), sink trait (T9); §6.3 (T6), §6.4 (T5), "source behaviours to handle everywhere" (T5/T6 tests, dedupe in T5); §7 (T4); §12 filesystem + JSON + naming (T9); §13 config/CLI/exit codes (T7, T9); §14 layout (T2–T9); §15 fixtures, parser and severity tests (T1, T4–T6); §17 Python deletion (T2). Not in this plan by design: §4/§8/§9/§10/§11 rendering and theme (plan 2), §6.1/§6.2 (plan 3), HTTP sink, container, deploy, notices (plan 4).
- Names reused across tasks: `ScanSet`, `ScanSource::fetch`, `ParseError`, `walk_json_files`, `dedupe_images`, `classify`, `clean_score`, `CvssScores`, `ScoreInput`, `Artifact`, `ReportSink`, `SourceKind` kebab names in file names – checked consistent.
- Review Focus items map to tests: 1 → `results_null_yields_image_without_findings`, `secret_and_license_classes_are_ignored`; 2 → `duplicate_vulnerability_counted_once_per_image`; 3 → `failed_scan_is_kept_as_failed`; 4 → `malformed_json_is_skipped_with_warning`, `run_with_empty_input_exits_3`; 5 → `missing_env_names_the_variable`.
