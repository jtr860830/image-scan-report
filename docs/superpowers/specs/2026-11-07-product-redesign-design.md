# Design: turning image-scan-report into a product

Status: draft for approval · Date: 2026-11-07 · Author: brainstormed with the maintainer; decisions attributed below.

This document describes a rewrite. The current repository is a single-customer Python script (NeuVector `scan_result.json` → Jinja2 → Markdown → WeasyPrint). None of it survives except the lesson it taught; the product described here replaces it entirely.

Throughout, **(user)** marks something the maintainer decided, **(call)** marks a decision I made that they can overrule, and **(builder)** marks something intentionally left open.

---

## 1. Intent

Organisations in Taiwan are starting to scan container images because security-compliance rules now require it. The scanners they run (Harbor's built-in Trivy, NeuVector) already know everything, but their built-in reports are written for engineers and look unprofessional. Auditors need a document.

This tool turns the results a scanner already holds into a PDF that works as **audit evidence**: a report an auditor or a manager can read, file, and be questioned about. It does not scan anything itself.

### What auditors ask **(user)**

1. How severe are the vulnerabilities, and how many are there at each level?
2. Which vulnerabilities exist (an inventory)?
3. Which images is each vulnerability on?
4. What has to be updated to fix them?

Every chapter of the report exists to answer one of these.

### Who reads it **(user)**

Auditors and managers. Engineers may use the per-image detail chapter, but the document is not a work list for them.

---

## 2. Goals, non-goals, anti-goals

**Goals**

- One run produces one professional, bilingual-capable PDF covering a whole batch of images.
- Scan results come from pluggable sources; two API sources and two file sources ship in version 1.
- The finished PDF goes to pluggable destinations; filesystem and HTTP upload ship in version 1.
- Works in air-gapped environments from a single container image with nothing fetched at run time.
- Severity is on one unified, documented, reproducible scale.
- Every dependency, font and colour system is open source.

**Non-goals (not in version 1, room left)**

- Trivy Operator / in-cluster workload scans (`VulnerabilityReport` CRDs).
- Scanning images; orchestrating scanners.
- Native S3 (or other object-store) clients. The HTTP sink covers presigned URLs and compatible gateways.
- HTML or other output formats besides PDF and the optional normalised JSON.
- Side-by-side bilingual pages. One language per run.

**Anti-goals (would make this a failure even if it worked) (user)**

- **Keeping state.** No database, no history, no trend comparison. The tool reads, renders, writes, exits. If reports must be kept, keep the PDFs.
- **Becoming a scan orchestrator.** It never starts Trivy or NeuVector, never waits for scans. In Kubernetes the API mode is the proper path; file mode exists for CI pipelines and local use and gets no Kubernetes-specific features.
- **Branding by fork.** Company or customer branding is a theme, never a code branch (section 11).

---

## 3. Constraints

| Constraint | Consequence |
|---|---|
| Customers are usually air-gapped **(user)** | Single container image; fonts, templates and the rendering engine inside it; no network access other than the configured scanner and destination; custom CA certificates supported. |
| Reports in English and Traditional Chinese (Taiwan) **(user)** | CJK-capable fonts embedded; Taiwanese vocabulary; scanner-supplied text (CVE descriptions, package names) stays in English untranslated **(call)**. |
| Repository documentation and code comments in English **(user)** | Applies to this document, README, comments, commit messages. The report's own strings are the only localised text. |
| Everything open source; fonts and colour systems from open-source projects **(user)** | Licence inventory kept in the repo (section 11). |
| Licence Apache-2.0 **(user)** | `LICENSE` file added; third-party notices for fonts (OFL) shipped alongside. |
| Maintainer is fluent in Rust, Go, C, JavaScript, Python **(user)** | Language choice was free; see section 4. |

---

## 4. Technology **(user)**

- **Language: Rust.**
- **Rendering: Typst, embedded as a library** (the `typst` crates, version pinned in `Cargo.lock`). Not the Typst CLI as a subprocess.
- **Deliverable: one container image** built `FROM scratch` (or distroless) containing one static binary; fonts and templates are embedded in the binary or copied beside it — **(builder)** either is acceptable as long as nothing is fetched at run time.

Why Typst (shared conclusion of my analysis and an independent Codex review): covers, automatic contents, running headers/footers, repeated table headers and page numbers are built in; templates are pleasant to iterate; no browser or native text-layout libraries; Apache-2.0. WeasyPrint was measured at 2 min 19 s / 1.5 GB for 10 000 table rows against Typst's 12 s / 590 MB.

Why embedded rather than the CLI **(user)**: one binary, no temp files or subprocess handling, and by construction no network code in the rendering path (we supply every file, font and package ourselves). The cost is that upgrading Typst can require code changes, since its library API moves between minor versions; this is accepted and bounded (two or three releases a year, small surface).

### Measured rendering behaviour (Typst 0.15.1, must be preserved)

A throwaway benchmark on real scanner data established three settings that matter. The builder must keep all three; without them the same document took 3× longer, 2× memory and 20× the file size.

| Setting | Effect at 10 000 rows |
|---|---|
| Disable PDF tagging (accessibility structure) | PDF 14 MB → 700 KB |
| Set monospace cells with a font change, not `raw` elements | 37 s → 21 s, 1.2 GB → 675 MB |
| Single-threaded layout | multi-threaded was slower (18.7 s vs 12 s wall) |

With all three: 10 000 rows 12 s / 590 MB; 30 000 rows 26 s / 1.4 GB; 50 000 rows 34 s / 2.1 GB / 974 pages / 3.2 MB. Memory grows about 40 MB per 1 000 table rows; document a 2–3 GiB limit for the largest realistic reports.

### Typst packages

No Typst Universe packages. The engine resolves packages from the network by default; our embedded "world" simply has no package resolver. Summary tiles and the severity bar are drawn with native primitives (`rect`, `grid`, `table`).

---

## 5. Architecture

```
config.yaml ─┐
             ▼
      ┌─────────────┐    ┌───────────────┐    ┌──────────────┐    ┌────────────┐
      │ ScanSource  │──▶ │ normalise +   │──▶ │ render       │──▶ │ ReportSink │
      │ (trait)     │    │ classify      │    │ (Typst)      │    │ (trait)    │
      └─────────────┘    └───────────────┘    └──────────────┘    └────────────┘
        harbor-api         one data model        PDF (+ JSON)        filesystem
        neuvector-api      severity rule         one language         http
        neuvector-files
        trivy-files
```

- **`ScanSource`** – given the configured scope, returns the latest scan result of every image in scope, already in the normalised model. Implementations are compiled in and selected by `source.type`; there is no run-time plugin loading **(user)**.
- **`ReportSink`** – given an artifact (file name, bytes, media type), stores it. It does not know what a PDF is. Several sinks may be configured; each receives every artifact.
- The normalised model between them is serialisable; with `output.json: true` it is emitted as a second artifact **(call)**.

### Normalised model (sketch; exact field names are the builder's)

```
Report
  generated_at, language, organisation, theme
  source:  kind, display name, scanner name/version, vulnerability DB version/date (when the source gives them)
  scope:   human-readable description (registry + project, registry config name, or input directory)
  images:  [Image]
  findings:[Finding]            # one row per (image, vulnerability, package)
Image
  reference (registry/repository:tag), digest, os, size_bytes, created_at?
  scan: status (ok | failed | not_scanned), scanned_at?, scanner_version?, error?
Finding
  id (CVE-…, GHSA-…, RHSA-…, DLA-…), image reference
  severity            # ours, computed – see section 7
  severity_basis      # cvss3 | cvss2 | scanner_label | none
  score_v3?, score_v2?, score_source?   # e.g. nvd, redhat, scanner
  scanner_severity    # the label the scanner gave, verbatim
  package, installed_version, fixed_version?, fix_status?   # fixed | affected | will_not_fix | end_of_life | …
  description, links, published_at?
```

Derived views (computed at render time, not stored): unique vulnerabilities with affected-image lists; remediation groups keyed by (package, fixed version) with the images and severities they resolve; per-image counts; totals.

---

## 6. Sources

Scanners keep only the **latest** result per image; none of them offers history or "the set of images in the last run". A run therefore covers *everything in scope that has a result*, and the report shows each image's scan time so stale or failed scans are visible **(user: this matches what they want)**.

### 6.1 Harbor (built-in Trivy) – API

Verified against Harbor 2.15.4 / Trivy 0.75.0.

- Scope: one project (or all projects the credentials can see) **(call)**; optional repository filter **(builder)**.
- Calls: list repositories → list artifacts with `with_scan_overview=true&with_tag=true` → per artifact `GET …/additions/vulnerabilities` with header `X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1`.
- Auth: basic auth; a robot account is the recommended credential.
- Scan metadata: `scan_overview` gives status, start/end time, scanner name and version.
- Fields per vulnerability: `id`, `package`, `version`, `fix_version`, `severity` (Critical/High/Medium/Low/Unknown, Trivy's label), `status` (fixed / affected / will_not_fix / end_of_life / fix_deferred / under_investigation), `description`, `links`, `preferred_cvss`, `vendor_attributes.CVSS`.
- **CVSS reality:** `preferred_cvss.score_v2` is null in 100 % of rows and `vector_v3` is always empty. `preferred_cvss.score_v3` is present in ~97 % but Harbor chooses it non-deterministically when NVD is absent. Therefore **ignore `preferred_cvss` and read `vendor_attributes.CVSS` directly** – a map of source → `{V2Score, V3Score, V2Vector, V3Vector}`, sources seen: `nvd`, `redhat`, `bitnami`, `ghsa`, and others.
- Trivy's label disagrees with the CVSS v3 band in about a third of rows (it prefers distribution vendors' ratings), which is why we classify ourselves.
- Artifacts with several tags: report the artifact once with all its tags **(call)**. Untagged artifacts: include, shown by digest **(call)**.
- **Multi-architecture artifacts (image indexes) (user):** each platform-specific child artifact is its own image row, with a `platform` field (e.g. `linux/amd64`) on `Image`, because its scan results and findings differ. The index itself is not a row; its tags are shown on each child. Cover and summary counts therefore count children, and the appendix says so. The Harbor source walks an index's `references` to reach the children's vulnerability additions. Non-image artifacts (charts, SBOM-only, signatures) are skipped.

### 6.2 NeuVector – controller REST API, registry scans

Verified against NeuVector 5.6.4.

- Scope: one registry configuration by name **(call)**.
- Calls: `POST /v1/auth` (returns a token; the API may answer `need_to_reset_password` on first use – surface this as a clear error, do not try to reset) → `GET /v1/scan/registry/{name}/images` → per image `GET /v1/scan/registry/{name}/image/{image_id}` → `DELETE /v1/auth` on exit.
- The image list carries `repository`, `tag`, `digest`, `base_os`, `size`, `created_at`, `scanned_at`, `status`, `result`, `scanner_version`, `os_scan_status`, and per-severity counts.
- Fields per vulnerability: `name`, `severity` (Critical/High/Medium/Low), `score` (v2), `score_v3`, `vectors`, `vectors_v3`, `package_name`, `package_version`, `fixed_version`, `file_name`, `link`, `description`, `feed_rating`, `published_timestamp`.
- **CVSS reality:** both scores are always non-zero, but NeuVector fills in values for old vulnerabilities that have no real v3 score (observed 4.0 on 2014–2015 CVEs). Only one v3 score is exposed, so the NVD-first rule cannot apply here; NeuVector's choice (empirically closer to the distribution vendor's rating than to NVD) is taken as is.
- Older controllers downgrade Critical to High; treat the label as informational only.

### 6.3 NeuVector standalone scanner – files

The scanner container writes one `scan_result.json` per image; its `report` object has the same vulnerability fields as 6.2, so the parser is shared. Scope: a directory; every `*.json` that parses as this format is one image **(call)**. Because the scanner always writes the same file name, users put each result in its own sub-directory or rename; the tool walks the directory recursively **(call)**.

### 6.4 Trivy – files

`trivy image --format json` output (schema version 2): `ArtifactName`, `Metadata` (OS, ImageID, RepoDigests), `Results[]` each with `Target`, `Class`, `Type` and `Vulnerabilities[]` (`VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Status`, `Severity`, `CVSS{source → V3Score…}`, `Title`, `Description`, `References`, `PublishedDate`). Same CVSS source map as 6.1, so the same NVD-first rule applies. Scope: a directory, recursive **(call)**.

### Source behaviours to handle everywhere

- A missing score is `0`, `null` or absent depending on the source; all three mean "no score".
- Non-CVE identifiers exist (GHSA-, RHSA-, DLA-, DSA-, TEMP-); they are vulnerabilities like any other.
- Images with no findings are included with zero counts; they are evidence too.
- Failed or never-scanned images are listed in the appendix with their status; they are never silently dropped.
- The same scanner can under-report (observed: NeuVector 5 findings vs Harbor 691 on `python:3.6-slim`, both "successful"). The tool cannot detect this; the appendix states that coverage is the scanner's.

---

## 7. Severity classification **(user approved the rule)**

Severity in the report is **computed by this tool**, not copied from the scanner, so that every report uses one scale **(user: a unified scale is what auditors require)**.

1. Pick a CVSS v3 score:
   - Sources with a per-vendor map (Harbor, Trivy files): `nvd` first; otherwise the first present in a fixed order **(call: `redhat`, then the remaining sources alphabetically)**. Record which source was used.
   - NeuVector: its single `score_v3`.
2. Classify: Critical ≥ 9.0 · High 7.0–8.9 · Medium 4.0–6.9 · Low 0.1–3.9.
3. No v3 score → use the v2 score with the same thresholds (v2 has no Critical; 7.0–10.0 is High) and mark the basis as `cvss2`.
4. No score at all → use the scanner's label and mark the basis as `scanner_label`.
5. No label either (Trivy's `Unknown`) → **Unrated**, its own class, never folded into Low.

The scanner's own label is kept beside ours in the per-image detail so that a reader can reconcile the report with the Harbor or NeuVector UI. The appendix prints the rule and the score source so an auditor can verify any row against NVD.

Known and documented: the same rule does not give the same numbers across scanners, because the input scores differ (observed: ~half of the CVEs shared by Harbor and NeuVector on `centos:7` had different v3 scores). Harbor-based and NeuVector-based reports are therefore never merged into one document **(call)**.

---

## 8. The report

One run → one PDF → one language (`zh-TW` or `en`) **(user)**. All numbers below are the user's six-chapter skeleton, which they accepted as "looks good, not fully thought through"; treat chapter contents as provisional and the order as settled.

| # | Chapter | Answers | Contents |
|---|---|---|---|
| 1 | Cover | what is this | Organisation name, optional logo, report title, scope, source/scanner, number of images, scan time range, report date. |
| 2 | Summary | how many, how severe | Four severity tiles; a stacked bar; fixable count and share; images containing Critical/High; the highest-risk images (counts per severity); the top vulnerabilities to act on. A manager stops here. |
| 3 | Remediation | what to update | Grouped by (package, fixed version), ranked by what it resolves (Critical first, then High, …); each group lists the images affected. A separate list of findings with no fix (with the scanner's fix status where available: will-not-fix, end-of-life). Base-image end-of-life is called out when every finding on an OS package is unfixable **(builder: heuristic)**. |
| 4 | Vulnerability inventory | what exists, where | One row per unique vulnerability sorted by severity then score: id, severity, CVSS, package, fixed version, number of images; each row followed by its affected images. |
| 5 | Per-image detail | reverse lookup | One section per image: reference, digest, OS, size, scan time, counts, then its findings. Longest chapter, placed last. |
| 6 | Appendix | method and limits | Scanner and DB versions, report tool name/version, the severity rule and score sources, scope statement ("images stored in the registry, not workloads running in the cluster"), images not scanned or failed, images whose scan is older than the staleness threshold **(call: 30 days, configurable)**, known limitations from sections 6–7. |

Front matter: table of contents (chapters and per-image sections). Running header with report title and organisation; footer with page number "n / total" and report date.

Severity labels: keep the English words Critical / High / Medium / Low / Unrated in both languages **(call)** – they match the scanner UIs and are how Taiwanese practitioners say them.

Scanner descriptions are printed verbatim, escaped. They can be long; the per-image chapter shows them truncated with the full text in the inventory **(builder)**.

---

## 9. Visual design **(user chose direction C with Maple Mono)**

| Element | Choice | Licence |
|---|---|---|
| Colour system | Open Color | MIT |
| Text face | Inter (Latin) + Noto Sans TC (CJK), static weights 400/500/700 | OFL |
| Monospace | Maple Mono **NL** (no ligatures) static TTF, 400/700 – used for image references, identifiers, versions, digests, timestamps | OFL |
| Ink / muted / rules | Open Color gray 9 `#212529`, gray 7 `#495057`, gray 6 `#868e96`, gray 2 `#e9ecef`, gray 0 `#f8f9fa` | |
| Accent | indigo 7 `#4263eb` | |
| Severity | Critical violet 8 `#6741d9` · High red 8 `#e03131` · Medium orange 8 `#f08c00` · Low blue 7 `#1c7ed6` · Unrated gray 6 `#868e96`; tinted backgrounds violet 0 `#f3f0ff`, red 0 `#fff5f5`, yellow 0 `#fff9db`, blue 0 `#e7f5ff` | |

Rules the builder must keep:

- The severity palette passed a colour-vision-deficiency separation check (adjacent pairs ΔE ≥ 14, normal vision ≥ 18). **Do not** substitute the conventional red/orange/yellow sequence; it failed (orange is indistinguishable from both neighbours for deuteranopes and nearly so for everyone).
- A severity colour never appears without its text label. Numbers and labels are set in ink, not in the severity colour; the colour sits in a dot, bar or tinted chip beside them.
- Tables: hairline rules, no vertical lines, repeated header row, right-aligned tabular numerals, monospace only in identifier columns.
- Rounded tiles and chips (as in the mockup), generous white space, large summary numerals.
- Ligatures off everywhere in monospace text. Punctuation: Typst's CJK handling is acceptable; one known flaw (no compression between adjacent full-width punctuation marks) is tolerated.

Mockups from the brainstorm are in `.superpowers/brainstorm/*/content/visual-style*.html` for reference (not part of the product).

---

## 10. Internationalisation

- The template reads a string table for the selected language; two tables ship: `zh-TW` and `en`.
- Traditional Chinese uses Taiwanese computing vocabulary (映像檔, 弱點, 套件, 修補版本, 稽核, 倉庫). Not mainland terms.
- Dates in ISO 8601 in both languages; numbers with thousands separators.
- Typst `lang`/`region` set per language so hyphenation and CJK line breaking behave.

---

## 11. Theming and branding **(user agreed to the approach)**

The upstream project is white-label. A theme is a directory:

```
themes/default/
  theme.toml        # colours, font family names, product display name, URL
  cover.typ         # optional cover override
  logo.png|svg      # optional
```

- Cover shows the **customer's** organisation name and logo from the run configuration (`report.organization`, `report.logo`).
- The **theme's** logo is the product's or the company's. It appears small in the footer beside "Generated by <product name> <version>" – provenance an auditor appreciates – and nowhere else by default **(call)**. A `cover.typ` override receives both logos and may place them as it likes.
- The theme contract (`theme.toml` keys, the data `cover.typ` receives) is versioned; company-edition repositories depend on it with no code of their own, so it changes only with a major version **(call)**.
- A company edition is a separate tiny repository: `FROM <upstream image>:<version>`, copy its theme, set defaults. No code. Anything the company edition would need in code is a missing upstream setting.
- The existing "SUSE Security" wording, SUSE green and SUSE base image are customer-specific and are removed from this repository.

Licence inventory: `LICENSE` (Apache-2.0), `THIRD_PARTY_NOTICES.md` listing Typst (Apache-2.0), Inter, Noto Sans TC, Maple Mono (OFL-1.1), Open Color (MIT), and Rust crates (generated, e.g. with `cargo about`) **(builder: tool choice)**.

---

## 12. Outputs **(user: filesystem and HTTP first)**

- **`filesystem`**: `path`; file name pattern `<scope>-<source>-<YYYY-MM-DD>.pdf` **(call)**; overwrite on rerun the same day (stateless by design).
- **`http`**: `url`, `method` (PUT or POST), `headers` (values may reference environment variables as `${NAME}`), `mode: raw | multipart` **(call: both supported; raw sends the bytes with `Content-Type` and `Content-Disposition`, multipart sends a form field `file`)**, `ca_file`, `timeout`, retries with backoff **(builder: 3 attempts)**. Secrets in headers are never logged.
- Optional `json: true` emits the normalised model as `<same name>.json` to every sink **(call)**.

---

## 13. Configuration and operation

- One YAML file, default path `/etc/report/config.yaml`, overridable with `--config`. Sections: `source`, `report`, `output`, `theme`. Secrets are referenced by environment-variable name (`password_env`) or `${VAR}` placeholders, never inline **(call)**.
- CLI: `<bin> run [--config …]`, `<bin> check` (loads config, authenticates to the source, lists the scope, renders nothing) **(call)**, `<bin> version`.
- Exit codes **(call)**: 0 report produced (even if some images failed to fetch – they are listed in the appendix); 2 configuration error; 3 source unreachable or authentication failed; 4 render failure; 5 all sinks failed.
- Logs: structured, to stderr, no secrets.
- Container: runs as non-root; reads config and CA from mounts; writes to `/output` by default. Published to GHCR with semantic version tags; `podman save`/`load` is the air-gap transfer path, documented.
- Kubernetes: a CronJob example with ConfigMap + Secret + PVC in `deploy/`; resource request 1 CPU / 1 GiB, limit 3 GiB, with the 40 MB-per-1 000-rows rule of thumb in the docs.

---

## 14. Repository layout (proposed) **(builder may adjust)**

```
Cargo.toml                  single crate; name = product name (one constant, easy to rename)
src/
  main.rs, cli.rs, config.rs
  model/                    normalised types + serde
  severity.rs               section 7, with table-driven tests
  source/{mod,harbor,neuvector_api,neuvector_file,trivy_file}.rs
  sink/{mod,filesystem,http}.rs
  render/                   Typst world, font loading, template data
templates/                  *.typ, standalone-compilable with `typst watch` and a sample JSON for design work
strings/{zh-TW,en}.json
themes/default/
assets/fonts/               the static font files listed in section 9
fixtures/                   captured, sanitised scanner responses and files (see 15)
deploy/                     CronJob, Job, podman examples
docs/
```

The template must stay compilable with the Typst CLI of the same pinned version, reading the same JSON the binary feeds it, so that design iteration uses `typst watch` and production uses the embedded engine with no divergence.

---

## 15. Testing

- Parsers: unit tests against captured responses from a lab (Harbor 2.15.4/Trivy 0.75.0, NeuVector 5.6.4, 11 images) plus Trivy CLI output and NeuVector scanner output for the same images. Captures are sanitised (no credentials; hostnames replaced) and committed under `fixtures/`.
  - **State of the captures:** the Harbor and NeuVector API responses exist (captured 2026-11-06, held outside the repo by the maintainer). The Trivy CLI and NeuVector standalone-scanner files do **not** exist yet. Capturing them against the same 11 images, sanitising, and committing all four sets under `fixtures/` is the **first task of the plan**; the lab is still available for it.
  - The Typst benchmark that established the three rendering settings in section 4 used the CLI (`--no-pdf-tags`, `-j 1`, a `text(font: …)` call instead of `raw`). A short spike mapping these onto the pinned crate API (`typst-pdf` options, rayon thread-pool size) is the second task.
- Severity: table-driven tests for every branch of section 7, including the 0/null/absent variants and Unrated.
- Rendering: deterministic given a fixed "generated at" timestamp; golden tests compare extracted text of key pages and assert page counts, plus one large synthetic input (≥ 30 000 rows) asserting a time and memory budget in CI **(builder: thresholds)**.
- Sinks: filesystem on a temp dir; HTTP against a local mock server, including retry and multipart.
- End-to-end: `check` and `run` against fixture-backed mock HTTP servers for both APIs.

---

## 16. Known limitations (stated in the report's appendix)

- Severity is recomputed; counts can differ from the scanner's UI. The original label is shown for reconciliation.
- Scores differ between scanners for the same CVE; reports from different scanners are not comparable number-for-number.
- NeuVector fills a score for some old vulnerabilities; these cannot be distinguished.
- Coverage is the scanner's: a scanner can miss findings while reporting success.
- Scope is "images stored in the registry", not workloads running in a cluster.
- No history: comparisons between runs are out of scope.

---

## 17. Left to the builder

- Exact Rust crate choices (HTTP client with rustls and custom roots, YAML, CLI, logging, multipart).
- Internal module boundaries beyond section 14; error types.
- Remediation ranking formula and the base-image end-of-life heuristic.
- Description truncation length; column widths; page-break tuning.
- Retry counts, timeouts, CI performance thresholds.
- Whether fonts are embedded in the binary or shipped as files in the image.
- Migration: delete the Python implementation on the first commit of the rewrite or keep it on a branch until file-mode parity – either is fine.

### Release shape **(user)**

Version 1 is a single release with all four sources; nobody is waiting on a particular source, so the plan orders work by shared code (fixtures first; the model and severity rule; Harbor and Trivy-file sources, which share the CVSS source-map logic; NeuVector API and file sources, which share one parser; rendering; sinks) rather than by customer. Quality over speed.

## 18. Open

- **Product name** – the user is choosing one. Until then the working name is `judex` (chosen 2026-11-07 as a placeholder, not a decision); the crate name, the binary name and the `PRODUCT_NAME` constant are the only places it appears in code; the [rename checklist in docs/release.md](../../release.md#rename-procedure) lists every naming surface, including the container image, deployment examples and tests.

Rename checklist and guard: [release procedure](../../release.md#rename-procedure).
