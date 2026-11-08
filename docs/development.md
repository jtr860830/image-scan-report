# Development

Use the Rust toolchain pinned in [rust-toolchain.toml](../rust-toolchain.toml):
Rust 1.99.1 with rustfmt and clippy, edition 2024. Run commands from the repository
root. Cargo needs cached dependencies for offline operation; add `--offline` to
Cargo commands in a disconnected environment.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests cover configuration, scanner parsing, severity classification, derived
views, filesystem output and CLI/pipeline behavior. Real scanner inputs and their
capture procedure are documented in [fixtures/README.md](../fixtures/README.md).
Do not hand-edit captured fixtures; recapture them. Synthetic edge cases live in
`tests/data/`. No real failed-scan capture exists yet.

## Third-party notices

Install the pinned generator and regenerate notices from the repository root:

```sh
cargo install cargo-about --version 0.9.3 --locked --features cli
cargo about generate --config about.toml about.hbs -o THIRD_PARTY_NOTICES.md
```

A dependency bump requires running
`cargo about generate --config about.toml about.hbs -o THIRD_PARTY_NOTICES.md`
(the regeneration command reported by CI) and committing the result. CI generates
its comparison with the exact command
`cargo about generate --config about.toml about.hbs -o /tmp/THIRD_PARTY_NOTICES.md`.

Commit the generated `THIRD_PARTY_NOTICES.md` whenever dependencies, `about.toml`,
or `about.hbs` change. The CI `notices` job regenerates it and fails when the
committed file is stale. Rust licence notices come from cargo-about; the font
attributions and typesetting note are static text in `about.hbs`. Update the
font section there when changing the bundled fonts.

## Snapshots

The `insta` development dependency checks the normalised report JSON shape in
`tests/model_snapshot.rs` against `tests/snapshots/`. Inspect snapshot diffs when
changing the model. To accept an intentional update:

```sh
INSTA_UPDATE=always cargo test --test model_snapshot
```

Review the resulting snapshot diff and rerun the tests. The optional `cargo insta`
CLI provides interactive review (`cargo insta review`) when installed separately;
it is not required for the environment-variable workflow above and is not bundled
as a repository tool.

## Module map

| Location | Responsibility |
| --- | --- |
| `src/lib.rs` | Library module exports |
| `src/main.rs` | Entry point, logging, summaries and exit handling |
| `src/cli.rs` | clap commands: version, check, run and render-data |
| `src/config.rs` | YAML schema, validation, defaults and environment resolution |
| `src/model/` | Normalised reports, images, findings and severity enum |
| `src/severity.rs` | Shared CVSS score selection and severity classification |
| `src/source/mod.rs` | ScanSource trait and source/parse errors |
| `src/source/http.rs` | Shared HTTP transport, TLS, retries and URL redaction |
| `src/source/harbor/` | Harbor API fetching and report mapping |
| `src/source/neuvector_api.rs` | NeuVector controller API source |
| `src/source/files.rs` | Recursive file discovery, timestamps and deduplication |
| `src/source/trivy_file.rs` | Trivy JSON parsing and file source |
| `src/source/neuvector_file.rs` | NeuVector standalone JSON mapping and file source |
| `src/source/neuvector/mod.rs`, `src/source/neuvector/report.rs` | NeuVector scanner report deserialisation types |
| `src/views.rs` | Pure derived counts, vulnerability/remediation groups and image summaries |
| `src/sink/mod.rs` | Artifact, ReportSink trait and sink construction |
| `src/sink/filesystem.rs` | Directory creation and atomic file replacement |
| `src/sink/http.rs` | Raw and multipart HTTP artifact uploads |
| `src/render/` | Embedded Typst engine, fonts, theme, strings and render model |
| `src/naming.rs` | Scope slugs and dated artifact names |
| `src/pipeline.rs` | Source construction, report assembly, PDF/JSON generation, render data, storage and exit codes |

The pipeline writes PDF through the embedded Typst renderer and serialises the
normalised model directly for JSON. API sources use the shared HTTP transport; the HTTP sink uploads artifacts via PUT or POST in raw or multipart mode,
with configurable headers, TLS settings and retries.

## Rendering and templates

`templates/report.typ` is the entry point, `templates/lib/` contains shared
formatting and layout helpers, and `templates/parts/` contains report chapters.
Use the [design iteration guide](design/README.md) with Typst CLI 0.15.1 and bundled fonts.

`src/render/strings.rs` defines the canonical string keys and is the source of truth.
To add a locale, add a complete translation JSON file under `strings/`,
extend `model::Language` and the string loader, and update language mapping in
`render::model`. Run string completeness and rendering tests for the new locale.
Visual preview PNGs live under `target/visual/`.

Rendering tests use the reduced fixture helper in `tests/support/data.rs` to
keep layout checks fast while retaining real scanner data. PDF pipeline and binary integration tests copy only alpine-3.12.json,
nginx-1.21.0.json and busybox-1.37.json into temporary directories using
`tests/support/reduced_fixtures.rs`. JSON-only tests still cover the complete inputs. Do not reduce or modify captured files in `fixtures/`.

## Renaming

Follow the [release and rename procedure](release.md). The library crate stays
named `image_scan_report` across product renames.

## Golden and performance regression checks

Run `cargo test --offline --test golden` for both languages. The three-image
fixture input keeps debug rendering fast. Snapshots cover normalized extracted
text from pages 1, 2, 3 and the last page, replacing the generated date with
`<DATE>`, plus both page counts (currently 7 each). Review intentional changes
with `INSTA_UPDATE=always cargo test --offline --test golden`, then rerun without
that variable. `cargo test --offline --test previews` regenerates all chapter PNGs at 110 ppi
under `target/visual/` for visual inspection; text snapshots do not detect every visual layout change.

Run the opt-in release budgets with:

```sh
/usr/bin/time -l cargo test --offline --release --test perf -- --ignored --nocapture --test-threads=1
```

The tests replicate all 11 fixture images with unique reference suffixes until
at least 30,000 or 50,000 findings are present. They time the complete zh-TW
`render::render_pdf` call, enforce 90/150 seconds respectively, and require more
than 400 pages. PDF page counting is outside the timed interval. The CI perf job
runs on manual dispatch and Mondays at 03:00 UTC, separately from push checks.
Measured on an Apple-silicon laptop with the release binary already
compiled, using a single test run:

```sh
/usr/bin/time -l cargo test --offline --release --test perf -- --ignored --nocapture --test-threads=1 fifty
```

### Rendering performance (measured 2026-11-08, release build, Apple Silicon, median of three)

| Findings | Pages | Wall time | Peak RSS |
|---|---|---|---|
| 30,576 | 2,227 | 8.4 s | 2.89 GB |
| 52,416 | 3,728 | 11.8 s | 4.39 GB |

Measured with the default release profile. The release profile shipped since
plan 4 (`lto = "thin"`, `codegen-units = 1`, `strip = true`) renders the same
52,416 findings in **10.9 s** with a **4.13 GB** peak — about 7 % faster and 6 %
smaller; the rule of thumb below keeps the more conservative numbers.

Rule of thumb from the two points: **about 0.8 GB plus 70 MB per 1,000 findings**
(the earlier "100 MB per 1,000" was an extrapolation from one point). A 20,000-finding
report therefore peaks near 2.2 GB; the Kubernetes examples request 1 GiB and limit
4 GiB, which covers roughly 45,000 findings. The CI perf job keeps a generous
150 s budget because GitHub runners are several times slower than this machine.

Four template experiments from the plan-2 deferred list were measured against this
baseline with the same protocol; none met the keep rule (≥ 5 % time or memory,
golden text and preview PNGs unchanged), so the templates are as plan 2 left them:

| Experiment | Time | Peak RSS | Output | Verdict |
|---|---|---|---|---|
| A — one table-level `stroke` closure instead of six `table.cell` wrappers per row | +18 % | ±0 | unchanged | rejected (the per-cell closure is dearer than the wrappers) |
| B — flat chip with a ● glyph instead of a nested `circle` | within noise | ±0 | ● enters the extracted text; 9 previews differ | rejected |
| C + D — `hyphenate: false` once per table; zero-width breaks only in identifiers over 20 characters | ±0 | −3 % | 3,300 pages instead of 3,728 and a changed golden text; previews unchanged | rejected under the rule — the page drop means lines wrap differently in the synthetic data, which the 11-image previews cannot show, so it is unsafe to take blind |

Peak RSS in the table comes from `/usr/bin/time -l`; the `peak_rss_mb=` line the perf
test prints is authoritative on Linux (`VmHWM`) but only a point sample on macOS.

The complete 11-image, 4,368-finding English report produced by
`cargo run --offline -- run --config examples/config-trivy-files.yaml` decreased
from the previous layout's 705 pages to 429 pages. Descriptions are capped at
600 characters and rendered only for Critical/High findings; remediation uses
30 cards followed by a compact table.

## API mock tests

API integration tests use httpmock with fixture-serving helpers in
`tests/support/harbor_mock.rs` and `tests/support/neuvector_mock.rs`. Point the
pipeline configuration or binary at the mock server and supply test credentials
through the environment. The Harbor subset helper serves three repositories
and one artifact each to keep PDF tests small. Use the captured fixture files without editing them; see
[fixture capture instructions](../fixtures/README.md).

Mock servers bind loopback sockets. These tests, including the closed-port
connection test, must run where loopback binding is permitted (some sandboxes deny it).
Compile them with `cargo test --offline --no-run` and run socket-free tests
where loopback binding is unavailable.

## Live verification

The API sources were run against a real Harbor and NeuVector before release.
The lab (two VMs' worth of k3s on one node) is private; the numbers below are
the record of what the release build did there. Re-run this table whenever a
source changes or a scanner is upgraded.

| Item | Value |
|---|---|
| Date | 2026-11-08 |
| Build | commit `1d66eea`, `cargo build --release --locked` in `rust:1.99-bookworm` (x86_64) |
| Harbor | 2.15.4 with Trivy v0.75.0, plain `http://` NodePort, project `demo` |
| Harbor result | `check` and `run` in both languages: 20 images (12 single-arch across 11 repositories — `demo/busybox` and `demo/nested/busybox` share one digest and both stay listed — plus 8 platform children of one multi-arch index), 4 383 findings; PDF 435 pages (zh-TW) / 434 pages (en), 1.8 MB; `run` 90 s wall (≈ 65 s fetching sequentially, ≈ 25 s rendering), peak RSS 860 MB. An earlier build of this branch reported 19 here because rows were deduplicated by digest; that is the bug the shared-digest regression tests now pin |
| NeuVector | 5.6.4 controller, self-signed certificate whose only SAN is `neuvector`, registry configuration `harbor-lab` |
| NeuVector with `insecure_skip_verify: true` | OK by IP; the warning line is printed once; 12 images, 3 560 findings, 348 pages, 18 s, RSS 716 MB |
| NeuVector with `ca_file` | OK when addressed as `https://neuvector:<port>` (hosts entry); by IP the handshake fails with exit 3 and `certificate not valid for name "…"; certificate is only valid for DnsName("neuvector")` — the expected behaviour, and the message tells the operator what to fix |
| Schema drift | none; every captured fixture shape matched the live responses |

Notes: NeuVector reports a multi-arch index as a single image (the amd64 child),
Harbor reports one row per platform child, so the same registry yields 12 and
20 images respectively. With `RUST_LOG=trace` neither run printed the Basic
credentials or the NeuVector token. The sequential Harbor fetch is the slow part of a run;
concurrent requests are a later optimisation.

## Code style

The project follows [Google's Rust Style Guide](https://google.github.io/styleguide/rustguide.html),
which defers to the official [Rust Style Guide](https://doc.rust-lang.org/style-guide/)
and [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).

- Use stable rustfmt options: edition 2024, width 100, and Unix newlines.
- Apply the nightly-only options by hand: `imports_granularity = "Module"`,
  `hex_literal_case = "Lower"`, and `format_macro_matchers = true`.
- Document public APIs; `missing_docs` is enabled and warnings fail Clippy checks.
- Name fallible constructors `try_new`; keep infallible constructors named `new`.
- Import items from one module per `use` statement. Avoid glob imports except inline
  test `use super::*` and non-leaf module re-exports.
- Scope traits to the function that needs them when they have only one use site,
  and qualify free-function calls with their module.
- Prefer `expect` with context over `unwrap`, use pattern matching for optional
  values, and document panic cases.
- Mark error types and pure result-producing helpers `#[must_use]`.
