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
| `src/source/files.rs` | Recursive file discovery, timestamps and deduplication |
| `src/source/trivy_file.rs` | Trivy JSON parsing and file source |
| `src/source/neuvector_file.rs` | NeuVector standalone JSON mapping and file source |
| `src/source/neuvector/mod.rs`, `src/source/neuvector/report.rs` | NeuVector scanner report deserialisation types |
| `src/views.rs` | Pure derived counts, vulnerability/remediation groups and image summaries |
| `src/sink/mod.rs` | Artifact, ReportSink trait and sink construction |
| `src/sink/filesystem.rs` | Directory creation and atomic file replacement |
| `src/naming.rs` | Scope slugs and dated artifact names |
| `src/pipeline.rs` | Source construction, report assembly, PDF/JSON generation, render data, storage and exit codes |

The pipeline writes PDF through the embedded Typst renderer and serialises the
normalised model directly for JSON. API sources and HTTP upload remain future work.

## Rendering and templates

`templates/report.typ` is the entry point, `templates/lib/` contains shared
formatting and layout helpers, and `templates/parts/` contains report chapters.
Use the README's design iteration commands with Typst CLI 0.15.1 and bundled fonts.

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

The product name lives in three places: `Cargo.toml` `[package] name`, the binary
name, and `PRODUCT_NAME` in `src/main.rs`. Cargo currently derives the binary name
from the package name (there is no explicit `[[bin]]` override). Renaming judex
touches exactly these three naming points, plus the literal in `tests/cli.rs` and
README prose. The library crate stays named `image_scan_report` across product renames.
Keep the CLI's version text and executable assertions aligned.

## Golden and performance regression checks

Run `cargo test --offline --test golden` for both languages. The three-image
fixture input keeps debug rendering fast. Snapshots cover normalized extracted
text from pages 1, 2, 3 and the last page, replacing the generated date with
`<DATE>`, plus both page counts (currently 7 each). Review intentional changes
with `INSTA_UPDATE=always cargo test --offline --test golden`, then rerun without
that variable. Existing chapter preview tests write PNGs under `target/visual/`
for visual inspection; text snapshots do not detect every visual layout change.

Run the opt-in release budgets with:

```sh
/usr/bin/time -l cargo test --offline --release --test perf -- --ignored --nocapture
```

The tests replicate all 11 fixture images with unique reference suffixes until
at least 30,000 or 50,000 findings are present. They time the complete zh-TW
`render::render_pdf` call, enforce 90/150 seconds respectively, and require more
than 400 pages. PDF page counting is outside the timed interval. The CI perf job
runs on manual dispatch and Mondays at 03:00 UTC, separately from push checks.
Peak RSS from the command includes compilation and both test processes.

Measured on macOS on 2026-11-08 (two tests run concurrently by the default Rust
test harness):

| Target | Actual findings | First run seconds | RSS rerun seconds | Pages |
| --- | ---: | ---: | ---: | ---: |
| 30k | 30,576 | 30.957 | 30.065 | 2,212 |
| 50k | 52,416 | 33.063 | 32.201 | 3,703 |

Both runs passed the unchanged budgets. The requested `/usr/bin/time -l` command
reported 152.90 seconds including a 118-second release build, but sandbox policy
denied `sysctl kern.clockrate`, preventing its RSS output. A second invocation
wrapped in Python `resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss`
measured peak child RSS of 7,586,463,744 bytes (7.07 GiB). This is a whole-command
peak, not per-test memory; CI memory usage can differ.

The complete 11-image, 4,368-finding English report produced by
`cargo run --offline -- run --config examples/config-trivy-files.yaml` decreased
from the controller's 705-page baseline to 429 pages. Descriptions are capped at
600 characters and rendered only for Critical/High findings; remediation uses
30 cards followed by a compact table. To recount the generated PDF:

```sh
REPORT_PDF=out/trivy-trivy-files-2026-11-07.pdf cargo test --offline --test golden full_fixture_page_count -- --ignored --nocapture
```

Use the actual generated filename for `REPORT_PDF`.
