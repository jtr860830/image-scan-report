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
`tests/data/`.

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
| `src/cli.rs` | clap commands: version, check and run |
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
| `src/pipeline.rs` | Source construction, report assembly, JSON generation, storage and exit codes |

The pipeline serialises the normalised model directly; derived views are available
for later rendering. File sources and filesystem JSON output work now. PDF,
API sources and HTTP upload belong to later plans. Consult the
[design specification](superpowers/specs/2026-11-07-product-redesign-design.md)
and [core pipeline plan](superpowers/plans/2026-11-07-core-pipeline.md) for scope.

## Renaming

The product name lives in three places: `Cargo.toml` `[package] name`, the binary
name, and `PRODUCT_NAME` in `src/main.rs`. Cargo currently derives the binary name
from the package name (there is no explicit `[[bin]]` override). Renaming judex
touches exactly these three naming points, plus the literal in `tests/cli.rs` and
README mentions. Keep the CLI's version text and executable assertions aligned.
