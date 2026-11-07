# judex

judex turns existing container-image vulnerability scans into audit reports.
It normalises Trivy and NeuVector scanner JSON into a shared model without scanning images itself.

This milestone supports file sources and JSON output to the filesystem. PDF,
Harbor and NeuVector API sources, and HTTP upload are in progress; see the
[product specification](docs/superpowers/specs/2026-11-07-product-redesign-design.md)
and [core pipeline plan](docs/superpowers/plans/2026-11-07-core-pipeline.md).

## Quick start

Install the Rust toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml),
then run these commands from the repository root:

```sh
cargo run -- version
cargo run -- check --config examples/config-trivy-files.yaml
cargo run -- run --config examples/config-trivy-files.yaml
```

For an environment with dependencies already cached and no network, add
`--offline` after `cargo run` in each command.
The [runnable example](examples/config-trivy-files.yaml) reads `./fixtures/trivy`
and writes JSON to `./out`, creating the directory if needed. Relative paths
resolve from the working directory, not the configuration file's directory.
See [fixture provenance](fixtures/README.md) for how the scanner inputs were captured.

`version` prints `judex 0.1.0`. `check` fetches and parses the source and prints
`Trivy (files): ./fixtures/trivy: 11 images, 4368 findings`; it does not write artifacts or validate
output availability. `run` prints `Report: 11 images, 4368 findings`, followed by
one destination and filename per stored artifact. Counts depend on the inputs.
The example produces `out/trivy-trivy-files-YYYY-MM-DD.json`, using the UTC run
date. In general filenames are `<slug(scope)>-<source-type>-<YYYY-MM-DD>.json`;
file-source scope is the input directory's final component. Repeating a run on
the same date atomically overwrites the same filename.

## Configuration reference

Configuration is YAML with required `source`, `report`, and `output` sections.
Unknown keys are rejected. “Required” below means there is no default;
optional fields default to `null`. `output` must contain at least one destination,
`report.organization` must be nonblank, and at least one report format must be enabled.

### Source

| Key | Type / values | Default |
| --- | --- | --- |
| `source.type` | `trivy-files`, `neuvector-files`, `harbor`, `neuvector` | Required |
| `source.path` | Directory path; required for either file source | Required |
| `source.url` | String; Harbor or NeuVector API URL | Required for API sources |
| `source.project` | Optional string; Harbor only | `null` |
| `source.registry` | String; NeuVector API only | Required for `neuvector` |
| `source.username` | String; either API source | Required for API sources |
| `source.password_env` | String naming the password environment variable; either API source | Required for API sources |
| `source.ca_file` | Optional certificate file path; either API source | `null` |

File sources recursively discover JSON files. Invalid reports are skipped with a
warning; no usable reports is a source failure. For NeuVector standalone scanner
files, use `neuvector-files` and a directory such as `./fixtures/neuvector-scanner`.

`harbor` and `neuvector` are accepted by the configuration parser but rejected by
both `check` and `run` with “arrives in a later release” in this build.
`password_env` names a variable (for example `HARBOR_PASSWORD`), not the password
itself. Passwords are read when an API source connects; this build never connects.
The existing [Harbor example](examples/config.yaml) describes future functionality
and cannot run in this milestone.

### Report

| Key | Type / values | Default |
| --- | --- | --- |
| `report.language` | `en` or `zh-TW` | Required |
| `report.organization` | Nonblank string | Required |
| `report.logo` | Optional file path | `null` |
| `report.stale_after_days` | Unsigned 32-bit integer | `30` |
| `report.json` | Boolean | `false` |
| `report.pdf` | Boolean | `true` |

Set `json: true` and `pdf: false` for this build. Enabling PDF currently emits a
warning and produces no PDF; a PDF-only run fails with exit code 4 and writes no
artifacts. Logo and stale-age settings are reserved for rendering and derived
views; they do not change the JSON report. The configuration's `organization`
is serialised as `organisation` in the normalised JSON model.

### Output

`output` is a list of tagged destinations, each with its own `type`.

| Key in each `output[]` entry | Type / values | Default |
| --- | --- | --- |
| `type` | `filesystem` or `http` | Required |
| `path` | Directory path; filesystem only | Required for `filesystem` |
| `url` | String; HTTP only | Required for `http` |
| `method` | String, `PUT` or `POST` (case insensitive); HTTP only | `PUT` |
| `headers` | Map of string header names to string values; HTTP only | `{}` |
| `mode` | `raw` or `multipart`; HTTP only | `raw` |
| `ca_file` | Optional certificate file path; HTTP only | `null` |
| `timeout_secs` | Unsigned 64-bit integer; HTTP only | `30` |

HTTP outputs are accepted by the parser but rejected by both `check` and `run`
with “arrives in a later release”. Both validate outputs before fetching the source.
Header values expand `${VAR}` placeholders when configuration is loaded; an unset
variable fails with its name. Valid names use ASCII letters or underscore first,
then letters, digits or underscores. Expansion is one pass, malformed placeholders
stay literal, and replacement values are not expanded again. Other configuration
strings do not receive this substitution. Keep credentials in environment variables.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (including partial output success) |
| `2` | Configuration or CLI argument error; includes unsupported sources/outputs |
| `3` | Source failure, including no usable input reports |
| `4` | Rendering / JSON serialisation failure |
| `5` | Every artifact write failed |

Errors are printed to stderr as `error: ...`; warnings also go to stderr.
A run with some successful writes returns `0` and reports failed sinks on stderr.
These codes indicate pipeline outcomes, not vulnerability severity thresholds.

## Development and licence

See [development notes](docs/development.md) for checks, snapshots and module layout.
Licensed under [Apache-2.0](LICENSE).
