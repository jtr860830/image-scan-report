# Judex

[![CI](https://github.com/jtr860830/judex/actions/workflows/ci.yml/badge.svg)](https://github.com/jtr860830/judex/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/jtr860830/judex?include_prereleases)](https://github.com/jtr860830/judex/releases)

judex turns existing container-image vulnerability scans into audit reports.
It normalises Trivy and NeuVector scanner JSON and results from the Harbor and NeuVector APIs into a shared model without scanning images itself.

Sources: Trivy and NeuVector scanner files, the Harbor API and the NeuVector controller API.
Outputs: PDF and JSON to filesystem directories and HTTP endpoints.

## Sample reports

Two reports rendered by judex 0.1.0 with the default theme from four of the Trivy
fixtures in `tests/fixtures/trivy/` (alpine 3.22, busybox 1.37, nginx 1.21.0 and the
log4shell demo application; 4 images, 828 findings):

- [English](docs/samples/sample-report-en.pdf)
- [繁體中文](docs/samples/sample-report-zh-TW.pdf)

To regenerate them, copy those four JSON files into a directory named `demo`, point a
`trivy-files` source at it, set `report.language` to `en` or `zh-TW`, and run
`judex run --config <that config>`.

## Install

Download the native Linux tarball for x86_64 or aarch64 and `SHA256SUMS` from
[releases](https://github.com/jtr860830/judex/releases). Verify it with
`sha256sum -c SHA256SUMS --ignore-missing`, extract it, and put `judex` on your PATH.
The container image is `ghcr.io/jtr860830/judex:<ver>`. See the
[release guide](docs/release.md) for assets and air-gap bundles.

Native binaries require glibc >= 2.39 (built on ubuntu-24.04). Use the container
image on hosts with older glibc.

### First run from the tarball

```sh
tar -xzf judex-vX.Y.Z-<target>.tar.gz
cd judex-vX.Y.Z-<target>
cp examples/config.yaml ./config.yaml
# Edit config.yaml for your source, credentials and output.
./judex check --config ./config.yaml
./judex run --config ./config.yaml
```

Use `RUST_LOG=debug` for diagnostics; even `trace` never prints credentials.

### Container installation

Use `ghcr.io/jtr860830/judex:<ver>` with a release tag, a config whose filesystem
output points to `/var/lib/judex/reports`, and a writable `./out` directory:

```sh
podman run --rm --read-only --security-opt no-new-privileges -v ./config.yaml:/etc/judex/config.yaml:ro,Z -v ./out:/var/lib/judex/reports:Z -e HARBOR_PASSWORD ghcr.io/jtr860830/judex:<ver>
```

For air-gapped hosts, transfer the image with `podman save` and `podman load`.
See [container installation](docs/container.md) for the wrapper script, mounts,
permissions, secrets, local builds, and air-gap commands.

See [container sizing](docs/container.md#resources).

## Kubernetes

See the [Kubernetes deployment examples](deploy/k8s/README.md) for a weekly
CronJob, a one-off Job, secrets, CA certificates, and report retrieval.

## Quick start

Install the Rust toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml),
then run these commands from the repository root:

```sh
cargo run -- version
cargo run -- check --config deploy/examples/config-trivy-files.yaml
cargo run -- run --config deploy/examples/config-trivy-files.yaml
```

For an environment with dependencies already cached and no network, add
`--offline` after `cargo run` in each command.
The [runnable example](deploy/examples/config-trivy-files.yaml) reads `./tests/fixtures/trivy`
and writes PDF and JSON to `./out`, creating the directory if needed. Relative paths
resolve from the working directory, not the configuration file's directory.
See [fixture provenance](tests/fixtures/README.md) for how the scanner inputs were captured.

`--version` (or `-V`) and `version` print `judex <ver>`. `check` fetches and parses the source and prints
`Trivy (files): ./tests/fixtures/trivy: 11 images (11 scanned, 0 failed, 0 not scanned), 4368 findings; product: judex <ver>; theme: default`; it validates output configuration and the theme without
writing artifacts. `run` prints `Report: 11 images, 4368 findings`, followed by
one destination and filename per stored artifact. Counts depend on the inputs.
The example produces `out/trivy-trivy-files-YYYY-MM-DD.pdf` and a matching JSON file, using the UTC run
date. In general filenames are `<slug(scope)>-<source-type>-<YYYY-MM-DD>.<pdf|json>`;
file-source scope is the input directory's final component. Repeating a run on
the same date atomically overwrites the same filename.

## Configuration reference

When `--config` is omitted for `run`, `check`, or `render-data`, a non-empty
`JUDEX_CONFIG` is authoritative and used as-is; a missing file is an error.
An empty value is ignored. Otherwise, use the first existing file in this order:
`$XDG_CONFIG_HOME/judex/config.yaml`, `/etc/judex/config.yaml`.
Use XDG only when `XDG_CONFIG_HOME` is a non-empty absolute path; otherwise use
`$HOME/.config/judex/config.yaml`. Skip that fallback when `HOME` is unset or
empty. The distroless container sets `HOME=/home/nonroot`, so it searches
`/home/nonroot/.config/judex/config.yaml`, which is normally absent.
If no file exists, exit 2 and list every candidate; if the pre-0.2.0
configuration still exists, include a migration hint.

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
| `source.ca_file` | Optional PEM CA bundle path; either API source | `null` |
| `source.insecure_skip_verify` | Boolean; either API source; disables TLS verification | `false` |
| `source.timeout_secs` | Positive unsigned integer; request timeout in seconds | `30` |

File sources recursively discover JSON files. Invalid reports are skipped with a
warning; no usable reports is a source failure. For NeuVector standalone scanner
files, use `neuvector-files` and a directory such as `./tests/fixtures/neuvector-scanner`.

Start from the [Harbor example](deploy/examples/config.yaml) or the
[NeuVector example](deploy/examples/config-neuvector.yaml): they are templates, so
replace the URL, credentials and file paths (CA bundle, logo) with yours, then
run `judex check --config <file>` followed by `judex run --config <file>`.
`url` must use HTTP or HTTPS. `password_env` names an environment variable,
not the password itself; a missing variable fails with exit code 2.
Use a least-privilege read-only account: a read-only project member in Harbor (Guest is sufficient; Limited Guest should work but was not verified),
or a reader role in NeuVector.

Harbor scope is `<authority>/<project>`; omit `project` to include all accessible
projects (scope `<authority> (all projects)`). NeuVector scope is
`<authority>/<registry>`; `registry` is the configured scanner registry name,
not a registry endpoint URL. Harbor multi-arch indexes produce one row per
platform child, such as `repo:tag (linux/arm64)`; attestation children are skipped.
Should two children of one index share a platform string, the second is written
`repo:tag (linux/arm64, <12-digit digest>)` so the rows stay distinct.
Authentication/authorisation failures (HTTP 401/403) abort the whole source with
exit 3; any other per-artifact failure becomes a Failed row. Connection or discovery failures still fail the source.

Mount the appliance's exported CA certificate as a PEM bundle and set `ca_file`
to its path. Invalid or unreadable CA files fail with exit code 2. As a last
resort for appliances whose CA cannot be exported, remove `ca_file` and set
`insecure_skip_verify: true`. This disables certificate verification and prints a warning with the redacted URL: `source https://host/path: TLS certificate verification is disabled` once per check/run.
The two settings cannot be combined.

The default trust store is the bundled Mozilla root set. The OS store is not
consulted (the image ships no system certificates); `ca_file` replaces the bundled
roots. 3xx redirects are not followed: fix the configured URL to the final endpoint.
A path prefix in `url`, such as `https://host/harbor`, is supported.
`timeout_secs` covers the whole response download.

Across API sources, NeuVector rows have no platform. Harbor `os` is the image OS
from the manifest; NeuVector `os` is the detected distro. Harbor sizes are compressed,
while NeuVector sizes are uncompressed. NeuVector's scanner version is its CVE
database version.

Harbor scan states:

| Scanner state | Report state |
| --- | --- |
| `Success` | Ok |
| `Error` or unknown state | Failed |
| `Running`, `Pending`, `Scheduled` | NotScanned (scan in progress) |
| Missing or empty | NotScanned |

A Success scan whose vulnerability report is missing or has no `vulnerabilities` field is listed as Failed (vulnerability report missing); a report with an empty list is a clean image. If the report request itself fails, the row is Failed with that HTTP error instead.

NeuVector scan states (case insensitive):

| Scanner state / result | Report state |
| --- | --- |
| `finished` / `succeeded` | Ok |
| `finished` / any other result | Failed |
| `scheduled`, `scanning` | NotScanned (scan in progress) |
| Missing or empty | NotScanned |
| Any other state | Failed |

### Report

| Key | Type / values | Default |
| --- | --- | --- |
| `report.language` | `en` or `zh-TW` | Required |
| `report.organization` | Nonblank string | Required |
| `report.logo` | Optional file path | `null` |
| `report.stale_after_days` | Unsigned 32-bit integer | `30` |
| `report.describe_severities` | List of lowercase severities: `critical`, `high`, `medium`, `low`, `unrated`; `[]` disables descriptions | `[critical, high]` |
| `report.description_chars` | Description character limit (at least 50), followed by an ellipsis when truncated | `600` |
| `report.remediation_cards` | Number of remediation groups shown as cards; remaining groups use a table; `0` means table only | `30` |
| `report.min_severity` | `critical`, `high`, `medium` or `low`; omit lower bands from inventory, remediation and per-image tables; always keep Unrated | `null` (no floor) |
| `report.image_detail` | `full` or `counts`; counts shows only each image’s metadata card and severity counts | `full` |
| `report.max_table_rows` | Positive integer; first N rows of the inventory and each image table after sorting, most severe first | `null` (no cap) |
| `report.json` | Boolean | `false` |
| `report.pdf` | Boolean | `true` |

PDF is enabled by default; enable `json: true` to also write the normalised report.
The configuration's `organization` is serialised as `organisation` in JSON.
`stale_after_days` controls the appendix's stale-scan threshold.

**Large reports.** Prefer per-scope reports first, then use the content settings
above to reduce detail. See [container resources](docs/container.md#resources)
for sizing. The summary’s tiles, bar, facts and rankings, per-image severity
counts and appendix always cover the full report. `unrated` as a floor and a
zero row cap are configuration errors (exit 2).

The PDF states omissions: a line under the summary lede when the floor hides
findings; “Rows not shown: N” under capped tables, with “(complete list in the
JSON artifact)” when JSON output is enabled; and “Filters applied: ...” in the
appendix Method section. Counts-only detail adds one note under the chapter
heading directing readers to the inventory’s per-vulnerability findings.
The JSON artifact is always the complete normalised report; `render-data` JSON
includes a `filters` block. No CSV output is provided. Chunked/batch rendering
remains out of scope ([#11](https://github.com/jtr860830/judex/issues/11)).

### Theme

Set `report.logo` to a local PNG or SVG file to place the customer logo on the cover. Theme logos appear beside the product credit in the appendix.

The optional top-level `theme.path` points to a directory containing `theme.toml`
and an optional `logo.png` or `logo.svg`. Select the theme in this order:
`theme.path`, `$JUDEX_THEME_DIR`, embedded default. A set `JUDEX_THEME_DIR` must
be non-empty and contain a valid `theme.toml`; an invalid selected directory
exits 2 for `run`, `check`, and `render-data`.
Copy [assets/themes/default/theme.toml](assets/themes/default/theme.toml) to customise product
branding, colours and font families. Unknown keys and invalid values fail with
exit code 2 before fetching scans. Paths resolve from the working directory.

```yaml
theme:
  path: ./assets/themes/default
```

The theme's `[product] name` supplies `meta.product_name` in `render-data` JSON.
The default displays `judex <ver>`; an edition named `Arishem` displays
`Arishem <ver> (judex)`. `--version` and `version` use the environment theme or
embedded default, without reading configuration. An invalid `JUDEX_THEME_DIR`
then prints the upstream identity, warns once on stderr, and exits 0.
HTTP `User-Agent` is `judex/<ver>` or `Arishem/<ver> judex/<ver>`; every
character of the product name outside the RFC 9110 token set becomes `-`.

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
| `timeout_secs` | Positive timeout in seconds; HTTP only | `30` |
| `insecure_skip_verify` | Disable TLS verification; cannot combine with `ca_file` | `false` |

HTTP outputs upload each artifact separately. The URL may contain literal `{filename}`, replaced with each artifact’s percent-encoded filename. PUT requires `{filename}` when `report.json: true` so artifacts have distinct destinations; POST may omit it. `check` and `run` validate outputs before fetching the source. URLs must use HTTP(S) without embedded credentials.
Raw mode sends the artifact bytes with its media type and
`Content-Disposition: attachment; filename="<name>"`:

```sh
curl -X PUT -H 'Content-Type: application/pdf' -H 'Content-Disposition: attachment; filename="report.pdf"' --data-binary @report.pdf https://reports.example.com/upload
```

Multipart mode sends one form-data part named `file`, including filename and media type:

```sh
curl -X POST -F 'file=@report.pdf;type=application/pdf' https://reports.example.com/upload
```

HTTP outputs do not follow 3xx responses. `timeout_secs` covers the whole upload; large PDFs may need a larger value.

PUT is idempotent: transport errors and HTTP 5xx responses retry twice (after 1 and 2 seconds),
resending the body. POST uploads are sent once; choose a POST endpoint that tolerates a missing upload rather than a duplicated one. HTTP 4xx responses fail immediately. Partial output success
exits zero; exit 5 means every artifact write failed.
Mount the endpoint's exported CA certificate as a PEM bundle and set `ca_file`
to its path. Invalid or unreadable CA files fail with exit code 2. As a last
resort for endpoints whose CA cannot be exported, remove `ca_file` and set
`insecure_skip_verify: true`. This disables certificate verification and prints a warning with the redacted URL: `output https://host/path: TLS certificate verification is disabled` once per check/run.
The two settings cannot be combined.

Header values expand `${VAR}` placeholders when configuration is loaded; an unset
variable fails with its name. Valid names use ASCII letters or underscore first,
then letters, digits or underscores. Expansion is one pass, malformed placeholders
stay literal, and replacement values are not expanded again. Other configuration
strings do not receive this substitution. Keep credentials in environment variables.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (including partial output success) |
| `2` | Configuration or CLI argument error |
| `3` | Source failure, including no usable input reports |
| `4` | Rendering / JSON serialisation failure |
| `5` | Every artifact write failed |

Errors are printed to stderr as `error: ...`; warnings also go to stderr.
A run with some successful writes returns `0` and reports failed sinks on stderr.
These codes indicate pipeline outcomes, not vulnerability severity thresholds.

See the [design iteration guide](docs/design/README.md) for Typst previews.

## Development and licence

See [development notes](docs/development.md) for checks, snapshots and module layout.
Licensed under [Apache-2.0](LICENSE).
See [third-party notices](docs/development.md#third-party-notices) for regeneration.
