# Deploying judex

Use judex to turn existing Harbor, NeuVector or Trivy vulnerability results into
an audit PDF. It never scans images. Each invocation runs once, writes the
configured PDF and optional normalised JSON artifact (a structured data file in a
common format) to directories or HTTP endpoints, and exits. Schedule invocations
externally.

Read [the report guide](reading-the-report.md) before distributing a report.
Native release bundles preserve `docs/manual/` and include `docs/container.md`;
`examples/` is their copy of the repository's `deploy/examples/`. Links into
`deploy/`, `tests/fixtures/` and `docs/samples/` refer to the repository.

## Installation

Follow [Install](../../README.md#install) for a native binary (glibc ≥ 2.39) or
the image `ghcr.io/jtr860830/judex:<ver>`. Replace `<ver>` with a release tag.

## Local check

Check sample file inputs before configuring scanner credentials. From the root of a
repository checkout (the example configuration uses paths relative to it), with the
binary on PATH, run:

```sh
judex check --config deploy/examples/config-trivy-files.yaml
```

In an extracted native bundle, use:

```sh
./judex check --config examples/config-trivy-files.yaml
```

The archive includes the configuration, not the sample JSON inputs. Before the
bundle command, copy the Trivy sample files from a checkout's `tests/fixtures/trivy/`
and set `source.path` in the example configuration to that local directory.
See [fixture provenance](../../tests/fixtures/README.md) for the sample inputs.
`check` fetches and parses data without producing a PDF or JSON artifact.

## Prerequisites

In Harbor, open the project's Configuration and enable “Automatically scan
images on push”. Also configure a scheduled scan-all under Administration →
Interrogation Services → Vulnerability. Push scanning covers new images;
scan-all refreshes existing images against updated vulnerability databases.
A read-only project member (Guest) is verified; a robot account is not. A robot
needs list/read access to repositories, artifacts and scan reports; all-projects
mode requires a system-level robot. Use credentials that can see every project
you intend to report on.

In NeuVector, open Assets → Registries, add the registry with Auto Scan and a
repository filter covering the intended images, and create a reader account for
judex. The API source reads that registry configuration's results, rather than
starting scans. Check the registry's rescan options for periodic refreshes rather
than looking for a Harbor-style scan-all equivalent. Console wording and rescan
options are version-dependent and have not been verified from this repository.

For Trivy files, save `trivy image --format json` output for each image into an
input directory. For the NeuVector standalone scanner, collect its
`scan_result.json` outputs into separate subdirectories or rename them so they
do not overwrite one another. Both file sources walk a directory recursively.
Invalid reports are skipped with warnings; no usable reports is a source error.
See [fixture provenance](../../tests/fixtures/README.md) for captured examples.

Run the scanner before judex. The cover's **Scan Period** spans the earliest and
latest available scan dates, rather than the judex run time. The appendix lists
successful scans older than `report.stale_after_days` (30 by default), including
successful scans with no timestamp. A newly generated PDF can contain old scans.

File sources use an embedded scan timestamp when available and otherwise the JSON
file's modification time. Preserve modification times when transferring files;
copying them can make old results appear recent.

## Configuration

Copy [the Harbor example](../../deploy/examples/config.yaml) into your own
configuration file. Follow the [configuration reference](../../README.md#configuration-reference)
for accepted fields and defaults; do not use the example's placeholder endpoints
or paths unchanged. Relative paths resolve from the working directory.

Set `source.url` to Harbor's base URL as used in the browser, including any path
prefix but without `/api/v2.0`; judex appends the API path. Use the final address
because redirects are not followed. Set `source.project`
to one project for a bounded report; omit it to include every project accessible
to the account. Use separate configurations per project when a combined report
is too large or readers have different responsibilities.

Set `source.username` to the reader account and `source.password_env` to an
environment variable name such as `HARBOR_PASSWORD`. Export that variable in the
runtime environment. Keep credentials out of YAML, command arguments and images.

For a private CA, mount its exported PEM bundle and set `source.ca_file` to its
runtime path. This replaces the bundled trust roots; the OS certificate store is
not used. Remove the example's CA setting for a publicly trusted endpoint.
Use `insecure_skip_verify: true` only as a last resort when the CA cannot be
exported, removing `ca_file` first. The two options cannot be combined.

Set `report.language` to `en` or `zh-TW`, and `report.organization` to the customer
organisation printed on the cover. Set `report.logo` to a readable local PNG or
SVG, or remove it when no logo is needed. Choose `stale_after_days` to match the
scanner's refresh policy, rather than using the PDF generation date as evidence
of freshness. `report.logo` and `source.ca_file` must refer to files available
inside the runtime environment; missing mounts make `check` fail with exit 2.

Keep PDF enabled and set `report.json: true` when auditors need complete data
for reconciliation. For large reports, first split the scope, then consider a
severity floor (the minimum severity band retained in detail) or other detail limits:

| Setting | Use it when |
| --- | --- |
| `min_severity` | Readers need detail only for the higher bands; Unrated remains visible and summary counts stay complete. |
| `image_detail: counts` | Repeated per-image findings make the PDF too long; retain metadata and full counts. |
| `max_table_rows` | Limit the inventory and each image table after sorting, most severe first. |

The PDF declares omissions; the JSON remains complete. See
[report settings](../../README.md#report) for values and restrictions.

Set a filesystem output to a writable directory. In a container, use
`/var/lib/judex/reports` and mount persistent storage there. The directory is
created if needed. Filenames contain the scope, source type and UTC run date;
a repeat run on the same date overwrites the same files atomically.

Remove the example's HTTP output if it is not needed. To upload artifacts,
configure the endpoint URL, method and mode; use `{filename}` in a PUT URL when
JSON is also enabled so PDF and JSON have separate destinations. Header values
can reference `${UPLOAD_TOKEN}` from the environment. Set the output's own
`ca_file` for a private endpoint CA. `check` validates this configuration but
does not test an upload. See [HTTP output](../../README.md#output) for the wire
formats, timeouts, TLS and retry behaviour.

### Other sources

For the [NeuVector example](../../deploy/examples/config-neuvector.yaml), use
`type: neuvector`, a controller URL, and `registry` instead of `project`.
`registry` is the configured scanner registry name, not its endpoint URL.
Reference `NEUVECTOR_PASSWORD` through `password_env`; the report and outputs
work the same way.

For [Trivy files](../../deploy/examples/config-trivy-files.yaml), use
`type: trivy-files` and `path` pointing to the input directory. For standalone
NeuVector results, use `type: neuvector-files` with the same directory approach.
Remove API credentials and TLS settings: file sources reject API keys (exit 2).
Keep only `type` and `path` in `source`. Mount the input read-only in a container
and use its container path in the configuration.

## Configuration location

Use `--config` for scheduled runs. See the README's
[lookup rule](../../README.md#configuration-reference) for discovery when it is
omitted. The container sets `HOME=/home/nonroot`; its normally absent XDG file
means the image finds `/etc/judex/config.yaml` when mounted there and no override
is set.

## Mounts

Follow the container guide's [mounts](../container.md#mounts) for configuration,
CA, logo, file inputs and writable report storage.

## Execution

```sh
judex check --config ./config.yaml
judex run --config ./config.yaml
```

`check` loads configuration, validates the theme and output settings, and fetches
and parses the source as in the local check above. Its line has this
shape (counts and source description vary):

```text
<source>: N images (N scanned, N failed, N not scanned), N findings; product: judex <ver>; theme: default
```

Inspect **failed** and **not scanned** first after deployment. A zero findings
count does not establish coverage when images have no successful scan. Check the
scanner's status and permissions before treating the report as complete.
`theme` is `config`, `env` or `default`, identifying how the theme was selected.
See the README for [run output](../../README.md#quick-start) and
[exit-code meanings](../../README.md#exit-codes). Use the actions below to
respond to each result.

| Exit code | Operator action |
| --- | --- |
| `0` | Inspect coverage and sink warnings; confirm every expected artifact arrived. |
| `2` | Correct configuration, CLI arguments, missing secret variables, CA files or theme setup. |
| `3` | Restore source connectivity/permissions or provide usable input reports. |
| `4` | Inspect rendering diagnostics and the input data. |
| `5` | Check destination access, available storage and upload logs. |

These are pipeline outcomes, not severity thresholds. Failed or unscanned images
can still appear in a successfully produced report. API authentication or
authorisation failures abort the source; other per-artifact failures can become
Failed rows. Use `RUST_LOG=debug` for diagnostics.

## Scheduling and report retrieval

Follow [Kubernetes deployment](../../deploy/k8s/README.md) for the ConfigMap,
Secret, CA, PVC, CronJob and one-off Job. Schedule judex after the scanner's
refresh window: for example, Harbor scan-all daily at 02:00 UTC using a custom
cron schedule, then judex Monday at 06:00 UTC (the supplied CronJob runs
`0 2 * * 1`, Monday at 02:00 — change its `schedule`). Harbor's Daily preset runs at
midnight UTC, so it does not express that example. Set the CronJob's
`spec.timeZone` explicitly to align with Harbor's UTC; without it, the supplied
CronJob uses the controller's timezone. Leave enough time for scans to finish
and confirm completion in the scanner; scheduling alone does not guarantee fresh
results.

After a report Job completes, mount `report-output` in a temporary helper pod
and copy `/var/lib/judex/reports` with `kubectl cp`. Use the exact helper commands
in [Retrieve reports](../../deploy/k8s/README.md#retrieve-reports); the helper
needs `tar`. Avoid a helper on another node while the report Job uses the RWO
PVC. Job history cleanup does not remove retained PDFs and JSON.

For HTTP-only delivery, replace the filesystem output, supply the upload secret,
and remove the unused output volume and mount from both workloads. Check the
endpoint for each artifact even when the run exits zero.

For Podman, follow [container installation](../container.md) for the wrapper,
UID 65532 write permissions, read-only input mounts, secret forwarding and
air-gap transfer. Configure paths as seen inside the container.

## Resources

Use [resource guidance](../container.md#resources) for measured memory estimates
and allow disk space for both formats. Split per project before increasing
limits indefinitely. Use the large-report settings above when readers need a
shorter PDF; they reduce displayed detail while preserving full summary counts
and JSON. Monitor memory and retained files for the actual scope.

## Edition images

An edition built with `FROM` the upstream image, a theme directory and
`JUDEX_THEME_DIR` behaves identically. With no `theme.path` override, `check`
shows `theme: env` and the edition's product display, such as
`Arishem <ver> (judex)`. Follow [Building an edition image](../container.md#building-an-edition-image)
and the [theme reference](../../README.md#theme).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| TLS or CA error | Exit 2: correct an unreadable or invalid CA file/mount. Exit 3 from the source: check the URL and trust roots when the TLS handshake is rejected. For uploads, inspect sink diagnostics. |
| Wrong credentials / HTTP 401 or 403 | Check `password_env`, the runtime secret and read permissions for the intended scope. |
| API: `no images found in <scope>`; files: `no scan results found in <dir>` | Check the selected project/registry, account visibility, directory mount and parser warnings. |
| Configuration not found | Read the listed candidates; correct `--config` or the authoritative `JUDEX_CONFIG`. |
| Kubernetes `OOMKilled` / exit 137 | Increase available memory or split scope; consult resource guidance and reduce PDF detail. |
| Theme error | Check the selected directory and `theme.toml`; selection is `theme.path`, then `JUDEX_THEME_DIR`, then default. |
| Empty-looking report / nothing scanned | Inspect failed and not-scanned counts, scanner scheduling and the appendix; generation does not scan images. |
