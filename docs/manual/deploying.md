# Deploy judex

Use judex to turn existing Harbor, NeuVector or Trivy vulnerability results into
an audit PDF. It never scans images. Each invocation runs once, writes the
configured PDF and optional normalised JSON to directories or HTTP endpoints,
and exits. Schedule invocations externally.

Read [the report guide](reading-the-report.md) before distributing a report.
The links below refer to the repository checkout; native release bundles also
include both manual files beside `docs/container.md`.

## Enable scanning first

In Harbor, open the project's Configuration and enable “Automatically scan
images on push”. Also configure a scheduled scan-all under Administration →
Interrogation Services → Vulnerability. Push scanning covers new images;
scan-all refreshes existing images against updated vulnerability databases.
Create a read-only robot account or user for judex; a project Guest is sufficient.
Use credentials that can see every project you intend to report on.

In NeuVector, open Assets → Registries, add the registry with Auto Scan and a
repository filter covering the intended images, and create a reader account for
judex. The API source reads that registry configuration's results, rather than
starting scans. Console wording can vary with the scanner version.

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
file's modification time. Preserve
modification times when transferring files; copying them can make old results
appear recent.

## Configure Harbor

Copy [the Harbor example](../../deploy/examples/config.yaml) into your own
configuration file. Follow the [configuration reference](../../README.md#configuration-reference)
for accepted fields and defaults; do not use the example's placeholder endpoints
or paths unchanged. Relative paths resolve from the working directory.

Set `source.url` to the Harbor API's final HTTP(S) endpoint. Set `source.project`
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
of freshness.

Keep PDF enabled and set `report.json: true` when auditors need complete data
for reconciliation. For large reports, first split the scope, then consider:

| Setting | Use it when |
| --- | --- |
| `min_severity` | Readers need higher severity detail; Unrated remains visible and summary counts stay complete. |
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

### Adapt the source

For the [NeuVector example](../../deploy/examples/config-neuvector.yaml), use
`type: neuvector`, a controller URL, and `registry` instead of `project`.
`registry` is the configured scanner registry name, not its endpoint URL.
Reference `NEUVECTOR_PASSWORD` through `password_env`; the report and outputs
work the same way.

For [Trivy files](../../deploy/examples/config-trivy-files.yaml), use
`type: trivy-files` and `path` pointing to the input directory. For standalone
NeuVector results, use `type: neuvector-files` with the same directory approach.
API credentials and TLS settings are unnecessary for file sources. Mount the
input read-only in a container and use its container path in the configuration.

## Locate the configuration

Pass `--config` explicitly for repeatable scheduled runs. Otherwise a non-empty
`JUDEX_CONFIG` is authoritative: a missing file is an error, not a reason to
search elsewhere. With no override, judex tries the XDG configuration path and
then `/etc/judex/config.yaml`. A valid `XDG_CONFIG_HOME` gives
`$XDG_CONFIG_HOME/judex/config.yaml`; otherwise the fallback is
`$HOME/.config/judex/config.yaml` when HOME is available. See the
[exact lookup rule](../../README.md#configuration-reference), including empty
and relative environment values.

Use these container paths and configure the matching mounts:

| Path | Purpose |
| --- | --- |
| `/etc/judex/config.yaml` | Read-only YAML configuration |
| `/etc/judex/ca.pem` | Optional read-only CA bundle |
| `/etc/judex/logo.png` | Optional read-only cover logo |
| `/var/lib/judex/scans` | Read-only file-source inputs |
| `/var/lib/judex/reports` | Writable report directory |

## Check, then run

```sh
judex check --config ./config.yaml
judex run --config ./config.yaml
```

`check` loads configuration, validates the theme and output settings, and fetches
and parses the source without rendering or storing artifacts. Its line has this
shape (counts and source description vary):

```text
<source>: N images (N scanned, N failed, N not scanned), N findings; product: judex <ver>; theme: default
```

Inspect **failed** and **not scanned** first after deployment. A zero findings
count does not establish coverage when images have no successful scan. Check the
scanner's status and permissions before treating the report as complete.
`theme` is `config`, `env` or `default`, identifying how the theme was selected.
`run` prints `Report: N images, N findings`, followed by stored destinations and
filenames. Errors and warnings go to stderr.

| Exit code | Operator action |
| --- | --- |
| `0` | Inspect coverage and sink warnings; partial artifact storage success also returns zero. |
| `2` | Correct configuration, CLI arguments, missing secret variables, CA files or theme setup. |
| `3` | Restore source connectivity/permissions or provide usable input reports. |
| `4` | Investigate rendering or JSON serialisation failure. |
| `5` | Restore output access; every artifact write failed. |

These are pipeline outcomes, not severity thresholds. Failed or unscanned images
can still appear in a successfully produced report. API authentication or
authorisation failures abort the source; other per-artifact failures can become
Failed rows. Use `RUST_LOG=debug` for diagnostics.

## Schedule and retrieve reports

Follow [Kubernetes deployment](../../deploy/k8s/README.md) for the ConfigMap,
Secret, CA, PVC, CronJob and one-off Job. Schedule judex after the scanner's
refresh window: for example, Harbor scan-all daily at 02:00 and judex Monday at
06:00. Adjust the supplied CronJob, which runs Monday at 02:00 in the controller's
timezone. Leave enough time for scans to finish and confirm completion in the
scanner; scheduling alone does not guarantee fresh results.

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

## Size the run

Use [resource guidance](../container.md#resources) for measured memory estimates
and allow disk space for both formats. Split per project before increasing
limits indefinitely. Use the large-report settings above when readers need a
shorter PDF; they reduce displayed detail while preserving full summary counts
and JSON. Monitor memory and retained files for the actual scope.

## Use an edition image

An edition built with `FROM` the upstream image, a theme directory and
`JUDEX_THEME_DIR` behaves identically. With no `theme.path` override, `check`
shows `theme: env` and the edition's product display, such as
`Arishem <ver> (judex)`. Follow [Building an edition image](../container.md#building-an-edition-image)
and the [theme reference](../../README.md#theme).

## Resolve common failures

| Symptom | Check |
| --- | --- |
| TLS or CA error | Check the final URL and readable PEM mount; set the CA on the source or output that failed. |
| Wrong credentials / HTTP 401 or 403 | Check `password_env`, the runtime secret and read permissions for the intended scope. |
| “No images found” or no usable input | Check the selected project/registry, account visibility, directory mount and parser warnings. |
| Configuration not found | Read the listed candidates; correct `--config` or the authoritative `JUDEX_CONFIG`. |
| Container OOM-killed | Increase available memory or split scope; consult resource guidance and reduce PDF detail. |
| Theme error | Check the selected directory and `theme.toml`; selection is `theme.path`, then `JUDEX_THEME_DIR`, then default. |
| Empty-looking report / nothing scanned | Inspect failed and not-scanned counts, scanner scheduling and the appendix; generation does not scan images. |
