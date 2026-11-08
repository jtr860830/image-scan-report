# Scanner fixtures

Every file under this directory is real scanner output, captured from a lab
instance and used as test input for the parsers. None of it is documentation or
hand-written sample data. Do not edit the files by hand; recapture instead.

Captured: 2026-11-06 (Harbor and NeuVector API) and 2026-11-07 (Trivy CLI and
NeuVector standalone scanner).

## Tool versions

| Tool | Version |
|---|---|
| Harbor | 2.15.4 (`harbor_version` v2.15.4-d8841742) |
| Harbor's built-in Trivy adapter | 0.75.0 |
| Trivy CLI | 0.75.0 (`trivy_0.75.0_Linux-64bit.tar.gz`, `--scanners vuln`) |
| NeuVector controller | 5.6.4 |
| NeuVector scanner (lab) | `docker.io/neuvector/scanner:6` |
| NeuVector scanner (standalone captures) | `docker.io/neuvector/scanner:6`, run under podman 4.9.3 |
| NeuVector CVE DB | 4.318 (created 2026-11-02T20:36:35Z, from `neuvector-api/scanner.json`) |

## Images

`nginx:1.21.0`, `alpine:3.12`, `alpine:3.22`, `redis:6.0.5`, `python:3.6-slim`,
`ubuntu:18.04`, `centos:7`, `postgres:12.4`, `httpd:2.4.49`, `busybox:1.37`,
`ghcr.io/christophetd/log4shell-vulnerable-app:latest`.

Harbor and the NeuVector API scanned them in Harbor project `demo`. The Trivy
CLI and the standalone scanner pulled them from their public registries
(Docker Hub `library/*`, and ghcr.io for log4shell). Because image `latest` and
upstream rebuilds move, digests may differ between the Harbor copy and the
public-registry captures.

## Layout

| Path | Contents |
|---|---|
| `harbor/` | Harbor REST API responses (`systeminfo`, `scanners`, `repositories`, `artifacts-*`, `vulns/`) |
| `neuvector-api/` | NeuVector controller REST API responses (`scanner`, `registries`, `registry-images`, `images/`) |
| `trivy/<repo>-<tag>.json` | `trivy image --format json --scanners vuln` output |
| `neuvector-scanner/<repo>-<tag>/scan_result.json` | Standalone scanner file output (`/var/neuvector/scan_result.json`) |

`<repo>-<tag>` uses the last path segment of the repository, for example
`log4shell-vulnerable-app-latest`.

## How the standalone scanner was run

```sh
podman run --rm \
  -e SCANNER_ON_DEMAND=true \
  -e SCANNER_REGISTRY=https://registry-1.docker.io \   # https://ghcr.io for log4shell
  -e SCANNER_REPOSITORY=library/<repo> \                # christophetd/log4shell-vulnerable-app for log4shell
  -e SCANNER_TAG=<tag> \
  -v <dir>:/var/neuvector docker.io/neuvector/scanner:6
```

Variable names follow https://open-docs.neuvector.com/scanning/scanners.
Note `SCANNER_ON_DEMAND=true` is required.

## Sanitisation

Lab addresses were rewritten: the private lab IPv4 address with port 30002 to
`harbor.example.test`, and other private lab IPv4 addresses to
`neuvector.example.test`. No credentials were present
(`password` fields in the API captures are empty; the registry `username` is
`admin`). Remaining matches for "secret"/"password" are scanner content, such as
the Debian `snakeoil` placeholder key reported for `postgres:12.4` and Perl
module file names. Everything else is untouched.


## Additional API captures (2026-11-08)

These captures use the same Harbor 2.15.4, Trivy 0.75.0, and NeuVector 5.6.4
versions listed above. Lab addresses were sanitised as described above.

| Path | Contents |
|---|---|
| `harbor/multiarch/artifacts-alpine-multi.json` | Harbor artifact list for `demo/alpine-multi:3.20`, an OCI image index with 16 child references |
| `harbor/multiarch/child-<digest12>.json` | Each of the 16 child artifacts, fetched with `?with_scan_overview=true&with_tag=true` |
| `harbor/multiarch/vulns-<digest12>.json` | Vulnerability additions for the 8 scanned platform children |
| `harbor/projects.json` | Harbor project list |
| `harbor/repositories-paged-p1.json` | First repository page with `page_size=2` |
| `harbor/repositories-paged-p1.headers` | First-page HTTP response headers, including `X-Total-Count: 11` and a `Link` to `page=2&page_size=2` with `rel="next"` |
| `harbor/repositories-paged-p2.json` | Second repository page with `page_size=2` |
| `harbor/repositories-after.json` | Full repository list after the pushes |
| `harbor/artifacts-junk-artifact.json` | Deliberately non-image OCI artifact with Harbor type `JUNK` |
| `neuvector-api/rescan/registry.json` | Registry summary after the rescan |
| `neuvector-api/rescan/registry-images.json` | Registry image list after the rescan, containing 12 images |

Of the index's 16 children, 8 are platform images with scan status `Success`.
The other 8 are attestation manifests with platform `unknown/unknown` and no
`scan_overview`; they are not failed image scans.

NeuVector lists the index as a single image, `demo/alpine-multi:3.20`, using
its amd64 child digest
`sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`.
A real failed NeuVector scan could not be provoked: NeuVector ignores the
`JUNK` artifact. The `Failed` branch therefore keeps the synthetic envelope
used by the tests rather than claiming a captured failure response.

Outside this directory, `tests/data/tls/ca.pem` is a self-signed test CA for
custom CA certificate loading, and `tests/data/tls/not-a-cert.pem` is invalid
certificate input for testing rejection. These are test inputs, not scanner
captures.
