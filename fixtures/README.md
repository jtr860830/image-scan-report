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

Lab addresses were rewritten: `192.168.1.x:30002` to `harbor.example.test` and
any other `192.168.1.x` to `neuvector.example.test`. No credentials were present
(`password` fields in the API captures are empty; the registry `username` is
`admin`). Remaining matches for "secret"/"password" are scanner content, such as
the Debian `snakeoil` placeholder key reported for `postgres:12.4` and Perl
module file names. Everything else is untouched.
