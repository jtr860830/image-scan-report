# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-09

### Changed

- Move container paths and Kubernetes namespace/labels:

  | Old | New |
  | --- | --- |
  | `/etc/report/config.yaml` | `/etc/judex/config.yaml` |
  | `/etc/report/ca.pem` | `/etc/judex/ca.pem` |
  | `/etc/report/logo.png` | `/etc/judex/logo.png` |
  | `/output` | `/var/lib/judex/reports` |
  | CronJob `image-scan-report` | `judex` |
  | Job `image-scan-report-once` | `judex-once` |
  | `/etc/report/harbor-ca.pem`, `/etc/report/neuvector-ca.pem` | `/etc/judex/ca.pem` |
  | File-source example mount `/fixtures` | `/var/lib/judex/scans` |
  | Image CMD `run --config /etc/report/config.yaml` | `run` |
  | Kubernetes namespace/labels `image-scan-report` | `judex` |

- Display `judex <ver>` or `<edition> <ver> (judex)` for `--version` and
  `version`. Change the `check` tail from
  `; theme: <theme product>; product: <name> <ver>` to
  `; product: <display>; theme: <config|env|default>`.
- Library API: `build_source`, `build_sinks`, `client_from_tls`, and `tls_client`
  take `user_agent`; `run`, `check`, and `write_render_data` take `&Runtime`.
  Remove `USER_AGENT`; reject `HttpOptions::default()` until `user_agent` is set.
- Send `judex/<ver>` or `<edition>/<ver> judex/<ver>` as the HTTP User-Agent;
  replace every non-RFC 9110 token character in the edition name with `-`.

### Added

- Add operator and report-reading manuals, included in native release archives.
- Add optional report settings `min_severity`, `image_detail` and `max_table_rows`
  for large reports, with omission statements below the summary lede and capped
  tables and in the appendix Method section.
- Add configuration discovery; see README › [Configuration reference](README.md#configuration-reference).
- Add environment theme selection and theme-source reporting; see README › [Theme](README.md#theme).

### Removed

- The `image-scan-report/<ver>` HTTP User-Agent.
- The hard default `--config /etc/report/config.yaml`.

### Fixed

- Summary table: vulnerability ids with seven-digit sequence numbers and long
  fixed-version strings ran into the neighbouring columns (#15). The table now
  uses the same identifier wrapping and column widths as the inventory.

## [0.1.0] - 2026-11-09

### Added

- Import existing scans from Trivy files, NeuVector scanner files, Harbor API
  and NeuVector controller API, without scanning images again.
- Six-chapter PDF audit reports in English and Traditional Chinese, with JSON
  output for automation, configurable branding and bundled fonts.
- Filesystem and HTTP outputs, including multiple destinations, raw and multipart
  uploads, configurable headers, custom CAs, timeouts and retries.
- Non-root container image, Kubernetes Job/CronJob examples and Podman wrapper.
- Native Linux x86_64/aarch64 release archives, checksums, draft release notes
  and multi-architecture GHCR images. Release candidates never update `latest`;
  only stable releases move that tag.

### Changed

- Apply one unified CVSS v3 severity rule across sources while retaining the
  scanner's original label for reconciliation.
- Validate configuration and source inputs with `check` before generating reports.
- Define automation exit codes: 0 for success (including partial destination
  success), 2 for configuration errors, 3 for
  source failures, 4 for rendering failures and 5 when all output sinks fail.

### Known limitations

- Severity is recomputed; counts can differ from the scanner's UI. The original label is shown for reconciliation.
- Scores differ between scanners for the same CVE; reports from different scanners are not comparable number-for-number.
- NeuVector fills a score for some old vulnerabilities; these cannot be distinguished.
- Coverage is the scanner's: a scanner can miss findings while reporting success.
- Scope is "images stored in the registry", not workloads running in a cluster.
- No history: comparisons between runs are out of scope.

[Unreleased]: https://github.com/jtr860830/judex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jtr860830/judex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jtr860830/judex/releases/tag/v0.1.0
