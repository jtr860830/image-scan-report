# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.1] - unreleased

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

[1.0.0-rc.1]: https://github.com/jtr860830/image-scan-report/releases/tag/v1.0.0-rc.1
