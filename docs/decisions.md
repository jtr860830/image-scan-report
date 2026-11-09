# Decisions

Decisions that shape the product, with the reason, newest first. Add an entry
when a direction is chosen or reversed; never edit an old entry — supersede it
with a new one. The design document
(`superpowers/specs/2026-11-07-product-redesign-design.md`) holds the original
design; this file holds what changed or was settled afterwards.

## 2026-11-09 — Large-report settings (#11)

- Keep the summary complete so content limits cannot understate risk; keep
  per-image counts full so an image’s totals remain useful for reconciliation.
- Never filter Unrated findings: missing severity evidence is not low risk.
- Use `min_severity`, `image_detail` and `max_table_rows` to reduce detail while
  stating omissions, so readers can distinguish presentation from coverage.
- Show the summary filter note only when a severity floor hides findings; cap-only
  tables and the counts-only image chapter state their own limits instead.
- Do not add CSV: the complete JSON artifact already carries every row.
- Keep chunked rendering shelved: per-scope reports and content controls address
  the artifact’s size first ([#11](https://github.com/jtr860830/judex/issues/11)).
- See [report settings](../README.md#report) and the
  [CHANGELOG](../CHANGELOG.md#unreleased).

## 2026-11-08 — Template experiments

Keep template changes only with ≥ 5 % time or memory improvement and unchanged
golden text and preview PNGs; none qualified in the [measurement table](development.md#rendering-performance-measured-2026-11-08-release-build-apple-silicon-median-of-three).

## 2026-11-09 — Standard paths, environment theme, edition identity (PR #17)

- Follow FHS inside the image and XDG on hosts because published standards exist.
- Make `JUDEX_CONFIG` authoritative to avoid reporting from the wrong configuration.
- Reject an empty theme directory to avoid cwd surprises; degrade version-only
  identity with one warning line so diagnostics remain usable.
- See [Configuration reference](../README.md#configuration-reference),
  [Theme](../README.md#theme) and the [migration changes](../CHANGELOG.md#unreleased).
  Supersedes the spec's `/etc/report/config.yaml` and `/output` paths.

## 2026-11-09 — Large reports

- The limit is the artifact, not the renderer. Use per-scope reports and content
  knobs (issue #11), not chunked rendering. Chunked/batch rendering is shelved
  until a single scope exceeds roughly 40,000 findings in practice.

## 2026-11-09 — Company edition

- An edition is `FROM` the upstream image plus a theme directory; never a fork,
  no code. Hiding the upstream origin of an edition image (re-basing layers,
  overriding labels) was considered and rejected as not worth the trouble.
- The edition keeps no version of its own; its image tag is the upstream
  version it wraps.

## 2026-11-09 — Name and first release

- Product name `judex` (README heading `Judex`; binary, image and theme stay
  lowercase). First release `0.1.0`, not `1.0.0-rc.1`: interfaces may still
  move and 0.x says so. See the [release rules](release.md#cutting-a-release).

## 2026-11-08 — Report defaults

- Reduce pages and focus auditors on actionable findings; make content controls
  configurable. See the [measured reduction](development.md#golden-and-performance-regression-checks)
  and [report configuration](../README.md#report).

## 2026-11-07 — Design (see the spec)

See the [original design](superpowers/specs/2026-11-07-product-redesign-design.md).
