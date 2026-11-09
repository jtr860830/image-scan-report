# Decisions

Decisions that shape the product, with the reason, newest first. Add an entry
when a direction is chosen or reversed; never edit an old entry — supersede it
with a new one. The design document
(`superpowers/specs/2026-11-07-product-redesign-design.md`) holds the original
design; this file holds what changed or was settled afterwards.

## 2026-11-09 — Standard paths, environment theme, edition identity (PR #17)

- Image paths follow FHS: `/etc/judex/{config.yaml,ca.pem,logo.png}`,
  `/var/lib/judex/reports` (output), `/var/lib/judex/scans` (file-source
  example). Configuration lookup on a host follows XDG: `$JUDEX_CONFIG` →
  `$XDG_CONFIG_HOME/judex/config.yaml` → `/etc/judex/config.yaml`. No
  compatibility shim for the 0.1.0 paths; the not-found error names the move.
- `JUDEX_CONFIG`, when set, is authoritative like `--config`: a missing file is
  an error, never a fall-through to another configuration.
- Theme precedence: `theme.path` → `JUDEX_THEME_DIR` → embedded default. A set
  variable that is empty or invalid is an error; `--version` alone degrades to
  the upstream identity with one warning line.
- The product identity shown by `--version`, `check` and the HTTP User-Agent
  comes from the theme's `product.name`: `judex 0.2.0` or `Arishem 0.2.0
  (judex)`; `judex/0.2.0` or `Arishem/0.2.0 judex/0.2.0`.
- Kubernetes namespace, labels and workload names are `judex`.

## 2026-11-09 — Large reports

- Rendering cost is linear (≈ 0.8 GB + 70 MB per 1,000 findings); the limit is
  the artifact, not the renderer. The answer is per-scope reports and content
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
  move and 0.x says so. Release candidates never move the `latest` image tag;
  the tag must equal the Cargo version.

## 2026-11-08 — Report defaults

- Descriptions only for Critical and High, capped at 600 characters; 30
  remediation cards then a compact table; all three configurable
  (`report.describe_severities`, `description_chars`, `remediation_cards`).
- Customer logo on the cover; theme logo beside the generated-by credit.

## 2026-11-07 — Design (see the spec)

- Rust with Typst embedded as a library (over Go + Typst CLI). Apache-2.0.
  Open Color palette, Inter + Noto Sans TC, Maple Mono NL. English and
  Traditional Chinese reports; English-only repository.
- The tool reads existing scans and never scans. Stateless: no history or
  trends. One unified severity scale from CVSS v3 with the scanner's label kept
  in the detail and an explicit Unrated class.
