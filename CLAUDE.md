# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PDF report generator for NeuVector container image scans. Reads `scan_result.json` and outputs a styled PDF via a three-stage pipeline: **Jinja2 → Markdown → WeasyPrint**.

## Commands

```bash
# Install dependencies (local dev)
pip install -r requirements.txt

# Run locally
python3 main.py -i scan_result.json -o report.pdf

# Build container
podman build -t suse-security-report:0.1.0 .

# Run container (mounts CWD to /mnt)
podman run --rm -v $(pwd):/mnt suse-security-report:0.1.0

# Air-gap packaging
podman save suse-security-report:0.1.0 -o suse-security-report.tar
podman load -i suse-security-report.tar
```

## Rendering Pipeline

`main.py` orchestrates three stages:

1. **`extract_context(data)`** — parses `scan_result.json`, computes `size_mb` (bytes ÷ 1 048 576), extracts `scan_date` as `created_at[:10]`, and sorts vulnerabilities `High → Medium → Low` (then by name).
2. **Jinja2 render** — `templates/report.md.j2` rendered with the context dict → Markdown string.
3. **Markdown → HTML → PDF** — `markdown.markdown()` with `tables` + `fenced_code` extensions, then `weasyprint.HTML(string=…).write_pdf()` with `static/print.css`.

## Template (`templates/report.md.j2`)

The template mixes raw HTML (cover `<div>`) with Markdown. Key constraints:

- **`trim_blocks=True, lstrip_blocks=True`** — mandatory; prevents blank lines from breaking Markdown table rows inside `{% for %}` loops.
- **`{{ v.description | e }}`** — always HTML-escape CVE descriptions; they may contain `<script>`, `<meta>`, etc.
- The cover page is a raw `<div class="cover">` block; everything after is standard Markdown.

### Jinja2 Context Fields

| Variable | Source in `scan_result.json` |
|---|---|
| `registry`, `repository`, `tag`, `image_id` | `report.*` |
| `base_os`, `digest` | `report.*` |
| `size_mb` | `report.size` ÷ 1 048 576, rounded to 1 decimal |
| `created_at` | `report.created_at` — image build timestamp |
| `report_date` | `datetime.now(UTC)` formatted as YYYY-MM-DD — used on cover page |
| `report_datetime` | `datetime.now(UTC)` formatted as YYYY-MM-DDTHH:MM:SSZ — used in Image Info table |
| `cvedb_version`, `cvedb_create_time` | `report.*` |
| `vulnerabilities` | sorted High → Medium → Low, then by name |
| `cve_high`, `cve_medium`, `cve_low` | filtered sublists of `vulnerabilities` |

CVE object fields used in the template: `name`, `severity`, `score` (v2), `score_v3`, `package_name`, `package_version`, `fixed_version`, `file_name`, `link`, `description`.

## Stylesheet (`static/print.css`)

Print-oriented layout targeting WeasyPrint. Notable rules:
- `p { text-align: left }` — avoids justify mode breaking technical strings.
- `.cover` uses `page-break-after: always` to isolate the cover page.
- SUSE brand green: `#73ba25`.
- `td { word-break: break-all }` handles long CVE IDs and hashes; `td:first-child` exempts the first column.

## Container Details

- Base image: `registry.suse.com/bci/python:3.13` (SUSE BCI)
- System packages installed by `zypper`: `libpango-1_0-0 libcairo2 libgdk_pixbuf-2_0-0 suse-fonts` (required by WeasyPrint)
- App installed at `/opt/suse-security-report`; runtime I/O at `/mnt` (Linux FHS for temp mounts)
- Default entrypoint reads `/mnt/scan_result.json`, writes `/mnt/report.pdf`

## Severity Classification

CVSS v2 thresholds (NeuVector uses v2 for classification):

| Severity | CVSS v2 |
|----------|---------|
| Low      | 0.0 – 3.9 |
| Medium   | 4.0 – 6.9 |
| High     | 7.0 – 10.0 |
