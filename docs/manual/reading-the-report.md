# Reading the report

Open [the English sample PDF](../samples/sample-report-en.pdf) and follow its
sections below. It contains four sample images and 828 findings, produced with
0.1.0. Reports from later versions can contain filter notes, described at the end.
The `zh-TW` report has the same structure and interpretation in Traditional
Chinese; severity labels remain in English.

For deployment and coverage checks, see [Deploying judex](deploying.md).

## Cover

The cover is titled **Container Image Vulnerability Scan Report**. Check the
organisation and optional logo before reading its numbers.

| Label | Interpretation |
| --- | --- |
| Scope | Harbor server address (host and port) / project (or all accessible projects), NeuVector server address / registry configuration, or the file directory's final component. |
| Scan Source | The source from which results were collected. |
| Images | Included image records, including clean, failed and not-scanned records. Harbor multi-architecture children count separately. |
| Scan Period | Earliest–latest available scan dates across the included images; missing dates do not enter the range. |
| Generated | The report generation date, rather than a new scan date. |

A recent **Generated** date does not make an old scan current. Use **Contents**
to navigate the chapters and individual image sections.

## Summary

A unique vulnerability is one identifier (a vulnerability reference, such as a
CVE number from Common Vulnerabilities and Exposures) across the report. A finding
is an occurrence for an image and package: one CVE affecting one package on three
images gives one unique vulnerability and three findings. The same identifier
can also affect several packages on one image.

**Summary** states the image and unique-vulnerability totals. Its four tiles
count Critical, High, Medium and Low findings; a separate Unrated chip appears
when that count is non-zero. The bar shows the findings' severity distribution.
Unrated means missing usable severity evidence, not low risk.

The fact **have fixes available** counts findings with a fixed version and gives
their share of all findings. **images contain Critical or High vulnerabilities**
counts images with at least one such finding, rather than the number of affected
packages. These facts, the bar and Priority Vulnerabilities appear only when
findings exist; otherwise Summary shows **No vulnerabilities found.**

Read **Priority Images** for up to 10 images with the highest severity counts,
ranked by Critical count, then High, Medium and Low, with reference as the tie
breaker. **Priority Vulnerabilities** shows up to 15 identifiers ranked by severity,
then score, then identifier; it lists package names, fixed versions and
affected-image counts. These rankings are complete-data views even when detail is filtered.

A note below the opening sentence appears when a severity floor (the minimum
severity band included in detail) hides findings. It states the minimum band and how many lower-band findings remain counted but
are not listed. Do not reconcile summary totals only against visible detail rows.

## Remediation

**Remediation** groups fixable findings by package and fixed version. A group
can cover several installed versions and images. **Resolves … vulnerabilities**
counts findings in each severity band for that upgrade group, including hidden
lower bands when a severity floor is set; it is not a count of distinct CVE
identifiers. **Affects … images** counts distinct images in the group. Groups are ranked by Critical, High, Medium and Low counts, then package
and fixed version. Additional groups appear under **Further fixes**.

Treat each package/version pair as a starting point for a tested image rebuild.
It is scanner-provided upgrade evidence, not a validated deployment change or a
complete operational fix list. A card may abbreviate a long image list with
`+N`; consult the inventory or normalised JSON artifact (a machine-readable report
in a shared data format) for the rest.

**Vulnerabilities Without Fixes** counts findings without a fixed version across
the complete report, regardless of a severity floor, and groups them by scanner
status:

| Status | Read it as |
| --- | --- |
| Affected | Reported affected, with no fixed version supplied. |
| Fix Deferred | The scanner reports a deferred fix. |
| Will Not Fix | The scanner reports that no fix is planned. |
| End of Life | The scanner reports end-of-life status. |
| Under Investigation | The scanner reports an unresolved investigation. |
| Other | No status was supplied, or the status was `unknown`. |
| `Other (<raw value>)` | An unrecognised status was supplied; its raw value is shown. |

These statuses do not establish exploitability or approve accepting the risk.
Assess mitigation, replacement or a supported base image with the image owner.

## Vulnerability Inventory

**Vulnerability Inventory** has one row per vulnerability identifier, with
severity, **CVSS** (Common Vulnerability Scoring System), package names, fixed
versions and affected-image count. **Affected Images** lists image references below each row; a long list is
abbreviated after 20 entries with `+N`.

An identifier seen with different severities or scores is represented by its
highest severity and highest available score across findings. Packages and fixed
versions are combined, so use Image Details or JSON to match a specific installed
package to its fixed version. `—` in **Fixed Version** means no fixed version
was supplied for that row; `—` in **CVSS** means no usable numerical score.
Rows are ordered by severity, descending score, then identifier.

## Image Details

Each image section in **Image Details** shows **Digest** (the content hash
identifying the image), **Platform**, **Operating System**, **Size**, **Created**, **Scanned** and
**Vulnerabilities by Severity**; **Tags** appears when applicable. A dash denotes
missing metadata. Platform and OS availability depend on the source; Harbor
sizes are compressed and NeuVector sizes are uncompressed.

In full mode, **Vulnerability Details** lists the identifier, severity, CVSS,
package, installed version and fixed version. Selected severity bands may include
truncated descriptions. Fallback severity annotations show `v2` or `label: …`.
Failed and not-scanned records display their status rather than a clean result.

With `image_detail: counts`, metadata and complete severity counts remain, but
finding tables are omitted. A chapter note directs readers to the inventory,
which is itself subject to filtering. A row cap reports **Rows not shown: N**
under each affected table; the per-image counts still include every finding.

## Appendix

Under **Methodology**, inspect **Scanner**, **Vulnerability Database** and
**Report Tool**. Missing source metadata is shown as a dash, not inferred.
**Severity Rules** describes the common scale:

| CVSS v3 score | Severity |
| --- | --- |
| ≥ 9.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Medium |
| 0.1–3.9 | Low |
| No score or usable label | Unrated |

When no usable v3 score exists, judex uses v2: scores from 7.0 upwards are High,
so this fallback cannot produce Critical. With neither score, a recognised
scanner label supplies the band and receives an annotation. Missing, zero and
non-finite scores are not usable; Unrated stays separate.

**CVSS Score Sources** counts findings by selected score source. For Harbor and
Trivy, selection prefers NVD (the National Vulnerability Database), then Red Hat
(a vendor score source), then other source names in alphabetical order, first looking across v3 scores and only then v2. NeuVector supplies its
single score source rather than a vendor-choice map.

Check **Images Not Scanned or Failed** before interpreting low totals. These
images are in scope but do not provide successful scan evidence. Check
**Images Not Scanned in Over N Days** for successful scans older than the
configured threshold, including successful scans with no timestamp.

Read **Limitations**: severity is recomputed; score sources and scanner coverage
differ; NeuVector fills some older scores; registry contents do not represent
running workloads; each report is independent and tracks no history.

## Differences from the scanner interface

judex computes severity from CVSS evidence rather than simply copying the
scanner's label. A different source preference or vendor score can move a finding
to another band. Multi-architecture image counting and scan-state handling can
also affect comparisons; see [source behaviour](../../README.md#source).

Compare a specific identifier, image digest, package, score source and scan time
before comparing totals. Do not compare Harbor and NeuVector totals as if their
input scores and detection coverage were identical. A successful scan can still
miss vulnerabilities; judex inherits the scanner's coverage.

## Report scope and limits

Use the report as evidence of the images and scan results collected for the
stated scope, at their recorded scan times. It is not a live inventory of running
workloads, proof that an image is safe, or a complete fix list. It does not scan,
validate proposed upgrades or compare runs. Preserve the configuration and JSON
alongside the PDF when repeatable reconciliation matters.

## Filtered reports

Consult [report settings](../../README.md#report) for the controls. Look for:

| Signal | Meaning |
| --- | --- |
| Summary note about a minimum band | `min_severity` hid lower-band findings from detail, while retaining Unrated. |
| **Rows not shown: N** | `max_table_rows` capped the inventory or an individual image table. |
| **Groups not shown: N (below …)** | Remediation groups fell below the severity floor. |
| **Tables list findings at or above High (Unrated is always listed); counts include every finding.** | Image Details has a severity floor in full mode (High stands for whichever band was configured). |
| **… unique vulnerabilities at or above High (Unrated included).** | The inventory opening count covers the retained severity bands. |
| **No findings at or above High.** | No retained findings are available for that detail table or remediation groups. |
| Image Details chapter note about counts | `image_detail: counts` omitted per-image finding tables. |
| **Filters applied: …** in Methodology | The configured floor, counts-only mode and/or row cap is active. |

The summary note appears only when a severity floor actually hides findings;
cap-only reports announce their limits at the tables. Full summary facts and
rankings, per-image counts and appendix evidence remain complete. The inventory
can have a smaller unique-vulnerability count. For remediation counts, see
[Remediation](#remediation).

When `report.json: true`, the normalised JSON artifact retains every finding,
including rows and groups omitted from the PDF. The PDF's row-cap note then adds
“(complete list in the JSON artifact)”. If JSON was not enabled, request a new run
with JSON or less restrictive settings before concluding that omitted rows do
not exist.
