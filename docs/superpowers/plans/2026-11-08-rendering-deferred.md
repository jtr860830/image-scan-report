# Plan 2 — deferred items and rulings

Carried out of the execution ledger when plan 2 (rendering) finished on 2026-11-08. Later plans' pre-flight should read this; items are fixed when a task touches the file, not before.

## Maintainer decisions

Decided by the maintainer on 2026-11-08: defaults kept (descriptions for Critical/High at 600 chars; 30 remediation cards), configurable via report.describe_severities, report.description_chars, report.remediation_cards; logo placement confirmed as implemented.

## Performance follow-ups (plan 4, before sizing the container)

- Measured: 50 000 findings → 14.9 s, 3 703 pages, peak RSS 5.1 GB (release, single run). About 100 MB per 1 000 findings with the full template vs 40 MB in the plain-table spike.
- Experiments, in order: table-level stroke function instead of six `table.cell` wrappers per row; flatten `chip` to one box with a glyph dot; `hyphenate: false` once per table; insert zero-width breaks only in identifiers longer than ~20 chars. Re-measure 50k after each.

## Deferred minor findings

- T1: font_book() does not assert each file yields a face; Noto copyright holder and subset note missing from notices/README; Typst version missing in notices; README mentions a manifest not in the repo.
- T2: empty strings are not placeholdered (Some("") prints blank); inventory score uses score_v3 only (views-level); unfixable_by_status/fix_status emit snake_case keys that Task 3 strings must map; failed_images includes NotScanned (intended).
- T3: zh-TW fact_fixable reorder ("{fixable} 個弱點（{percent}%）已有修補版本"), fact_high_or_worse add "等級弱點", appendix_rule_text smoother wording, image_meta_digest "Digest"; en plurals at count 1 (template concern), basis_none / limit_recomputed wording; limit_registry_scope duplicates appendix_scope_text; forbidden-term test could add 数据库/生成/配置/软件/网络/支持.
- T4: logo file-name case handling undocumented; PNG-wins-over-SVG not asserted; UnsupportedLogo gives no reason and the wrapped message repeats "theme"; Parse tests do not assert the path; colour list in validate duplicates the struct.
- T5: engine rebuilt per render (fonts re-parsed); num assumes integers; determinism only checked within one process.
- T5: move `muted` into lib/theme.typ so header/footer/chapters share it; logo-in-preview test asserts only a PNG signature.
- T6: chip-key test does not assert the display-label path is unused; count assertions match small integers trivially; zero-findings negative assertion could pass vacuously.
- T7: rank-order test uses substring find positions; status-label hard-codes the known key list; magic numbers 12 and 40 in remediation.typ.
- T8: a hairline sits between a finding row and its own image sub-row, and the pair can split across a page; long-id test lacks a positive full-render assertion; loose `+5` substring.
- T9: `identifier`/`secondary`/header closure duplicated between images.typ and inventory.typ (hoist to lib/theme.typ); empty-description sub-row omission untested; finding row + description sub-row can split across pages; RenderOptions built inline in tests.
- T10: score-sources table reuses the section title as its column header (add a `col_source` key); engine test stub strips parts by string replacement; footer substring match.
- T11: render-data now also validates outputs (consequence of the shared helper; acceptable); check output format changed (documented).
- T12: docs mention "plan 4" (internal reference; fix in Task 13); the 100 MB/1 000 slope is an extrapolation from one point (hedged); CI perf job runs both tests concurrently (document).
- parked: `Logo.PNG` upper-case extension rejected; 6 pt gutter indent when there is no theme logo; README placement of the report.logo note; render-data users must copy report-logo.<ext> into the template root.
