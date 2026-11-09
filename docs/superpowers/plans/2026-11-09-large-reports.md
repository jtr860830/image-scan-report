# Large Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep a single report readable when one scope is large (issue #11): a severity floor, a lighter per-image chapter, and a row cap that points at the JSON artifact for the rest — while the summary keeps counting everything and the PDF says what was left out.

**Architecture:** Three new `report` settings flow from `ReportConfig` through `RenderOptions` into `render::model::build`, which already owns the shape of every chapter. The summary is built from the full finding set; the inventory, remediation and per-image chapters are built from a filtered and capped view, and a new `Filters` block in `RenderData` records what was omitted so the templates can say so. The JSON artifact (`report.json`) is the normalised `Report` and stays complete. No new output type (CSV was considered and dropped: the JSON already carries every row).

**Tech Stack:** Rust 2024, serde (YAML config), Typst templates under `assets/templates/`, bundled strings `assets/strings/{en,zh-TW}.json`, insta golden snapshots.

**Spec:** GitHub issue #11 and `docs/superpowers/specs/2026-11-07-product-redesign-design.md` (six chapters; the report is audit evidence, so omissions must be stated).

## Global Constraints

- Defaults preserve today's output byte for byte: with none of the three settings set, `cargo test --offline --test golden` passes unchanged and the previews are identical.
- Summary tiles, severity bar, fact boxes and ranking tables always count the **full** report; filters affect inventory, remediation and per-image chapters only. Wherever a chapter is partial, the PDF says what is omitted and that the JSON artifact (when `report.json` is on) holds everything.
- Unrated findings are never dropped by `min_severity` (an unknown is not a low).
- English with British spelling in code and docs; both languages get every new string (`tests/strings.rs` completeness test must pass); Google Rust Style Guide; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --offline` clean after every task.
- The product name literal stays only in `src/main.rs`.
- `docs/superpowers/**` is historical: append checkmarks only.
- Breaking changes: none intended; new settings are optional with defaults.

## Decisions taken in this plan (my calls — review first)

| Topic | Decision |
|---|---|
| `report.min_severity` | Optional, one of `critical`, `high`, `medium`, `low`; omitted = no floor. Drops findings strictly below the floor from inventory, remediation and per-image tables; Unrated always kept. |
| `report.image_detail` | `full` (default, today's chapter) or `counts` (per image: the metadata card and severity counts only, no finding rows; the inventory's "affected images" lines remain the cross-reference). The issue's `critical_high_only` is covered by `min_severity`, and its `table` mode by the existing `describe_severities: []`; neither gets a second spelling. |
| `report.max_table_rows` | Optional positive integer; caps the inventory table and each per-image table to the first N rows in their existing sort order; omitted = no cap. |
| Where omissions are stated | Summary: one line under the lede when any filter is active (`Inventory and image tables show Critical and above; 312 Medium/Low findings are counted above but not listed.`). Inventory lede and each capped table: `… and 1,204 more rows; the complete list is in the JSON artifact` (or without the JSON clause when `report.json` is off). Appendix "Method": a sentence restating the active filters. |
| JSON artifact | Unchanged and complete; `render-data` JSON gains `filters`. |
| CSV output | Not added (issue mentioned it; JSON already carries every row). Recorded in `docs/decisions.md`. |
| Validation | `max_table_rows: 0` is a configuration error (exit 2); unknown `image_detail` or `min_severity` values are parse errors (exit 2). |

## Review Focus

1. `min_severity: low` with findings that have no score and no label (Unrated): they must still appear in inventory and per-image tables. Test in Task 2.
2. `max_table_rows` smaller than the number of Critical rows: the cap applies after sorting, so the dropped rows are the least severe — assert the first row kept is the most severe and the "more rows" count equals total − N. Test in Task 2.
3. `image_detail: counts` combined with `max_table_rows`: no per-image table exists, so no per-image "more rows" line may appear, while the inventory still shows its own. Test in Task 3.
4. Both languages: every new string key present in `zh-TW.json` and rendered with Noto Sans TC without tofu — the strings completeness test plus a zh-TW render test that extracts the omission sentence. Test in Task 3.
5. Summary "filters active" line absent when nothing is configured — golden snapshots must not change. Task 3 Step 6.

---

### Task 1: Configuration and render options

**Files:**
- Modify: `src/config.rs` (`ReportConfig`: three fields, defaults, validation; a new `ImageDetail` enum)
- Modify: `src/pipeline.rs` (`render_options`)
- Modify: `src/render/model.rs` (`RenderOptions`: three fields; `Default` impl)
- Test: `tests/config.rs`, `src/config.rs` unit tests if the file already has them

**Interfaces:**
- Produces in `config`:
  ```rust
  /// How much of each image's findings the per-image chapter shows.
  #[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
  #[serde(rename_all = "snake_case")]
  pub enum ImageDetail { #[default] Full, Counts }

  // in ReportConfig, all with serde defaults:
  /// Findings below this band are left out of the inventory, remediation and image tables;
  /// `None` keeps every band. Unrated findings are always kept.
  pub min_severity: Option<Severity>,
  /// Per-image chapter content; defaults to `Full`.
  pub image_detail: ImageDetail,
  /// Maximum rows in the inventory table and in each image table; `None` means no cap.
  pub max_table_rows: Option<usize>,
  ```
  `validate` rejects `max_table_rows == Some(0)` with `ConfigError::Invalid("report.max_table_rows must be at least 1")`.
- Produces in `render::model::RenderOptions`: `min_severity: Option<Severity>`, `image_detail: ImageDetail` (re-export or move the enum so `render` does not depend on `config`; put the enum in `crate::model` next to `Severity` and have `config` use it), `max_table_rows: Option<usize>`.
- Consumes: `Severity` (`crate::model`), which already deserialises from YAML (`describe_severities`) and implements `Ord` with Critical highest.

- [ ] **Step 1: Write the failing config tests in `tests/config.rs`**

Follow the file's existing table-driven pattern (`("describe_severities: [critical, high, medium]", "ok")`). Add rows: `("min_severity: high", "ok")`, `("min_severity: unrated", "parse")`, `("min_severity: nonsense", "parse")`, `("image_detail: counts", "ok")`, `("image_detail: table", "parse")`, `("max_table_rows: 200", "ok")`, `("max_table_rows: 0", "invalid")`. Extend the defaults assertion: `min_severity == None`, `image_detail == ImageDetail::Full`, `max_table_rows == None`. (`min_severity: unrated` is a parse error because the floor is a band, and Unrated is not a band — if `Severity`'s serde accepts `unrated`, make `min_severity` its own validation error instead and say so in the report.)

- [ ] **Step 2: Run them and confirm failure**

Run: `cargo test --offline --test config`
Expected: compile error (unknown fields).

- [ ] **Step 3: Implement the fields, the enum and validation; thread them through `render_options`**

- [ ] **Step 4: Run the config tests and the full suite**

Run: `cargo test --offline --test config && cargo test --offline`
Expected: PASS; golden unchanged because `RenderOptions` defaults are the old behaviour.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/pipeline.rs src/render/model.rs src/model tests/config.rs
git commit -m "Add min_severity, image_detail and max_table_rows report settings"
```

---

### Task 2: Filtering, capping and omission facts in the render model

**Files:**
- Modify: `src/render/model.rs` (`build`, `image_details`, new `Filters` struct in `RenderData`, new `omitted` fields on `ImageDetail` and `RenderData.inventory_omitted`)
- Test: `tests/render_model.rs`

**Interfaces:**
- Produces in `render::model`:
  ```rust
  /// What the configured filters left out of the inventory, remediation and image chapters.
  #[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
  pub struct Filters {
      /// Lowercase key of the severity floor (`critical`…`low`), or empty when none.
      pub min_severity_key: String,
      /// English label of the floor, or empty.
      pub min_severity_label: String,
      /// Findings below the floor that the summary counts but the tables omit.
      pub hidden_findings: usize,
      /// `full` or `counts`.
      pub image_detail: String,
      /// Row cap, or 0 when none.
      pub max_table_rows: usize,
      /// Whether a JSON artifact is written alongside, so the omission text can point at it.
      pub json_artifact: bool,
      /// True when any of the above changes the output; templates key on this.
      pub active: bool,
  }
  ```
  `RenderData` gains `filters: Filters` and `inventory_omitted: usize` (rows cut from the inventory by the cap). `ImageDetail` gains `findings_omitted: usize` and `show_findings: bool` (false under `image_detail: counts`). `RenderOptions` gains `json_artifact: bool` (set by `pipeline::render_options` from `cfg.report.json`).
- Consumes: `RenderOptions` fields from Task 1.

- [ ] **Step 1: Write the failing tests in `tests/render_model.rs`**

Using the existing fixture helpers (`data::fixture_report(3)` or a hand-built `Report` with known severities):

```rust
#[test]
fn min_severity_hides_lower_bands_but_keeps_unrated_and_summary_counts() {
    // report: 2 critical, 3 high, 4 medium, 5 low, 1 unrated across two images
    // opts.min_severity = Some(Severity::High)
    // assert inventory has 2+3+1 rows; every image's findings have no medium/low;
    // summary.counts.medium == 4 and .low == 5 still; filters.hidden_findings == 9;
    // filters.active && filters.min_severity_key == "high"
}
#[test]
fn max_table_rows_caps_after_sorting_and_counts_the_rest() {
    // 7 inventory rows, opts.max_table_rows = Some(3): inventory.len() == 3,
    // inventory[0].severity_key == "critical", inventory_omitted == 4;
    // for an image with 5 findings: findings.len() == 3, findings_omitted == 2
}
#[test]
fn image_detail_counts_drops_rows_but_keeps_counts() {
    // opts.image_detail = Counts: every image.findings is empty, show_findings == false,
    // findings_omitted == 0, counts unchanged; inventory unaffected
}
#[test]
fn no_filters_means_inactive_and_zero_omissions() {
    // defaults: filters == Filters::default() with image_detail "full", active == false
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --offline --test render_model`
Expected: compile error on the new fields.

- [ ] **Step 3: Implement in `build`**

Build `let kept: Vec<&Finding>` = findings at or above the floor plus Unrated; use `kept` for `unique_vulnerabilities`, `grouped` (hence remediation and image details) and the remediation totals; keep `summary(report, …)` on the full report. Apply `max_table_rows` to the inventory after `unique_vulnerabilities` (it is already sorted) and to each image's sorted `findings`; record the omitted counts. `views::remediation_groups`, `views::fixable` and `views::image_summaries` take slices — pass the kept slice where the chapter is filtered and the full one for the summary.

- [ ] **Step 4: Run the model tests and the golden tests**

Run: `cargo test --offline --test render_model --test golden`
Expected: PASS, golden unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/render/model.rs src/pipeline.rs tests/render_model.rs
git commit -m "Filter and cap the detail chapters, keeping the summary complete"
```

---

### Task 3: Templates and strings say what was omitted

**Files:**
- Modify: `assets/templates/parts/summary.typ`, `inventory.typ`, `images.typ`, `appendix.typ`
- Modify: `assets/strings/en.json`, `assets/strings/zh-TW.json`
- Test: `tests/render_summary.rs`, `tests/render_inventory.rs`, `tests/render_images.rs`, `tests/render_appendix.rs`, `tests/strings.rs` (existing completeness test), `tests/golden.rs` (must stay green), `tests/previews.rs` (regenerate for inspection)

**Interfaces:**
- New string keys (both languages; English text given, zh-TW to match the register of the existing strings):
  - `filters_summary_note`: `Inventory, remediation and image tables show {band} and above; {count} lower findings are counted above but not listed.`
  - `filters_rows_omitted`: `… and {count} more rows`
  - `filters_rows_omitted_json`: `… and {count} more rows; the complete list is in the JSON artifact`
  - `filters_image_counts_only`: `Findings are listed per vulnerability in the inventory; this report shows counts per image.`
  - `filters_method_note`: `Filters applied: {details}.` where `{details}` is assembled in Typst from the active parts (`minimum severity {band}`, `image chapter counts only`, `at most {n} rows per table`), joined with `; `.
- Consumes: `data.filters`, `data.inventory_omitted`, `image.findings_omitted`, `image.show_findings` from Task 2.

- [ ] **Step 1: Write the failing render tests**

In each chapter test file, one test that sets the relevant `RenderOptions` on `fixture_data`, renders, extracts text and asserts the English sentence (with numbers formatted by `num`) appears — summary note (`render_summary.rs`), inventory omitted line with and without `json_artifact` (`render_inventory.rs`), per-image omitted line under a cap and its absence under `image_detail: counts` plus the `filters_image_counts_only` sentence (`render_images.rs`), the method note (`render_appendix.rs`). One zh-TW test in `render_summary.rs` asserting the zh-TW note text. Add the five keys to the strings completeness expectations if the test enumerates keys.

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --offline --test render_summary --test render_inventory --test render_images --test render_appendix --test strings`
Expected: FAIL — strings missing, text absent.

- [ ] **Step 3: Implement the templates and strings**

Summary: after the lede, `if data.filters.active and data.filters.hidden_findings > 0 { secondary(theme, tr("filters_summary_note", band: …, count: num(…))) }`. Inventory: after the table, the omitted line when `data.inventory_omitted > 0`, choosing the JSON variant by `data.filters.json_artifact`. Images: when `image.show_findings` is false, render the metadata card and counts and one `filters_image_counts_only` line instead of the table; when a table is capped, the omitted line below it. Appendix "Method": the `filters_method_note` sentence when `data.filters.active`. Keep the existing `hairline-table` and typography helpers; no new styles.

- [ ] **Step 4: Run the chapter tests, strings, golden and previews**

Run: `cargo test --offline --test render_summary --test render_inventory --test render_images --test render_appendix --test strings --test golden --test previews`
Expected: PASS; golden unchanged (defaults); previews regenerated under `target/visual/` for the controller to look at.

- [ ] **Step 5: Render one filtered report for visual inspection**

Run: `cargo run --offline --release -- run --config <scratch config with min_severity: high, image_detail: counts, max_table_rows: 50, json: true>` on `tests/fixtures/trivy` and rasterise the summary, inventory and one image page (controller step; see `docs/design/README.md` for tools).
Expected: the three omission sentences read naturally in both languages; no tofu.

- [ ] **Step 6: Commit**

```bash
git add assets/templates assets/strings tests
git commit -m "State omitted findings and rows in the summary, inventory, images and appendix"
```

---

### Task 4: Documentation

**Files:**
- Modify: `README.md` (configuration table: three new `report` keys with defaults and the Unrated rule; a short "Large reports" paragraph under the report section pointing at `docs/container.md#resources` for sizing)
- Modify: `CHANGELOG.md` `[Unreleased]` → `### Added`
- Modify: `docs/decisions.md` (entry: summary stays complete, Unrated never filtered, CSV not added because JSON carries every row, chunked rendering still shelved — link to issue #11)
- Modify: `deploy/examples/config.yaml` (the three keys, commented out, with one-line comments)

- [ ] **Step 1: Write the documentation**
- [ ] **Step 2: Check** — `grep -n 'min_severity\|image_detail\|max_table_rows' README.md CHANGELOG.md docs/decisions.md deploy/examples/config.yaml` shows each key documented once in README and mentioned in the other three; every relative link resolves.
- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md docs/decisions.md deploy/examples/config.yaml
git commit -m "Document the large-report settings"
```

---

## Self-review notes

- Spec coverage: #11's three knobs → Tasks 1–3; "document the memory rule of thumb" was done in PR #19; CSV deliberately not implemented (Decisions table, Task 4 records it).
- Type consistency: `ImageDetail` lives in `crate::model` (Task 1) and is consumed by `config`, `render::model` (Tasks 1–2) and serialised as `full`/`counts` strings in `Filters` (Task 2) for the templates (Task 3).
- Review Focus 1–5 each name a test above; item 5 is the golden suite run in Tasks 1–3.
- Proportion: the plan names signatures and tests, not bodies; the one algorithmic choice (filter before grouping, cap after sorting) is stated once in Task 2 Step 3.
