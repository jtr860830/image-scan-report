# Rendering Implementation Plan (plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `judex run` produces the six-chapter audit PDF in Traditional Chinese or English from the normalised report, using Typst embedded as a library, bundled open-source fonts, and a swappable theme.

**Architecture:** Rust builds a `RenderData` document (report facts + derived views + locale strings + theme values) and hands it to an embedded Typst engine as a virtual `data.json`; the Typst templates are static files compiled into the binary and are also compilable with the Typst CLI of the same version for design iteration (`judex render-data` writes the same `data.json` to disk). The engine runs single-threaded with PDF tagging off, as plan 1's benchmark established.

**Tech Stack:** Rust (existing crate), `typst` 0.15 + `typst-pdf` 0.15 via `typst-as-lib` 0.17 (`default-features = false`, no `packages` feature), `rayon` 1 (thread-pool size), `toml` 1 (theme files), dev: `lopdf` 0.47 (page counts), `pdf-extract` 0.12 (text assertions), `typst-render` 0.15 (PNG previews for humans), `insta`, `tempfile`. Fonts: Inter 4.1 (static TTF), Noto Sans TC (static subset OTF), Maple Mono NL (static TTF) — all OFL-1.1.

**Spec:** `docs/superpowers/specs/2026-11-07-product-redesign-design.md` — sections 4 (rendering behaviour, no packages), 8 (chapters), 9 (visual design), 10 (i18n), 11 (theming), 13 (`theme` config), 15 (golden and performance tests). Also read `docs/superpowers/plans/2026-11-07-core-pipeline-deferred.md` (plan-1 items this plan picks up: the `theme` config key; the PDF-only `check`/`run` mismatch).

## Global Constraints

- Everything plan 1 established still binds: product name only in `Cargo.toml [package] name`, the binary name and `PRODUCT_NAME`; library crate `image_scan_report`; English code, comments and repo docs; Apache-2.0; no network at run time; Codex-era build note — run cargo `--offline` after the controller fetches.
- Rendering settings (spec §4, measured): PDF tagging **off** (`PdfOptions { tagged: false, .. }`); monospace via `text(font: …)`, never `raw`; a rayon global pool of **1** thread, built before the first compile; **no Typst Universe packages** — the engine has no package resolver and the templates import only local files.
- Fonts (spec §9), static files only, bundled in the binary: Inter Regular/Medium/Bold (`Inter-Regular.ttf`, `Inter-Medium.ttf`, `Inter-Bold.ttf`), Noto Sans TC Regular/Medium/Bold (`NotoSansTC-Regular.otf`, `NotoSansTC-Medium.otf`, `NotoSansTC-Bold.otf`), Maple Mono NL Regular/Bold (`MapleMonoNL-Regular.ttf`, `MapleMonoNL-Bold.ttf`). Text font stack `("Inter", "Noto Sans TC")`, monospace `("Maple Mono NL", "Noto Sans TC")`. No system fonts are searched.
- Palette (spec §9, Open Color): ink `#212529`, secondary `#495057`, muted `#868e96`, rule `#e9ecef`, surface `#f8f9fa`, accent `#4263eb`; severity Critical `#6741d9`, High `#e03131`, Medium `#f08c00`, Low `#1c7ed6`, Unrated `#868e96`; tints violet `#f3f0ff`, red `#fff5f5`, yellow `#fff9db`, blue `#e7f5ff`, gray `#f1f3f5`. A severity colour never appears without its text label; numbers and labels are set in ink, the colour sits in a dot, bar or tinted chip beside them.
- Severity labels stay English (Critical / High / Medium / Low / Unrated) in both languages (spec §8). Scanner-supplied text (descriptions, package names, references) is printed verbatim and never translated or interpreted as markup.
- Page: A4, margins 16 mm sides / 22 mm top / 20 mm bottom, body 8.5 pt, running header "<report title> · <organisation>", footer "<report date> · n / total" (spec §8). Tables: hairline horizontal rules only, repeated header row, right-aligned tabular numerals.
- i18n (spec §10): string tables `strings/zh-TW.json` and `strings/en.json` with identical key sets; Taiwanese vocabulary (映像檔, 弱點, 套件, 修補版本, 稽核, 倉庫); ISO 8601 dates; `set text(lang: "zh", region: "TW")` for zh-TW, `lang: "en"` for en.
- Theme (spec §11): a directory with `theme.toml` (colours, font family names, product display name and URL) and an optional `logo.png|svg`; the default theme is embedded; `theme.path` in the config selects another; the theme contract is versioned (`version = 1` in `theme.toml`).
- Determinism: a PDF rendered twice from the same `Report` and the same `generated_at` is byte-identical (the PDF timestamp comes from `generated_at`; `ident` is the report's scope + source + date).
- Performance budget (spec §4): 30 000 findings render in under 90 s and 50 000 in under 150 s on the CI runner in release mode; memory is documented, not asserted.

## Review Focus

Inputs the spec implies but no happy-path task exercises; each has a pinned test in the owning task:

1. A run whose images have **zero findings** (e.g. only `busybox`): every chapter renders with its "no vulnerabilities" sentence, no empty-table panic, page count ≥ 4 (Task 11).
2. **Oversized strings** — a 6 000-character description, a 300-character package version, a 250-character image reference — must wrap or truncate inside the page; nothing overflows the page box and the page count stays finite (Task 9 for descriptions, Task 8 for identifiers).
3. **Characters outside the bundled fonts** (emoji, rare CJK, zero-width and control characters inside a description) must not abort the render; control characters are stripped before the data reaches Typst (Task 2).
4. **Missing optional facts** — no digest, no OS, no size, no scan time, no fixed version, `Unrated` severity, an `Other("…")` fix status — print the locale's placeholder "—"/"未提供" and never the word `none`/`null` (Task 2 + Task 9).
5. **Theme errors** — `theme.path` pointing at a directory without `theme.toml`, a `theme.toml` with an unknown key or a bad colour, a logo that is neither PNG nor SVG — fail at config load with exit 2 and a message naming the file (Task 4).

---

### Task 1: Bundle the fonts and third-party notices

**Files:**
- Create: `assets/fonts/{Inter-Regular,Inter-Medium,Inter-Bold}.ttf`, `assets/fonts/{NotoSansTC-Regular,NotoSansTC-Medium,NotoSansTC-Bold}.otf`, `assets/fonts/{MapleMonoNL-Regular,MapleMonoNL-Bold}.ttf`, `assets/fonts/README.md`, `assets/fonts/LICENSE-Inter.txt`, `assets/fonts/LICENSE-NotoSansTC.txt`, `assets/fonts/LICENSE-MapleMono.txt`, `THIRD_PARTY_NOTICES.md`, `src/render/mod.rs`, `src/render/fonts.rs`, `tests/fonts.rs`
- Modify: `Cargo.toml` (dependencies `typst = "0.15"`, `typst-as-lib = { version = "0.17", default-features = false }`, `typst-pdf = "0.15"`, `rayon = "1"`, `toml = "1"`; dev `lopdf = "0.47"`, `pdf-extract = "0.12"`, `typst-render = "0.15"`), `src/lib.rs` (`pub mod render;`)

**Interfaces:**
- Produces: `render::fonts::embedded_fonts() -> &'static [(&'static str, &'static [u8])]` (file name, bytes, `include_bytes!`), `render::fonts::font_book() -> typst::text::FontBook` built from them, `render::fonts::FAMILIES: [&str; 3] = ["Inter", "Noto Sans TC", "Maple Mono NL"]`.

- [ ] **Step 1: Download the font files** — Inter 4.1 release zip (`extras/ttf/Inter-Regular.ttf` etc.), `notofonts/noto-cjk` `Sans/SubsetOTF/TC/NotoSansTC-{Regular,Medium,Bold}.otf`, Maple Mono latest `MapleMonoNL-TTF.zip` (`MapleMonoNL-Regular.ttf`, `MapleMonoNL-Bold.ttf`). Record each source URL, version and SHA-256 in `assets/fonts/README.md`; copy each project's OFL licence file beside them. The controller does the download (the implementer sandbox has no network) and the implementer verifies the hashes.
- [ ] **Step 2: Write the failing test**
```rust
// tests/fonts.rs
#[test] fn bundled_fonts_cover_three_families_with_regular_and_bold() {
    let book = image_scan_report::render::fonts::font_book();
    for family in image_scan_report::render::fonts::FAMILIES {
        let weights: Vec<_> = book.families().find(|(name, _)| *name == family).expect(family).1.map(|i| i.variant.weight).collect();
        assert!(weights.contains(&typst::text::FontWeight::REGULAR), "{family} regular");
        assert!(weights.contains(&typst::text::FontWeight::BOLD), "{family} bold");
    }
}
#[test] fn embedded_font_count_is_eight() { assert_eq!(image_scan_report::render::fonts::embedded_fonts().len(), 8); }
```
- [ ] **Step 3: Run to verify failure** — `cargo test --offline --test fonts` → compile error.
- [ ] **Step 4: Implement `src/render/fonts.rs`** (`typst::text::Font::iter(Bytes)` over each file; `FontBook::from_infos`), `src/render/mod.rs` with `pub mod fonts;`, `THIRD_PARTY_NOTICES.md` listing Typst (Apache-2.0), the three fonts (OFL-1.1), Open Color (MIT) and pointing at `cargo about` output for crates **(call: generating the crate list is plan 4)**.
- [ ] **Step 5: Run** → PASS. `cargo clippy --offline --all-targets -- -D warnings` clean.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat: bundle Inter, Noto Sans TC and Maple Mono NL with notices"`

---

### Task 2: Render data model

**Files:**
- Create: `src/render/model.rs`, `tests/render_model.rs`, `tests/snapshots/render_model__*.snap`

**Interfaces:**
- Consumes: `model::{Report, Image, Finding, Severity, ScanState, FixStatus}`, `views::*`, `render::strings::Strings` (Task 3 — this task defines the field as `BTreeMap<String, String>` and Task 3 fills it), `render::theme::Theme` (Task 4 — same approach: a `serde_json::Value` named `theme` here, replaced by the typed `Theme` in Task 4).
- Produces (all `Serialize`, `Debug`, `Clone`, `PartialEq`):

```rust
pub struct RenderOptions { pub language: Language, pub stale_after_days: u32, pub product_name: String, pub product_version: String, pub top_images: usize /* 10 */, pub top_findings: usize /* 15 */ }
pub struct RenderData {
    pub meta: Meta,                 // product_name, product_version, generated_at (RFC 3339), generated_date (YYYY-MM-DD), language ("zh-TW"|"en"), organisation, logo: Option<String> (data URI or file name, Task 4)
    pub source: SourceFacts,        // display_name, scanner_name, scanner_version, db_version, db_updated_at — each already a display string ("—" when absent)
    pub scope: String,
    pub summary: Summary,           // images_total, findings_total (rows), unique_total, counts: SeverityCounts, fixable, fixable_percent (0–100 integer), images_with_high_or_worse, bar: Vec<BarSegment{severity_label, percent: f32}>, top_images: Vec<ImageRow>, top_findings: Vec<UniqueRow>
    pub remediation: Remediation,   // groups: Vec<RemediationRow{package, fixed_version, resolves: SeverityCounts, images: Vec<String>}>, unfixable_total, unfixable_by_status: Vec<(String /*status label*/, usize)>
    pub inventory: Vec<UniqueRow>,  // id, severity_label, score ("9.8" or "—"), packages (joined ", "), fixed_versions (joined ", " or "—"), images: Vec<String>, image_count
    pub images: Vec<ImageDetail>,   // reference, tags, digest, platform, os, size ("184.6 MB" or "—"), created_at, scanned_at, scan_state ("ok"|"failed"|"not_scanned"), scan_error, scanner_version, counts, findings: Vec<FindingRow>
    pub appendix: Appendix,         // failed_images: Vec<(reference, error)>, stale_images: Vec<(reference, scanned_at)>, stale_after_days, severity_rule: Vec<(label, range)>, score_sources: Vec<(source, count)>, limitations: Vec<String> (keys into strings)
    pub strings: BTreeMap<String, String>,
    pub theme: serde_json::Value,
}
pub struct FindingRow { pub id, pub severity_label, pub severity_key /* "critical"… for colour lookup */, pub score, pub package, pub installed_version, pub fixed_version, pub fix_status: Option<String>, pub scanner_severity: Option<String>, pub basis: String, pub description: String /* control chars stripped, truncated to 1 200 chars with "…" */, pub links: Vec<String> }
pub fn build(report: &Report, opts: &RenderOptions, strings: BTreeMap<String, String>, theme: serde_json::Value) -> RenderData
pub fn sanitize(text: &str) -> String   // removes C0/C1 control characters except \n and \t, collapses \r\n to \n
pub fn format_size(bytes: Option<u64>) -> String   // "184.6 MB", "5.3 KB", "—"
```
Sorting inside `ImageDetail.findings`: severity desc, score desc (None last), id asc. `images` in the order of `views::image_summaries`. `fixable_percent` rounds half up. `inventory` is `views::unique_vulnerabilities`. `appendix.score_sources` counts `score_source` over findings.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn builds_from_trivy_fixtures_and_snapshots()   // run TrivyFileSource over fixtures/trivy, assemble a Report with generated_at 2026-11-08T00:00:00Z, build with en strings (empty map ok for this test) → insta::assert_json_snapshot! of (meta, summary, remediation.groups[..3], inventory[..3], images[0].reference, appendix)
#[test] fn placeholders_never_print_none()               // a Finding with every Option None and Unrated → score "—", fixed_version "—", fix_status None, basis "none"; ImageDetail with None digest/os/size/scanned_at → "—" each
#[test] fn sanitize_strips_control_characters()         // "a\u{0}b\u{7}c\r\nd\u{200B}" → "abc\nd\u{200B}" (zero-width stays; it is a valid char)
#[test] fn description_is_truncated()                   // 6 000 'x' → len 1 201 ending with '…'
#[test] fn format_size_cases()                          // 184_600_000 → "184.6 MB"; 5_400 → "5.3 KB"; None → "—"
#[test] fn bar_percents_sum_to_100()                    // counts 7/64/151/96/0 → segments sum within 0.01
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement.** - [ ] **Step 4: Run, accept snapshot, run again** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: render data model"`

---

### Task 3: Locale strings

**Files:**
- Create: `strings/zh-TW.json`, `strings/en.json`, `src/render/strings.rs`, `tests/strings.rs`

**Interfaces:**
- Produces: `render::strings::load(language: Language) -> BTreeMap<String, String>` (from `include_str!`), `render::strings::KEYS: &[&str]` (the complete key list, the single source of truth for the template).

Key set (exact): `report_title`, `cover_subtitle`, `cover_scope`, `cover_source`, `cover_images`, `cover_scan_range`, `cover_generated`, `ch_summary`, `ch_remediation`, `ch_inventory`, `ch_images`, `ch_appendix`, `toc_title`, `summary_lede` (template with `{images}` and `{unique}`), `tile_critical`…`tile_unrated` (5), `fact_fixable` (`{fixable}`, `{percent}`), `fact_high_or_worse` (`{count}`, `{total}`), `sec_top_images`, `sec_top_findings`, `col_image`, `col_id`, `col_severity`, `col_cvss`, `col_package`, `col_installed`, `col_fixed`, `col_images`, `col_count`, `col_status`, `col_scanned_at`, `col_error`, `remediation_lede`, `remediation_resolves` (`{critical}`, `{high}`, `{medium}`, `{low}`), `remediation_affects` (`{count}`), `remediation_unfixable_title`, `remediation_unfixable_lede` (`{count}`), `status_fixed`, `status_affected`, `status_will_not_fix`, `status_end_of_life`, `status_fix_deferred`, `status_under_investigation`, `status_other`, `inventory_lede` (`{count}`), `inventory_affected`, `image_meta_digest`, `image_meta_platform`, `image_meta_os`, `image_meta_size`, `image_meta_created`, `image_meta_scanned`, `image_meta_counts`, `image_findings_title`, `image_scan_failed` (`{error}`), `no_findings`, `appendix_method`, `appendix_scanner`, `appendix_db`, `appendix_tool`, `appendix_rule_title`, `appendix_rule_text`, `appendix_sources_title`, `appendix_scope_text`, `appendix_failed_title`, `appendix_stale_title` (`{days}`), `appendix_limitations_title`, `limit_recomputed`, `limit_sources_differ`, `limit_filled_scores`, `limit_coverage`, `limit_registry_scope`, `limit_no_history`, `placeholder` ("—"), `generated_by` (`{product}`, `{version}`), `page_of` (`{page}`, `{total}`), `basis_cvss3`, `basis_cvss2`, `basis_scanner_label`, `basis_none`, `scan_state_ok`, `scan_state_failed`, `scan_state_not_scanned`.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn both_locales_have_exactly_the_key_set()   // keys of zh-TW == keys of en == KEYS, no extras, no empties
#[test] fn zh_tw_uses_taiwanese_terms()              // zh-TW values contain 映像檔, 弱點, 套件, 修補版本, 稽核; and contain none of 镜像, 漏洞, 软件包 (simplified/mainland forms)
#[test] fn placeholders_match_between_locales()       // for each key, the set of {name} placeholders is identical in both files
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Write both JSON files and `strings.rs`.** zh-TW copy is Taiwanese (報告標題 `容器映像檔弱點掃描報告`, chapters `總覽`、`修補建議`、`弱點盤點`、`各映像檔明細`、`附錄`); en copy is plain professional English (`Container Image Vulnerability Scan Report`, `Summary`, `Remediation`, `Vulnerability Inventory`, `Image Details`, `Appendix`). - [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: zh-TW and en string tables"`

---

### Task 4: Theme

**Files:**
- Create: `themes/default/theme.toml`, `src/render/theme.rs`, `tests/theme.rs`, `tests/data/theme/{bad-colour,unknown-key,no-toml-dir/.keep,bad-logo/theme.toml,bad-logo/logo.gif}`
- Modify: `src/config.rs` (add `#[serde(default)] pub theme: ThemeConfig { path: Option<PathBuf> }` to `Config`; `deny_unknown_fields` stays), `examples/config.yaml` (add a commented `theme:` block)

**Interfaces:**
- Produces:
```rust
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)] #[serde(deny_unknown_fields)]
pub struct Theme { pub version: u32 /* must be 1 */, pub product: Product { name: String, url: Option<String> }, pub colors: Colors, pub fonts: Fonts, #[serde(skip)] pub logo: Option<Logo> }
pub struct Colors { ink, secondary, muted, rule, surface, accent, critical, high, medium, low, unrated, tint_critical, tint_high, tint_medium, tint_low, tint_unrated: String }  // each validated as #rrggbb
pub struct Fonts { pub text: Vec<String> /* ["Inter","Noto Sans TC"] */, pub mono: Vec<String> /* ["Maple Mono NL","Noto Sans TC"] */ }
pub struct Logo { pub file_name: String /* "logo.png" | "logo.svg" */, pub bytes: Vec<u8> }
pub fn default_theme() -> Theme                                     // parsed from include_str!("../../themes/default/theme.toml")
pub fn load(dir: Option<&Path>) -> Result<Theme, ThemeError>       // None → default; Some → dir/theme.toml (+ logo.png or logo.svg if present); errors name the file
#[derive(thiserror::Error, Debug)] pub enum ThemeError { Read(PathBuf, io::Error), Parse(PathBuf, String), Invalid(PathBuf, String), UnsupportedLogo(PathBuf) }
impl Theme { pub fn to_render_value(&self) -> serde_json::Value }   // the `theme` object Typst reads: colours, fonts, product, logo file name
impl From<ThemeError> for ConfigError  // → ConfigError::Invalid(message)
```
`themes/default/theme.toml` carries exactly the Global Constraints palette and font stacks, `product.name = "judex"` **(call: the default theme shows the working product name; the company edition overrides it)**, `product.url` empty.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn default_theme_matches_spec_palette()        // critical "#6741d9", high "#e03131", medium "#f08c00", low "#1c7ed6", accent "#4263eb"; fonts.text == ["Inter","Noto Sans TC"]
#[test] fn theme_dir_without_toml_is_read_error()      // tests/data/theme/no-toml-dir → ThemeError::Read naming theme.toml
#[test] fn unknown_key_is_parse_error()                // tests/data/theme/unknown-key
#[test] fn bad_colour_is_invalid()                     // "#12345" → Invalid mentioning the key
#[test] fn gif_logo_is_unsupported()                   // bad-logo → UnsupportedLogo
#[test] fn custom_theme_overrides_and_loads_png_logo() // a tempdir theme with a 1×1 PNG → logo Some, product name changed
#[test] fn config_accepts_theme_path()                 // YAML with `theme: { path: /x }` parses; absence → None
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement** (`toml::from_str`, colour regex-free check: 7 chars, `#`, hex digits). - [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: theme loading with the default Open Color theme"`

---

### Task 5: Typst engine and the document skeleton (cover, page frame)

**Files:**
- Create: `src/render/engine.rs`, `templates/report.typ`, `templates/lib/theme.typ`, `templates/lib/fmt.typ`, `templates/parts/cover.typ`, `tests/render_engine.rs`, `tests/support/pdf.rs` (shared test helpers: `page_count(&[u8]) -> usize` via lopdf, `text(&[u8]) -> String` via pdf-extract, `write_preview(name, &[u8], page)` → `target/visual/<name>-<page>.png` via typst-render is **not** possible from PDF bytes, so previews are produced by the engine's `render_png` below)
- Modify: `src/render/mod.rs` (`pub mod engine; pub mod model; pub mod strings; pub mod theme; pub fn render_pdf(...)`)

**Interfaces:**
- Produces:
```rust
pub struct Renderer { /* TypstEngine with static sources + fonts */ }
impl Renderer {
    pub fn new() -> Renderer                                             // embeds every templates/**/*.typ via include_str!, fonts from Task 1; builds the rayon pool (1 thread) once via std::sync::Once
    pub fn render_pdf(&self, data: &RenderData, generated_at: DateTime<Utc>) -> Result<Vec<u8>, RenderError>   // data → "data.json" static file; PdfOptions { tagged: false, timestamp: from generated_at, ident: Smart::Custom(format!("{}|{}|{}", data.scope, data.source.display_name, data.meta.generated_date)), ..Default }
    pub fn render_png(&self, data: &RenderData, page: usize, ppi: f32) -> Result<Vec<u8>, RenderError>          // typst-render, for previews and visual tests only (cfg(any(test, feature = "preview")))
}
#[derive(thiserror::Error, Debug)] pub enum RenderError { #[error("template compilation failed:\n{0}")] Compile(String) /* joined diagnostics with file:line */, #[error("PDF export failed: {0}")] Pdf(String), #[error("{0}")] Data(String) }
pub fn render_pdf(report: &Report, opts: &RenderOptions, theme: &Theme) -> Result<Vec<u8>, RenderError>      // in render/mod.rs: strings::load + model::build + Renderer (a process-wide OnceLock<Renderer>)
```
Template contract: `templates/report.typ` does `#let data = json("data.json")`, sets `document(title: data.strings.report_title, date: none)`, page A4 with the margins above, header/footer from `data.strings` and `data.meta`, `set text(font: data.theme.fonts.text, size: 8.5pt, lang/region from data.meta.language)`; `lib/theme.typ` exposes `sev-color(key)`, `sev-tint(key)`, `chip(label, key)`, `mono(body)`; `lib/fmt.typ` exposes `t(key, ..named)` (string lookup with `{name}` substitution), `num(n)` (thousands separators); `parts/cover.typ` renders the cover (organisation, optional logo, title, scope, source, image count, scan range, report date). This task renders cover + an empty body; chapters are added by Tasks 6–10 as `#import "parts/x.typ": x` lines.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn renders_cover_only_document()        // RenderData from Task 2's fixture build (en) → PDF starts with %PDF, page_count == 1, text contains "Container Image Vulnerability Scan Report" and the organisation
#[test] fn zh_tw_cover_uses_cjk_font()          // zh-TW data → text contains "容器映像檔弱點掃描報告"; PDF bytes contain "NotoSansTC"
#[test] fn render_is_deterministic()            // same data + generated_at twice → identical bytes
#[test] fn compile_error_names_file_and_line()  // a Renderer built with an injected broken template (test-only constructor `Renderer::with_sources(&[(path, src)])`) → RenderError::Compile containing "report.typ:" 
#[test] fn preview_png_is_written()             // render_png page 1 at 72 ppi → PNG signature; write to target/visual/cover.png
```
- [ ] **Step 2: Run to verify failure.** - [ ] **Step 3: Implement** engine (`TypstEngine::builder().with_static_source_file_resolver(...).with_static_file_resolver([("data.json", bytes)]).fonts(...)`; `rayon::ThreadPoolBuilder::new().num_threads(1).build_global()` inside `Once`), templates, `render_pdf`. - [ ] **Step 4: Run** → PASS; open `target/visual/cover.png` (the controller looks at it).
- [ ] **Step 5: Commit** — `git commit -am "feat: embedded Typst engine with the cover page"`

---

### Task 6: Summary chapter

**Files:**
- Create: `templates/parts/summary.typ`, `tests/render_summary.rs`
- Modify: `templates/report.typ` (import + `summary(data)` after the cover; `outline()` placeholder stays for Task 10)

Content (spec §8, mockup direction C): chapter heading; lede `summary_lede`; four tiles (Critical/High/Medium/Low) plus a smaller Unrated line when `counts.unrated > 0`, each tile a tinted rounded box with the count in ink at 32 pt and the label with a severity dot; the stacked bar (`rect` segments with 2 pt gaps, rounded ends, heights 8 pt) followed by a legend with dots; two fact boxes (`fact_fixable`, `fact_high_or_worse`); table `sec_top_images` (reference in mono, five numeric columns); table `sec_top_findings` (id mono, chip, score, package, fixed version mono, image count).

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn summary_page_has_counts_and_tables()   // fixture data (en) → page 2 text contains "Summary", the four labels, the total unique count, and the first top image reference
#[test] fn summary_handles_zero_findings()        // Report with one image and no findings → renders; text contains strings.no_findings; no panic on empty tables
#[test] fn summary_preview()                      // png page 2 → target/visual/summary.png
```
- [ ] **Step 2–4: fail → implement → pass**; controller views the PNG and compares against the mockup.
- [ ] **Step 5: Commit** — `git commit -am "feat: summary chapter"`

---

### Task 7: Remediation chapter

**Files:**
- Create: `templates/parts/remediation.typ`, `tests/render_remediation.rs`
- Modify: `templates/report.typ`

Content: lede; one block per `remediation.groups` entry (bold "package → fixed version" in mono, `remediation_resolves` with the four counts, `remediation_affects`, then the image list in mono at 7.5 pt, at most 12 shown then "+N"); a closing section `remediation_unfixable_title` with the by-status table (status label via `status_*` strings, count). Page break before the chapter; blocks may not split across pages (`block(breakable: false)`) unless taller than a page.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn remediation_lists_groups_in_rank_order()   // fixture data → text order: the first group's package appears before the second's (take both from RenderData)
#[test] fn remediation_unfixable_table_present()      // text contains strings.remediation_unfixable_title and a status label
#[test] fn remediation_preview()
```
- [ ] **Step 2–5** as above; commit `feat: remediation chapter`.

---

### Task 8: Vulnerability inventory chapter

**Files:**
- Create: `templates/parts/inventory.typ`, `tests/render_inventory.rs`
- Modify: `templates/report.typ`

Content: lede with the unique count; one table with repeated header: id (mono), chip, score, packages, fixed versions (mono), image count; under each row a second full-width row listing the affected images in mono 7 pt (`table.cell(colspan: 6)`), at most 20 then "+N". Columns: `(2.9cm, 1.5cm, 1cm, 1fr, 3.2cm, 1.2cm)`. Long identifiers must break: apply `text(hyphenate: false)` and insert zero-width break opportunities after `/`, `:`, `.`, `-`, `+`, `_` in mono cells via `lib/fmt.typ` `breakable-id(s)`.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn inventory_lists_every_unique_vulnerability()   // page count grows with inventory length; text contains the first and last inventory ids
#[test] fn long_identifiers_stay_inside_the_page()        // Review Focus 2: a RenderData with a 250-char reference and a 300-char version → renders, page width unchanged (lopdf MediaBox == A4 on every page), page count < 10
#[test] fn inventory_preview()
```
- [ ] **Step 2–5**; commit `feat: vulnerability inventory chapter`.

---

### Task 9: Per-image detail chapter

**Files:**
- Create: `templates/parts/images.typ`, `tests/render_images.rs`
- Modify: `templates/report.typ`

Content: one section per `images` entry (heading level 2 = the reference in mono, which the outline lists); metadata grid (`image_meta_*` keys; digest full, platform, OS, size, created, scanned, counts as chips); when `scan_state != "ok"` a tinted callout with `image_scan_failed`; else the findings table (id, chip, score, package, installed, fixed) with repeated header; when no findings, `no_findings`. Descriptions are **not** in this chapter (spec: truncated description belongs to the inventory? — **call:** descriptions appear only here, under each finding row as a 7.5 pt secondary-ink paragraph, truncated by Task 2 to 1 200 chars; the inventory stays compact).

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn image_sections_follow_summary_order()       // text order of references == RenderData.images order
#[test] fn failed_image_shows_error_callout()          // an image with scan_state "failed" and error "manifest unknown" → text contains the error
#[test] fn oversized_description_is_contained()        // Review Focus 2: 6 000-char description (already truncated by model) and a description with emoji + rare CJK (U+2A6A5) + U+200B → renders; no panic
#[test] fn optional_facts_show_placeholder()           // Review Focus 4: image with all None → text contains "—" at least 4 times in that section and never "none"/"null"
#[test] fn images_preview()
```
- [ ] **Step 2–5**; commit `feat: per-image detail chapter`.

---

### Task 10: Appendix, table of contents, running header/footer

**Files:**
- Create: `templates/parts/appendix.typ`, `tests/render_appendix.rs`
- Modify: `templates/report.typ` (outline after the cover: chapters + image sections, `depth: 2`; header/footer finalised with `page_of` and `generated_by`)

Content: method table (source, scanner, DB version/date, tool name/version); severity rule table (`appendix_rule_*`); score-source counts; scope text; failed images table; stale images table with the threshold; limitations list (six `limit_*` strings); `generated_by` line.

- [ ] **Step 1: Write the failing tests**
```rust
#[test] fn appendix_has_rule_and_limitations()      // last page text contains strings.appendix_rule_title, "9.0", all six limit_* strings
#[test] fn toc_lists_chapters_and_images()          // page 2 text contains the five chapter titles and the first image reference with page numbers
#[test] fn footer_shows_page_of_total()             // every page's text contains "1 / N"-style pattern for its index (check pages 1, 2, last)
#[test] fn stale_and_failed_tables_render()         // data with one stale and one failed image → both references on the last page
```
- [ ] **Step 2–5**; commit `feat: appendix and table of contents`.

---

### Task 11: Pipeline integration and `render-data`

**Files:**
- Modify: `src/pipeline.rs` (PDF artifact), `src/cli.rs` + `src/main.rs` (`RenderData { config: PathBuf, out: PathBuf }` subcommand), `src/config.rs` (nothing new beyond Task 4), `README.md`, `docs/development.md`, `examples/config-trivy-files.yaml` (`pdf: true`), `.gitignore` (`/templates/data.json`)
- Test: `tests/pipeline.rs` (replace `pdf_only_fails_with_exit_4`), `tests/cli.rs`

**Interfaces:**
- Consumes: `render::render_pdf(&Report, &RenderOptions, &Theme)`, `render::theme::load`.
- Produces: `run` emits `<base>.pdf` (`application/pdf`) when `report.pdf`; `RenderOptions` built from `ReportConfig` and `PRODUCT_NAME`/`PRODUCT_VERSION` (passed into `pipeline::run` as a `ProductInfo { name, version }` parameter so the library never hard-codes the name); `check` also loads the theme; `judex render-data --config c.yaml --out templates/data.json` writes `RenderData` JSON for `typst watch templates/report.typ` (document the CLI version pin: Typst CLI **0.15.1**, equal to the crate).

- [ ] **Step 1: Write the failing tests**
```rust
// tests/pipeline.rs
#[test] fn run_writes_pdf_and_json()                  // fixtures/trivy, pdf+json → both files exist; PDF page_count >= 6; JSON parses
#[test] fn run_with_zero_findings_renders()           // Review Focus 1: a tempdir with only fixtures/trivy/busybox-1.37.json → PDF with page_count >= 4, text contains no_findings
#[test] fn theme_path_errors_exit_2()                 // Review Focus 5: theme.path → tests/data/theme/unknown-key → RunError::Config, exit 2, message names theme.toml
// tests/cli.rs
#[test] fn render_data_subcommand_writes_json()       // judex render-data … → file exists, has "strings" and "theme" keys
#[test] fn run_default_config_produces_pdf()          // config with only pdf (default) → exit 0, .pdf written
```
- [ ] **Step 2–4: fail → implement → pass.** The `OnceLock<Renderer>` means the first render in a process pays template compilation once. Update README (quick start now yields a PDF; `theme` section; `render-data` + `typst watch` workflow), `docs/development.md` (template layout, string keys, how to add a locale, preview PNGs under `target/visual/`).
- [ ] **Step 5: Commit** — `git commit -am "feat: PDF output in run and the render-data command"`

---

### Task 12: Golden, visual-regression and performance tests

**Files:**
- Create: `tests/golden.rs`, `tests/perf.rs`, `tests/snapshots/golden__*.snap`, `.github/workflows/ci.yml` (add a `perf` job)

- [ ] **Step 1: Write the tests**
```rust
// tests/golden.rs
#[test] fn golden_text_zh_tw()   // fixtures/trivy → zh-TW PDF → insta::assert_snapshot!(text of pages 1..=3 and the last page, with the generated date replaced by <DATE>)
#[test] fn golden_text_en()
#[test] fn golden_page_count()   // zh-TW and en page counts snapshot
// tests/perf.rs
#[test] #[ignore = "release-mode budget; run with cargo test --release --test perf -- --ignored"]
fn thirty_thousand_findings_under_budget()   // replicate the Trivy fixture images until findings >= 30_000 (suffix references with -rN), render zh-TW, assert elapsed < 90 s and page_count > 400
#[test] #[ignore] fn fifty_thousand_findings_under_budget()   // >= 50_000, < 150 s
```
- [ ] **Step 2: Run** — `cargo test --offline --test golden`, accept snapshots, run again → PASS; `cargo test --offline --release --test perf -- --ignored` → PASS with the measured times printed; record the times and peak RSS (`/usr/bin/time -l` on macOS, `-v` on Linux) in `docs/development.md`.
- [ ] **Step 3: CI** — add a `perf` job that runs the two ignored tests in release mode on `ubuntu-latest`, not blocking merges (`continue-on-error: false` but on a `workflow_dispatch` + weekly schedule **(call)**).
- [ ] **Step 4: Commit** — `git commit -am "test: golden text snapshots and performance budget"`

---

### Task 13: Design pass against the mockup

**Files:**
- Modify: `templates/**/*.typ`, `themes/default/theme.toml` as needed
- Create: `docs/design/README.md` (where previews live, how to iterate with `typst watch`, the palette and type scale as implemented)

The controller renders every chapter preview (`target/visual/*.png`) from the fixture data in both languages and compares them with the accepted mockup direction C (`.superpowers/brainstorm/*/content/visual-style-c-maple.html` — not in the repo; the controller holds it) and the spec §9 rules: tinted rounded tiles and chips, hairline tables, numerals right-aligned, severity colour never alone, Chinese punctuation and line breaking acceptable, mono identifiers breakable. Findings go back to a fix round like any review; this task ends when the controller signs off the previews and the golden snapshots are re-accepted.

- [ ] **Step 1:** render previews for both languages (`cargo test --offline --test render_* -- --nocapture`), view them.
- [ ] **Step 2:** adjust templates; re-run golden tests, accept.
- [ ] **Step 3: Commit** — `git commit -am "style: align the report with the accepted visual direction"`

---

## Self-review notes

- Spec coverage: §4 (engine settings, no packages — T5), §8 chapters (T5–T10), §9 fonts/palette/rules (T1, T4, T5–T9, T13), §10 (T3, T5), §11 theme + `theme` key + versioned contract (T4, T11), §12 PDF artifact (T11), §13 `render-data`/`check` theme (T11), §15 golden + perf (T12). Plan-1 deferred items picked up: `theme` key (T4), PDF-only mismatch (T11 removes the exit-4 branch; `check` loads the theme).
- Type consistency: `RenderData`/`RenderOptions`/`FindingRow` (T2) used by T5–T11; `Theme::to_render_value` (T4) feeds `RenderData.theme`; `strings::load` (T3) feeds `RenderData.strings`; `Renderer::render_pdf`/`render_png` (T5) used by every template test; `render::render_pdf` (T5) used by T11.
- Review Focus → tests: 1 `summary_handles_zero_findings` + `run_with_zero_findings_renders`; 2 `long_identifiers_stay_inside_the_page` + `oversized_description_is_contained`; 3 `sanitize_strips_control_characters` + the emoji/rare-CJK case in T9; 4 `placeholders_never_print_none` + `optional_facts_show_placeholder`; 5 the four theme error tests + `theme_path_errors_exit_2`.
- Proportion: the plan fixes names, keys, columns and tests; template bodies are the implementer's.
