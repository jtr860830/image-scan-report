# Report design

Regenerate all chapter previews in English and Traditional Chinese, plus the
35-group remediation table, with `cargo test --offline --test previews`.
PNGs live in `target/visual/` at 110 ppi: `cover`, `toc`, `summary`,
`remediation`, `inventory`, `images`, and `appendix`, suffixed `-en` or `-zh`.
The additional table preview is `remediation-table-zh.png`.

For interactive iteration, generate render data as described in the repository
README, place it at `templates/data.json`, then run from the repository root:

```sh
typst watch templates/report.typ --root templates templates/out.pdf --font-path assets/fonts --ignore-system-fonts
```

Edit chapter templates under `templates/parts/` and shared helpers in
`templates/lib/theme.typ`. Review both languages and regenerate previews and
golden snapshots after intentional layout changes.

The default palette comes from `themes/default/theme.toml`: ink #212529,
secondary #495057, muted #868e96, hairline #e9ecef, surface #f8f9fa,
accent #4263eb. Severity pairs are Critical #6741d9 / #f3f0ff,
High #e03131 / #fff5f5, Medium #f08c00 / #fff9db,
Low #1c7ed6 / #e7f5ff, and Unrated #868e96 / #f1f3f5.
Always accompany severity colour with its label. Tiles and chips use rounded,
tinted backgrounds; table numerals align right.

Text uses Inter with Noto Sans TC fallback; identifiers use Maple Mono NL with
Noto Sans TC fallback. Chapter headings are 22 pt, sections 11 pt, body 8.5 pt,
table headers 7.5 pt muted, sub-rows 7–7.5 pt, mono metadata 8 pt, and chips 7 pt.
Image headings are 13 pt; TOC image entries are 8.5 pt mono. Summary tile counts
are 30 pt bold. Identifiers may wrap at punctuation without visible hyphens.

Descriptions appear only for Critical/High findings and are capped at 600
characters. Remediation shows 30 cards, then a compact table for remaining groups.
