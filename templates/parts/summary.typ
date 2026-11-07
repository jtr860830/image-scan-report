#import "../lib/fmt.typ": t, num
#import "../lib/theme.typ": sev-color, chip, mono, section-title, hairline-table, tile, fact-box, secondary, header

#let summary(data) = {
  pagebreak(weak: true)
  let s = data.summary
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let keys = ("critical", "high", "medium", "low")
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_summary"))
  secondary(theme, tr("summary_lede", images: num(s.images_total), unique: num(s.unique_total)))
  v(10pt)
  if s.findings_total == 0 {
    secondary(theme, tr("no_findings"))
  }
  grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 8pt,
    ..keys.map(key => tile(theme, tr("tile_" + key), key, num(s.counts.at(key)))))
  if s.counts.unrated > 0 {
    v(5pt)
    chip(theme, tr("tile_unrated") + " " + num(s.counts.unrated), "unrated")
  }
  if s.findings_total > 0 {
    v(10pt)
    grid(columns: s.bar.map(segment => segment.percent * 1fr), gutter: 2pt,
      ..s.bar.map(segment => rect(width: 100%, height: 9pt, radius: 2pt,
        fill: sev-color(theme, segment.severity_key), stroke: none)))
    v(5pt)
    text(size: 7.5pt)[
      #for segment in s.bar {
        let key = segment.severity_key
        box[#box(circle(radius: 2.5pt, fill: sev-color(theme, key), stroke: none)) #tr("tile_" + key) #num(s.counts.at(key))]
        h(10pt)
      }
    ]
    v(10pt)
    grid(columns: (1fr, 1fr), gutter: 8pt,
      fact-box(theme, num(s.fixable), tr("fact_fixable", fixable: num(s.fixable), percent: s.fixable_percent)),
      fact-box(theme, num(s.images_with_high_or_worse), tr("fact_high_or_worse", count: num(s.images_with_high_or_worse), total: num(s.images_total))))
  }
  section-title(theme, tr("sec_top_images"))
  hairline-table(theme,
    columns: (1fr, auto, auto, auto, auto),
    align: (left, right, right, right, right),
    table.header(header(theme, tr("col_image")), ..keys.map(key => header(theme, tr("tile_" + key)))),
    ..s.top_images.map(row => (mono(theme, row.reference), ..keys.map(key => num(row.counts.at(key))))).flatten())
  if s.findings_total > 0 {
    section-title(theme, tr("sec_top_findings"))
    hairline-table(theme,
      columns: (2.8cm, 1.9cm, 1cm, 1fr, 3cm, 1.1cm),
      align: (left, left, right, left, left, right),
      table.header(..("col_id", "col_severity", "col_cvss", "col_package", "col_fixed", "col_images").map(key => header(theme, tr(key)))),
      ..s.top_findings.map(row => (
        mono(theme, row.id), chip(theme, tr("tile_" + row.severity_key), row.severity_key),
        row.score, row.packages, mono(theme, row.fixed_versions), num(row.image_count),
      )).flatten())
  }
}
