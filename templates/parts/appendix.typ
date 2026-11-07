#import "../lib/fmt.typ": t, num, breakable-id
#import "../lib/theme.typ": chip, mono, section-title, hairline-table

#let appendix(data) = {
  pagebreak(weak: true)
  let a = data.appendix
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let muted(body) = text(fill: rgb(theme.colors.muted), body)
  let identifier(body) = text(hyphenate: false, mono(theme, breakable-id(body)))
  let present(parts) = {
    let values = parts.filter(value => value != "" and value != "—")
    if values.len() == 0 { "—" } else { values.join(" · ") }
  }
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_appendix"))
  section-title(theme, tr("appendix_method"))
  hairline-table(theme,
    columns: (3cm, 1fr),
    muted(tr("appendix_scanner")), present((data.source.display_name, data.source.scanner_name, data.source.scanner_version)),
    muted(tr("appendix_db")), present((data.source.db_version, data.source.db_updated_at)),
    muted(tr("appendix_tool")), data.meta.product_name + " " + data.meta.product_version,
  )
  section-title(theme, tr("appendix_rule_title"))
  tr("appendix_rule_text")
  v(4pt)
  hairline-table(theme,
    columns: (1fr, auto), align: (left, right),
    ..a.severity_rule.map(row => (
      chip(theme, row.at(0), lower(row.at(0))), mono(theme, row.at(1)),
    )).flatten())
  section-title(theme, tr("appendix_sources_title"))
  hairline-table(theme,
    columns: (1fr, auto), align: (left, right),
    table.header(muted(tr("appendix_sources_title")), muted(tr("col_count"))),
    ..a.score_sources.map(row => (mono(theme, row.at(0)), num(row.at(1)))).flatten())
  v(8pt)
  par(tr("appendix_scope_text"))
  section-title(theme, tr("appendix_failed_title"))
  if a.failed_images.len() == 0 {
    muted("—")
  } else {
    hairline-table(theme,
      columns: (1fr, 1fr),
      table.header(muted(tr("col_image")), muted(tr("col_error"))),
      ..a.failed_images.map(row => (identifier(row.at(0)), row.at(1))).flatten())
  }
  section-title(theme, tr("appendix_stale_title", days: a.stale_after_days))
  if a.stale_images.len() == 0 {
    muted("—")
  } else {
    hairline-table(theme,
      columns: (1fr, auto),
      table.header(muted(tr("col_image")), muted(tr("col_scanned_at"))),
      ..a.stale_images.map(row => (identifier(row.at(0)), mono(theme, row.at(1)))).flatten())
  }
  section-title(theme, tr("appendix_limitations_title"))
  enum(..a.limitations.map(key => tr(key)))
  v(8pt)
  text(size: 8pt, fill: rgb(theme.colors.muted), tr("generated_by", product: data.meta.product_name, version: data.meta.product_version))
}
