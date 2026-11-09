#import "../lib/fmt.typ": t, num
#import "../lib/theme.typ": chip, mono, section-title, hairline-table, identifier, muted, header

#let appendix(data) = {
  pagebreak(weak: true)
  let a = data.appendix
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let present(parts) = {
    let values = parts.filter(value => value != "" and value != "—")
    if values.len() == 0 { "—" } else { values.join(" · ") }
  }
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_appendix"))
  section-title(theme, tr("appendix_method"))
  hairline-table(theme,
    columns: (3.6cm, 1fr),
    muted(theme, tr("appendix_scanner")), present((data.source.display_name, data.source.scanner_name, data.source.scanner_version)),
    muted(theme, tr("appendix_db")), present((data.source.db_version, data.source.db_updated_at)),
    muted(theme, tr("appendix_tool")), data.theme.product.name + " " + data.meta.product_version,
  )
  if data.filters.active {
    v(8pt)
    let details = ()
    if data.filters.min_severity_key != "" {
      details.push(tr("filters_min_severity", band: data.filters.min_severity_label))
    }
    if data.filters.image_detail == "counts" {
      details.push(tr("filters_image_counts"))
    }
    if data.filters.max_table_rows > 0 {
      details.push(tr("filters_max_rows", n: num(data.filters.max_table_rows)))
    }
    muted(theme, tr("filters_method_note", details: details.join(tr("filters_detail_sep"))))
  }
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
    table.header(header(theme, tr("col_source")), header(theme, tr("col_count"))),
    ..a.score_sources.map(row => (mono(theme, row.at(0)), num(row.at(1)))).flatten())
  v(8pt)
  par(tr("appendix_scope_text"))
  section-title(theme, tr("appendix_failed_title"))
  if a.failed_images.len() == 0 {
    muted(theme, "—")
  } else {
    hairline-table(theme,
      columns: (1fr, auto, 1fr),
      table.header(header(theme, tr("col_image")), header(theme, tr("col_status")), header(theme, tr("col_error"))),
      ..a.failed_images.map(row => (identifier(theme, row.reference), tr("scan_state_" + row.state), row.error)).flatten())
  }
  section-title(theme, tr("appendix_stale_title", days: a.stale_after_days))
  if a.stale_images.len() == 0 {
    muted(theme, "—")
  } else {
    hairline-table(theme,
      columns: (1fr, auto),
      table.header(header(theme, tr("col_image")), header(theme, tr("col_scanned_at"))),
      ..a.stale_images.map(row => (identifier(theme, row.at(0)), mono(theme, row.at(1)))).flatten())
  }
  section-title(theme, tr("appendix_limitations_title"))
  enum(..a.limitations.map(key => tr(key)))
  v(8pt)
  let credit = tr("generated_by", product: theme.product.name, version: data.meta.product_version)
  if theme.product.url != none and theme.product.url != "" {
    credit += " · " + theme.product.url
  }
  grid(columns: (auto, 1fr), column-gutter: 6pt, align: horizon,
    if theme.logo != none { image("/" + theme.logo, height: 6mm) },
    text(size: 8pt, fill: rgb(theme.colors.muted), credit))
}
