#import "../lib/fmt.typ": t, num, breakable-id
#import "../lib/theme.typ": chip, hairline-table, identifier, secondary, muted, header

#let inventory(data) = {
  pagebreak(weak: true)
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_inventory"))
  secondary(theme, tr(if data.filters.min_severity_key != "" { "inventory_lede_floor" } else { "inventory_lede" }, count: num(data.inventory.len() + data.inventory_omitted), band: data.filters.min_severity_label))
  v(10pt)
  if data.inventory.len() == 0 {
    secondary(theme, tr(if data.filters.min_severity_key != "" { "filters_none_at_floor" } else { "no_findings" }, band: data.filters.min_severity_label))
  } else {
    hairline-table(theme,
      columns: (2.9cm, 1.9cm, 1cm, 1fr, 3.2cm, 1.2cm),
      align: (left, left, right, left, left, right),
      table.header(..("col_id", "col_severity", "col_cvss", "col_package", "col_fixed", "col_images").map(key => header(theme, tr(key)))),
      ..data.inventory.map(row => (
        identifier(theme, row.id), chip(theme, row.severity_label, row.severity_key),
        row.score, text(hyphenate: false, breakable-id(row.packages)),
        identifier(theme, row.fixed_versions), num(row.image_count),
      ).map(cell => table.cell(stroke: (bottom: none), cell)) + (
        table.cell(colspan: 6, align: left)[
          #text(size: 7pt, fill: rgb(theme.colors.muted))[
            #tr("inventory_affected") #identifier(theme, row.images.slice(0, calc.min(20, row.images.len())).join(" · "))#if row.images.len() > 20 { " · +" + num(row.images.len() - 20) }
          ]
        ],
      )).flatten())
  }
  if data.inventory_omitted > 0 {
    secondary(theme, tr(if data.filters.json_artifact { "filters_rows_omitted_json" } else { "filters_rows_omitted" }, count: num(data.inventory_omitted)))
  }
}
