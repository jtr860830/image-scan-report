#import "../lib/fmt.typ": t, num, breakable-id
#import "../lib/theme.typ": chip, mono, hairline-table

#let inventory(data) = {
  pagebreak(weak: true)
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let secondary(body) = text(fill: rgb(theme.colors.secondary), body)
  let identifier(body) = text(hyphenate: false, mono(theme, breakable-id(body)))
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_inventory"))
  secondary(tr("inventory_lede", count: num(data.inventory.len())))
  v(10pt)
  if data.inventory.len() == 0 {
    secondary(tr("no_findings"))
  } else {
    let header(body) = text(size: 7.5pt, hyphenate: false, fill: rgb(theme.colors.muted), body)
    hairline-table(theme,
      columns: (2.9cm, 1.9cm, 1cm, 1fr, 3.2cm, 1.2cm),
      align: (left, left, right, left, left, right),
      table.header(..("col_id", "col_severity", "col_cvss", "col_package", "col_fixed", "col_images").map(key => header(tr(key)))),
      ..data.inventory.map(row => (
        identifier(row.id), chip(theme, row.severity_label, row.severity_key),
        row.score, text(hyphenate: false, breakable-id(row.packages)),
        identifier(row.fixed_versions), num(row.image_count),
        table.cell(colspan: 6, align: left)[
          #text(size: 7pt, fill: rgb(theme.colors.muted))[
            #tr("inventory_affected") #identifier(row.images.slice(0, calc.min(20, row.images.len())).join(" · "))#if row.images.len() > 20 { " · +" + num(row.images.len() - 20) }
          ]
        ],
      )).flatten())
  }
}
