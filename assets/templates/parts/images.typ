#import "../lib/fmt.typ": t, num, breakable-id
#import "../lib/theme.typ": chip, section-title, hairline-table, card, identifier, secondary, muted, header

#let images(data) = {
  pagebreak(weak: true)
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_images"))
  if data.filters.image_detail == "counts" {
    secondary(theme, tr("filters_image_counts_only"))
  }
  for (i, image) in data.images.enumerate() {
    if i > 0 { v(12pt) }
    block(breakable: false)[
    #heading(level: 2, text(size: 13pt, identifier(theme, image.reference)))
    #text(size: 8pt)[
      #grid(
        columns: (3.6cm, 1fr), row-gutter: 3.5pt,
        ..((if image.show_tags { (("image_meta_tags", identifier(theme, image.tags.join(", "))),) } else { () }) + (
          ("image_meta_digest", identifier(theme, image.digest)),
          ("image_meta_platform", image.platform),
          ("image_meta_os", image.os),
          ("image_meta_size", image.size),
          ("image_meta_created", image.created_at),
          ("image_meta_scanned", image.scanned_at),
          ("image_meta_counts", {
            for key in ("critical", "high", "medium", "low", "unrated") {
              chip(theme, tr("tile_" + key) + " " + num(image.counts.at(key)), key)
              h(3pt)
            }
          }),
        )).map(pair => (text(fill: rgb(theme.colors.muted), tr(pair.at(0))), pair.at(1))).flatten()
      )
    ]
    ]
    if image.scan_state != "ok" {
      v(6pt)
      block(fill: rgb(theme.colors.tint_high), radius: 6pt)[
        #card(theme)[#text(fill: rgb(theme.colors.high), if image.scan_state == "not_scanned" { tr("scan_state_not_scanned") } else { tr("image_scan_failed", error: image.scan_error) })]
      ]
    } else if image.show_findings {
      section-title(theme, tr("image_findings_title"))
      if image.findings.len() == 0 {
        secondary(theme, tr("no_findings"))
      } else {
        hairline-table(theme,
          columns: (2.9cm, 1.9cm, 1cm, 1fr, 2.6cm, 2.6cm),
          align: (left, left, right, left, left, left),
          table.header(..("col_id", "col_severity", "col_cvss", "col_package", "col_installed", "col_fixed").map(key => header(theme, tr(key)))),
          ..image.findings.map(row => (
            identifier(theme, row.id), chip(theme, row.severity_label, row.severity_key),
            row.score, text(hyphenate: false, breakable-id(row.package)),
            identifier(theme, row.installed_version), identifier(theme, row.fixed_version),
          ).map(cell => table.cell(stroke: if (row.show_description and row.description != "") or row.basis in ("cvss2", "scanner_label") { (bottom: none) } else { (bottom: 0.4pt + rgb(theme.colors.rule)) }, cell)) + if not ((row.show_description and row.description != "") or row.basis in ("cvss2", "scanner_label")) { () } else {
            (table.cell(colspan: 6, [
              #if row.basis in ("cvss2", "scanner_label") {
                text(size: 6.5pt, fill: rgb(theme.colors.muted), box[
                  #if row.basis == "cvss2" { tr("basis_cvss2") } else { tr("basis_scanner_label") + row.scanner_severity }
                ])
                if row.show_description and row.description != "" { " · " }
              }
              #if row.show_description and row.description != "" {
                text(size: 7.5pt, fill: rgb(theme.colors.secondary), hyphenate: true, row.description)
              }
            ]),)
          }).flatten())
      }
      if image.findings_omitted > 0 {
        secondary(theme, tr(if data.filters.json_artifact { "filters_rows_omitted_json" } else { "filters_rows_omitted" }, count: num(image.findings_omitted)))
      }
    }
  }
}
