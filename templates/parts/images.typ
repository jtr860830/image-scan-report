#import "../lib/fmt.typ": t, num, breakable-id
#import "../lib/theme.typ": chip, mono, section-title, hairline-table, card

#let images(data) = {
  pagebreak(weak: true)
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let identifier(body) = text(hyphenate: false, mono(theme, breakable-id(body)))
  let secondary(body) = text(fill: rgb(theme.colors.secondary), body)
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_images"))
  for image in data.images {
    heading(level: 2, text(size: 13pt, identifier(image.reference)))
    text(size: 8pt)[
      #grid(
        columns: (3cm, 1fr), row-gutter: 3pt,
        ..(
          ("image_meta_digest", identifier(image.digest)),
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
        ).map(pair => (text(fill: rgb(theme.colors.muted), tr(pair.at(0))), pair.at(1))).flatten()
      )
    ]
    if image.scan_state != "ok" {
      v(6pt)
      block(fill: rgb(theme.colors.tint_high), radius: 6pt)[
        #card(theme)[#text(fill: rgb(theme.colors.high), tr("image_scan_failed", error: image.scan_error))]
      ]
    } else {
      section-title(theme, tr("image_findings_title"))
      if image.findings.len() == 0 {
        secondary(tr("no_findings"))
      } else {
        let header(body) = text(size: 7.5pt, hyphenate: false, fill: rgb(theme.colors.muted), body)
        hairline-table(theme,
          columns: (2.9cm, 1.9cm, 1cm, 1fr, 2.6cm, 2.6cm),
          align: (left, left, right, left, left, left),
          table.header(..("col_id", "col_severity", "col_cvss", "col_package", "col_installed", "col_fixed").map(key => header(tr(key)))),
          ..image.findings.map(row => (
            identifier(row.id), chip(theme, row.severity_label, row.severity_key),
            row.score, text(hyphenate: false, breakable-id(row.package)),
            identifier(row.installed_version), identifier(row.fixed_version),
          ) + if not row.show_description or row.description == "" { () } else {
            (table.cell(colspan: 6, text(size: 7.5pt, fill: rgb(theme.colors.secondary), hyphenate: true, row.description)),)
          }).flatten())
      }
    }
  }
}
