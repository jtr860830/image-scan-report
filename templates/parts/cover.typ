#import "../lib/fmt.typ": num
#let cover(data) = {
  let colors = data.theme.colors
  let strings = data.strings
  let dates = data.images.map(i => i.scanned_at).filter(d => d != "—").sorted()
  let scan-range = if dates.len() > 0 { dates.first() + " – " + dates.last() } else { "—" }
  v(18mm)
  text(fill: rgb(colors.muted), tracking: 1pt, data.meta.organisation)
  if data.theme.logo != none {
    v(8mm)
    image("/" + data.theme.logo, height: 14mm)
  }
  v(20mm)
  block(width: 100%)[#text(size: 26pt, weight: "bold", strings.report_title)]
  v(6mm)
  line(length: 100%, stroke: 3pt + rgb(colors.accent))
  v(14mm)
  grid(
    columns: (30mm, 1fr), column-gutter: 8mm, row-gutter: 6mm,
    text(fill: rgb(colors.muted), strings.cover_scope), [#data.scope],
    text(fill: rgb(colors.muted), strings.cover_source), [#data.source.display_name],
    text(fill: rgb(colors.muted), strings.cover_images), [#num(data.summary.images_total)],
    text(fill: rgb(colors.muted), strings.cover_scan_range), [#scan-range],
    text(fill: rgb(colors.muted), strings.cover_generated), [#data.meta.generated_date],
  )
}
