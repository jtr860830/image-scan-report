#import "../lib/fmt.typ": t, num, status-label
#import "../lib/theme.typ": mono, section-title, hairline-table, card

#let remediation(data) = {
  pagebreak(weak: true)
  let r = data.remediation
  let theme = data.theme
  let tr(key, ..args) = t(data.strings, key, ..args)
  let secondary(body) = text(fill: rgb(theme.colors.secondary), body)
  set text(number-width: "tabular")
  heading(level: 1, tr("ch_remediation"))
  secondary(tr("remediation_lede"))
  v(10pt)
  if r.groups.len() == 0 {
    secondary(tr("no_findings"))
  }
  for (i, group) in r.groups.enumerate() {
    if i > 0 { v(6pt) }
    card(theme, breakable: group.images.len() > 40)[
      #text(size: 10pt, weight: "semibold")[#mono(theme, group.package) → #mono(theme, group.fixed_version)]
      #v(3pt)
      #secondary[
        #tr("remediation_resolves", critical: num(group.resolves.critical), high: num(group.resolves.high), medium: num(group.resolves.medium), low: num(group.resolves.low))
        #tr("remediation_affects", count: num(group.images.len()))
      ]
      #v(3pt)
      #text(size: 7.5pt, fill: rgb(theme.colors.secondary))[
        #mono(theme, group.images.slice(0, calc.min(12, group.images.len())).join(" · "))#if group.images.len() > 12 { " · +" + num(group.images.len() - 12) }
      ]
    ]
  }
  section-title(theme, tr("remediation_unfixable_title"))
  secondary(tr("remediation_unfixable_lede", count: num(r.unfixable_total)))
  v(6pt)
  let header(body) = text(size: 7.5pt, fill: rgb(theme.colors.muted), body)
  hairline-table(theme,
    columns: (1fr, auto), align: (left, right),
    table.header(header(tr("col_status")), header(tr("col_count"))),
    ..r.unfixable_by_status.map(row => (status-label(data.strings, row.at(0)), num(row.at(1)))).flatten())
}
