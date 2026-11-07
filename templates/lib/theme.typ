#let sev-color(theme, key) = rgb(theme.colors.at(key))
#let sev-tint(theme, key) = rgb(theme.colors.at("tint_" + key))
#let chip(theme, label, key) = box(
  fill: sev-tint(theme, key), radius: 3pt, inset: (x: 5pt, y: 2pt),
)[#box(circle(radius: 2pt, fill: sev-color(theme, key), stroke: none)) #text(fill: rgb(theme.colors.ink), label)]
#let mono(theme, body) = text(font: theme.fonts.mono, body)

#let section-title(theme, body) = block(above: 14pt, below: 6pt, sticky: true)[
  #text(size: 11pt, weight: "semibold", fill: rgb(theme.colors.ink), body)
]
#let hairline-table(theme, ..args) = {
  set table(
    stroke: (x, y) => (top: none, bottom: 0.4pt + rgb(theme.colors.rule), left: none, right: none),
    inset: (x: 4pt, y: 6pt),
  )
  table(..args)
}
#let tile(theme, label, key, count) = block(
  width: 100%, fill: sev-tint(theme, key), radius: 6pt, inset: 10pt,
)[
  #text(size: 30pt, weight: "bold", number-type: "lining", number-width: "tabular", str(count))
  #v(4pt)
  #box(circle(radius: 3.5pt, fill: sev-color(theme, key), stroke: none))
  #text(size: 8pt, fill: rgb(theme.colors.secondary), label)
]
#let fact-box(theme, number, sentence) = block(
  width: 100%, stroke: 0.4pt + rgb(theme.colors.rule), radius: 6pt, inset: 10pt,
)[
  #text(size: 14pt, weight: "bold", number-width: "tabular", str(number))
  #v(4pt)
  #text(fill: rgb(theme.colors.secondary), sentence)
]
