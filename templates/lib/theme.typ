#let sev-color(theme, key) = rgb(theme.colors.at(key))
#let sev-tint(theme, key) = rgb(theme.colors.at("tint_" + key))
#let chip(theme, label, key) = box(
  fill: sev-tint(theme, key), radius: 3pt, inset: (x: 5pt, y: 2pt),
)[#circle(radius: 2pt, fill: sev-color(theme, key)) #text(fill: rgb(theme.colors.ink), label)]
#let mono(theme, body) = text(font: theme.fonts.mono, body)
