#import "parts/appendix.typ": appendix
#import "parts/images.typ": images
#import "parts/inventory.typ": inventory
#import "parts/remediation.typ": remediation
#import "parts/summary.typ": summary
#import "lib/fmt.typ": t
#import "parts/cover.typ": cover
#let data = json("data.json")
#set document(title: data.strings.report_title, date: none)
#set page(
  paper: "a4",
  margin: (x: 16mm, top: 22mm, bottom: 20mm),
  header: text(size: 8pt, fill: rgb(data.theme.colors.muted))[
    #data.strings.report_title #h(1fr) #data.meta.organisation
  ],
  footer: context text(size: 8pt, fill: rgb(data.theme.colors.muted))[
    #data.meta.generated_date #h(1fr)
    #t(data.strings, "page_of", page: counter(page).get().first(), total: counter(page).final().first())
  ],
)
#set text(
  font: data.theme.fonts.text,
  size: 8.5pt,
  fill: rgb(data.theme.colors.ink),
  lang: if data.meta.language == "zh-TW" { "zh" } else { "en" },
  region: if data.meta.language == "zh-TW" { "TW" } else { none },
)
#set par(justify: false)
#set heading(numbering: none)
#show heading.where(level: 1): it => block(below: 12pt)[#text(size: 22pt, weight: "bold", it.body)]
#show heading.where(level: 2): it => block(above: 6pt, sticky: true)[#text(weight: "semibold", it.body)]
#page(header: none, footer: none)[#cover(data)]

#page[
  #heading(level: 1, outlined: false, t(data.strings, "toc_title"))
  #show outline.entry.where(level: 2): it => {
    set text(font: data.theme.fonts.mono)
    it
  }
  #outline(title: none, depth: 2, indent: 1.2em)
]

#summary(data)

#remediation(data)

#inventory(data)

#images(data)

#appendix(data)
