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
#page(header: none, footer: none)[#cover(data)]
