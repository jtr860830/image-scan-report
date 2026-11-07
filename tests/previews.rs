use image_scan_report::{model::Language, render::engine::Renderer};
#[allow(dead_code)]
#[path = "support/data.rs"]
mod data;
#[allow(dead_code)]
#[path = "support/pdf.rs"]
mod pdf;

#[test]
fn all_chapter_previews() {
    std::fs::create_dir_all("target/visual").unwrap();
    let renderer = Renderer::new();
    for (language, suffix) in [(Language::En, "en"), (Language::ZhTw, "zh")] {
        let mut data = data::fixture_data(language, 3);
        let bytes = renderer
            .render_pdf(&data, None, "2026-11-08T00:00:00Z".parse().unwrap())
            .unwrap();
        let pages = pdf::page_texts(&bytes);
        for (name, key) in [
            ("cover", "report_title"),
            ("toc", "toc_title"),
            ("summary", "ch_summary"),
            ("remediation", "ch_remediation"),
            ("inventory", "ch_inventory"),
            ("images", "ch_images"),
            ("appendix", "ch_appendix"),
        ] {
            let page = if name == "cover" {
                1
            } else if name == "toc" {
                2
            } else {
                pages
                    .iter()
                    .enumerate()
                    .skip(2)
                    .find(|(_, text)| text.contains(&data.strings[key]))
                    .unwrap()
                    .0
                    + 1
            };
            let png = renderer.render_png(&data, None, page, 110.0).unwrap();
            std::fs::write(format!("target/visual/{name}-{suffix}.png"), png).unwrap();
        }
        if suffix == "zh" {
            let prototype = data.remediation.groups[0].clone();
            data.remediation.groups = (0..35)
                .map(|i| {
                    let mut row = prototype.clone();
                    row.package = format!("package-{i:02}");
                    row
                })
                .collect();
            let bytes = renderer
                .render_pdf(&data, None, "2026-11-08T00:00:00Z".parse().unwrap())
                .unwrap();
            let pages = pdf::page_texts(&bytes);
            let page = pages
                .iter()
                .enumerate()
                .skip(2)
                .find(|(_, text)| text.contains(&data.strings["remediation_more_title"]))
                .unwrap()
                .0
                + 1;
            std::fs::write(
                "target/visual/remediation-table-zh.png",
                renderer.render_png(&data, None, page, 110.0).unwrap(),
            )
            .unwrap();
        }
    }
}
