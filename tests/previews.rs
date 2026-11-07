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
            .render_pdf(&data, None, None, "2026-11-08T00:00:00Z".parse().unwrap())
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
            let png = renderer.render_png(&data, None, None, page, 110.0).unwrap();
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
                .render_pdf(&data, None, None, "2026-11-08T00:00:00Z".parse().unwrap())
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
                renderer.render_png(&data, None, None, page, 110.0).unwrap(),
            )
            .unwrap();
        }
    }
}

#[test]
fn theme_branding_previews() {
    use image_scan_report::render::theme;
    let mut data = data::fixture_data(Language::En, 3);
    let logo = theme::Logo {
        file_name: "logo.png".into(),
        bytes: pdf::LOGO_PNG.to_vec(),
    };
    let mut theme = theme::default_theme();
    theme.logo = Some(logo.clone());
    data.theme = theme.to_render_value();
    let renderer = Renderer::new();
    let bytes = renderer
        .render_pdf(
            &data,
            Some(&logo),
            None,
            "2026-11-08T00:00:00Z".parse().unwrap(),
        )
        .unwrap();
    let last = pdf::page_count(&bytes);
    assert_eq!(pdf::image_count(&bytes, 1), 0);
    assert!(pdf::image_count(&bytes, last as u32) > 0);
    std::fs::create_dir_all("target/visual").unwrap();
    for (name, page) in [("cover-theme", 1), ("appendix-theme", last)] {
        std::fs::write(
            format!("target/visual/{name}.png"),
            renderer
                .render_png(&data, Some(&logo), None, page, 110.0)
                .unwrap(),
        )
        .unwrap();
    }
}
