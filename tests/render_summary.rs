use image_scan_report::{
    model::{Language, Report},
    render::{
        engine::Renderer,
        model::{self, RenderData, RenderOptions},
        strings, theme,
    },
};
#[path = "support/data.rs"]
mod data;
#[path = "support/pdf.rs"]
mod pdf;

fn fixture(language: Language) -> (Report, RenderOptions, RenderData) {
    let report = data::fixture_report(3);
    let opts = RenderOptions {
        language: language.clone(),
        stale_after_days: 30,
        product_name: "judex".into(),
        product_version: "0.1.0".into(),
        top_images: 10,
        top_findings: 15,
    };
    let data = data::fixture_data(language, 3);
    (report, opts, data)
}

#[test]
fn summary_page_has_counts_and_tables() {
    let (report, _, data) = fixture(Language::En);
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    assert!(pdf::page_count(&bytes) >= 2);
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let text = doc.extract_text(&[2]).unwrap();
    for key in [
        "ch_summary",
        "tile_critical",
        "tile_high",
        "tile_medium",
        "tile_low",
        "sec_top_images",
        "sec_top_findings",
    ] {
        assert!(text.contains(&data.strings[key]), "{key}: {text}");
    }
    assert!(
        text.replace(',', "")
            .contains(&data.summary.unique_total.to_string()),
        "{text}"
    );
    assert!(
        text.contains(&data.summary.top_images[0].reference),
        "{text}"
    );
    assert!(text.contains(&data.summary.top_findings[0].id), "{text}");
    for count in [data.summary.counts.critical, data.summary.counts.high] {
        assert!(text.replace(',', "").contains(&count.to_string()), "{text}");
    }
}

#[test]
fn summary_handles_zero_findings() {
    let (mut report, opts, _) = fixture(Language::En);
    report.images.truncate(1);
    report.findings.clear();
    let data = model::build(
        &report,
        &opts,
        strings::load(Language::En),
        theme::default_theme().to_render_value(),
    );
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let text = pdf::text(&bytes);
    assert!(text.contains(&data.strings["no_findings"]), "{text}");
    assert!(text.contains(&data.strings["sec_top_images"]));
    assert!(!text.contains(&data.strings["sec_top_findings"]));
    let fact = data.strings["fact_fixable"]
        .replace("{fixable}", "0")
        .replace("{percent}", "0");
    assert!(!text.contains(&fact), "{text}");
}

#[test]
fn summary_preview() {
    std::fs::create_dir_all("target/visual").unwrap();
    for (language, name) in [(Language::En, "en"), (Language::ZhTw, "zh")] {
        let (_, _, data) = fixture(language);
        let bytes = Renderer::new().render_png(&data, None, 2, 110.0).unwrap();
        assert!(bytes.starts_with(b"\x89PNG"));
        std::fs::write(format!("target/visual/summary-{name}.png"), &bytes).unwrap();
        if name == "en" {
            std::fs::write("target/visual/summary.png", bytes).unwrap();
        }
    }
}

#[test]
fn summary_severity_chips_use_keys_and_fit() {
    let (report, _, mut data) = fixture(Language::En);
    // Labels are display data, never color lookup keys.
    data.summary.bar[0].severity_label = "Display label".into();
    data.summary.top_findings.truncate(2);
    for (row, key) in data
        .summary
        .top_findings
        .iter_mut()
        .zip(["critical", "unrated"])
    {
        row.severity_key = key.into();
        row.severity_label = "Display label".into();
    }
    let renderer = Renderer::new();
    let bytes = renderer
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let text = pdf::text(&bytes);
    assert!(text.contains("Critical"));
    assert!(text.contains("Unrated"));
    std::fs::create_dir_all("target/visual").unwrap();
    std::fs::write(
        "target/visual/summary-chips.png",
        renderer.render_png(&data, None, 2, 110.0).unwrap(),
    )
    .unwrap();
}
