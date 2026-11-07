use image_scan_report::{
    config::ReportConfig,
    model::{Language, Report},
    pipeline::assemble_report,
    render::{
        engine::Renderer,
        model::{self, RenderData, RenderOptions},
        strings, theme,
    },
    source::{ScanSource, trivy_file::TrivyFileSource},
};
#[path = "support/pdf.rs"]
mod pdf;

fn fixture(language: Language) -> (Report, RenderOptions, RenderData) {
    let report = assemble_report(
        TrivyFileSource {
            dir: "fixtures/trivy".into(),
        }
        .fetch()
        .unwrap(),
        &ReportConfig {
            language: language.clone(),
            organization: "Example Organisation".into(),
            logo: None,
            stale_after_days: 30,
            json: false,
            pdf: true,
        },
        "2026-11-08T00:00:00Z".parse().unwrap(),
    );
    let opts = RenderOptions {
        language: language.clone(),
        stale_after_days: 30,
        product_name: "judex".into(),
        product_version: "0.1.0".into(),
        top_images: 10,
        top_findings: 15,
    };
    let data = model::build(
        &report,
        &opts,
        strings::load(language),
        theme::default_theme().to_render_value(),
    );
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
