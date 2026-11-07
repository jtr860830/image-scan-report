use image_scan_report::{
    model::Language,
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

fn render(data: &RenderData) -> Vec<u8> {
    Renderer::new()
        .render_pdf(data, None, "2026-11-08T00:00:00Z".parse().unwrap())
        .unwrap()
}

fn chapter(bytes: &[u8], title: &str) -> (usize, String) {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    let page = (3..=pdf::page_count(bytes) as u32)
        .find(|p| doc.extract_text(&[*p]).unwrap().contains(title))
        .unwrap();
    let pages: Vec<_> = (page..=pdf::page_count(bytes) as u32).collect();
    (page as usize, doc.extract_text(&pages).unwrap())
}
fn compact(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
        .collect()
}
#[test]
fn image_sections_follow_summary_order() {
    let data = data::fixture_data(Language::En, 3);
    let (_, text) = chapter(&render(&data), &data.strings["ch_images"]);
    let text = compact(&text);
    let positions: Vec<_> = data
        .images
        .iter()
        .map(|i| text.find(&compact(&i.reference)).unwrap())
        .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(
        data.images.iter().map(|i| &i.reference).collect::<Vec<_>>(),
        data.summary
            .top_images
            .iter()
            .map(|i| &i.reference)
            .collect::<Vec<_>>()
    );
}
#[test]
fn failed_image_shows_error_callout() {
    let mut data = data::fixture_data(Language::En, 3);
    data.images.truncate(1);
    data.images[0].scan_state = "failed".into();
    data.images[0].scan_error = "manifest unknown".into();
    data.images[0].findings[0].id = "MUST-NOT-RENDER".into();
    let (_, text) = chapter(&render(&data), &data.strings["ch_images"]);
    assert!(text.contains("manifest unknown"));
    assert!(!text.contains("MUST-NOT-RENDER"));
}
#[test]
fn oversized_description_is_contained() {
    let mut report = data::fixture_report(3);
    report.findings[0].severity = image_scan_report::model::Severity::Critical;
    report.findings[0].description =
        format!("Unicode 😀 𪚥\u{200b} {}", "long description ".repeat(400));
    let data = model::build(
        &report,
        &RenderOptions {
            language: Language::En,
            stale_after_days: 30,
            product_name: "judex".into(),
            product_version: "0.1.0".into(),
            top_images: 10,
            top_findings: 15,
        },
        strings::load(Language::En),
        theme::default_theme().to_render_value(),
    );
    let row = data
        .images
        .iter()
        .flat_map(|i| &i.findings)
        .find(|r| r.description.starts_with("Unicode"))
        .unwrap();
    assert_eq!(row.description.chars().count(), 601);
    assert!(row.description.ends_with('…'));
    let bytes = render(&data);
    assert!(pdf::text(&bytes).contains("Unicode"));
    let (_, text) = chapter(&bytes, &data.strings["ch_images"]);
    assert!(text.contains("Unicode"));
    for (w, h) in pdf::page_sizes(&bytes) {
        assert!((w - 595.276).abs() < 0.5 && (h - 841.89).abs() < 0.5);
    }
}
#[test]
fn optional_facts_show_placeholder() {
    let mut report = data::fixture_report(1);
    let image = &mut report.images[0];
    image.digest = None;
    image.platform = None;
    image.os = None;
    image.size_bytes = None;
    image.created_at = None;
    image.scan.scanned_at = None;
    image.scan.scanner_version = None;
    image.scan.error = None;
    report.findings.clear();
    let data = model::build(
        &report,
        &RenderOptions {
            language: Language::En,
            stale_after_days: 30,
            product_name: "judex".into(),
            product_version: "0.1.0".into(),
            top_images: 10,
            top_findings: 15,
        },
        strings::load(Language::En),
        theme::default_theme().to_render_value(),
    );
    let (_, text) = chapter(&render(&data), &data.strings["ch_images"]);
    assert!(text.matches('—').count() >= 4, "{text}");
    assert!(!text.to_lowercase().contains("none") && !text.to_lowercase().contains("null"));
    assert!(text.contains(&data.strings["no_findings"]));
}
#[test]
fn images_preview() {
    std::fs::create_dir_all("target/visual").unwrap();
    for (lang, name) in [(Language::En, "en"), (Language::ZhTw, "zh")] {
        let data = data::fixture_data(lang, 3);
        let (page, _) = chapter(&render(&data), &data.strings["ch_images"]);
        let png = Renderer::new()
            .render_png(&data, None, page, 110.0)
            .unwrap();
        std::fs::write(format!("target/visual/images-{name}.png"), png).unwrap();
    }
}

#[test]
fn medium_description_is_not_rendered() {
    let mut data = data::fixture_data(Language::En, 3);
    let row = &mut data.images[0].findings[0];
    row.severity_key = "medium".into();
    row.severity_label = "Medium".into();
    row.show_description = false;
    row.description = "MEDIUM-DESCRIPTION-SENTINEL".into();
    assert!(!pdf::text(&render(&data)).contains("MEDIUM-DESCRIPTION-SENTINEL"));
}
