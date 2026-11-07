use image_scan_report::{
    model::{Language, Report},
    render::{
        engine::Renderer,
        model::{RenderData, RenderOptions},
    },
};
#[path = "support/data.rs"]
mod data;
#[path = "support/pdf.rs"]
mod pdf;

fn fixture(language: Language) -> (Report, RenderOptions, RenderData) {
    let report = data::fixture_report(3);
    let opts = RenderOptions {
        describe_severities: vec![
            image_scan_report::model::Severity::Critical,
            image_scan_report::model::Severity::High,
        ],
        description_chars: 600,
        remediation_cards: 30,
        customer_logo: None,
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

fn compact_inventory(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
        .collect()
}

fn chapter(bytes: &[u8], title: &str) -> (u32, String) {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    let page = (3..=pdf::page_count(bytes) as u32)
        .find(|page| doc.extract_text(&[*page]).unwrap().contains(title))
        .expect("inventory chapter page");
    let pages: Vec<_> = (page..=pdf::page_count(bytes) as u32).collect();
    (page, doc.extract_text(&pages).unwrap())
}

#[test]
fn inventory_lists_every_unique_vulnerability() {
    let (report, _, mut data) = fixture(Language::En);
    let renderer = Renderer::new();
    let bytes = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    chapter(&bytes, &data.strings["ch_inventory"]);
    assert!(pdf::text(&bytes).contains(&data.strings["ch_inventory"]));
    let text: String = pdf::text(&bytes)
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
        .collect();
    for row in &data.inventory {
        assert!(text.contains(&row.id), "missing {}", row.id);
    }
    let removed_id = data.inventory[1].id.clone();
    data.inventory.truncate(1);
    let small = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&small, &data.strings["ch_inventory"]);
    let inventory_text = text.split(&data.strings["ch_images"]).next().unwrap();
    assert!(!compact_inventory(inventory_text).contains(&removed_id));
}

#[test]
fn long_identifiers_stay_inside_the_page() {
    let (report, _, mut data) = fixture(Language::En);
    data.inventory.truncate(2);
    data.images.truncate(1);
    data.remediation.groups.clear();
    data.summary.top_images.clear();
    data.summary.top_findings.clear();
    let reference = format!("registry.example/{}:tag", "a".repeat(229));
    let version = format!("1.{}+build", "b".repeat(292));
    for row in &mut data.inventory {
        row.images = vec![reference.clone()];
        row.fixed_versions = version.clone();
    }
    data.images[0].reference = reference;
    data.images[0].findings.truncate(1);
    data.images[0].findings[0].fixed_version = version;
    let bytes = Renderer::new()
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    for (width, height) in pdf::page_sizes(&bytes) {
        assert!((width - 595.276).abs() < 0.5, "width {width}");
        assert!((height - 841.89).abs() < 0.5, "height {height}");
    }
    assert!(pdf::page_count(&bytes) < 10);
}

#[test]
fn inventory_caps_images_and_handles_empty_inventory() {
    let (report, _, mut data) = fixture(Language::En);
    data.inventory.truncate(1);
    data.inventory[0].images = (0..25).map(|i| format!("affected{i:02}")).collect();
    data.inventory[0].image_count = 25;
    let renderer = Renderer::new();
    let bytes = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_inventory"]);
    assert!(text.contains("affected19"));
    assert!(!text.contains("affected20"));
    assert!(text.contains("+5"));
    data.inventory.clear();
    let bytes = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_inventory"]);
    assert!(text.contains(&data.strings["no_findings"]));
    assert!(text.contains(&data.strings["inventory_lede"].replace("{count}", "0")));
}
