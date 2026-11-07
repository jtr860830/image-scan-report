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

fn chapter(bytes: &[u8], title: &str) -> (u32, String) {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    let page = (3..=pdf::page_count(bytes) as u32)
        .find(|page| doc.extract_text(&[*page]).unwrap().contains(title))
        .expect("remediation chapter page");
    let pages: Vec<_> = (page..=pdf::page_count(bytes) as u32).collect();
    (page, doc.extract_text(&pages).unwrap())
}

#[test]
fn remediation_lists_groups_in_rank_order() {
    let (report, _, data) = fixture(Language::En);
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_remediation"]);
    let first = &data.remediation.groups[0];
    let second = &data.remediation.groups[1];
    // A package can have multiple ranked upgrade targets.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let target = |row: &image_scan_report::render::model::RemediationRow| {
        format!("{}→{}", row.package, row.fixed_version)
    };
    assert!(compact.find(&target(first)).unwrap() < compact.find(&target(second)).unwrap());
    assert!(text.contains(&first.fixed_version), "{text}");
    let references: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
        .collect();
    assert!(references.contains(&first.images[0]), "{text}");
}

#[test]
fn remediation_unfixable_table_present() {
    let (report, _, data) = fixture(Language::En);
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_remediation"]);
    assert!(text.contains(&data.strings["remediation_unfixable_title"]));
    assert!(text.contains(&data.strings["status_affected"]));
    assert!(pdf::text(&bytes).contains(&data.strings["col_status"]));
}

#[test]
fn remediation_preview() {
    std::fs::create_dir_all("target/visual").unwrap();
    for (language, name) in [(Language::En, "en"), (Language::ZhTw, "zh")] {
        let (report, _, data) = fixture(language);
        let renderer = Renderer::new();
        let bytes = renderer
            .render_pdf(&data, None, report.generated_at)
            .unwrap();
        let (page, _) = chapter(&bytes, &data.strings["ch_remediation"]);
        let png = renderer
            .render_png(&data, None, page as usize, 110.0)
            .unwrap();
        assert!(png.starts_with(b"\x89PNG"));
        std::fs::write(format!("target/visual/remediation-{name}.png"), png).unwrap();
    }
}

#[test]
fn remediation_handles_empty_groups_and_status_fallbacks() {
    let (report, _, mut data) = fixture(Language::En);
    data.remediation.groups.clear();
    let keys = [
        "fixed",
        "affected",
        "will_not_fix",
        "end_of_life",
        "fix_deferred",
        "under_investigation",
        "unknown",
        "vendor_pending",
    ];
    data.remediation.unfixable_by_status = keys.iter().map(|key| ((*key).into(), 1234)).collect();
    data.remediation.unfixable_total = 9872;
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_remediation"]);
    assert!(text.contains(&data.strings["no_findings"]));
    for key in &keys[..6] {
        assert!(
            text.contains(&data.strings[&format!("status_{key}")]),
            "{text}"
        );
    }
    assert!(text.contains(&format!(
        "{} (vendor_pending)",
        data.strings["status_other"]
    )));
    assert!(!text.contains("(unknown)"));
    assert!(text.contains("1,234"));
    assert!(text.contains("9,872"));
}

#[test]
fn remediation_caps_images_and_formats_counts() {
    let (report, _, mut data) = fixture(Language::En);
    data.remediation.groups.truncate(1);
    let group = &mut data.remediation.groups[0];
    group.images = (0..41).map(|i| format!("unique-image-{i:02}")).collect();
    group.resolves.critical = 1234;
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_remediation"]);
    assert!(text.contains("unique-image-11"));
    assert!(!text.contains("unique-image-12"));
    assert!(text.contains("+29"));
    assert!(text.contains("1,234"));
    let affects = data.strings["remediation_affects"].replace("{count}", "41");
    assert!(text.contains(&affects), "{text}");
}

#[test]
fn further_groups_use_compact_table() {
    let (report, _, mut data) = fixture(Language::En);
    let prototype = data.remediation.groups[0].clone();
    data.remediation.groups = (0..35)
        .map(|i| {
            let mut row = prototype.clone();
            row.package = format!("package-{i:02}");
            row
        })
        .collect();
    let bytes = Renderer::new()
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    let (_, text) = chapter(&bytes, &data.strings["ch_remediation"]);
    let text = text.replace('\u{200b}', "");
    let split = text.find(&data.strings["remediation_more_title"]).unwrap();
    assert!(text[..split].contains("package-00"));
    assert!(!text[..split].contains("package-30"));
    let tail: String = text[split..]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(tail.contains("package-30"), "{tail}");
}
