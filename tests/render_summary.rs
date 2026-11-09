//! Integration checks for render summary behavior.
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

#[test]
fn summary_page_has_counts_and_tables() {
    let (report, _, data) = fixture(Language::En);
    let bytes = Renderer::new()
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    assert!(pdf::page_count(&bytes) >= 3);
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let text = doc.extract_text(&[3]).unwrap();
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
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
            .collect::<String>()
            .contains(&data.summary.top_images[0].reference),
        "{text}"
    );
    assert!(
        text.replace('\u{200b}', "")
            .contains(&data.summary.top_findings[0].id),
        "{text}"
    );
    for count in [data.summary.counts.critical, data.summary.counts.high] {
        assert!(text.replace(',', "").contains(&count.to_string()), "{text}");
    }
}

#[test]
fn summary_long_identifiers_get_break_opportunities() {
    // Issue #15: a seven-digit CVE sequence number and a Debian version string ran into the
    // neighbouring columns because the summary table lacked the identifier treatment.
    let (report, _, mut data) = fixture(Language::En);
    let row = &mut data.summary.top_findings[0];
    row.id = "CVE-2019-1010022".into();
    row.fixed_versions = "2.9.14+dfsg-1.3~deb12u3".into();
    let bytes = Renderer::new()
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let text: String = doc
        .extract_text(&[3])
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(text.contains("CVE-\u{200b}2019-\u{200b}1010022"), "{text}");
    assert!(text.contains("dfsg-\u{200b}1.\u{200b}3~deb12u3"), "{text}");
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
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let text = pdf::text(&bytes);
    assert!(text.contains(&data.strings["no_findings"]), "{text}");
    assert!(text.contains(&data.strings["sec_top_images"]));
    assert!(!text.contains(&data.strings["sec_top_findings"]));
    let fact = data.strings["fact_fixable"].replace("{percent}", "0");
    assert!(!text.contains(&fact), "{text}");
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
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let text = pdf::text(&bytes);
    assert!(text.contains("Critical"));
    assert!(text.contains("Unrated"));
    std::fs::create_dir_all("target/visual").unwrap();
    std::fs::write(
        "target/visual/summary-chips.png",
        renderer.render_png(&data, None, None, 3, 110.0).unwrap(),
    )
    .unwrap();
}

#[test]
fn edition_metadata_and_appendix_credit_agree() {
    let (report, mut opts, _) = fixture(Language::En);
    opts.product_name = "Edition".into();
    let mut theme = theme::default_theme();
    theme.product.name = "Edition".into();
    let data = model::build(
        &report,
        &opts,
        strings::load(Language::En),
        theme.to_render_value(),
    );
    assert_eq!(
        serde_json::to_value(&data).unwrap()["meta"]["product_name"],
        "Edition"
    );
    let bytes = image_scan_report::render::render_pdf(&report, &opts, &theme).unwrap();
    let text = pdf::text(&bytes);
    assert_eq!(
        text.matches("Generated by Edition 0.1.0").count(),
        1,
        "{text}"
    );
}
