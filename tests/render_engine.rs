//! Integration checks for render engine behavior.
use image_scan_report::{
    model::{Language, Report},
    render::{
        engine::{RenderError, Renderer},
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
        min_severity: None,
        image_detail: image_scan_report::model::ImageDetail::Full,
        max_table_rows: None,
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
fn renders_cover_and_summary_document() {
    let (report, opts, _) = fixture(Language::En);
    let bytes =
        image_scan_report::render::render_pdf(&report, &opts, &theme::default_theme()).unwrap();
    assert!(bytes.starts_with(b"%PDF"));
    assert!(pdf::page_count(&bytes) >= 2);
    let text = pdf::text(&bytes);
    assert!(
        text.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("Container Image Vulnerability Scan Report"),
        "{text}"
    );
    assert!(
        text.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .contains("ExampleOrganisation")
    );
}
#[test]
fn zh_tw_cover_uses_cjk_font() {
    let (report, _, data) = fixture(Language::ZhTw);
    let bytes = Renderer::new()
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    assert!(pdf::text(&bytes).contains("容器映像檔弱點掃描報告"));
    assert!(String::from_utf8_lossy(&bytes).contains("NotoSansTC"));
}
#[test]
fn render_is_deterministic() {
    let (report, _, data) = fixture(Language::En);
    let renderer = Renderer::new();
    assert_eq!(
        renderer
            .render_pdf(&data, None, None, report.generated_at)
            .unwrap(),
        renderer
            .render_pdf(&data, None, None, report.generated_at)
            .unwrap()
    );
}
#[test]
fn compile_error_names_file_and_line() {
    let (report, _, data) = fixture(Language::En);
    let renderer =
        Renderer::with_sources(&[("report.typ", "// Valid first line\n#missing()".into())]);
    let err = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap_err();
    assert!(matches!(err, RenderError::Compile(_)));
    assert!(err.to_string().contains("report.typ:2"), "{err}");
}
#[test]
fn preview_png_is_written() {
    let (_, _, data) = fixture(Language::En);
    let bytes = Renderer::new()
        .render_png(&data, None, None, 1, 72.0)
        .unwrap();
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    std::fs::create_dir_all("target/visual").unwrap();
    std::fs::write("target/visual/cover.png", bytes).unwrap();
}

#[test]
fn body_frame_and_template_helpers_work() {
    let (report, _, data) = fixture(Language::En);
    let source = format!(
        "{}\n#import \"lib/theme.typ\": chip, mono\n#text(\"Body marker\")\n#chip(data.theme, \"High\", \"high\")\n#mono(data.theme, \"literal #text[test]\")\n#num(1234567)\n#pagebreak()\nSecond body page",
        include_str!("../assets/templates/report.typ")
            .replace("\"lib/fmt.typ\": t", "\"lib/fmt.typ\": t, num")
            .replace("#summary(data)", "")
            .replace("#remediation(data)", "")
            .replace("#inventory(data)", "")
            .replace("#images(data)", "")
            .replace("#appendix(data)", "")
    );
    let renderer = Renderer::with_sources(&[("report.typ", source)]);
    let bytes = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    assert_eq!(pdf::page_count(&bytes), 4);
    let text = pdf::text(&bytes);
    assert!(text.contains("2 / 4"), "{text}");
    assert!(text.contains("4 / 4"), "{text}");
    assert!(!text.contains("1 / 4"), "cover must have no footer: {text}");
    assert!(text.contains("1,234,567"), "{text}");
    assert!(text.contains("literal #text[test]"), "{text}");
}

#[test]
fn logo_is_passed_through_public_entry_point() {
    let (report, opts, _) = fixture(Language::En);
    let mut theme = theme::default_theme();
    theme.product.name = "Theme Product".into();
    theme.product.url = Some("https://example.test".into());
    theme.logo = Some(theme::Logo {
        file_name: "logo.png".into(),
        bytes: pdf::LOGO_PNG.to_vec(),
    });
    let bytes = image_scan_report::render::render_pdf(&report, &opts, &theme).unwrap();
    assert!(pdf::page_count(&bytes) >= 2);
    let pages = pdf::page_texts(&bytes);
    assert!(pages.last().unwrap().contains("Theme Product"));
    assert!(pages.last().unwrap().contains("https://example.test"));
    assert_eq!(pdf::image_count(&bytes, 1), 0);
    assert!(pdf::image_count(&bytes, pdf::page_count(&bytes) as u32) > 0);
    let data = model::build(
        &report,
        &opts,
        strings::load(Language::En),
        theme.to_render_value(),
    );
    assert!(
        Renderer::new()
            .render_png(&data, theme.logo.as_ref(), None, 1, 72.0)
            .unwrap()
            .starts_with(b"\x89PNG")
    );
}

#[test]
fn empty_scan_range_and_external_text_are_safe() {
    let (report, _, mut data) = fixture(Language::En);
    data.images.clear();
    data.scope = "#panic(\"must remain literal\")".into();
    let bytes = Renderer::new()
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap();
    let text = pdf::text(&bytes);
    assert!(text.contains("#panic(\"must remain literal\")"), "{text}");
    assert!(text.contains('—'), "{text}");
}

#[test]
fn preview_rejects_invalid_page_and_resolution() {
    let (_, _, data) = fixture(Language::En);
    let renderer = Renderer::new();
    for page in [0, 999] {
        assert!(matches!(
            renderer.render_png(&data, None, None, page, 72.0),
            Err(RenderError::Data(_))
        ));
    }
    for ppi in [0.0, -1.0, f32::NAN, f32::INFINITY] {
        assert!(matches!(
            renderer.render_png(&data, None, None, 1, ppi),
            Err(RenderError::Data(_))
        ));
    }
}

#[test]
fn missing_translation_names_key() {
    let (report, _, data) = fixture(Language::En);
    let renderer = Renderer::with_sources(&[(
        "report.typ",
        "#import \"lib/fmt.typ\": t\n#t((:), \"absent_key\")".into(),
    )]);
    let err = renderer
        .render_pdf(&data, None, None, report.generated_at)
        .unwrap_err();
    assert!(
        err.to_string().contains("missing string key: absent_key"),
        "{err}"
    );
    assert!(!err.to_string().contains("(span"));
}
