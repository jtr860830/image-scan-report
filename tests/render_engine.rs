use image_scan_report::{
    config::ReportConfig,
    model::{Language, Report},
    pipeline::assemble_report,
    render::{
        engine::{RenderError, Renderer},
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
        .render_pdf(&data, None, report.generated_at)
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
            .render_pdf(&data, None, report.generated_at)
            .unwrap(),
        renderer
            .render_pdf(&data, None, report.generated_at)
            .unwrap()
    );
}
#[test]
fn compile_error_names_file_and_line() {
    let (report, _, data) = fixture(Language::En);
    let renderer =
        Renderer::with_sources(&[("report.typ", "// Valid first line\n#missing()".into())]);
    let err = renderer
        .render_pdf(&data, None, report.generated_at)
        .unwrap_err();
    assert!(matches!(err, RenderError::Compile(_)));
    assert!(err.to_string().contains("report.typ:2"), "{err}");
}
#[test]
fn preview_png_is_written() {
    let (_, _, data) = fixture(Language::En);
    let bytes = Renderer::new().render_png(&data, None, 1, 72.0).unwrap();
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    std::fs::create_dir_all("target/visual").unwrap();
    std::fs::write("target/visual/cover.png", bytes).unwrap();
}

#[test]
fn body_frame_and_template_helpers_work() {
    let (report, _, data) = fixture(Language::En);
    let source = format!(
        "{}\n#import \"lib/theme.typ\": chip, mono\n#text(\"Body marker\")\n#chip(data.theme, \"High\", \"high\")\n#mono(data.theme, \"literal #text[test]\")\n#num(1234567)\n#pagebreak()\nSecond body page",
        include_str!("../templates/report.typ")
            .replace("\"lib/fmt.typ\": t", "\"lib/fmt.typ\": t, num")
            .replace("#summary(data)", "")
            .replace("#remediation(data)", "")
    );
    let renderer = Renderer::with_sources(&[("report.typ", source)]);
    let bytes = renderer
        .render_pdf(&data, None, report.generated_at)
        .unwrap();
    assert_eq!(pdf::page_count(&bytes), 3);
    let text = pdf::text(&bytes);
    assert!(text.contains("2 / 3"), "{text}");
    assert!(text.contains("3 / 3"), "{text}");
    assert!(!text.contains("1 / 3"), "cover must have no footer: {text}");
    assert!(text.contains("1,234,567"), "{text}");
    assert!(text.contains("literal #text[test]"), "{text}");
}

#[test]
fn logo_is_passed_through_public_entry_point() {
    let (report, opts, _) = fixture(Language::En);
    let mut theme = theme::default_theme();
    theme.logo = Some(theme::Logo {
        file_name: "logo.svg".into(),
        bytes: br##"<svg xmlns="http://www.w3.org/2000/svg" width="80" height="40"><rect width="80" height="40" fill="#4263eb"/></svg>"##.to_vec(),
    });
    let bytes = image_scan_report::render::render_pdf(&report, &opts, &theme).unwrap();
    assert!(pdf::page_count(&bytes) >= 2);
    let data = model::build(
        &report,
        &opts,
        strings::load(Language::En),
        theme.to_render_value(),
    );
    assert!(
        Renderer::new()
            .render_png(&data, theme.logo.as_ref(), 1, 72.0)
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
        .render_pdf(&data, None, report.generated_at)
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
            renderer.render_png(&data, None, page, 72.0),
            Err(RenderError::Data(_))
        ));
    }
    for ppi in [0.0, -1.0, f32::NAN, f32::INFINITY] {
        assert!(matches!(
            renderer.render_png(&data, None, 1, ppi),
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
        .render_pdf(&data, None, report.generated_at)
        .unwrap_err();
    assert!(
        err.to_string().contains("missing string key: absent_key"),
        "{err}"
    );
    assert!(!err.to_string().contains("(span"));
}
