use image_scan_report::{
    config::ReportConfig,
    model::{Language, Report},
    pipeline::assemble_report,
    render::{
        model::{self, RenderData, RenderOptions},
        strings, theme,
    },
    source::{ScanSource, trivy_file::TrivyFileSource},
};

pub fn fixture_report(max_images: usize) -> Report {
    let mut report = assemble_report(
        TrivyFileSource {
            dir: "fixtures/trivy".into(),
        }
        .fetch()
        .unwrap(),
        &ReportConfig {
            language: Language::En,
            describe_severities: vec![
                image_scan_report::model::Severity::Critical,
                image_scan_report::model::Severity::High,
            ],
            description_chars: 600,
            remediation_cards: 30,
            organization: "Example Organisation".into(),
            logo: None,
            stale_after_days: 30,
            json: false,
            pdf: true,
        },
        "2026-11-08T00:00:00Z".parse().unwrap(),
    );
    report.images.truncate(max_images);
    report.findings.retain(|finding| {
        report
            .images
            .iter()
            .any(|image| image.reference == finding.image)
    });
    report
}

pub fn fixture_data(language: Language, max_images: usize) -> RenderData {
    let report = fixture_report(max_images);
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
    model::build(
        &report,
        &opts,
        strings::load(language),
        theme::default_theme().to_render_value(),
    )
}
