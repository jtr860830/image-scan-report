//! Integration checks for render model behavior.
use image_scan_report::{
    config::ReportConfig,
    model::*,
    pipeline::assemble_report,
    render::model::*,
    source::{ScanSource, trivy_file::TrivyFileSource},
};
use std::collections::BTreeMap;
fn opts() -> RenderOptions {
    RenderOptions {
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
        language: Language::En,
        stale_after_days: 30,
        product_name: "judex".into(),
        product_version: "0.1.0".into(),
        top_images: 10,
        top_findings: 15,
    }
}
fn report() -> Report {
    let set = TrivyFileSource {
        dir: "tests/fixtures/trivy".into(),
    }
    .fetch()
    .unwrap();
    assemble_report(
        set,
        &ReportConfig {
            language: Language::En,
            min_severity: None,
            image_detail: image_scan_report::model::ImageDetail::Full,
            max_table_rows: None,
            describe_severities: vec![
                image_scan_report::model::Severity::Critical,
                image_scan_report::model::Severity::High,
            ],
            description_chars: 600,
            remediation_cards: 30,
            organization: "Example".into(),
            logo: None,
            stale_after_days: 30,
            json: true,
            pdf: false,
        },
        "2026-11-08T00:00:00Z".parse().unwrap(),
    )
}
fn render(r: &Report) -> RenderData {
    build(r, &opts(), BTreeMap::new(), serde_json::Value::Null)
}
fn finding() -> Finding {
    Finding {
        id: "CVE-test".into(),
        image: "test".into(),
        severity: Severity::Unrated,
        severity_basis: SeverityBasis::None,
        score_v3: None,
        score_v2: None,
        score_source: None,
        scanner_severity: None,
        package: "pkg".into(),
        installed_version: "1".into(),
        fixed_version: None,
        fix_status: None,
        description: String::new(),
        links: vec![],
        published_at: None,
    }
}
#[test]
fn builds_from_trivy_fixtures_and_snapshots() {
    let d = render(&report());
    #[derive(serde::Serialize)]
    struct Snapshot<'a> {
        meta: &'a Meta,
        summary: &'a Summary,
        groups: &'a [RemediationRow],
        inventory: &'a [UniqueRow],
        reference: &'a str,
        finding: &'a FindingRow,
        appendix: &'a Appendix,
    }
    insta::assert_json_snapshot!(Snapshot {
        meta: &d.meta,
        summary: &d.summary,
        groups: &d.remediation.groups[..d.remediation.groups.len().min(3)],
        inventory: &d.inventory[..d.inventory.len().min(3)],
        reference: &d.images[0].reference,
        finding: &d.images[0].findings[0],
        appendix: &d.appendix
    });
}
#[test]
fn placeholders_never_print_none() {
    let mut r = report();
    r.findings = vec![finding()];
    r.images = vec![Image {
        reference: "test".into(),
        tags: vec![],
        digest: None,
        platform: None,
        os: None,
        size_bytes: None,
        created_at: None,
        scan: ScanStatus {
            state: ScanState::Ok,
            scanned_at: None,
            scanner_version: None,
            error: None,
        },
    }];
    let d = render(&r);
    let f = &d.images[0].findings[0];
    assert_eq!(
        (
            &*f.score,
            &*f.fixed_version,
            &*f.fix_status,
            &*f.scanner_severity,
            &*f.basis
        ),
        ("—", "—", "—", "—", "none")
    );
    let i = &d.images[0];
    assert_eq!(i.platform, "—");
    assert_eq!(i.scanner_version, "—");
    assert_eq!(
        (&*i.digest, &*i.os, &*i.size, &*i.scanned_at),
        ("—", "—", "—", "—")
    );
}
#[test]
fn sanitize_strips_control_characters() {
    assert_eq!(
        sanitize("a\u{0}b\u{7}c\r\nd\u{200B}\r\u{85}\t"),
        "abc\nd\u{200B}\n\t"
    );
}
#[test]
fn description_is_truncated() {
    let mut r = report();
    let mut f = finding();
    f.image = r.images[0].reference.clone();
    f.description = "x".repeat(6000);
    r.findings = vec![f];
    let d = render(&r);
    let s = &d
        .images
        .iter()
        .find(|i| !i.findings.is_empty())
        .unwrap()
        .findings[0]
        .description;
    assert_eq!(s.chars().count(), 601);
    assert!(s.ends_with('…'));
    r.findings[0].description = "é".repeat(1300);
    let d = render(&r);
    let s = &d
        .images
        .iter()
        .find(|i| !i.findings.is_empty())
        .unwrap()
        .findings[0]
        .description;
    assert_eq!(s.chars().count(), 601);
    assert_eq!(s, &format!("{}…", "é".repeat(600)));
}
#[test]
fn format_size_cases() {
    assert_eq!(format_size(Some(184_600_000)), "184.6 MB");
    assert_eq!(format_size(Some(5400)), "5.4 KB");
    assert_eq!(format_size(None), "—");
}
#[test]
fn bar_percents_sum_to_100() {
    let mut r = report();
    r.findings.clear();
    for (severity, n) in [
        (Severity::Critical, 7),
        (Severity::High, 64),
        (Severity::Medium, 151),
        (Severity::Low, 96),
    ] {
        for _ in 0..n {
            let mut f = finding();
            f.severity = severity;
            r.findings.push(f);
        }
    }
    let d = render(&r);
    assert_eq!(d.summary.bar.len(), 4);
    assert!((d.summary.bar.iter().map(|b| b.percent).sum::<f32>() - 100.).abs() < 0.01);
    r.findings.clear();
    assert!(render(&r).summary.bar.is_empty());
}

#[test]
fn ordering_status_groups_and_rounding() {
    let mut r = report();
    r.images.truncate(1);
    let mut a = finding();
    a.image = r.images[0].reference.clone();
    a.id = "A".into();
    a.severity = Severity::High;
    a.score_v2 = Some(7.1);
    a.fix_status = Some(FixStatus::Other("custom".into()));
    let mut b = a.clone();
    b.id = "B".into();
    b.score_v3 = Some(8.0);
    b.fixed_version = Some("2".into());
    let mut c = a.clone();
    c.id = "C".into();
    c.score_v2 = None;
    c.fix_status = Some(FixStatus::WillNotFix);
    let mut d = a.clone();
    d.id = "D".into();
    d.score_v2 = None;
    d.severity = Severity::Critical;
    d.fix_status = None;
    let mut e = a.clone();
    e.id = "E".into();
    e.score_v2 = None;
    e.fix_status = Some(FixStatus::WillNotFix);
    let mut f = b.clone();
    f.id = "F".into();
    f.score_v3 = Some(7.5);
    let mut g = b.clone();
    g.id = "G".into();
    g.score_v3 = Some(7.5);
    let mut h = b.clone();
    h.id = "H".into();
    h.fixed_version = None;
    h.fix_status = None;
    r.findings = vec![a, b, c, d, e, f, g, h];
    let mut options = opts();
    options.top_images = 0;
    options.top_findings = 1;
    let data = build(&r, &options, BTreeMap::new(), serde_json::Value::Null);
    assert_eq!(data.summary.fixable_percent, 38); // 3 / 8 = 37.5%, rounded up.
    assert!(data.summary.top_images.is_empty());
    assert_eq!(data.summary.top_findings.len(), 1);
    assert_eq!(
        data.images[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        ["D", "B", "H", "F", "G", "A", "C", "E"]
    );
    assert_eq!(
        data.remediation.unfixable_by_status,
        vec![
            ("unknown".into(), 2),
            ("will_not_fix".into(), 2),
            ("custom".into(), 1)
        ]
    );
    assert_eq!(data.appendix.score_sources, vec![("—".into(), 8)]);
    assert_eq!(data.images[0].counts.total(), 8);
}

#[test]
fn build_sanitizes_every_external_string() {
    let mut r = report();
    let dirty = "a\u{0}b\u{7}c";
    r.scope = dirty.into();
    r.organisation = dirty.into();
    r.source.display_name = dirty.into();
    r.source.scanner_name = Some(dirty.into());
    r.source.scanner_version = Some(dirty.into());
    r.source.db_version = Some(dirty.into());
    r.images.truncate(1);
    let i = &mut r.images[0];
    i.reference = dirty.into();
    i.tags = vec![dirty.into()];
    i.digest = Some(dirty.into());
    i.platform = Some(dirty.into());
    i.os = Some(dirty.into());
    i.scan.scanner_version = Some(dirty.into());
    i.scan.error = Some(dirty.into());
    i.scan.scanned_at = None;
    let mut failed = i.clone();
    failed.reference = format!("failed{dirty}");
    failed.scan.state = ScanState::Failed;
    r.images.push(failed);
    let mut f = finding();
    f.image = dirty.into();
    f.id = dirty.into();
    f.package = dirty.into();
    f.installed_version = dirty.into();
    f.fix_status = Some(FixStatus::Other("x\u{1}y".into()));
    f.scanner_severity = Some(dirty.into());
    f.description = dirty.into();
    f.links = vec![dirty.into()];
    f.score_source = Some(dirty.into());
    let mut fixed = f.clone();
    fixed.fixed_version = Some(dirty.into());
    r.findings = vec![f, fixed];
    let data = render(&r);
    let json = serde_json::to_string(&data).unwrap();
    for escape in ["\\u0000", "\\u0001", "\\u0007"] {
        assert!(!json.contains(escape), "unsanitized escape: {escape}");
    }
    assert_eq!(data.remediation.unfixable_by_status, vec![("xy".into(), 1)]);
    assert_eq!(data.appendix.score_sources, vec![("abc".into(), 2)]);
    assert_eq!(data.images.len(), 2);
    assert_eq!(data.images[0].findings.len(), 2);
}

#[test]
fn description_visibility_follows_severity() {
    let mut report = report();
    let image = report.images[0].reference.clone();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unrated,
    ] {
        let mut row = finding();
        row.image = image.clone();
        row.severity = severity;
        report.findings = vec![row];
        let data = render(&report);
        let row = data.images.iter().flat_map(|i| &i.findings).next().unwrap();
        assert_eq!(
            row.show_description,
            matches!(severity, Severity::Critical | Severity::High)
        );
    }
}

#[test]
fn configurable_descriptions_and_card_limit() {
    let mut r = report();
    r.images.truncate(1);
    r.findings = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unrated,
    ]
    .into_iter()
    .map(|severity| {
        let mut f = finding();
        f.image = r.images[0].reference.clone();
        f.severity = severity;
        f.description = "é".repeat(101);
        f
    })
    .collect();
    let mut options = opts();
    options.describe_severities = vec![Severity::Medium];
    options.description_chars = 100;
    options.remediation_cards = 2;
    let d = build(&r, &options, BTreeMap::new(), serde_json::Value::Null);
    assert_eq!(d.remediation.cards, 2);
    for row in &d.images[0].findings {
        assert_eq!(row.show_description, row.severity_key == "medium");
        assert_eq!(row.description, format!("{}…", "é".repeat(100)));
    }
    options.describe_severities.clear();
    let d = build(&r, &options, BTreeMap::new(), serde_json::Value::Null);
    assert!(d.images[0].findings.iter().all(|row| !row.show_description));
}
