use chrono::{DateTime, Utc};
use scanreport::model::*;

#[test]
fn report_json_shape_is_stable() {
    let timestamp = DateTime::parse_from_rfc3339("2026-11-07T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let report = Report {
        generated_at: timestamp,
        language: Language::ZhTw,
        organisation: "Example Organisation".into(),
        source: SourceInfo {
            kind: SourceKind::TrivyFiles,
            display_name: "Fixture scans".into(),
            scanner_name: Some("Trivy".into()),
            scanner_version: Some("1.0".into()),
            db_version: Some("2".into()),
            db_updated_at: Some(timestamp),
        },
        scope: "Production".into(),
        images: vec![Image {
            reference: "example/app:latest".into(),
            tags: vec!["latest".into()],
            digest: Some("sha256:abc".into()),
            platform: Some("linux/amd64".into()),
            os: Some("alpine".into()),
            size_bytes: Some(1024),
            created_at: Some(timestamp),
            scan: ScanStatus {
                state: ScanState::Ok,
                scanned_at: Some(timestamp),
                scanner_version: Some("1.0".into()),
                error: None,
            },
        }],
        findings: vec![
            Finding {
                id: "CVE-2026-0001".into(),
                image: "example/app:latest".into(),
                severity: Severity::Critical,
                severity_basis: SeverityBasis::Cvss3,
                score_v3: Some(9.8),
                score_v2: Some(7.5),
                score_source: Some("NVD".into()),
                scanner_severity: Some("CRITICAL".into()),
                package: "openssl".into(),
                installed_version: "1.0".into(),
                fixed_version: Some("1.1".into()),
                fix_status: Some(FixStatus::Fixed),
                description: "Example vulnerability".into(),
                links: vec!["https://example.com/CVE-2026-0001".into()],
                published_at: Some(timestamp),
            },
            Finding {
                id: "CVE-2026-0002".into(),
                image: "example/app:latest".into(),
                severity: Severity::Unrated,
                severity_basis: SeverityBasis::None,
                score_v3: None,
                score_v2: None,
                score_source: None,
                scanner_severity: None,
                package: "libexample".into(),
                installed_version: "2.0".into(),
                fixed_version: None,
                fix_status: Some(FixStatus::Other("pending review".into())),
                description: "Unscored vulnerability".into(),
                links: vec![],
                published_at: None,
            },
        ],
    };
    insta::assert_json_snapshot!(report);
    let json = serde_json::to_string(&report).unwrap();
    assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);
    let mut finding_without_status = report.findings[0].clone();
    finding_without_status.fix_status = None;
    let value = serde_json::to_value(&finding_without_status).unwrap();
    assert!(value["fix_status"].is_null());
    assert_eq!(
        serde_json::from_value::<Finding>(value).unwrap(),
        finding_without_status
    );
}

#[test]
fn severity_orders_critical_first() {
    use scanreport::model::Severity::*;
    let mut v = vec![Low, Unrated, Critical, Medium, High];
    v.sort_by(|a, b| b.cmp(a));
    assert_eq!(v, vec![Critical, High, Medium, Low, Unrated]);
}

#[test]
fn fix_status_parses_known_and_other() {
    use scanreport::model::FixStatus;
    assert_eq!(FixStatus::parse("will_not_fix"), FixStatus::WillNotFix);
    assert_eq!(FixStatus::parse("End-Of-Life"), FixStatus::EndOfLife);
    assert_eq!(FixStatus::parse("weird"), FixStatus::Other("weird".into()));
}

#[test]
fn fix_status_normalises_known_separators_and_preserves_unknown() {
    for (input, expected) in [
        ("FIXED", FixStatus::Fixed),
        ("Affected", FixStatus::Affected),
        ("Will Not Fix", FixStatus::WillNotFix),
        ("end_of_life", FixStatus::EndOfLife),
        ("Fix-Deferred", FixStatus::FixDeferred),
        ("Under Investigation", FixStatus::UnderInvestigation),
        ("Custom-STATUS", FixStatus::Other("Custom-STATUS".into())),
    ] {
        assert_eq!(FixStatus::parse(input), expected);
    }
}

#[test]
fn severity_labels_are_stable() {
    for (severity, label) in [
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::Unrated, "Unrated"),
    ] {
        assert_eq!(severity.label(), label);
    }
}
