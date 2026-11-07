use Severity::*;
use chrono::{Duration, TimeZone, Utc};
use scanreport::model::{Finding, Image, ScanState, ScanStatus, Severity, SeverityBasis};
use scanreport::views::*;

fn f(
    id: &str,
    image: &str,
    severity: Severity,
    score: Option<f32>,
    pkg: &str,
    fixed: Option<&str>,
) -> Finding {
    Finding {
        id: id.into(),
        image: image.into(),
        severity,
        severity_basis: SeverityBasis::ScannerLabel,
        score_v3: score,
        score_v2: None,
        score_source: None,
        scanner_severity: None,
        package: pkg.into(),
        installed_version: "1.0".into(),
        fixed_version: fixed.map(str::to_owned),
        fix_status: None,
        description: String::new(),
        links: vec![],
        published_at: None,
    }
}

fn image(reference: &str) -> Image {
    Image {
        reference: reference.into(),
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
    }
}

#[test]
fn counts_and_fixable() {
    let findings: Vec<_> = [Critical, High, Medium, Low, Unrated, Critical]
        .into_iter()
        .map(|s| f("CVE", "a", s, None, "pkg", (s == Critical).then_some("")))
        .collect();
    let c = counts(&findings);
    assert_eq!(
        c,
        SeverityCounts {
            critical: 2,
            high: 1,
            medium: 1,
            low: 1,
            unrated: 1
        }
    );
    assert_eq!(c.total(), 6);
    assert_eq!(c.high_or_worse(), 3);
    assert_eq!(fixable(&findings), 2);
    assert_eq!(counts(&[]), SeverityCounts::default());
    assert_eq!(fixable(&[]), 0);
}

#[test]
fn unique_vulnerabilities_merge_images_and_take_max_severity() {
    let findings = vec![
        f("CVE-1", "img-b", Critical, Some(9.1), "z", Some("3")),
        f("CVE-1", "img-a", High, Some(7.5), "a", Some("2")),
        f("CVE-1", "img-a", Low, None, "a", None),
        f("CVE-1", "img-a", High, Some(8.0), "a", Some("2")),
    ];
    let v = unique_vulnerabilities(&findings);
    assert_eq!(v.len(), 1);
    assert_eq!(
        v[0],
        UniqueVulnerability {
            id: "CVE-1".into(),
            severity: Critical,
            score_v3: Some(9.1),
            packages: vec!["a".into(), "z".into()],
            fixed_versions: vec!["2".into(), "3".into()],
            images: vec!["img-a".into(), "img-b".into()]
        }
    );
    assert!(unique_vulnerabilities(&[]).is_empty());
}

#[test]
fn unique_sort_order() {
    let findings = vec![
        f("none-z", "a", High, None, "p", None),
        f("slow", "a", High, Some(7.5), "p", None),
        f("fast-b", "a", High, Some(8.1), "p", None),
        f("critical", "a", Critical, None, "p", None),
        f("fast-a", "a", High, Some(8.1), "p", None),
        f("none-a", "a", High, None, "p", None),
    ];
    let ids: Vec<_> = unique_vulnerabilities(&findings)
        .into_iter()
        .map(|v| v.id)
        .collect();
    assert_eq!(
        ids,
        ["critical", "fast-a", "fast-b", "slow", "none-a", "none-z"]
    );
}

#[test]
fn remediation_groups_rank_by_what_they_resolve() {
    let findings = vec![
        f("1", "b", Critical, None, "xz", Some("5.6.2")),
        f("2", "b", Critical, None, "openssl", Some("3.0.15")),
        f("3", "a", Critical, None, "openssl", Some("3.0.15")),
        f("4", "a", High, None, "z", Some("2")),
        f("5", "a", High, None, "a", Some("3")),
        f("6", "a", High, None, "a", Some("2")),
    ];
    let groups = remediation_groups(&findings);
    assert_eq!(
        groups
            .iter()
            .map(|g| (g.package.as_str(), g.fixed_version.as_str()))
            .collect::<Vec<_>>(),
        [
            ("openssl", "3.0.15"),
            ("xz", "5.6.2"),
            ("a", "2"),
            ("a", "3"),
            ("z", "2")
        ]
    );
    assert_eq!(groups[0].resolves.critical, 2);
    assert_eq!(groups[1].resolves.critical, 1);
    assert_eq!(groups[0].images, ["a", "b"]);
}

#[test]
fn remediation_skips_unfixable() {
    assert!(remediation_groups(&[f("1", "a", Critical, None, "p", None)]).is_empty());
    assert!(remediation_groups(&[]).is_empty());
}

#[test]
fn image_summaries_include_zero_count_images() {
    let images = vec![image("zero"), image("b"), image("a"), image("critical")];
    let findings = vec![
        f("1", "b", High, None, "p", None),
        f("2", "a", High, None, "p", None),
        f("3", "critical", Critical, None, "p", None),
        f("4", "absent", Critical, None, "p", None),
    ];
    let summaries = image_summaries(&images, &findings);
    assert_eq!(
        summaries
            .iter()
            .map(|s| s.reference.as_str())
            .collect::<Vec<_>>(),
        ["critical", "a", "b", "zero"]
    );
    assert_eq!(summaries[3].counts, SeverityCounts::default());
    assert_eq!(summaries[0].counts.critical, 1);
    assert_eq!(summaries[1].counts.high, 1);
    assert_eq!(images_with_high_or_worse(&summaries), 3);
    assert_eq!(images_with_high_or_worse(&[]), 0);
    assert!(image_summaries(&[], &findings).is_empty());
}

#[test]
fn stale_images_by_threshold_and_missing_time() {
    let now = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
    let threshold = now - Duration::days(7);
    let mut images: Vec<_> = [
        "missing",
        "old",
        "boundary",
        "fresh",
        "failed",
        "not-scanned",
        "failed-old",
    ]
    .into_iter()
    .map(image)
    .collect();
    images[1].scan.scanned_at = Some(threshold - Duration::seconds(1));
    images[2].scan.scanned_at = Some(threshold);
    images[3].scan.scanned_at = Some(now);
    images[4].scan.state = ScanState::Failed;
    images[5].scan.state = ScanState::NotScanned;
    images[6].scan.state = ScanState::Failed;
    images[6].scan.scanned_at = Some(threshold - Duration::days(1));
    assert_eq!(
        stale_images(&images, now, 7)
            .iter()
            .map(|i| i.reference.as_str())
            .collect::<Vec<_>>(),
        ["missing", "old"]
    );
    assert_eq!(
        stale_images(&images, now, 0)
            .iter()
            .map(|i| i.reference.as_str())
            .collect::<Vec<_>>(),
        ["missing", "old", "boundary"]
    );
    assert!(stale_images(&[], now, 7).is_empty());
}
