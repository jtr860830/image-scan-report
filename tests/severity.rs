use rstest::rstest;
use scanreport::model::{Severity, Severity::*, SeverityBasis};
use scanreport::severity::{
    CvssScores, ScoreInput, band_v2, band_v3, classify, clean_score, label_to_severity,
};

#[rstest]
#[case(10.0, Critical)]
#[case(9.0, Critical)]
#[case(8.9, High)]
#[case(7.0, High)]
#[case(6.9, Medium)]
#[case(4.0, Medium)]
#[case(3.9, Low)]
#[case(0.1, Low)]
fn v3_bands(#[case] s: f32, #[case] want: Severity) {
    assert_eq!(band_v3(s), want);
}

#[rstest]
#[case(10.0, High)]
#[case(7.0, High)]
#[case(6.9, Medium)]
#[case(3.9, Low)]
fn v2_bands_have_no_critical(#[case] s: f32, #[case] want: Severity) {
    assert_eq!(band_v2(s), want);
}

#[test]
fn clean_score_drops_zero_and_rounds() {
    assert_eq!(clean_score(Some(0.04)), None);
    assert_eq!(clean_score(Some(f64::INFINITY)), None);
    assert_eq!(clean_score(Some(0.0)), None);
    assert_eq!(clean_score(Some(7.46)), Some(7.5));
    assert_eq!(clean_score(None), None);
}

fn scores(source: &str, v3: Option<f32>, v2: Option<f32>) -> (String, CvssScores) {
    (source.to_owned(), CvssScores { v3, v2 })
}

#[test]
fn nvd_wins_over_redhat() {
    let cvss = [
        scores("redhat", Some(7.4), None),
        scores("nvd", Some(10.0), Some(5.0)),
    ];
    let result = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: None,
    });
    assert_eq!(result.severity, Critical);
    assert_eq!(result.basis, SeverityBasis::Cvss3);
    assert_eq!(result.score_source.as_deref(), Some("nvd"));
    assert_eq!(result.score_v3, Some(10.0));
    assert_eq!(result.score_v2, Some(5.0));
}

#[test]
fn redhat_wins_when_nvd_absent() {
    let cvss = [
        scores("julia", Some(3.3), None),
        scores("redhat", Some(4.4), None),
    ];
    let result = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: None,
    });
    assert_eq!(result.severity, Medium);
    assert_eq!(result.score_source.as_deref(), Some("redhat"));
    assert_eq!(result.score_v3, Some(4.4));
}

#[test]
fn alphabetical_after_redhat() {
    let cvss = [
        scores("julia", Some(3.3), None),
        scores("bitnami", Some(9.1), None),
    ];
    let result = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: None,
    });
    assert_eq!(result.severity, Critical);
    assert_eq!(result.score_source.as_deref(), Some("bitnami"));
    assert_eq!(result.score_v3, Some(9.1));
}

#[test]
fn source_without_v3_is_skipped_for_v3() {
    let cvss = [
        scores("nvd", None, Some(5.0)),
        scores("redhat", Some(8.0), None),
    ];
    let result = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: None,
    });
    assert_eq!(result.severity, High);
    assert_eq!(result.basis, SeverityBasis::Cvss3);
    assert_eq!(result.score_source.as_deref(), Some("redhat"));
    assert_eq!(result.score_v3, Some(8.0));
    assert_eq!(result.score_v2, None);
}

#[test]
fn falls_back_to_v2() {
    let cvss = [scores("nvd", None, Some(7.5))];
    let result = classify(&ScoreInput {
        cvss: &cvss,
        scanner_label: Some("Critical"),
    });
    assert_eq!(result.severity, High);
    assert_eq!(result.basis, SeverityBasis::Cvss2);
    assert_eq!(result.score_source.as_deref(), Some("nvd"));
    assert_eq!(result.score_v2, Some(7.5));
    assert_eq!(result.score_v3, None);
}

#[test]
fn falls_back_to_scanner_label() {
    let result = classify(&ScoreInput {
        cvss: &[],
        scanner_label: Some("High"),
    });
    assert_eq!(result.severity, High);
    assert_eq!(result.basis, SeverityBasis::ScannerLabel);
    assert_eq!(result.score_source, None);
    assert_eq!(result.score_v3, None);
    assert_eq!(result.score_v2, None);
}

#[test]
fn unrated_when_nothing() {
    let result = classify(&ScoreInput {
        cvss: &[],
        scanner_label: Some("Unknown"),
    });
    assert_eq!(result.severity, Unrated);
    assert_eq!(result.basis, SeverityBasis::None);
    assert_eq!(result.score_source, None);
    assert_eq!(result.score_v3, None);
    assert_eq!(result.score_v2, None);
}

#[test]
fn unrated_when_label_missing() {
    let result = classify(&ScoreInput {
        cvss: &[],
        scanner_label: None,
    });
    assert_eq!(result.severity, Unrated);
    assert_eq!(result.basis, SeverityBasis::None);
    assert_eq!(result.score_source, None);
    assert_eq!(result.score_v3, None);
    assert_eq!(result.score_v2, None);
}

#[rstest]
#[case(f64::NAN)]
#[case(-1.0)]
fn clean_score_drops_invalid(#[case] raw: f64) {
    assert_eq!(clean_score(Some(raw)), None);
}

#[rstest]
#[case("cRiTiCaL", Some(Critical))]
#[case("HIGH", Some(High))]
#[case("medium", Some(Medium))]
#[case("Low", Some(Low))]
#[case("Unknown", None)]
#[case("", None)]
fn scanner_labels(#[case] label: &str, #[case] want: Option<Severity>) {
    assert_eq!(label_to_severity(label), want);
}
