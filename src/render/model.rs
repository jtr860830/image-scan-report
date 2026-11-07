//! Display-ready report data, independent of the rendering backend.
use crate::{
    model::*,
    views::{self, SeverityCounts},
};
use chrono::SecondsFormat;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
pub const PLACEHOLDER: &str = "—";
#[derive(Clone, Debug)]
pub struct RenderOptions {
    pub language: Language,
    pub stale_after_days: u32,
    pub product_name: String,
    pub product_version: String,
    pub top_images: usize,
    pub top_findings: usize,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RenderData {
    pub meta: Meta,
    pub source: SourceFacts,
    pub scope: String,
    pub summary: Summary,
    pub remediation: Remediation,
    pub inventory: Vec<UniqueRow>,
    pub images: Vec<ImageDetail>,
    pub appendix: Appendix,
    pub strings: BTreeMap<String, String>,
    pub theme: serde_json::Value,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Meta {
    pub product_name: String,
    pub product_version: String,
    pub generated_at: String,
    pub generated_date: String,
    pub language: String,
    pub organisation: String,
    pub logo: Option<String>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct SourceFacts {
    pub display_name: String,
    pub scanner_name: String,
    pub scanner_version: String,
    pub db_version: String,
    pub db_updated_at: String,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Summary {
    pub images_total: usize,
    pub findings_total: usize,
    pub unique_total: usize,
    pub counts: SeverityCounts,
    pub fixable: usize,
    pub fixable_percent: usize,
    pub images_with_high_or_worse: usize,
    pub bar: Vec<BarSegment>,
    pub top_images: Vec<ImageRow>,
    pub top_findings: Vec<UniqueRow>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct BarSegment {
    pub severity_key: String,
    pub severity_label: String,
    pub percent: f32,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageRow {
    pub reference: String,
    pub counts: SeverityCounts,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct UniqueRow {
    pub severity_key: String,
    pub id: String,
    pub severity_label: String,
    pub score: String,
    pub packages: String,
    pub fixed_versions: String,
    pub images: Vec<String>,
    pub image_count: usize,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Remediation {
    pub groups: Vec<RemediationRow>,
    pub unfixable_total: usize,
    pub unfixable_by_status: Vec<(String, usize)>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RemediationRow {
    pub package: String,
    pub fixed_version: String,
    pub resolves: SeverityCounts,
    pub images: Vec<String>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageDetail {
    pub reference: String,
    pub tags: Vec<String>,
    pub digest: String,
    pub platform: String,
    pub os: String,
    pub size: String,
    pub created_at: String,
    pub scanned_at: String,
    pub scan_state: String,
    pub scan_error: String,
    pub scanner_version: String,
    pub counts: SeverityCounts,
    pub findings: Vec<FindingRow>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FindingRow {
    pub id: String,
    pub severity_label: String,
    pub severity_key: String,
    pub score: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: String,
    pub fix_status: String,
    pub scanner_severity: String,
    pub basis: String,
    pub description: String,
    pub show_description: bool,
    pub links: Vec<String>,
}
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Appendix {
    pub failed_images: Vec<(String, String)>,
    pub stale_images: Vec<(String, String)>,
    pub stale_after_days: u32,
    pub severity_rule: Vec<(String, String)>,
    pub score_sources: Vec<(String, usize)>,
    pub limitations: Vec<String>,
}

pub fn sanitize(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|&c| {
            c == '\n' || c == '\t' || !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
        })
        .collect()
}
pub fn format_size(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return PLACEHOLDER.into();
    };
    for (unit, divisor) in [
        ("TB", 1_000_000_000_000u64),
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("KB", 1000),
    ] {
        if bytes >= divisor {
            return format!("{:.1} {unit}", bytes as f64 / divisor as f64);
        }
    }
    format!("{bytes} B")
}
fn display(value: Option<&str>) -> String {
    value.map(sanitize).unwrap_or_else(|| PLACEHOLDER.into())
}
fn date(value: Option<chrono::DateTime<chrono::Utc>>) -> String {
    value
        .map(|v| v.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| PLACEHOLDER.into())
}
fn score(value: Option<f32>) -> String {
    value
        .map(|v| format!("{v:.1}"))
        .unwrap_or_else(|| PLACEHOLDER.into())
}
fn status(value: &FixStatus) -> String {
    sanitize(match value {
        FixStatus::Fixed => "fixed",
        FixStatus::Affected => "affected",
        FixStatus::WillNotFix => "will_not_fix",
        FixStatus::EndOfLife => "end_of_life",
        FixStatus::FixDeferred => "fix_deferred",
        FixStatus::UnderInvestigation => "under_investigation",
        FixStatus::Other(s) => s,
    })
}
fn frequencies(values: impl Iterator<Item = String>) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_insert(0) += 1;
    }
    let mut result: Vec<_> = counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    result
}
fn finding_row(f: &Finding) -> FindingRow {
    let mut description = sanitize(&f.description);
    if description.chars().count() > 600 {
        description = description.chars().take(600).chain(['…']).collect();
    }
    FindingRow {
        id: sanitize(&f.id),
        severity_label: f.severity.label().into(),
        severity_key: f.severity.label().to_lowercase(),
        score: score(f.score_v3.or(f.score_v2)),
        package: sanitize(&f.package),
        installed_version: sanitize(&f.installed_version),
        fixed_version: display(f.fixed_version.as_deref()),
        fix_status: display(f.fix_status.as_ref().map(status).as_deref()),
        scanner_severity: display(f.scanner_severity.as_deref()),
        basis: match f.severity_basis {
            SeverityBasis::Cvss3 => "cvss3",
            SeverityBasis::Cvss2 => "cvss2",
            SeverityBasis::ScannerLabel => "scanner_label",
            SeverityBasis::None => "none",
        }
        .into(),
        description,
        show_description: matches!(f.severity, Severity::Critical | Severity::High),
        links: f.links.iter().map(|s| sanitize(s)).collect(),
    }
}
pub fn build(
    report: &Report,
    opts: &RenderOptions,
    strings: BTreeMap<String, String>,
    theme: serde_json::Value,
) -> RenderData {
    let summaries = views::image_summaries(&report.images, &report.findings);
    let inventory: Vec<_> = views::unique_vulnerabilities(&report.findings)
        .into_iter()
        .map(|v| UniqueRow {
            id: sanitize(&v.id),
            severity_label: v.severity.label().into(),
            severity_key: v.severity.label().to_lowercase(),
            score: score(v.score_v3),
            packages: sanitize(&v.packages.join(", ")),
            fixed_versions: if v.fixed_versions.is_empty() {
                PLACEHOLDER.into()
            } else {
                sanitize(&v.fixed_versions.join(", "))
            },
            image_count: v.images.len(),
            images: sanitized_strings(&v.images),
        })
        .collect();
    let mut grouped: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for finding in &report.findings {
        grouped
            .entry(finding.image.as_str())
            .or_default()
            .push(finding);
    }
    let mut images_by_reference: HashMap<&str, &Image> = HashMap::new();
    for image in &report.images {
        images_by_reference
            .entry(image.reference.as_str())
            .or_insert(image);
    }
    let images = image_details(&summaries, &images_by_reference, &grouped);
    RenderData {
        meta: Meta {
            product_name: sanitize(&opts.product_name),
            product_version: sanitize(&opts.product_version),
            generated_at: date(Some(report.generated_at)),
            generated_date: report.generated_at.format("%Y-%m-%d").to_string(),
            language: match opts.language {
                Language::En => "en",
                Language::ZhTw => "zh-TW",
            }
            .into(),
            organisation: sanitize(&report.organisation),
            logo: None,
        },
        source: SourceFacts {
            display_name: sanitize(&report.source.display_name),
            scanner_name: display(report.source.scanner_name.as_deref()),
            scanner_version: display(report.source.scanner_version.as_deref()),
            db_version: display(report.source.db_version.as_deref()),
            db_updated_at: date(report.source.db_updated_at),
        },
        scope: sanitize(&report.scope),
        summary: summary(report, opts, &summaries, &inventory),
        remediation: remediation(report, &grouped),
        inventory,
        images,
        appendix: appendix(report, opts, &grouped),
        strings,
        theme,
    }
}

fn sanitized_strings(values: &[String]) -> Vec<String> {
    values.iter().map(|v| sanitize(v)).collect()
}

fn summary(
    report: &Report,
    opts: &RenderOptions,
    summaries: &[views::ImageSummary],
    inventory: &[UniqueRow],
) -> Summary {
    let counts = views::counts(&report.findings);
    let rows = report.findings.len();
    let fixable = views::fixable(&report.findings);
    let bar = [
        (Severity::Critical, counts.critical),
        (Severity::High, counts.high),
        (Severity::Medium, counts.medium),
        (Severity::Low, counts.low),
        (Severity::Unrated, counts.unrated),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(s, n)| BarSegment {
        severity_label: s.label().into(),
        severity_key: s.label().to_lowercase(),
        percent: n as f32 * 100.0 / rows as f32,
    })
    .collect();
    Summary {
        images_total: report.images.len(),
        findings_total: rows,
        unique_total: inventory.len(),
        counts,
        fixable,
        fixable_percent: if rows == 0 {
            0
        } else {
            ((fixable as u128 * 100 + rows as u128 / 2) / rows as u128) as usize
        },
        images_with_high_or_worse: views::images_with_high_or_worse(summaries),
        bar,
        top_images: summaries
            .iter()
            .take(opts.top_images)
            .map(|s| ImageRow {
                reference: sanitize(&s.reference),
                counts: s.counts.clone(),
            })
            .collect(),
        top_findings: inventory.iter().take(opts.top_findings).cloned().collect(),
    }
}

fn remediation(report: &Report, grouped: &HashMap<&str, Vec<&Finding>>) -> Remediation {
    let rows = report.findings.len();
    let fixable = views::fixable(&report.findings);
    Remediation {
        groups: views::remediation_groups(&report.findings)
            .into_iter()
            .map(|g| RemediationRow {
                package: sanitize(&g.package),
                fixed_version: sanitize(&g.fixed_version),
                resolves: g.resolves,
                images: sanitized_strings(&g.images),
            })
            .collect(),
        unfixable_total: rows - fixable,
        unfixable_by_status: frequencies(
            grouped
                .values()
                .flatten()
                .filter(|f| f.fixed_version.is_none())
                .map(|f| {
                    f.fix_status
                        .as_ref()
                        .map(status)
                        .unwrap_or_else(|| "unknown".into())
                }),
        ),
    }
}

fn appendix(
    report: &Report,
    opts: &RenderOptions,
    grouped: &HashMap<&str, Vec<&Finding>>,
) -> Appendix {
    Appendix {
        failed_images: report
            .images
            .iter()
            .filter(|i| i.scan.state != ScanState::Ok)
            .map(|i| (sanitize(&i.reference), display(i.scan.error.as_deref())))
            .collect(),
        stale_images: views::stale_images(
            &report.images,
            report.generated_at,
            opts.stale_after_days,
        )
        .into_iter()
        .map(|i| (sanitize(&i.reference), date(i.scan.scanned_at)))
        .collect(),
        stale_after_days: opts.stale_after_days,
        severity_rule: [
            ("Critical", "≥ 9.0"),
            ("High", "7.0 – 8.9"),
            ("Medium", "4.0 – 6.9"),
            ("Low", "0.1 – 3.9"),
        ]
        .into_iter()
        .map(|(a, b)| (a.into(), b.into()))
        .collect(),
        score_sources: frequencies(
            grouped
                .values()
                .flatten()
                .map(|f| display(f.score_source.as_deref())),
        ),
        limitations: [
            "limit_recomputed",
            "limit_sources_differ",
            "limit_filled_scores",
            "limit_coverage",
            "limit_registry_scope",
            "limit_no_history",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

fn image_details(
    summaries: &[views::ImageSummary],
    images_by_reference: &HashMap<&str, &Image>,
    grouped: &HashMap<&str, Vec<&Finding>>,
) -> Vec<ImageDetail> {
    summaries
        .iter()
        .filter_map(|s| {
            let image = images_by_reference.get(s.reference.as_str())?;
            let mut findings = grouped
                .get(s.reference.as_str())
                .cloned()
                .unwrap_or_default();
            findings.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(
                        || match (a.score_v3.or(a.score_v2), b.score_v3.or(b.score_v2)) {
                            (Some(a), Some(b)) => b.total_cmp(&a),
                            (Some(_), None) => std::cmp::Ordering::Less,
                            (None, Some(_)) => std::cmp::Ordering::Greater,
                            _ => std::cmp::Ordering::Equal,
                        },
                    )
                    .then_with(|| a.id.cmp(&b.id))
            });
            Some(ImageDetail {
                reference: sanitize(&image.reference),
                tags: sanitized_strings(&image.tags),
                digest: display(image.digest.as_deref()),
                platform: display(image.platform.as_deref()),
                os: display(image.os.as_deref()),
                size: format_size(image.size_bytes),
                created_at: date(image.created_at),
                scanned_at: date(image.scan.scanned_at),
                scan_state: match image.scan.state {
                    ScanState::Ok => "ok",
                    ScanState::Failed => "failed",
                    ScanState::NotScanned => "not_scanned",
                }
                .into(),
                scan_error: display(image.scan.error.as_deref()),
                scanner_version: display(image.scan.scanner_version.as_deref()),
                counts: s.counts.clone(),
                findings: findings.into_iter().map(finding_row).collect(),
            })
        })
        .collect()
}
