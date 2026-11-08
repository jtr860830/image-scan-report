//! Display-ready report data, independent of the rendering backend.
use crate::model::{
    Finding, FixStatus, Image, Language, Report, ScanState, Severity, SeverityBasis,
};
use crate::views::{self, SeverityCounts};
use chrono::SecondsFormat;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
/// Em dash shown in place of a missing value.
pub const PLACEHOLDER: &str = "—";
/// Report settings from the `report:` configuration plus the summary ranking sizes.
#[derive(Clone, Debug)]
pub struct RenderOptions {
    /// Bands whose findings show their description in the image tables.
    pub describe_severities: Vec<Severity>,
    /// Characters kept from each sanitised description before `…` is appended.
    pub description_chars: usize,
    /// Remediation groups shown as cards; the rest are listed in a table.
    pub remediation_cards: usize,
    /// Customer logo for the cover, from `report.logo`.
    pub customer_logo: Option<super::theme::Logo>,
    /// Report language, written to `Meta::language`.
    pub language: Language,
    /// Successful scans older than this many days are listed as stale.
    pub stale_after_days: u32,
    /// Application name, written to `Meta::product_name`.
    pub product_name: String,
    /// Application version, printed with the theme's product name in the appendix.
    pub product_version: String,
    /// Number of images in the summary ranking; the pipeline uses 10.
    pub top_images: usize,
    /// Number of vulnerabilities in the summary ranking; the pipeline uses 15.
    pub top_findings: usize,
}
impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            describe_severities: vec![Severity::Critical, Severity::High],
            description_chars: 600,
            remediation_cards: 30,
            customer_logo: None,
            language: Language::En,
            stale_after_days: 30,
            product_name: env!("CARGO_PKG_NAME").into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            top_images: 10,
            top_findings: 15,
        }
    }
}
/// Template input, serialised to `data.json` for the Typst templates.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RenderData {
    /// Cover and generation facts.
    pub meta: Meta,
    /// Scanner provenance as display strings.
    pub source: SourceFacts,
    /// Sanitised scope label.
    pub scope: String,
    /// Totals, the severity bar, and the top-ranked images and vulnerabilities.
    pub summary: Summary,
    /// Upgrade groups and counts of findings without a fix.
    pub remediation: Remediation,
    /// One row per vulnerability id, worst first.
    pub inventory: Vec<UniqueRow>,
    /// Per-image detail sections, most affected image first.
    pub images: Vec<ImageDetail>,
    /// Method, failed and stale scans, score sources, and limitation keys.
    pub appendix: Appendix,
    /// Bundled strings for the report language, keyed by [`super::strings::KEYS`].
    pub strings: BTreeMap<String, String>,
    /// Theme from [`super::theme::Theme::to_render_value`].
    pub theme: serde_json::Value,
}
/// Product, generation, organisation and language facts for the cover.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Meta {
    /// Sanitised application name.
    pub product_name: String,
    /// Sanitised application version.
    pub product_version: String,
    /// Generation time as RFC 3339 UTC with whole seconds.
    pub generated_at: String,
    /// Generation date as `YYYY-MM-DD`, also part of the PDF identifier.
    pub generated_date: String,
    /// Language tag, `en` or `zh-TW`.
    pub language: String,
    /// Sanitised organisation name for the cover.
    pub organisation: String,
    /// Template file name of the customer logo, `report-logo.<ext>`; `None` without one.
    pub logo: Option<String>,
}
/// Display-ready scanner identity and vulnerability database provenance.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct SourceFacts {
    /// Sanitised source label.
    pub display_name: String,
    /// Scanner name, or [`PLACEHOLDER`].
    pub scanner_name: String,
    /// Scanner version, or [`PLACEHOLDER`].
    pub scanner_version: String,
    /// Vulnerability database version, or [`PLACEHOLDER`].
    pub db_version: String,
    /// Vulnerability database build time as RFC 3339, or [`PLACEHOLDER`].
    pub db_updated_at: String,
}
/// Aggregate counts and rankings used in the report overview.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Summary {
    /// Number of images in the report.
    pub images_total: usize,
    /// Number of findings across all images.
    pub findings_total: usize,
    /// Number of distinct vulnerability ids.
    pub unique_total: usize,
    /// Findings per severity band.
    pub counts: SeverityCounts,
    /// Number of findings that list a fixed version.
    pub fixable: usize,
    /// `fixable` as a percentage of all findings, rounded half up; 0 without findings.
    pub fixable_percent: usize,
    /// Number of images with at least one high or critical finding.
    pub images_with_high_or_worse: usize,
    /// Severity bar segments for each non-empty band, worst first.
    pub bar: Vec<BarSegment>,
    /// Ranked rows of the most affected images, at most `top_images` of them.
    pub top_images: Vec<ImageRow>,
    /// Ranked inventory rows of the worst vulnerabilities, at most `top_findings` of them.
    pub top_findings: Vec<UniqueRow>,
}
/// One severity band's share of the findings in the severity bar.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct BarSegment {
    /// Lowercase band key, such as `critical`, that selects colours and translated labels.
    pub severity_key: String,
    /// English band label from `Severity::label`; templates translate via `severity_key`.
    pub severity_label: String,
    /// Share of all findings in this band, from 0 to 100.
    pub percent: f32,
}
/// Image reference and severity totals in the summary ranking.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageRow {
    /// Sanitised image reference.
    pub reference: String,
    /// Findings per severity band.
    pub counts: SeverityCounts,
}
/// Display-ready vulnerability grouped across packages and images.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct UniqueRow {
    /// Lowercase band key, such as `critical`, that selects colours and translated labels.
    pub severity_key: String,
    /// Sanitised vulnerability id.
    pub id: String,
    /// English band label from `Severity::label`, shown as is in the inventory chip.
    pub severity_label: String,
    /// Highest score to one decimal, or [`PLACEHOLDER`].
    pub score: String,
    /// Comma-separated affected packages.
    pub packages: String,
    /// Comma-separated fixed versions, or [`PLACEHOLDER`] when none.
    pub fixed_versions: String,
    /// Sanitised references of the affected images.
    pub images: Vec<String>,
    /// Number of affected images.
    pub image_count: usize,
}
/// Upgrade groups and counts of findings without an available fix.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Remediation {
    /// Number of groups shown as cards, from `remediation_cards`.
    pub cards: usize,
    /// Upgrade groups ranked by the critical, high, medium and low counts they resolve.
    pub groups: Vec<RemediationRow>,
    /// Number of findings without a fixed version.
    pub unfixable_total: usize,
    /// `(fix status, count)` pairs for findings without a fix, most frequent first; a missing
    /// status counts as `unknown`.
    pub unfixable_by_status: Vec<(String, usize)>,
}
/// Display-ready package upgrade and the findings it resolves.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RemediationRow {
    /// Sanitised package name.
    pub package: String,
    /// Sanitised target version.
    pub fixed_version: String,
    /// Severity counts of the findings resolved by this upgrade.
    pub resolves: SeverityCounts,
    /// Sanitised references of the images containing the package.
    pub images: Vec<String>,
}
/// Display-ready metadata and finding rows for one container image.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageDetail {
    /// Sanitised tags of the image.
    pub tags: Vec<String>,
    /// Whether to list the tags: there are several, or one that differs from the reference's.
    pub show_tags: bool,
    /// Sanitised image reference.
    pub reference: String,
    /// Manifest digest, or [`PLACEHOLDER`].
    pub digest: String,
    /// Platform label, or [`PLACEHOLDER`].
    pub platform: String,
    /// Operating system, or [`PLACEHOLDER`].
    pub os: String,
    /// Size string from [`format_size`], such as `12.3 MB`.
    pub size: String,
    /// Creation time as RFC 3339, or [`PLACEHOLDER`].
    pub created_at: String,
    /// Scan time as RFC 3339, or [`PLACEHOLDER`].
    pub scanned_at: String,
    /// Scan state key, `ok`, `failed` or `not_scanned`, that the template maps to a localised
    /// label.
    pub scan_state: String,
    /// Sanitised scan error, or [`PLACEHOLDER`].
    pub scan_error: String,
    /// Scanner version, or [`PLACEHOLDER`].
    pub scanner_version: String,
    /// Findings per severity band for this image.
    pub counts: SeverityCounts,
    /// The image's findings, worst severity first, then highest score, then id.
    pub findings: Vec<FindingRow>,
}
/// Display-ready finding in an image's detail table.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FindingRow {
    /// Sanitised vulnerability id.
    pub id: String,
    /// English band label from `Severity::label`, shown as is in the chip.
    pub severity_label: String,
    /// Lowercase band key, such as `critical`, that selects colours and translated labels.
    pub severity_key: String,
    /// Score to one decimal, v3 or else v2, or [`PLACEHOLDER`].
    pub score: String,
    /// Sanitised package name.
    pub package: String,
    /// Sanitised installed version.
    pub installed_version: String,
    /// Fixed version, or [`PLACEHOLDER`].
    pub fixed_version: String,
    /// Fix status key such as `will_not_fix`, an unknown status verbatim, or [`PLACEHOLDER`].
    pub fix_status: String,
    /// Scanner's raw severity label, or [`PLACEHOLDER`]; shown when the label decided the band.
    pub scanner_severity: String,
    /// Severity basis key: `cvss3`, `cvss2`, `scanner_label` or `none`.
    pub basis: String,
    /// Sanitised description, cut to `description_chars` characters plus `…`.
    pub description: String,
    /// Whether the finding's band is in `describe_severities`.
    pub show_description: bool,
}
/// Image whose scan failed or has not completed, for the appendix.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FailedImage {
    /// Sanitised image reference.
    pub reference: String,
    /// Scan state key, `failed` or `not_scanned`, that the template translates.
    pub state: String,
    /// Scan error, or [`PLACEHOLDER`].
    pub error: String,
}
/// Appendix tables: scan gaps, stale scans, the severity rule and score sources.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Appendix {
    /// Images whose scan state is not `ok`.
    pub failed_images: Vec<FailedImage>,
    /// `(reference, scan time)` of successful scans with no scan time or one older than
    /// `stale_after_days`.
    pub stale_images: Vec<(String, String)>,
    /// Staleness threshold in days, shown in the section title.
    pub stale_after_days: u32,
    /// `(band, CVSS range)` rows describing the banding rule.
    pub severity_rule: Vec<(String, String)>,
    /// `(score source, finding count)` pairs, most frequent first; findings without a score
    /// count under [`PLACEHOLDER`].
    pub score_sources: Vec<(String, usize)>,
    /// Translation keys of the limitation notes, in display order.
    pub limitations: Vec<String>,
}

/// Normalise line endings to `\n` and drop control characters other than newline and tab.
pub fn sanitize(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|&c| {
            c == '\n' || c == '\t' || !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
        })
        .collect()
}
/// Format a byte count in decimal units with one decimal, such as `1.5 MB`, or
/// [`PLACEHOLDER`] for `None`.
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
fn finding_row(f: &Finding, opts: &RenderOptions) -> FindingRow {
    let mut description = sanitize(&f.description);
    if description.chars().count() > opts.description_chars {
        description = description
            .chars()
            .take(opts.description_chars)
            .chain(['…'])
            .collect();
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
        show_description: opts.describe_severities.contains(&f.severity),
    }
}
/// Build the template input from a report, its options, bundled strings and the theme.
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
            score: score(v.score),
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
    let images = image_details(&summaries, &images_by_reference, &grouped, opts);
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
            logo: opts
                .customer_logo
                .as_ref()
                .map(|logo| logo.report_file_name()),
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
        remediation: remediation(report, &grouped, opts),
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

fn remediation(
    report: &Report,
    grouped: &HashMap<&str, Vec<&Finding>>,
    opts: &RenderOptions,
) -> Remediation {
    let rows = report.findings.len();
    let fixable = views::fixable(&report.findings);
    Remediation {
        cards: opts.remediation_cards,
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
            .map(|i| FailedImage {
                reference: sanitize(&i.reference),
                state: if i.scan.state == ScanState::Failed {
                    "failed"
                } else {
                    "not_scanned"
                }
                .into(),
                error: display(i.scan.error.as_deref()),
            })
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
            ("Unrated", "—"),
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
    opts: &RenderOptions,
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
            let reference = image
                .reference
                .split(" (")
                .next()
                .unwrap_or(&image.reference);
            let reference_tag = reference
                .rsplit_once(':')
                .filter(|(name, tag)| !name.contains('@') && !tag.contains('/'))
                .map(|(_, tag)| tag);
            let show_tags = image.tags.len() > 1
                || image
                    .tags
                    .first()
                    .is_some_and(|tag| Some(tag.as_str()) != reference_tag);
            Some(ImageDetail {
                tags: image.tags.iter().map(|tag| sanitize(tag)).collect(),
                show_tags,
                reference: sanitize(&image.reference),
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
                findings: findings.into_iter().map(|f| finding_row(f, opts)).collect(),
            })
        })
        .collect()
}
