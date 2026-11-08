//! Display-ready report data, independent of the rendering backend.
use crate::model::{
    Finding, FixStatus, Image, Language, Report, ScanState, Severity, SeverityBasis,
};
use crate::views::{self, SeverityCounts};
use chrono::SecondsFormat;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
/// Display text used when a report value is unavailable.
pub const PLACEHOLDER: &str = "—";
/// Content limits and presentation choices supplied to report generation.
#[derive(Clone, Debug)]
pub struct RenderOptions {
    /// Severity bands whose findings include descriptions in the report. An empty list indicates no entries.
    pub describe_severities: Vec<Severity>,
    /// Maximum number of characters shown in each finding description.
    pub description_chars: usize,
    /// Maximum number of remediation groups displayed as cards.
    pub remediation_cards: usize,
    /// Optional organization branding embedded in the report. None indicates that the value is unavailable.
    pub customer_logo: Option<super::theme::Logo>,
    /// Language selected for report labels and explanatory text.
    pub language: Language,
    /// Scan age threshold in days used to flag stale images.
    pub stale_after_days: u32,
    /// Application name displayed in report branding.
    pub product_name: String,
    /// Application version displayed in report branding.
    pub product_version: String,
    /// Maximum number of images included in the summary ranking.
    pub top_images: usize,
    /// Maximum number of vulnerabilities included in the summary ranking.
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
/// Display-ready sections serialized as input to embedded templates.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RenderData {
    /// Generation, language, and organization facts displayed in the report.
    pub meta: Meta,
    /// Scanner identity and origin of the input data.
    pub source: SourceFacts,
    /// Human-readable registry, project, or directory scope of the scan.
    pub scope: String,
    /// Aggregate scan counts and ranked findings for the report overview.
    pub summary: Summary,
    /// Grouped package upgrades and counts of findings without fixes.
    pub remediation: Remediation,
    /// Deduplicated vulnerability rows for the inventory table. An empty list indicates no entries.
    pub inventory: Vec<UniqueRow>,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<ImageDetail>,
    /// Supplementary scan limitations and diagnostic tables.
    pub appendix: Appendix,
    /// Localized report text indexed by stable template keys.
    pub strings: BTreeMap<String, String>,
    /// Colors, fonts, and product branding supplied to report templates.
    pub theme: serde_json::Value,
}
/// Product, generation, organization, and localization facts for the report cover.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Meta {
    /// Application name displayed in report branding.
    pub product_name: String,
    /// Application version displayed in report branding.
    pub product_version: String,
    /// UTC instant at which the report was generated.
    pub generated_at: String,
    /// Calendar date displayed in the report metadata.
    pub generated_date: String,
    /// Language selected for report labels and explanatory text.
    pub language: String,
    /// Organization name displayed on the report cover.
    pub organisation: String,
    /// Optional branding asset to embed in the report. None indicates that the value is unavailable.
    pub logo: Option<String>,
}
/// Display-ready scanner identity and vulnerability database provenance.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct SourceFacts {
    /// Human-readable source label displayed in the report.
    pub display_name: String,
    /// Name of the scanner that generated this result.
    pub scanner_name: String,
    /// Version of the scanner that generated this result.
    pub scanner_version: String,
    /// Version of the vulnerability database used by the scanner.
    pub db_version: String,
    /// Timestamp of the scanner vulnerability database update.
    pub db_updated_at: String,
}
/// Aggregate counts and rankings used in the report overview.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Summary {
    /// Total number of distinct scanned image records.
    pub images_total: usize,
    /// Total number of image-specific vulnerability findings.
    pub findings_total: usize,
    /// Number of distinct vulnerability identifiers.
    pub unique_total: usize,
    /// Finding totals grouped by normalized severity.
    pub counts: SeverityCounts,
    /// Number of findings with an available fixed version.
    pub fixable: usize,
    /// Integer percentage of findings with an available fix.
    pub fixable_percent: usize,
    /// Number of images containing high or critical findings.
    pub images_with_high_or_worse: usize,
    /// Severity distribution segments for the summary chart. An empty list indicates no entries.
    pub bar: Vec<BarSegment>,
    /// Maximum number of images included in the summary ranking. An empty list indicates no entries.
    pub top_images: Vec<ImageRow>,
    /// Maximum number of vulnerabilities included in the summary ranking. An empty list indicates no entries.
    pub top_findings: Vec<UniqueRow>,
}
/// One severity band's label and percentage in the distribution chart.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct BarSegment {
    /// Stable severity key used to select styles and translations.
    pub severity_key: String,
    /// Localized severity label displayed in the report.
    pub severity_label: String,
    /// Share of the total, expressed as a percentage from zero to one hundred.
    pub percent: f32,
}
/// Image reference and severity totals used in a summary ranking.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageRow {
    /// Canonical image reference used to associate findings with an image.
    pub reference: String,
    /// Finding totals grouped by normalized severity.
    pub counts: SeverityCounts,
}
/// Display-ready deduplicated vulnerability and affected-package details.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct UniqueRow {
    /// Stable severity key used to select styles and translations.
    pub severity_key: String,
    /// Scanner-provided vulnerability identifier.
    pub id: String,
    /// Localized severity label displayed in the report.
    pub severity_label: String,
    /// Effective CVSS score selected for severity classification.
    pub score: String,
    /// Affected package names in this vulnerability group.
    pub packages: String,
    /// Package versions that resolve the grouped vulnerabilities.
    pub fixed_versions: String,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<String>,
    /// Number of affected image references in this group.
    pub image_count: usize,
}
/// Upgrade groups and counts of findings without available fixes.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Remediation {
    /// Maximum number of remediation cards to display.
    pub cards: usize,
    /// Package and target-version groups that can be remediated together. An empty list indicates no entries.
    pub groups: Vec<RemediationRow>,
    /// Number of findings without an available fixed version.
    pub unfixable_total: usize,
    /// Counts of findings without fixes, grouped by scanner fix status. An empty list indicates no entries.
    pub unfixable_by_status: Vec<(String, usize)>,
}
/// Display-ready target upgrade and the findings it resolves.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RemediationRow {
    /// Affected software package identifier.
    pub package: String,
    /// Package version containing the fix, when the scanner supplies one.
    pub fixed_version: String,
    /// Severity counts for findings resolved by this upgrade.
    pub resolves: SeverityCounts,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<String>,
}
/// Display-ready metadata and finding rows for one container image.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ImageDetail {
    /// Alternative tags identifying the same image content. An empty list indicates no entries.
    pub tags: Vec<String>,
    /// Whether additional image tags should be displayed.
    pub show_tags: bool,
    /// Canonical image reference used to associate findings with an image.
    pub reference: String,
    /// Content digest reported by the registry.
    pub digest: String,
    /// Operating system and architecture label for the image.
    pub platform: String,
    /// Operating system identified by the scanner.
    pub os: String,
    /// Image size reported by the scanner, in bytes before display formatting.
    pub size: String,
    /// Creation time of the scanned image.
    pub created_at: String,
    /// Time of the most recent vulnerability scan.
    pub scanned_at: String,
    /// Display label describing whether the image scan succeeded.
    pub scan_state: String,
    /// Display text explaining an unsuccessful scan.
    pub scan_error: String,
    /// Version of the scanner that generated this result.
    pub scanner_version: String,
    /// Finding totals grouped by normalized severity.
    pub counts: SeverityCounts,
    /// Normalized vulnerabilities associated with scanned images. An empty list indicates no entries.
    pub findings: Vec<FindingRow>,
}
/// Display-ready package vulnerability with localized severity and remediation text.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FindingRow {
    /// Scanner-provided vulnerability identifier.
    pub id: String,
    /// Localized severity label displayed in the report.
    pub severity_label: String,
    /// Stable severity key used to select styles and translations.
    pub severity_key: String,
    /// Effective CVSS score selected for severity classification.
    pub score: String,
    /// Affected software package identifier.
    pub package: String,
    /// Package version detected in the scanned image.
    pub installed_version: String,
    /// Package version containing the fix, when the scanner supplies one.
    pub fixed_version: String,
    /// Scanner assessment of whether a package fix is available.
    pub fix_status: String,
    /// Original severity label retained alongside the normalized severity.
    pub scanner_severity: String,
    /// Rule that determined the effective severity.
    pub basis: String,
    /// Human-readable explanation of the vulnerability.
    pub description: String,
    /// Whether the finding description should be visible.
    pub show_description: bool,
}
/// Image reference and diagnostic for an unsuccessful or incomplete scan.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FailedImage {
    /// Canonical image reference used to associate findings with an image.
    pub reference: String,
    /// Normalized scan outcome used to distinguish success, failure, and unscanned images.
    pub state: String,
    /// Diagnostic explaining an unsuccessful scan or operation.
    pub error: String,
}
/// Supplementary tables covering scan gaps, stale images, and severity rules.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Appendix {
    /// Images with unsuccessful or incomplete scans. An empty list indicates no entries.
    pub failed_images: Vec<FailedImage>,
    /// Image references paired with their scan dates when older than the configured threshold. An empty list indicates no entries.
    pub stale_images: Vec<(String, String)>,
    /// Scan age threshold in days used to flag stale images.
    pub stale_after_days: u32,
    /// Explanations of the rules used for severity classification. An empty list indicates no entries.
    pub severity_rule: Vec<(String, String)>,
    /// Finding counts grouped by the selected CVSS vendor source. An empty list indicates no entries.
    pub score_sources: Vec<(String, usize)>,
    /// Explanations of incomplete coverage and scanner constraints. An empty list indicates no entries.
    pub limitations: Vec<String>,
}

/// Remove control characters that cannot be displayed in the report.
pub fn sanitize(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|&c| {
            c == '\n' || c == '\t' || !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
        })
        .collect()
}
/// Format a byte count for display, using a placeholder when unknown.
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
/// Build display-ready report sections from normalized scan data.
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
