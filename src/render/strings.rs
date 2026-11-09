//! Bundled report translations and their canonical template keys.

use std::collections::BTreeMap;

use crate::model::Language;

/// Every translation key, in report order; each bundled locale must define exactly these.
pub const KEYS: &[&str] = &[
    "report_title",
    "cover_scope",
    "cover_source",
    "cover_images",
    "cover_scan_range",
    "cover_generated",
    "ch_summary",
    "ch_remediation",
    "ch_inventory",
    "ch_images",
    "ch_appendix",
    "toc_title",
    "summary_lede",
    "tile_critical",
    "tile_high",
    "tile_medium",
    "tile_low",
    "tile_unrated",
    "fact_fixable",
    "fact_high_or_worse",
    "sec_top_images",
    "sec_top_findings",
    "col_image",
    "col_id",
    "col_severity",
    "col_cvss",
    "col_package",
    "col_installed",
    "col_fixed",
    "col_images",
    "col_count",
    "col_source",
    "col_status",
    "col_scanned_at",
    "col_error",
    "remediation_lede",
    "remediation_more_title",
    "remediation_more_lede",
    "remediation_resolves",
    "remediation_affects",
    "remediation_unfixable_title",
    "remediation_unfixable_lede",
    "status_fixed",
    "status_affected",
    "status_will_not_fix",
    "status_end_of_life",
    "status_fix_deferred",
    "status_under_investigation",
    "status_other",
    "inventory_lede",
    "inventory_affected",
    "image_meta_tags",
    "image_meta_digest",
    "image_meta_platform",
    "image_meta_os",
    "image_meta_size",
    "image_meta_created",
    "image_meta_scanned",
    "image_meta_counts",
    "image_findings_title",
    "image_scan_failed",
    "no_findings",
    "appendix_method",
    "appendix_scanner",
    "appendix_db",
    "appendix_tool",
    "appendix_rule_title",
    "appendix_rule_text",
    "appendix_sources_title",
    "appendix_scope_text",
    "appendix_failed_title",
    "appendix_stale_title",
    "appendix_limitations_title",
    "limit_recomputed",
    "limit_sources_differ",
    "limit_filled_scores",
    "limit_coverage",
    "limit_registry_scope",
    "limit_no_history",
    "generated_by",
    "page_of",
    "basis_cvss3",
    "basis_cvss2",
    "basis_scanner_label",
    "basis_none",
    "scan_state_ok",
    "scan_state_failed",
    "scan_state_not_scanned",
];

/// Parse the bundled `en` or `zh-TW` strings into a key-to-text map.
///
/// # Panics
///
/// Panics if the bundled locale file is not a JSON object of strings, which would be a
/// build defect rather than a caller error.
pub fn load(language: Language) -> BTreeMap<String, String> {
    let source = match language {
        Language::ZhTw => include_str!("../../assets/strings/zh-TW.json"),
        Language::En => include_str!("../../assets/strings/en.json"),
    };
    serde_json::from_str(source)
        .expect("bundled report locale must be valid JSON with string values")
}
