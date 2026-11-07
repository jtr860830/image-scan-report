use std::collections::BTreeSet;

use image_scan_report::{
    model::Language,
    render::strings::{KEYS, load},
};

fn placeholders(value: &str) -> BTreeSet<&str> {
    value
        .split('{')
        .skip(1)
        .map(|part| part.split_once('}').expect("closed placeholder").0)
        .collect()
}

#[test]
fn both_locales_have_exactly_the_key_set() {
    let expected: BTreeSet<_> = KEYS.iter().copied().collect();
    assert_eq!(expected.len(), KEYS.len(), "duplicate canonical key");
    for language in [Language::ZhTw, Language::En] {
        let strings = load(language);
        assert_eq!(
            strings.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected
        );
        assert!(strings.values().all(|value| !value.trim().is_empty()));
    }
}

#[test]
fn zh_tw_uses_taiwanese_terms() {
    let strings = load(Language::ZhTw);
    let values = strings.values().cloned().collect::<Vec<_>>().join(" ");
    for term in ["映像檔", "弱點", "套件", "修補版本", "稽核"] {
        assert!(values.contains(term), "missing {term}");
    }
    for term in ["镜像", "漏洞", "软件包", "鏡像", "軟體包"] {
        assert!(!values.contains(term), "forbidden {term}");
    }
}

#[test]
fn placeholders_match_between_locales() {
    let zh = load(Language::ZhTw);
    let en = load(Language::En);
    for key in KEYS {
        let expected: BTreeSet<_> = match *key {
            "summary_lede" => vec!["images", "unique"],
            "fact_fixable" => vec!["fixable", "percent"],
            "fact_high_or_worse" => vec!["count", "total"],
            "remediation_resolves" => vec!["critical", "high", "medium", "low"],
            "remediation_affects" | "remediation_unfixable_lede" | "inventory_lede" => {
                vec!["count"]
            }
            "image_scan_failed" => vec!["error"],
            "appendix_stale_title" => vec!["days"],
            "generated_by" => vec!["product", "version"],
            "page_of" => vec!["page", "total"],
            _ => vec![],
        }
        .into_iter()
        .collect();
        assert_eq!(placeholders(&zh[*key]), expected, "{key}");
        assert_eq!(placeholders(&zh[*key]), placeholders(&en[*key]), "{key}");
    }
}
