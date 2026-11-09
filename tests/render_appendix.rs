//! Integration checks for render appendix behavior.
use image_scan_report::{
    model::Language,
    render::{engine::Renderer, model::RenderData},
};
#[path = "support/data.rs"]
mod data;
#[allow(dead_code)]
#[path = "support/pdf.rs"]
mod pdf;

fn render(data: &RenderData) -> Vec<u8> {
    Renderer::new()
        .render_pdf(data, None, None, "2026-11-08T00:00:00Z".parse().unwrap())
        .unwrap()
}
fn compact(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200b}')
        .collect()
}
#[test]
fn appendix_has_rule_and_limitations() {
    for lang in [Language::En, Language::ZhTw] {
        let data = data::fixture_data(lang, 3);
        let pages = pdf::page_texts(&render(&data));
        let text = compact(pages.last().unwrap());
        assert!(text.contains(&compact(&data.strings["appendix_rule_title"])));
        assert!(text.contains("9.0"));
        assert!(text.contains("Unrated—"));
        assert!(text.contains(&compact(&data.strings["appendix_sources_title"])));
        for key in &data.appendix.limitations {
            assert!(text.contains(&compact(&data.strings[key])), "{key}");
        }
    }
}
#[test]
fn toc_lists_chapters_and_images() {
    for lang in [Language::En, Language::ZhTw] {
        let data = data::fixture_data(lang, 3);
        let pages = pdf::page_texts(&render(&data));
        let toc = compact(&pages[1]);
        assert!(toc.contains(&compact(&data.strings["toc_title"])));
        for key in [
            "ch_summary",
            "ch_remediation",
            "ch_inventory",
            "ch_images",
            "ch_appendix",
        ] {
            assert!(toc.contains(&compact(&data.strings[key])), "{key}");
            let page = pages
                .iter()
                .enumerate()
                .skip(2)
                .find(|(_, p)| compact(p).contains(&compact(&data.strings[key])))
                .unwrap()
                .0
                + 1;
            assert!(toc.replace('.', "").contains(&format!(
                "{}{}",
                compact(&data.strings[key]),
                page
            )));
        }
        assert!(toc.contains(&compact(&data.images[0].reference)));
    }
}
#[test]
fn footer_shows_page_of_total() {
    for lang in [Language::En, Language::ZhTw] {
        let data = data::fixture_data(lang, 3);
        let pages = pdf::page_texts(&render(&data));
        for i in [0, 1, pages.len() - 1] {
            let footer = data.strings["page_of"]
                .replace("{page}", &(i + 1).to_string())
                .replace("{total}", &pages.len().to_string());
            assert_eq!(compact(&pages[i]).contains(&compact(&footer)), i != 0);
            if i != 0 {
                assert!(compact(&pages[i]).contains(&compact(&data.meta.organisation)));
            }
        }
    }
}
#[test]
fn stale_and_failed_tables_render() {
    for lang in [Language::En, Language::ZhTw] {
        let mut data = data::fixture_data(lang, 3);
        data.appendix.failed_images = vec![image_scan_report::render::model::FailedImage {
            reference: "registry.example/failed:latest".into(),
            state: "failed".into(),
            error: "manifest unknown".into(),
        }];
        data.appendix.stale_images =
            vec![("registry.example/stale:old".into(), "2026-01-01".into())];
        let pages = pdf::page_texts(&render(&data));
        let text = compact(pages.last().unwrap());
        for value in [
            "registry.example/failed:latest",
            "manifest unknown",
            "registry.example/stale:old",
            "2026-01-01",
        ] {
            assert!(text.contains(&compact(value)), "{value}");
        }
    }
}

#[test]
fn method_explains_active_filters() {
    let report = data::fixture_report(3);
    let mut opts = data::default_options(Language::En);
    opts.min_severity = Some(image_scan_report::model::Severity::High);
    opts.image_detail = image_scan_report::model::ImageDetail::Counts;
    opts.max_table_rows = Some(1);
    let data = image_scan_report::render::model::build(
        &report,
        &opts,
        image_scan_report::render::strings::load(Language::En),
        image_scan_report::render::theme::default_theme().to_render_value(),
    );
    assert!(compact(&pdf::text(&render(&data))).contains(&compact(
        "Filters applied: minimum severity High; image chapter counts only; table rows capped at 1."
    )));
}

#[test]
fn traditional_chinese_explains_floor_cap_and_counts() {
    let report = data::fixture_report(3);
    let mut opts = data::default_options(Language::ZhTw);
    opts.min_severity = Some(image_scan_report::model::Severity::Medium);
    opts.image_detail = image_scan_report::model::ImageDetail::Counts;
    opts.max_table_rows = Some(1);
    for json in [false, true] {
        opts.json_artifact = json;
        let data = image_scan_report::render::model::build(
            &report,
            &opts,
            image_scan_report::render::strings::load(Language::ZhTw),
            image_scan_report::render::theme::default_theme().to_render_value(),
        );
        assert!(data.inventory_omitted > 0);
        let text = compact(&pdf::text(&render(&data)));
        let omitted = if json {
            format!(
                "未顯示 {} 筆（完整清單見 JSON 檔案）",
                data.inventory_omitted
            )
        } else {
            format!("未顯示 {} 筆", data.inventory_omitted)
        };
        assert!(text.contains(&compact(&omitted)), "{omitted}");
        assert_eq!(
            text.matches(&compact(
                "弱點依識別碼列於弱點盤點中，並套用相同篩選條件；本章僅顯示各映像檔的統計數量。"
            ))
            .count(),
            1
        );
        assert!(text.contains(&compact(
            "已套用篩選條件：最低嚴重等級為 Medium；映像檔章節僅顯示統計數量；每個表格最多 1 筆。"
        )));
    }
}
