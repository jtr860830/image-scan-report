use image_scan_report::{model::Language, render::engine::Renderer};
#[allow(dead_code)]
#[path = "support/data.rs"]
mod data;
#[allow(dead_code)]
#[path = "support/pdf.rs"]
mod pdf;

fn golden(language: Language) -> (String, usize) {
    let data = data::fixture_data(language, 3);
    let bytes = Renderer::new()
        .render_pdf(&data, None, "2026-11-08T00:00:00Z".parse().unwrap())
        .unwrap();
    let pages = pdf::page_texts(&bytes);
    let text = [0, 1, 2, pages.len() - 1]
        .into_iter()
        .map(|i| format!("Page {}: {}", i + 1, pages[i]))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(&data.meta.generated_date, "<DATE>");
    (
        text.split_whitespace().collect::<Vec<_>>().join(" "),
        pdf::page_count(&bytes),
    )
}
#[test]
fn golden_text_zh_tw() {
    insta::assert_snapshot!(golden(Language::ZhTw).0);
}
#[test]
fn golden_text_en() {
    insta::assert_snapshot!(golden(Language::En).0);
}
#[test]
fn golden_page_count() {
    insta::assert_debug_snapshot!((golden(Language::ZhTw).1, golden(Language::En).1));
}
#[test]
#[ignore = "full fixture page count"]
fn full_fixture_page_count() {
    let bytes = std::fs::read(std::env::var("REPORT_PDF").unwrap()).unwrap();
    println!("Full fixture pages: {}", pdf::page_count(&bytes));
}
