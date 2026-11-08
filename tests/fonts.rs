//! Integration checks for fonts behavior.
#[test]
fn bundled_fonts_cover_three_families_with_regular_and_bold() {
    let book = image_scan_report::render::fonts::font_book();
    for family in image_scan_report::render::fonts::FAMILIES {
        let weights: Vec<_> = book
            .families()
            .find(|(name, _)| *name == family)
            .expect(family)
            .1
            .map(|index| book.info(index).expect("bundled font info").variant.weight)
            .collect();
        assert!(
            weights.contains(&typst::text::FontWeight::REGULAR),
            "{family} regular"
        );
        assert!(
            weights.contains(&typst::text::FontWeight::BOLD),
            "{family} bold"
        );
    }
}

#[test]
fn embedded_font_count_is_eight() {
    assert_eq!(image_scan_report::render::fonts::embedded_fonts().len(), 8);
}
