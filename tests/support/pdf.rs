pub fn page_count(pdf: &[u8]) -> usize {
    lopdf::Document::load_mem(pdf).unwrap().get_pages().len()
}

pub fn text(pdf: &[u8]) -> String {
    pdf_extract::extract_text_from_mem(pdf).unwrap()
}
