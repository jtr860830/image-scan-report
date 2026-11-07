pub fn page_count(pdf: &[u8]) -> usize {
    lopdf::Document::load_mem(pdf).unwrap().get_pages().len()
}

pub fn text(pdf: &[u8]) -> String {
    pdf_extract::extract_text_from_mem(pdf).unwrap()
}

#[allow(dead_code)]
pub fn page_sizes(pdf: &[u8]) -> Vec<(f64, f64)> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    doc.get_pages()
        .values()
        .map(|id| {
            let mut dict = doc.get_object(*id).unwrap().as_dict().unwrap();
            let bounds = loop {
                if let Ok(value) = dict.get(b"MediaBox") {
                    break value.as_array().unwrap();
                }
                let parent = dict.get(b"Parent").unwrap().as_reference().unwrap();
                dict = doc.get_object(parent).unwrap().as_dict().unwrap();
            };
            let n = |i: usize| f64::from(bounds[i].as_float().unwrap());
            (n(2) - n(0), n(3) - n(1))
        })
        .collect()
}
