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

#[allow(dead_code)]
pub fn page_texts(pdf: &[u8]) -> Vec<String> {
    let doc = lopdf::Document::load_mem(pdf).unwrap();
    doc.get_pages()
        .keys()
        .map(|page| doc.extract_text(&[*page]).unwrap())
        .collect()
}

#[allow(dead_code)]
pub const LOGO_PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0,
    0, 0, 58, 126, 155, 85, 0, 0, 0, 10, 73, 68, 65, 84, 120, 156, 99, 96, 0, 0, 0, 2, 0, 1, 72,
    175, 164, 113, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];

#[allow(dead_code)]
pub fn image_count(bytes: &[u8], page: u32) -> usize {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    doc.get_page_images(doc.get_pages()[&page]).unwrap().len()
}
