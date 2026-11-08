//! Bundled font faces for reproducible report rendering.

use typst::foundations::Bytes;
use typst::text::{Font, FontBook, FontInfo};

/// Family names that theme font lists may use; all are embedded in the binary.
pub const FAMILIES: [&str; 3] = ["Inter", "Noto Sans TC", "Maple Mono NL"];

/// Return the embedded font files as `(file name, bytes)` pairs in a fixed order.
pub fn embedded_fonts() -> &'static [(&'static str, &'static [u8])] {
    &[
        (
            "Inter-Regular.ttf",
            include_bytes!("../../assets/fonts/Inter-Regular.ttf"),
        ),
        (
            "Inter-Medium.ttf",
            include_bytes!("../../assets/fonts/Inter-Medium.ttf"),
        ),
        (
            "Inter-Bold.ttf",
            include_bytes!("../../assets/fonts/Inter-Bold.ttf"),
        ),
        (
            "NotoSansTC-Regular.otf",
            include_bytes!("../../assets/fonts/NotoSansTC-Regular.otf"),
        ),
        (
            "NotoSansTC-Medium.otf",
            include_bytes!("../../assets/fonts/NotoSansTC-Medium.otf"),
        ),
        (
            "NotoSansTC-Bold.otf",
            include_bytes!("../../assets/fonts/NotoSansTC-Bold.otf"),
        ),
        (
            "MapleMonoNL-Regular.ttf",
            include_bytes!("../../assets/fonts/MapleMonoNL-Regular.ttf"),
        ),
        (
            "MapleMonoNL-Bold.ttf",
            include_bytes!("../../assets/fonts/MapleMonoNL-Bold.ttf"),
        ),
    ]
}

/// Index every face in the embedded font files.
pub fn font_book() -> FontBook {
    let infos: Vec<FontInfo> = embedded_fonts()
        .iter()
        .flat_map(|(_, bytes)| Font::iter(Bytes::new(*bytes)))
        .map(|font| font.info().clone())
        .collect();
    FontBook::from_infos(infos)
}
