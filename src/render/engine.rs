//! Embedded Typst compilation and deterministic PDF export.
use super::{fonts, model::RenderData, theme::Logo};
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::sync::Once;
use typst::{
    diag::SourceDiagnostic,
    foundations::{Datetime, Smart},
};
use typst_as_lib::{TypstAsLibError, TypstEngine, conversions::IntoSource};
use typst_layout::PagedDocument;
use typst_pdf::{PdfOptions, Timestamp};

const SOURCES: &[(&str, &str)] = &[
    (
        "parts/inventory.typ",
        include_str!("../../templates/parts/inventory.typ"),
    ),
    (
        "parts/remediation.typ",
        include_str!("../../templates/parts/remediation.typ"),
    ),
    (
        "parts/summary.typ",
        include_str!("../../templates/parts/summary.typ"),
    ),
    ("report.typ", include_str!("../../templates/report.typ")),
    (
        "lib/theme.typ",
        include_str!("../../templates/lib/theme.typ"),
    ),
    ("lib/fmt.typ", include_str!("../../templates/lib/fmt.typ")),
    (
        "parts/cover.typ",
        include_str!("../../templates/parts/cover.typ"),
    ),
];

#[derive(thiserror::Error, Debug)]
pub enum RenderError {
    #[error("template compilation failed:\n{0}")]
    Compile(String),
    #[error("PDF export failed: {0}")]
    Pdf(String),
    #[error("{0}")]
    Data(String),
}

pub struct Renderer {
    sources: Vec<(&'static str, String)>,
}
impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}
impl Renderer {
    pub fn new() -> Self {
        static POOL: Once = Once::new();
        POOL.call_once(|| {
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build_global();
        });
        Self {
            sources: SOURCES
                .iter()
                .map(|&(name, source)| (name, source.to_owned()))
                .collect(),
        }
    }

    /// Override embedded template sources for diagnostic tests.
    #[doc(hidden)]
    pub fn with_sources(sources: &[(&'static str, String)]) -> Self {
        let mut renderer = Self::new();
        for (name, source) in sources {
            if let Some(entry) = renderer.sources.iter_mut().find(|entry| entry.0 == *name) {
                entry.1 = source.clone();
            } else {
                renderer.sources.push((name, source.clone()));
            }
        }
        renderer
    }

    fn diagnostics(&self, diagnostics: &[SourceDiagnostic]) -> String {
        diagnostics
            .iter()
            .map(|diagnostic| {
                let location = self
                    .sources
                    .iter()
                    .find_map(|(name, text)| {
                        let source = (*name, text.as_str()).into_source();
                        let range = match diagnostic.span.get() {
                            typst::syntax::DiagSpanKind::Number { id, num, sub_range }
                                if source.id() == id =>
                            {
                                source.range(num, sub_range)?
                            }
                            typst::syntax::DiagSpanKind::Range { id, range }
                                if source.id() == id =>
                            {
                                range
                            }
                            _ => return None,
                        };
                        let line = text[..range.start].bytes().filter(|b| *b == b'\n').count() + 1;
                        Some(format!("{name}:{line}"))
                    })
                    .unwrap_or_else(|| "<unknown>".into());
                let mut message = format!("{location}: {}", diagnostic.message);
                for hint in &diagnostic.hints {
                    message.push_str(&format!("\n  hint: {}", hint.v));
                }
                message
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn compile(
        &self,
        data: &RenderData,
        logo: Option<&Logo>,
    ) -> Result<PagedDocument, RenderError> {
        let bytes = serde_json::to_vec(data).map_err(|e| RenderError::Data(e.to_string()))?;
        let mut files = vec![("data.json", bytes.as_slice())];
        if let Some(logo) = logo {
            files.push((&logo.file_name, &logo.bytes));
        }
        let main = self
            .sources
            .iter()
            .find(|s| s.0 == "report.typ")
            .expect("embedded main template");
        let engine = TypstEngine::builder()
            .main_file((main.0, main.1.as_str()))
            .fonts(fonts::embedded_fonts().iter().map(|(_, bytes)| *bytes))
            .with_static_source_file_resolver(
                self.sources
                    .iter()
                    .map(|(name, source)| (*name, source.as_str())),
            )
            .with_static_file_resolver(files)
            .build();
        engine
            .compile::<PagedDocument>()
            .output
            .map_err(|err| match err {
                TypstAsLibError::TypstSource(diagnostics) => {
                    RenderError::Compile(self.diagnostics(&diagnostics))
                }
                other => RenderError::Compile(format!("<unknown>: {other}")),
            })
    }

    pub fn render_pdf(
        &self,
        data: &RenderData,
        logo: Option<&Logo>,
        generated_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, RenderError> {
        let doc = self.compile(data, logo)?;
        let date = Datetime::from_ymd_hms(
            generated_at.year(),
            generated_at.month() as u8,
            generated_at.day() as u8,
            generated_at.hour() as u8,
            generated_at.minute() as u8,
            generated_at.second() as u8,
        )
        .ok_or_else(|| {
            RenderError::Data("report timestamp is outside Typst's datetime range".into())
        })?;
        typst_pdf::pdf(
            &doc,
            &PdfOptions {
                tagged: false,
                timestamp: Some(Timestamp::new_utc(date)),
                ident: Smart::Custom(format!(
                    "{}|{}|{}",
                    data.scope, data.source.display_name, data.meta.generated_date
                )),
                ..Default::default()
            },
        )
        .map_err(|diagnostics| RenderError::Pdf(self.diagnostics(&diagnostics)))
    }

    /// Render a one-based page number at the requested pixels per inch.
    #[cfg(feature = "preview")]
    pub fn render_png(
        &self,
        data: &RenderData,
        logo: Option<&Logo>,
        page: usize,
        ppi: f32,
    ) -> Result<Vec<u8>, RenderError> {
        if !ppi.is_finite() || ppi <= 0.0 {
            return Err(RenderError::Data(
                "preview ppi must be finite and positive".into(),
            ));
        }
        let doc = self.compile(data, logo)?;
        let page = page
            .checked_sub(1)
            .and_then(|i| doc.pages().get(i))
            .ok_or_else(|| {
                RenderError::Data("preview page is out of range (pages are one-based)".into())
            })?;
        typst_render::render(
            page,
            &typst_render::RenderOptions {
                pixel_per_pt: (f64::from(ppi) / 72.0).into(),
                ..Default::default()
            },
        )
        .encode_png()
        .map_err(|err| RenderError::Data(err.to_string()))
    }
}
