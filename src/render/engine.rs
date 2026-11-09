//! Embedded Typst compilation and deterministic PDF export.
use super::fonts;
use super::model::RenderData;
use super::theme::Logo;
use chrono::{DateTime, Utc};
use std::sync::Once;
use typst::diag::SourceDiagnostic;
use typst::foundations::{Datetime, Smart};
use typst_as_lib::{TypstAsLibError, TypstEngine};
use typst_layout::PagedDocument;
use typst_pdf::{PdfOptions, Timestamp};

const SOURCES: &[(&str, &str)] = &[
    (
        "parts/appendix.typ",
        include_str!("../../assets/templates/parts/appendix.typ"),
    ),
    (
        "parts/images.typ",
        include_str!("../../assets/templates/parts/images.typ"),
    ),
    (
        "parts/inventory.typ",
        include_str!("../../assets/templates/parts/inventory.typ"),
    ),
    (
        "parts/remediation.typ",
        include_str!("../../assets/templates/parts/remediation.typ"),
    ),
    (
        "parts/summary.typ",
        include_str!("../../assets/templates/parts/summary.typ"),
    ),
    (
        "report.typ",
        include_str!("../../assets/templates/report.typ"),
    ),
    (
        "lib/theme.typ",
        include_str!("../../assets/templates/lib/theme.typ"),
    ),
    (
        "lib/fmt.typ",
        include_str!("../../assets/templates/lib/fmt.typ"),
    ),
    (
        "parts/cover.typ",
        include_str!("../../assets/templates/parts/cover.typ"),
    ),
];

/// Failure to serialise template input, compile templates, or encode rendered output.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum RenderError {
    /// Typst compilation failed; the message lists `file:line: message` diagnostics.
    #[error("template compilation failed:\n{0}")]
    Compile(String),
    /// PDF export failed after compilation.
    #[error("PDF export failed: {0}")]
    Pdf(String),
    /// Serialising the template input, converting the timestamp, or a preview request failed.
    #[error("{0}")]
    Data(String),
}

/// Typst renderer holding the embedded template sources.
pub struct Renderer {
    sources: Vec<(&'static str, String)>,
}
impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}
impl Renderer {
    /// Load the embedded templates and, once per process, try to limit the global rayon pool
    /// to one thread.
    pub fn new() -> Self {
        static POOL: Once = Once::new();
        POOL.call_once(|| {
            if let Err(error) = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build_global()
            {
                tracing::warn!(%error, "could not configure the global rendering thread pool");
            }
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
        use typst_as_lib::conversions::IntoSource;
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
        customer_logo: Option<&Logo>,
    ) -> Result<PagedDocument, RenderError> {
        let bytes = serde_json::to_vec(data).map_err(|e| RenderError::Data(e.to_string()))?;
        let mut files = vec![("data.json", bytes.as_slice())];
        if let Some(logo) = logo {
            files.push((&logo.file_name, &logo.bytes));
        }
        let customer_name = customer_logo.map(Logo::report_file_name);
        if let (Some(logo), Some(name)) = (customer_logo, customer_name.as_deref()) {
            files.push((name, &logo.bytes));
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

    /// Compile the templates with `data` and the logos, and export a PDF stamped with
    /// `generated_at`.
    ///
    /// # Errors
    ///
    /// Fails if `data` cannot be serialised, compilation fails, `generated_at` is outside
    /// Typst's date range, or PDF export fails.
    pub fn render_pdf(
        &self,
        data: &RenderData,
        logo: Option<&Logo>,
        customer_logo: Option<&Logo>,
        generated_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, RenderError> {
        use chrono::{Datelike, Timelike};

        let doc = self.compile(data, logo, customer_logo)?;
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

    /// Render one page, numbered from one, as PNG at `ppi` pixels per inch.
    ///
    /// # Errors
    ///
    /// Fails if `ppi` is not finite and positive, compilation fails, `page` is out of range, or
    /// PNG encoding fails.
    #[cfg(feature = "preview")]
    pub fn render_png(
        &self,
        data: &RenderData,
        logo: Option<&Logo>,
        customer_logo: Option<&Logo>,
        page: usize,
        ppi: f32,
    ) -> Result<Vec<u8>, RenderError> {
        if !ppi.is_finite() || ppi <= 0.0 {
            return Err(RenderError::Data(
                "preview ppi must be finite and positive".into(),
            ));
        }
        let doc = self.compile(data, logo, customer_logo)?;
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
