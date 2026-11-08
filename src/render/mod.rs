//! Report rendering: display-ready data, bundled strings, theme and fonts, compiled with
//! embedded Typst templates into a PDF.
pub mod fonts;

pub mod model;

pub mod strings;

pub mod theme;

pub mod engine;

/// Render `report` to PDF bytes with the bundled strings for its language and `theme`.
///
/// # Errors
///
/// Fails if the template input cannot be serialised, compilation or PDF export fails, or
/// the generation time is outside Typst's date range.
///
/// # Panics
///
/// Panics if a bundled locale file is not a JSON object of strings, which would be a build
/// defect rather than a caller error.
pub fn render_pdf(
    report: &crate::model::Report,
    opts: &model::RenderOptions,
    theme: &theme::Theme,
) -> Result<Vec<u8>, engine::RenderError> {
    static RENDERER: std::sync::OnceLock<engine::Renderer> = std::sync::OnceLock::new();
    let strings = strings::load(opts.language.clone());
    let data = model::build(report, opts, strings, theme.to_render_value());
    RENDERER.get_or_init(engine::Renderer::new).render_pdf(
        &data,
        theme.logo.as_ref(),
        opts.customer_logo.as_ref(),
        report.generated_at,
    )
}
