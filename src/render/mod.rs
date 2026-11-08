//! Report rendering with embedded templates and fonts.
/// Bundled font faces for reproducible report rendering.
pub mod fonts;

/// Display-ready report data, independent of the rendering backend.
pub mod model;

/// Bundled report translations and their canonical template keys.
pub mod strings;

/// Swappable report colors, fonts, and branding.
pub mod theme;

/// Embedded Typst compilation and deterministic PDF export.
pub mod engine;

/// Render a report using bundled translations, templates, and fonts.
///
/// # Errors
///
/// Fails if template compilation, generation-time conversion, or PDF export fails.
///
/// # Panics
///
/// Panics if bundled locale JSON is invalid or the embedded main template is missing.
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
