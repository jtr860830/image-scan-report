pub mod fonts;

pub mod model;

pub mod strings;

pub mod theme;

pub mod engine;

/// Render a report using bundled translations, templates, and fonts.
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
