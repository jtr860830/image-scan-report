//! Integration checks for theme behavior.
use image_scan_report::{
    config::Config,
    render::theme::{self, ThemeError},
};
use std::path::Path;

fn data(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/theme")
        .join(name)
}
#[test]
fn default_theme_matches_spec_palette() {
    let t = theme::default_theme();
    assert_eq!(
        (
            &*t.colors.critical,
            &*t.colors.high,
            &*t.colors.medium,
            &*t.colors.low,
            &*t.colors.accent
        ),
        ("#6741d9", "#e03131", "#f08c00", "#1c7ed6", "#4263eb")
    );
    assert_eq!(t.fonts.text, ["Inter", "Noto Sans TC"]);
    assert_eq!(t.fonts.mono, ["Maple Mono NL", "Noto Sans TC"]);
    assert_eq!(theme::load(None).unwrap(), t);
    assert_eq!(t.to_render_value()["logo"], serde_json::Value::Null);
}
#[test]
fn theme_dir_without_toml_is_read_error() {
    assert!(
        matches!(theme::load(Some(&data("no-toml-dir"))), Err(ThemeError::Read(p, _)) if p.ends_with("theme.toml"))
    );
}
#[test]
fn unknown_key_is_parse_error() {
    assert!(matches!(
        theme::load(Some(&data("unknown-key"))),
        Err(ThemeError::Parse(_, _))
    ));
}
#[test]
fn bad_colour_is_invalid() {
    assert!(
        matches!(theme::load(Some(&data("bad-colour"))), Err(ThemeError::Invalid(_, m)) if m.contains("critical"))
    );
}
#[test]
fn gif_logo_is_unsupported() {
    assert!(
        matches!(theme::load(Some(&data("bad-logo"))), Err(ThemeError::UnsupportedLogo(p)) if p.ends_with("logo.gif"))
    );
}
#[test]
fn custom_theme_overrides_and_loads_png_logo() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("theme.toml"),
        include_str!("data/theme/bad-logo/theme.toml").replace("judex", "Company"),
    )
    .unwrap();
    let png: [u8; 67] = [
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 0,
        0, 0, 0, 58, 126, 155, 85, 0, 0, 0, 10, 73, 68, 65, 84, 120, 156, 99, 96, 0, 0, 0, 2, 0, 1,
        72, 175, 164, 113, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    std::fs::write(dir.path().join("logo.png"), png).unwrap();
    let t = theme::load(Some(dir.path())).unwrap();
    assert_eq!(t.product.name, "Company");
    assert_eq!(t.logo.as_ref().unwrap().bytes, png);
    assert_eq!(t.to_render_value()["logo"], "logo.png");
    assert!(t.to_render_value().get("bytes").is_none());
}
#[test]
fn config_accepts_theme_path() {
    let yaml = include_str!("../examples/config-trivy-files.yaml");
    let c: Config = serde_yaml_ng::from_str(yaml).unwrap();
    assert_eq!(c.theme.path, None);
    let c: Config = serde_yaml_ng::from_str(&format!("{yaml}\ntheme: {{ path: /x }}\n")).unwrap();
    assert_eq!(c.theme.path.as_deref(), Some(Path::new("/x")));
}

#[test]
fn validation_and_strict_keys() {
    let original = include_str!("../themes/default/theme.toml");
    for (text, key) in [
        (original.replace("version = 1", "version = 2"), "version"),
        (
            original.replace("text = [\"Inter\", \"Noto Sans TC\"]", "text = []"),
            "fonts.text",
        ),
        (
            original.replace("mono = [\"Maple Mono NL\", \"Noto Sans TC\"]", "mono = []"),
            "fonts.mono",
        ),
        (original.replace("#212529", "#GGGGGG"), "ink"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("theme.toml"), text).unwrap();
        assert!(
            matches!(theme::load(Some(dir.path())), Err(ThemeError::Invalid(p, m)) if p.ends_with("theme.toml") && m.contains(key))
        );
    }
    for section in ["product", "colors", "fonts"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("theme.toml"),
            original.replace(
                &format!("[{section}]"),
                &format!("[{section}]\nunknown = true"),
            ),
        )
        .unwrap();
        assert!(matches!(
            theme::load(Some(dir.path())),
            Err(ThemeError::Parse(_, _))
        ));
    }
}

#[test]
fn svg_and_png_validation_and_precedence() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("theme.toml"),
        include_str!("../themes/default/theme.toml"),
    )
    .unwrap();
    for svg in ["<svg/>", "\u{feff} \n<?xml version=\"1.0\"?><svg/>"] {
        std::fs::write(dir.path().join("logo.svg"), svg).unwrap();
        let t = theme::load(Some(dir.path())).unwrap();
        assert_eq!(t.logo.unwrap().file_name, "logo.svg");
    }
    std::fs::write(dir.path().join("logo.png"), b"invalid PNG").unwrap();
    assert!(
        matches!(theme::load(Some(dir.path())), Err(ThemeError::UnsupportedLogo(p)) if p.ends_with("logo.png"))
    );
    std::fs::write(dir.path().join("logo.png"), b"\x89PNG\r\n\x1a\n").unwrap();
    assert_eq!(
        theme::load(Some(dir.path()))
            .unwrap()
            .logo
            .unwrap()
            .file_name,
        "logo.png"
    );
    std::fs::remove_file(dir.path().join("logo.png")).unwrap();
    std::fs::write(dir.path().join("logo.svg"), "<html/>").unwrap();
    assert!(matches!(
        theme::load(Some(dir.path())),
        Err(ThemeError::UnsupportedLogo(_))
    ));
}

#[test]
fn render_value_and_config_errors() {
    let t = theme::default_theme();
    let v = t.to_render_value();
    assert_eq!(
        v,
        serde_json::json!({"version": 1, "product": {"name":"judex", "url":""}, "colors": t.colors, "fonts": t.fonts, "logo": null})
    );
    let err: image_scan_report::config::ConfigError =
        theme::load(Some(&data("bad-colour"))).unwrap_err().into();
    assert!(
        matches!(err, image_scan_report::config::ConfigError::Invalid(m) if m.starts_with("theme: ") && m.contains("critical"))
    );
    let yaml = format!(
        "{}\ntheme: {{ unknown: true }}",
        include_str!("../examples/config-trivy-files.yaml")
    );
    assert!(serde_yaml_ng::from_str::<Config>(&yaml).is_err());
}

#[test]
fn unbundled_font_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("theme.toml"),
        include_str!("../themes/default/theme.toml").replace("Inter", "Helvetica"),
    )
    .unwrap();
    assert!(
        matches!(theme::load(Some(dir.path())), Err(ThemeError::Invalid(_, m))
        if m.contains("Helvetica") && m.contains("Inter"))
    );
}
