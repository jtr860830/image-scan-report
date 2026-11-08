//! Swappable report colors, fonts, and branding.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Versioned report branding, palette, and bundled font selections.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Theme {
    /// Schema or component version supplied by the producer.
    pub version: u32,
    /// Product identity used for report branding.
    pub product: Product,
    /// Report palette expressed as hexadecimal RGB strings.
    pub colors: Colors,
    /// Ordered font fallback families for body text and code.
    pub fonts: Fonts,
    /// Optional branding asset to embed in the report. None indicates that the value is unavailable.
    #[serde(skip)]
    pub logo: Option<Logo>,
}
/// Product identity displayed in report branding.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Display name supplied by the scanner or theme.
    pub name: String,
    /// Endpoint or external product URL used by this configuration. None indicates that the value is unavailable.
    pub url: Option<String>,
}
/// Report palette with colors encoded as six-digit hexadecimal RGB strings.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Colors {
    /// Primary text color expressed as a hexadecimal RGB string.
    pub ink: String,
    /// Color used for secondary text.
    pub secondary: String,
    /// Color used for low-emphasis labels.
    pub muted: String,
    /// Color used for separator lines.
    pub rule: String,
    /// Background color used for report panels.
    pub surface: String,
    /// Highlight color used for report accents.
    pub accent: String,
    /// Number of findings in the critical severity band.
    pub critical: String,
    /// Number of findings in the high severity band.
    pub high: String,
    /// Number of findings in the medium severity band.
    pub medium: String,
    /// Number of findings in the low severity band.
    pub low: String,
    /// Number of findings in the unrated severity band.
    pub unrated: String,
    /// Background tint used for critical severity labels.
    pub tint_critical: String,
    /// Background tint used for high severity labels.
    pub tint_high: String,
    /// Background tint used for medium severity labels.
    pub tint_medium: String,
    /// Background tint used for low severity labels.
    pub tint_low: String,
    /// Background tint used for unrated severity labels.
    pub tint_unrated: String,
}
/// Ordered bundled font fallback families for body and monospaced text.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Fonts {
    /// Ordered fallback families for proportional body text. An empty list indicates no entries.
    pub text: Vec<String>,
    /// Ordered fallback families for monospaced text. An empty list indicates no entries.
    pub mono: Vec<String>,
}
/// Validated PNG or SVG branding bytes with their source filename.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Logo {
    /// Artifact basename, including its format extension.
    pub file_name: String,
    /// Raw bytes of the encoded artifact or branding asset. An empty list indicates no entries.
    pub bytes: Vec<u8>,
}

impl Logo {
    /// Load and validate the configuration or resource at the supplied location.
    ///
    /// # Errors
    ///
    /// Fails when files cannot be read or the theme or logo fails validation.
    pub fn load(path: &Path) -> Result<Self, ThemeError> {
        let bytes = fs::read(path).map_err(|err| ThemeError::Read(path.to_owned(), err))?;
        Self::from_bytes(path, bytes)
    }

    fn from_bytes(path: &Path, bytes: Vec<u8>) -> Result<Self, ThemeError> {
        let valid = match path.extension().and_then(|ext| ext.to_str()) {
            Some("png") => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            Some("svg") => std::str::from_utf8(&bytes).is_ok_and(|text| {
                let text = text.trim_start_matches('\u{feff}').trim_start();
                text.starts_with("<svg") || text.starts_with("<?xml")
            }),
            _ => false,
        };
        if !valid {
            return Err(ThemeError::UnsupportedLogo(path.to_owned()));
        }
        let Some(file_name) = path.file_name() else {
            return Err(ThemeError::UnsupportedLogo(path.to_owned()));
        };
        Ok(Self {
            file_name: file_name.to_string_lossy().into_owned(),
            bytes,
        })
    }

    /// Choose a report-local logo filename while preserving the extension.
    pub fn report_file_name(&self) -> String {
        format!(
            "report-logo.{}",
            Path::new(&self.file_name)
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
        )
    }
}

/// Failure to read or validate a theme or branding asset.
#[derive(thiserror::Error, Debug)]
pub enum ThemeError {
    /// A required resource could not be read.
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, #[source] io::Error),
    /// A resource could not be decoded into the expected format.
    #[error("cannot parse {0}: {1}")]
    Parse(PathBuf, String),
    /// A decoded configuration value violates a validation constraint.
    #[error("invalid theme {0}: {1}")]
    Invalid(PathBuf, String),
    /// A branding asset has an unsupported extension or invalid content.
    #[error("unsupported logo {0}")]
    UnsupportedLogo(PathBuf),
}
impl From<ThemeError> for crate::config::ConfigError {
    fn from(err: ThemeError) -> Self {
        Self::Invalid(format!("theme: {err}"))
    }
}
impl Theme {
    /// Serialize theme settings for use by report templates.
    pub fn to_render_value(&self) -> serde_json::Value {
        serde_json::json!({"version": self.version, "product": self.product,
            "colors": self.colors, "fonts": self.fonts,
            "logo": self.logo.as_ref().map(|logo| &logo.file_name)})
    }
    fn validate(&self, path: &Path) -> Result<(), ThemeError> {
        let invalid = |message: String| ThemeError::Invalid(path.to_owned(), message);
        if self.version != 1 {
            return Err(invalid("version must be 1".into()));
        }
        for (key, value) in [
            ("ink", &self.colors.ink),
            ("secondary", &self.colors.secondary),
            ("muted", &self.colors.muted),
            ("rule", &self.colors.rule),
            ("surface", &self.colors.surface),
            ("accent", &self.colors.accent),
            ("critical", &self.colors.critical),
            ("high", &self.colors.high),
            ("medium", &self.colors.medium),
            ("low", &self.colors.low),
            ("unrated", &self.colors.unrated),
            ("tint_critical", &self.colors.tint_critical),
            ("tint_high", &self.colors.tint_high),
            ("tint_medium", &self.colors.tint_medium),
            ("tint_low", &self.colors.tint_low),
            ("tint_unrated", &self.colors.tint_unrated),
        ] {
            let bytes = value.as_bytes();
            if bytes.len() != 7 || bytes[0] != b'#' || !bytes[1..].iter().all(u8::is_ascii_hexdigit)
            {
                return Err(invalid(format!(
                    "colors.{key} must be # followed by six hex digits"
                )));
            }
        }
        for (key, list) in [("text", &self.fonts.text), ("mono", &self.fonts.mono)] {
            if list.is_empty() {
                return Err(invalid(format!("fonts.{key} must not be empty")));
            }
            for family in list {
                if !super::fonts::FAMILIES.contains(&family.as_str()) {
                    return Err(invalid(format!(
                        "fonts.{key}: unsupported family {family}; bundled families: {}",
                        super::fonts::FAMILIES.join(", ")
                    )));
                }
            }
        }
        Ok(())
    }
}
fn parse(text: &str, path: &Path) -> Result<Theme, ThemeError> {
    let theme: Theme =
        toml::from_str(text).map_err(|err| ThemeError::Parse(path.to_owned(), err.to_string()))?;
    theme.validate(path)?;
    Ok(theme)
}
/// Load the validated theme embedded in the executable.
///
/// # Panics
///
/// Panics if an embedded theme or required template is missing or invalid.
pub fn default_theme() -> Theme {
    parse(
        include_str!("../../themes/default/theme.toml"),
        Path::new("themes/default/theme.toml"),
    )
    .expect("embedded default theme must be valid")
}
/// Load and validate the configuration or resource at the supplied location.
///
/// # Errors
///
/// Fails when files cannot be read or the theme or logo fails validation.
pub fn load(dir: Option<&Path>) -> Result<Theme, ThemeError> {
    let Some(dir) = dir else {
        return Ok(default_theme());
    };
    let path = dir.join("theme.toml");
    let text = fs::read_to_string(&path).map_err(|err| ThemeError::Read(path.clone(), err))?;
    let mut theme = parse(&text, &path)?;
    for name in ["logo.png", "logo.svg"] {
        let path = dir.join(name);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(ThemeError::Read(path, err)),
        };
        theme.logo = Some(Logo::from_bytes(&path, bytes)?);
        return Ok(theme);
    }
    let mut entries = fs::read_dir(dir)
        .map_err(|err| ThemeError::Read(dir.to_owned(), err))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ThemeError::Read(dir.to_owned(), err))?;
    entries.sort();
    for path in entries {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("logo."))
            && path.is_file()
        {
            return Err(ThemeError::UnsupportedLogo(path));
        }
    }
    Ok(theme)
}
