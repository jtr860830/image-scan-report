//! Swappable report colours, fonts and branding, loaded from a `theme.toml` directory.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Report branding, palette and fonts parsed from `theme.toml`.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Theme {
    /// Theme contract version; must be 1.
    pub version: u32,
    /// Product name and URL credited in the report appendix.
    pub product: Product,
    /// Palette; every entry must be `#` followed by six hex digits.
    pub colors: Colors,
    /// Font fallback lists, limited to the bundled [`super::fonts::FAMILIES`].
    pub fonts: Fonts,
    /// Logo found beside `theme.toml`, shown with the appendix credit; `None` shows no logo.
    #[serde(skip)]
    pub logo: Option<Logo>,
}
/// Product identity credited in the report appendix.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Product name in the appendix credit and `check` output; `judex` in the default theme.
    pub name: String,
    /// Product URL appended to the appendix credit; `None` or empty omits it.
    pub url: Option<String>,
}
/// Report palette; every entry must be `#rrggbb`.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Colors {
    /// Primary text colour.
    pub ink: String,
    /// Secondary text colour.
    pub secondary: String,
    /// Colour of low-emphasis labels.
    pub muted: String,
    /// Colour of separator lines.
    pub rule: String,
    /// Background colour of panels.
    pub surface: String,
    /// Accent colour.
    pub accent: String,
    /// `#rrggbb` colour of the critical band in chips, tiles and the severity bar.
    pub critical: String,
    /// `#rrggbb` colour of the high band in chips, tiles and the severity bar.
    pub high: String,
    /// `#rrggbb` colour of the medium band in chips, tiles and the severity bar.
    pub medium: String,
    /// `#rrggbb` colour of the low band in chips, tiles and the severity bar.
    pub low: String,
    /// `#rrggbb` colour of the unrated band in chips, tiles and the severity bar.
    pub unrated: String,
    /// Background tint of critical severity chips.
    pub tint_critical: String,
    /// Background tint of high severity chips.
    pub tint_high: String,
    /// Background tint of medium severity chips.
    pub tint_medium: String,
    /// Background tint of low severity chips.
    pub tint_low: String,
    /// Background tint of unrated severity chips.
    pub tint_unrated: String,
}
/// Ordered fallback families for body and monospaced text.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Fonts {
    /// Body text families in fallback order; must be non-empty and bundled.
    pub text: Vec<String>,
    /// Monospaced families in fallback order; must be non-empty and bundled.
    pub mono: Vec<String>,
}
/// Logo image whose PNG signature or SVG prologue has been checked.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Logo {
    /// Source file name with its extension, which decides between PNG and SVG.
    pub file_name: String,
    /// Validated PNG or SVG file contents, never empty.
    pub bytes: Vec<u8>,
}

impl Logo {
    /// Read and validate a `.png` or `.svg` logo file.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read, its extension is not `png` or `svg` (lowercase), or
    /// its contents do not start like that format.
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

    /// Name under which templates see the customer logo: `report-logo.<ext>`.
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

/// Failure to read or validate a theme or logo.
#[derive(thiserror::Error, Debug)]
#[must_use]
pub enum ThemeError {
    /// `theme.toml`, a logo file or the theme directory could not be read.
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, #[source] io::Error),
    /// `theme.toml` is not valid TOML for [`Theme`].
    #[error("cannot parse {0}: {1}")]
    Parse(PathBuf, String),
    /// `theme.toml` breaks a rule: version not 1, a colour not `#rrggbb`, or a font list empty
    /// or naming an unbundled family.
    #[error("invalid theme {0}: {1}")]
    Invalid(PathBuf, String),
    /// A logo has the wrong extension or content, or the theme directory holds a `logo.*`
    /// file other than `logo.png` or `logo.svg`.
    #[error("unsupported logo {0}")]
    UnsupportedLogo(PathBuf),
}
impl From<ThemeError> for crate::config::ConfigError {
    fn from(err: ThemeError) -> Self {
        Self::Invalid(format!("theme: {err}"))
    }
}
impl Theme {
    /// Serialise the theme for templates, exposing the logo by file name only.
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
/// Parse the default theme embedded from `themes/default/theme.toml`, which has no logo.
///
/// # Panics
///
/// Panics if the embedded `theme.toml` is invalid, which would be a build defect rather
/// than a caller error.
pub fn default_theme() -> Theme {
    parse(
        include_str!("../../themes/default/theme.toml"),
        Path::new("themes/default/theme.toml"),
    )
    .expect("embedded default theme must be valid")
}
/// Load `theme.toml` and an optional logo from `dir`, or return [`default_theme`] for `None`.
///
/// # Errors
///
/// Fails if `theme.toml` or a logo cannot be read or is invalid, or `dir` holds a `logo.*`
/// file other than `logo.png` or `logo.svg`.
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
