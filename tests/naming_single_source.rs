//! Integration checks for naming single source behavior.
use std::{fs, path::Path};
use walkdir::WalkDir;

#[test]
fn product_name_appears_only_in_known_places() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("Cargo.toml")).unwrap()).unwrap();
    let name = manifest["package"]["name"].as_str().unwrap();
    let needle = name.to_lowercase();
    let mut hits = Vec::new();
    for directory in ["src", "templates", "strings"] {
        for entry in WalkDir::new(root.join(directory)) {
            let entry = entry.unwrap();
            if entry.file_type().is_file()
                && fs::read(entry.path())
                    .map(|bytes| String::from_utf8(bytes).ok())
                    .unwrap()
                    .is_some_and(|text| text.to_lowercase().contains(&needle))
            {
                hits.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    assert_eq!(hits, vec![Path::new("src/main.rs").to_path_buf()]);
    // The default theme deliberately repeats the product name for report branding.
    // It is outside the source/template/string guard and must track package renames.
    let theme: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("themes/default/theme.toml")).unwrap())
            .unwrap();
    assert_eq!(theme["product"]["name"].as_str().unwrap(), name);
}
