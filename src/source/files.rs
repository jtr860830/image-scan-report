//! Shared discovery, timestamps, and stable deduplication.
use super::SourceError;
use crate::model::{Finding, Image};
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

pub fn walk_json_files(dir: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let metadata = std::fs::metadata(dir).map_err(|e| SourceError::Unreadable(dir.into(), e))?;
    if !metadata.is_dir() {
        return Err(SourceError::Unreadable(
            dir.into(),
            std::io::Error::new(std::io::ErrorKind::NotADirectory, "expected directory"),
        ));
    }
    let mut paths = Vec::new();
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.map_err(|e| SourceError::Unreadable(dir.into(), e.into()))?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}
pub fn file_modified_at(path: &Path) -> Option<DateTime<Utc>> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .map(Into::into)
}
pub fn dedupe_images(items: Vec<(Image, Vec<Finding>)>) -> (Vec<Image>, Vec<Finding>) {
    let mut positions = HashMap::new();
    let mut selected: Vec<(Image, Vec<Finding>)> = Vec::new();
    for (image, findings) in items {
        // Keep digest and reference identities in separate namespaces.
        let key = match &image.digest {
            Some(d) => (true, d.clone()),
            None => (false, image.reference.clone()),
        };
        if let Some(&index) = positions.get(&key) {
            let existing: &mut (Image, Vec<Finding>) = &mut selected[index];
            if image.scan.scanned_at > existing.0.scan.scanned_at {
                *existing = (image, findings);
            }
        } else {
            positions.insert(key, selected.len());
            selected.push((image, findings));
        }
    }
    let mut images = Vec::new();
    let mut findings = Vec::new();
    for (image, entries) in selected {
        images.push(image);
        let mut seen = HashSet::new();
        findings.extend(entries.into_iter().filter(|f| {
            seen.insert((f.id.clone(), f.package.clone(), f.installed_version.clone()))
        }));
    }
    (images, findings)
}
