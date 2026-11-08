//! Shared discovery, timestamps, and stable deduplication.
use super::{ParseError, SourceError};
use crate::model::{Finding, Image, ScanSet, SourceInfo};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Find JSON input files recursively in deterministic path order.
///
/// # Errors
///
/// Fails if the directory is missing or unreadable, or a directory entry cannot be traversed.
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
/// Read a file modification time as UTC, or None when metadata is unavailable.
pub fn file_modified_at(path: &Path) -> Option<DateTime<Utc>> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .map(Into::into)
}
/// Merge duplicate image records and retain their associated findings.
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

/// Merge image records that share a reference and retain associated findings.
pub fn dedupe_images_by_reference(items: Vec<(Image, Vec<Finding>)>) -> (Vec<Image>, Vec<Finding>) {
    let mut positions = HashMap::new();
    let mut selected: Vec<(Image, Vec<Finding>)> = Vec::new();
    for (image, findings) in items {
        // Two rows are the same image only when both the reference and the
        // digest agree; a reference collision between different digests must
        // stay visible rather than hide one of the rows.
        let key = (image.reference.clone(), image.digest.clone());
        if let Some(&index) = positions.get(&key) {
            let existing: &mut (Image, Vec<Finding>) = &mut selected[index];
            if (image.scan.state == crate::model::ScanState::Ok
                && existing.0.scan.state != crate::model::ScanState::Ok)
                || ((image.scan.state == crate::model::ScanState::Ok)
                    == (existing.0.scan.state == crate::model::ScanState::Ok)
                    && image.scan.scanned_at > existing.0.scan.scanned_at)
            {
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

/// Deduplicated scan results and the directory scope shared by file sources.
pub struct FetchedDirectory {
    /// Human-readable registry, project, or directory scope of the scan.
    pub scope: String,
    /// Images included in this scan or vulnerability group. An empty list indicates no entries.
    pub images: Vec<Image>,
    /// Normalized vulnerabilities associated with scanned images. An empty list indicates no entries.
    pub findings: Vec<Finding>,
}

impl FetchedDirectory {
    /// Attach source metadata to the images and findings collected from a directory.
    pub fn into_scan_set(self, source: SourceInfo) -> ScanSet {
        ScanSet {
            source,
            scope: self.scope,
            images: self.images,
            findings: self.findings,
        }
    }
}

/// Read reports in sorted path order, skipping unrelated or invalid files.
///
/// # Errors
///
/// Fails if the input directory is unreadable or contains no usable image reports.
pub fn fetch_directory<F>(dir: &Path, mut parse: F) -> Result<FetchedDirectory, SourceError>
where
    F: FnMut(
        &Path,
        &[u8],
        Option<DateTime<Utc>>,
    ) -> Result<Option<(Image, Vec<Finding>)>, ParseError>,
{
    let mut items = Vec::new();
    for path in walk_json_files(dir)? {
        let parsed = std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                parse(&path, &bytes, file_modified_at(&path)).map_err(|e| e.to_string())
            });
        match parsed {
            Ok(Some(item)) => items.push(item),
            Ok(None) => {
                tracing::warn!(file = %path.display(), "not a recognised scan report; skipped")
            }
            Err(error) => {
                tracing::warn!(file = %path.display(), %error, "skipping unreadable or invalid scan report")
            }
        }
    }
    if items.is_empty() {
        return Err(SourceError::Empty(dir.into()));
    }
    let directory =
        std::fs::canonicalize(dir).map_err(|e| SourceError::Unreadable(dir.into(), e))?;
    let (images, findings) = dedupe_images(items);
    Ok(FetchedDirectory {
        scope: directory
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        images,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ScanState, ScanStatus};

    fn image(reference: &str, state: ScanState) -> Image {
        Image {
            reference: reference.into(),
            tags: vec![],
            digest: Some("sha256:shared".into()),
            platform: None,
            os: None,
            created_at: None,
            size_bytes: None,
            scan: ScanStatus {
                state,
                error: None,
                scanned_at: None,
                scanner_version: None,
            },
        }
    }

    #[test]
    fn reference_dedupe_keeps_order_and_success_wins() {
        let (images, _) = dedupe_images_by_reference(vec![
            (image("a:v1", ScanState::Failed), vec![]),
            (image("b:v1", ScanState::Ok), vec![]),
            (image("a:v1", ScanState::Ok), vec![]),
            (image("b:v1", ScanState::Failed), vec![]),
        ]);
        assert_eq!(
            images
                .iter()
                .map(|i| i.reference.as_str())
                .collect::<Vec<_>>(),
            ["a:v1", "b:v1"]
        );
        assert!(images.iter().all(|i| i.scan.state == ScanState::Ok));
    }

    #[test]
    fn reference_dedupe_keeps_rows_whose_digests_differ() {
        let mut other = image("a:v1", ScanState::Ok);
        other.digest = Some("sha256:other".into());
        let (images, _) = dedupe_images_by_reference(vec![
            (image("a:v1", ScanState::Ok), vec![]),
            (other, vec![]),
        ]);
        assert_eq!(images.len(), 2);
        assert_ne!(images[0].digest, images[1].digest);
    }
}
