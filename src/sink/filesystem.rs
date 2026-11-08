//! Atomic filesystem artifact storage.
use super::{Artifact, ReportSink, SinkError};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Artifact destination that writes files atomically within a directory.
pub struct FilesystemSink {
    /// Directory containing input scans or generated artifacts.
    pub dir: PathBuf,
}

impl ReportSink for FilesystemSink {
    fn describe(&self) -> String {
        format!("Filesystem: {}", self.dir.display())
    }

    fn store(&self, artifact: &Artifact) -> Result<(), SinkError> {
        use std::io::Write;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| SinkError::Other(error.to_string()))?
            .as_nanos();
        let temp = self.dir.join(format!(
            ".{}.{}.{nanos}.tmp",
            artifact.file_name,
            std::process::id()
        ));
        let mut created = false;
        let result = (|| {
            fs::create_dir_all(&self.dir)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            created = true;
            file.write_all(&artifact.bytes)?;
            drop(file);
            fs::rename(&temp, self.dir.join(&artifact.file_name))
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(SinkError::from)
    }
}
