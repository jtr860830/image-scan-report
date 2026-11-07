//! Atomic filesystem artifact storage.
use super::{Artifact, ReportSink, SinkError};
use std::{fs, path::PathBuf};

pub struct FilesystemSink {
    pub dir: PathBuf,
}

impl ReportSink for FilesystemSink {
    fn describe(&self) -> String {
        format!("Filesystem: {}", self.dir.display())
    }

    fn store(&self, artifact: &Artifact) -> Result<(), SinkError> {
        let temp = self.dir.join(format!(".{}.tmp", artifact.file_name));
        let result = (|| {
            fs::create_dir_all(&self.dir)?;
            fs::write(&temp, &artifact.bytes)?;
            fs::rename(&temp, self.dir.join(&artifact.file_name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(SinkError::from)
    }
}
