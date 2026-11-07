use judex::sink::{Artifact, ReportSink, filesystem::FilesystemSink};

#[test]
fn writes_and_overwrites_file() {
    let dir = tempfile::tempdir().unwrap();
    let sink = FilesystemSink {
        dir: dir.path().into(),
    };
    for bytes in [b"first".to_vec(), b"second".to_vec()] {
        sink.store(&Artifact {
            file_name: "report.json".into(),
            media_type: "application/json",
            bytes,
        })
        .unwrap();
    }
    assert_eq!(
        std::fs::read(dir.path().join("report.json")).unwrap(),
        b"second"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn creates_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let sink = FilesystemSink {
        dir: dir.path().join("nested/output"),
    };
    sink.store(&Artifact {
        file_name: "a.json".into(),
        media_type: "application/json",
        bytes: vec![],
    })
    .unwrap();
    assert!(sink.dir.join("a.json").is_file());
}

#[test]
fn failed_rename_removes_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("report.json")).unwrap();
    let sink = FilesystemSink {
        dir: dir.path().into(),
    };
    assert!(
        sink.store(&Artifact {
            file_name: "report.json".into(),
            media_type: "application/json",
            bytes: b"data".to_vec()
        })
        .is_err()
    );
    assert!(!dir.path().join(".report.json.tmp").exists());
    assert!(dir.path().join("report.json").is_dir());
}
