static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use std::path::Path;

use image_scan_report::config::{self, Config, ConfigError, HttpMode, OutputConfig, SourceConfig};
use image_scan_report::model::Language;

fn minimal() -> Config {
    config::load(Path::new("tests/data/config/trivy-files.yaml")).unwrap()
}

#[test]
fn loads_minimal_trivy_files_config() {
    let config = minimal();
    assert!(
        matches!(config.source, SourceConfig::TrivyFiles { path } if path == Path::new("/input"))
    );
    assert_eq!(config.report.language, Language::ZhTw);
    assert_eq!(config.report.stale_after_days, 30);
    assert!(config.report.pdf);
    assert!(!config.report.json);
}

#[test]
fn unknown_type_is_parse_error() {
    assert!(matches!(
        config::load(Path::new("tests/data/config/unknown-type.yaml")),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn empty_output_is_invalid() {
    let mut config = minimal();
    config.output.clear();
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn pdf_and_json_both_false_is_invalid() {
    let mut config = minimal();
    config.report.pdf = false;
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn header_env_placeholder_is_resolved() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // This variable belongs only to this test.
    unsafe { std::env::set_var("JUDEX_TEST_TOKEN", "abc") };
    let result = config::load(Path::new("tests/data/config/http.yaml"));
    unsafe { std::env::remove_var("JUDEX_TEST_TOKEN") };
    let config = result.unwrap();
    assert!(matches!(config.source, SourceConfig::NeuvectorFiles { .. }));
    let OutputConfig::Http {
        headers,
        method,
        mode,
        timeout_secs,
        ..
    } = &config.output[0]
    else {
        panic!("expected HTTP output");
    };
    assert_eq!(headers["Authorization"], "Bearer abc");
    assert_eq!(method, "PUT");
    assert_eq!(*mode, HttpMode::Raw);
    assert_eq!(*timeout_secs, 30);
}

#[test]
fn missing_env_names_the_variable() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("JUDEX_UNSET_VAR_7") };
    assert!(
        matches!(config::resolve_env("${JUDEX_UNSET_VAR_7}"), Err(ConfigError::MissingEnv(name)) if name == "JUDEX_UNSET_VAR_7")
    );
}

#[test]
fn example_config_in_repo_loads() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = config::load(Path::new("examples/config.yaml"));
    let nv_result = config::load(Path::new("examples/config-neuvector.yaml"));
    let config = result.unwrap();
    // Loading does not read source credentials or CA files.
    let neuvector = nv_result.unwrap();
    assert!(matches!(neuvector.source, SourceConfig::Neuvector { .. }));
    assert!(matches!(config.source, SourceConfig::Harbor { .. }));
    assert_eq!(config.output.len(), 1);
    assert_eq!(neuvector.output.len(), 1);
}

#[test]
fn validation_accepts_case_insensitive_put_and_post_only() {
    let mut config = minimal();
    config.output = vec![OutputConfig::Http {
        url: "https://example.test".into(),
        method: "post".into(),
        headers: Default::default(),
        mode: HttpMode::Raw,
        ca_file: None,
        timeout_secs: 30,
    }];
    for method in ["put", "PUT", "post", "PoSt", "GET", ""] {
        let OutputConfig::Http { method: actual, .. } = &mut config.output[0] else {
            unreachable!()
        };
        *actual = method.into();
        assert_eq!(
            config.validate().is_ok(),
            matches!(method, "put" | "PUT" | "post" | "PoSt")
        );
    }
}

#[test]
fn empty_organization_is_invalid_and_json_only_is_valid() {
    let mut config = minimal();
    config.report.pdf = false;
    config.report.json = true;
    config.validate().unwrap();
    config.report.organization.clear();
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn resolves_all_valid_placeholders_and_preserves_other_text() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("JUDEX_CONFIG_MULTI_7", "value") };
    let result = config::resolve_env(
        "a ${JUDEX_CONFIG_MULTI_7}/${JUDEX_CONFIG_MULTI_7} ${9BAD} ${} ${unfinished",
    );
    unsafe { std::env::remove_var("JUDEX_CONFIG_MULTI_7") };
    assert_eq!(result.unwrap(), "a value/value ${9BAD} ${} ${unfinished");
    assert_eq!(config::resolve_env("plain text").unwrap(), "plain text");
}

#[test]
fn missing_first_placeholder_is_reported() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::remove_var("JUDEX_CONFIG_FIRST_7");
        std::env::remove_var("JUDEX_CONFIG_SECOND_7");
    }
    assert!(
        matches!(config::resolve_env("${JUDEX_CONFIG_FIRST_7}${JUDEX_CONFIG_SECOND_7}"), Err(ConfigError::MissingEnv(name)) if name == "JUDEX_CONFIG_FIRST_7")
    );
}

#[test]
fn secret_from_env_reads_named_variable() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("JUDEX_CONFIG_SECRET_7", "secret") };
    let result = config::secret_from_env("JUDEX_CONFIG_SECRET_7");
    unsafe { std::env::remove_var("JUDEX_CONFIG_SECRET_7") };
    assert_eq!(result.unwrap(), "secret");
    assert!(
        matches!(config::secret_from_env("JUDEX_CONFIG_SECRET_7"), Err(ConfigError::MissingEnv(name)) if name == "JUDEX_CONFIG_SECRET_7")
    );
}

#[test]
fn unreadable_path_is_read_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.yaml");
    assert!(matches!(config::load(&path), Err(ConfigError::Read(actual, _)) if actual == path));
}

#[test]
fn loads_explicit_settings_and_expands_only_all_http_headers() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("JUDEX_CONFIG_OUTPUTS_7", "all-outputs") };
    let result = config::load(Path::new("tests/data/config/neuvector.yaml"));
    unsafe { std::env::remove_var("JUDEX_CONFIG_OUTPUTS_7") };
    let config = result.unwrap();
    let SourceConfig::Neuvector {
        registry,
        password_env,
        ca_file,
        ..
    } = &config.source
    else {
        panic!("expected NeuVector");
    };
    assert_eq!(registry, "production");
    assert_eq!(password_env, "JUDEX_SOURCE_PASSWORD_NOT_READ_7");
    assert_eq!(ca_file.as_deref(), Some(Path::new("/certs/source.pem")));
    assert_eq!(config.report.language, Language::En);
    assert_eq!(
        config.report.organization,
        "${JUDEX_ORGANIZATION_LITERAL_7}"
    );
    assert_eq!(
        config.report.logo.as_deref(),
        Some(Path::new("/assets/logo.png"))
    );
    assert_eq!(config.report.stale_after_days, 14);
    let OutputConfig::Http {
        url,
        headers,
        mode,
        ca_file,
        timeout_secs,
        ..
    } = &config.output[0]
    else {
        panic!("expected HTTP output");
    };
    assert_eq!(url, "https://upload.example.test/${JUDEX_URL_LITERAL_7}");
    assert!(headers.is_empty());
    assert_eq!(*mode, HttpMode::Multipart);
    assert_eq!(ca_file.as_deref(), Some(Path::new("/certs/upload.pem")));
    assert_eq!(*timeout_secs, 60);
    for output in &config.output[1..] {
        let OutputConfig::Http { headers, .. } = output else {
            panic!("expected HTTP output")
        };
        assert_eq!(headers["X-Token"], "all-outputs");
    }
}

fn assert_unknown_key_is_parse_error(yaml: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    assert!(matches!(config::load(&path), Err(ConfigError::Parse(_))));
}

#[test]
fn unknown_top_level_key_is_parse_error() {
    let yaml = include_str!("data/config/trivy-files.yaml");
    assert_unknown_key_is_parse_error(&format!("{yaml}\nreprot: typo\n"));
}

#[test]
fn unknown_report_key_is_parse_error() {
    let yaml = include_str!("data/config/trivy-files.yaml");
    assert_unknown_key_is_parse_error(&yaml.replace("report:", "report:\n  stale_after_day: 30"));
}

#[test]
fn unknown_output_key_is_parse_error() {
    let yaml = include_str!("data/config/trivy-files.yaml");
    assert_unknown_key_is_parse_error(
        &yaml.replace("type: filesystem", "type: filesystem\n    typo: true"),
    );
}

#[test]
fn unknown_harbor_source_key_is_parse_error() {
    let yaml = include_str!("../examples/config.yaml");
    assert_unknown_key_is_parse_error(&yaml.replace("type: harbor", "type: harbor\n  typo: true"));
}

#[test]
fn report_length_settings() {
    use image_scan_report::model::Severity;
    let defaults = minimal();
    assert_eq!(
        defaults.report.describe_severities,
        vec![Severity::Critical, Severity::High]
    );
    assert_eq!(defaults.report.description_chars, 600);
    assert_eq!(defaults.report.remediation_cards, 30);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let yaml = include_str!("data/config/trivy-files.yaml");
    for (settings, expected) in [
        ("describe_severities: [critical, high, medium]", "ok"),
        ("description_chars: 10", "invalid"),
        ("describe_severities: [unknown]", "parse"),
        (
            "describe_severities: []\n  remediation_cards: 0\n  description_chars: 50",
            "empty",
        ),
    ] {
        std::fs::write(
            &path,
            yaml.replace("report:", &format!("report:\n  {settings}")),
        )
        .unwrap();
        match (expected, config::load(&path)) {
            ("ok", Ok(cfg)) => assert_eq!(
                cfg.report.describe_severities,
                vec![Severity::Critical, Severity::High, Severity::Medium]
            ),
            ("empty", Ok(cfg)) => {
                assert!(cfg.report.describe_severities.is_empty());
                assert_eq!(cfg.report.remediation_cards, 0);
            }
            ("invalid", Err(ConfigError::Invalid(message))) => {
                assert!(message.contains("description_chars"))
            }
            ("parse", Err(ConfigError::Parse(_))) => (),
            (_, result) => panic!("unexpected result: {result:?}"),
        }
    }
}

fn api_source(kind: &str, extra: &str) -> SourceConfig {
    let registry = if kind == "neuvector" {
        "registry: production\n"
    } else {
        ""
    };
    serde_yaml_ng::from_str(&format!("type: {kind}\nurl: https://scanner.test\nusername: reader\npassword_env: PASSWORD\n{registry}{extra}")).unwrap()
}

#[test]
fn api_sources_accept_timeout_and_reject_bad_url() {
    for kind in ["harbor", "neuvector"] {
        let mut cfg = minimal();
        cfg.source = api_source(kind, "timeout_secs: 7");
        cfg.validate().unwrap();
        for bad in [
            "ftp://x",
            "not a url",
            "https://user@scanner.test",
            "https://user:secret@scanner.test",
            "https://:secret@scanner.test",
        ] {
            match &mut cfg.source {
                SourceConfig::Harbor { url, .. } | SourceConfig::Neuvector { url, .. } => {
                    *url = bad.into()
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(cfg.validate(), Err(ConfigError::Invalid(m)) if m.contains("source.url"))
            );
        }
        cfg.source = api_source(kind, "timeout_secs: 0");
        assert!(
            matches!(cfg.validate(), Err(ConfigError::Invalid(m)) if m.contains("timeout_secs"))
        );
    }
}

#[test]
fn insecure_skip_verify_parses_and_conflicts_with_ca() {
    for kind in ["harbor", "neuvector"] {
        let mut cfg = minimal();
        cfg.source = api_source(kind, "");
        assert!(matches!(
            cfg.source,
            SourceConfig::Harbor {
                timeout_secs: 30,
                insecure_skip_verify: false,
                ..
            } | SourceConfig::Neuvector {
                timeout_secs: 30,
                insecure_skip_verify: false,
                ..
            }
        ));
        cfg.source = api_source(kind, "insecure_skip_verify: true");
        cfg.validate().unwrap();
        cfg.source = api_source(kind, "insecure_skip_verify: true\nca_file: ca.pem");
        assert!(
            matches!(cfg.validate(), Err(ConfigError::Invalid(m)) if m.contains("ca_file") && m.contains("insecure_skip_verify"))
        );
    }
}
