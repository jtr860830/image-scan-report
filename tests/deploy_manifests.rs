use image_scan_report::config::Config;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::{fs, path::Path};

// Resource sizing contract: see docs/development.md.
const REQUEST_CPU: &str = "1";
const REQUEST_MEMORY: &str = "1Gi";
const LIMIT_CPU: &str = "2";
const LIMIT_MEMORY: &str = "4Gi";

#[test]
fn manifests_parse_and_pin_the_contract() {
    let mut documents = Vec::new();
    for entry in fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/k8s")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            let yaml = fs::read_to_string(&path).unwrap();
            for document in serde_yaml_ng::Deserializer::from_str(&yaml) {
                documents.push(Value::deserialize(document).expect("valid manifest YAML"));
            }
        }
    }
    let secret = documents
        .iter()
        .find(|d| d["kind"] == "Secret")
        .expect("Secret");
    let config = documents
        .iter()
        .find(|d| d["kind"] == "ConfigMap" && d["data"]["config.yaml"].is_string())
        .expect("application ConfigMap");
    let _: Config =
        serde_yaml_ng::from_str(config["data"]["config.yaml"].as_str().unwrap()).unwrap();
    for kind in ["CronJob", "Job"] {
        let job = documents.iter().find(|d| d["kind"] == kind).expect(kind);
        let spec = if kind == "CronJob" {
            &job["spec"]["jobTemplate"]["spec"]
        } else {
            &job["spec"]
        };
        let pod = &spec["template"]["spec"];
        for container in pod["containers"].as_sequence().expect("containers") {
            assert_eq!(
                container["image"].as_str().unwrap(),
                format!("ghcr.io/jtr860830/judex:{}", env!("CARGO_PKG_VERSION"))
            );
            assert!(
                pod["securityContext"]["runAsNonRoot"] == true
                    || container["securityContext"]["runAsNonRoot"] == true
            );
            assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
            assert_eq!(
                container["securityContext"]["allowPrivilegeEscalation"],
                false
            );
            for (section, cpu, memory) in [
                ("requests", REQUEST_CPU, REQUEST_MEMORY),
                ("limits", LIMIT_CPU, LIMIT_MEMORY),
            ] {
                assert_eq!(container["resources"][section]["cpu"], cpu);
                assert_eq!(container["resources"][section]["memory"], memory);
            }
            for path in ["/etc/report/config.yaml", "/output"] {
                assert!(
                    container["volumeMounts"]
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .any(|m| m["mountPath"] == path)
                );
            }
            assert_eq!(
                container["envFrom"][0]["secretRef"]["name"],
                secret["metadata"]["name"]
            );
        }
    }
}
