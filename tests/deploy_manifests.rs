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
    let pvc: Value = serde_yaml_ng::from_str(
        &fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/k8s/pvc.yaml"))
            .unwrap(),
    )
    .unwrap();
    let cronjob = documents.iter().find(|d| d["kind"] == "CronJob").unwrap();
    let job = documents.iter().find(|d| d["kind"] == "Job").unwrap();
    assert_eq!(
        cronjob["spec"]["jobTemplate"]["spec"]["template"],
        job["spec"]["template"]
    );
    assert_eq!(cronjob["spec"]["schedule"], "0 2 * * 1");
    assert_eq!(cronjob["spec"]["concurrencyPolicy"], "Forbid");
    for kind in ["CronJob", "Job"] {
        let job = documents.iter().find(|d| d["kind"] == kind).expect(kind);
        let spec = if kind == "CronJob" {
            &job["spec"]["jobTemplate"]["spec"]
        } else {
            &job["spec"]
        };
        assert_eq!(spec["backoffLimit"], 1);
        let pod = &spec["template"]["spec"];
        assert_eq!(pod["restartPolicy"], "Never");
        let volumes = pod["volumes"].as_sequence().unwrap();
        let volume = |name: &str| volumes.iter().find(|v| v["name"] == name).unwrap();
        assert_eq!(
            volume("config")["configMap"]["name"],
            config["metadata"]["name"]
        );
        assert_eq!(
            volume("output")["persistentVolumeClaim"]["claimName"],
            pvc["metadata"]["name"]
        );
        assert_eq!(volume("ca")["configMap"]["optional"], true);
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
            assert_eq!(
                container["securityContext"]["capabilities"]["drop"],
                serde_yaml_ng::to_value(["ALL"]).unwrap()
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
