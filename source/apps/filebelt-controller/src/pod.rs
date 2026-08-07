// SPDX-License-Identifier: Apache-2.0

//! Deterministic restricted Pod and bootstrap Secret rendering.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use std::net::SocketAddr;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::catalog::CatalogEntry;

#[derive(Clone, Debug)]
pub struct RunnerPodRequest {
    pub invocation_id: Uuid,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub catalog_entry: String,
    pub bootstrap_token: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RunnerPodSettings<'a> {
    pub namespace: &'a str,
    pub release_name: &'a str,
    pub runner_image: &'a str,
    pub runner_service_account: &'a str,
    pub broker_addresses: &'a [String],
    pub broker_server_name: &'a str,
    pub broker_client_tls_secret: &'a str,
    pub gateway_addresses: &'a [String],
    pub gateway_server_name: &'a str,
    pub gateway_client_tls_secret: &'a str,
    pub gateway_egress_profile: &'a str,
}

#[must_use]
pub fn runner_resource_name(invocation_id: Uuid) -> String {
    format!("filebelt-mcp-{}", invocation_id.simple())
}

pub fn build_runner_secret(request: &RunnerPodRequest, namespace: &str) -> Result<Value, String> {
    if !(32..=4096).contains(&request.bootstrap_token.len()) {
        return Err("runner bootstrap token length is outside the allowed range".into());
    }
    let name = runner_resource_name(request.invocation_id);
    Ok(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": runner_labels(request, None),
        },
        "immutable": true,
        "type": "Opaque",
        "data": {
            "bootstrap-token": BASE64.encode(request.bootstrap_token.as_slice()),
        },
    }))
}

pub fn build_runner_pod(
    request: &RunnerPodRequest,
    entry: &CatalogEntry,
    settings: &RunnerPodSettings<'_>,
) -> Result<Value, String> {
    if request.catalog_entry != entry.name {
        return Err("runner request does not match verified catalog entry".into());
    }
    if entry.egress_profile != settings.gateway_egress_profile {
        return Err(
            "catalog egress profile is not enabled for this runner gateway identity".into(),
        );
    }
    validate_numeric_addresses(settings.broker_addresses, "broker")?;
    validate_numeric_addresses(settings.gateway_addresses, "gateway")?;
    let name = runner_resource_name(request.invocation_id);
    let server_image = format!("{}@{}", entry.repository, entry.image);
    let architectures: Vec<Value> = entry
        .architectures
        .iter()
        .map(|architecture| json!(architecture))
        .collect();
    let mut child_arguments = vec![
        "child".to_owned(),
        "--socket".to_owned(),
        "/run/filebelt-mcp/stdio.sock".to_owned(),
        "--".to_owned(),
        entry.command.clone(),
    ];
    child_arguments.extend(entry.arguments.clone());
    let mut relay_arguments = vec![
        "relay".to_owned(),
        "--socket".to_owned(),
        "/run/filebelt-mcp/stdio.sock".to_owned(),
        "--invocation-id".to_owned(),
        request.invocation_id.to_string(),
    ];
    for address in settings.broker_addresses {
        relay_arguments.push("--broker-address".to_owned());
        relay_arguments.push(address.clone());
    }
    relay_arguments.extend([
        "--broker-server-name".to_owned(),
        settings.broker_server_name.to_owned(),
        "--broker-ca".to_owned(),
        "/run/secrets/broker-tls/ca.crt".to_owned(),
        "--broker-certificate".to_owned(),
        "/run/secrets/broker-tls/tls.crt".to_owned(),
        "--broker-private-key".to_owned(),
        "/run/secrets/broker-tls/tls.key".to_owned(),
    ]);
    for address in settings.gateway_addresses {
        relay_arguments.push("--gateway-address".to_owned());
        relay_arguments.push(address.clone());
    }
    relay_arguments.extend([
        "--gateway-server-name".to_owned(),
        settings.gateway_server_name.to_owned(),
        "--gateway-ca".to_owned(),
        "/run/secrets/gateway-tls/ca.crt".to_owned(),
        "--gateway-certificate".to_owned(),
        "/run/secrets/gateway-tls/tls.crt".to_owned(),
        "--gateway-private-key".to_owned(),
        "/run/secrets/gateway-tls/tls.key".to_owned(),
        "--bootstrap-token-file".to_owned(),
        "/run/secrets/bootstrap/bootstrap-token".to_owned(),
    ]);
    Ok(json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": settings.namespace,
            "labels": runner_labels(request, Some(settings.release_name)),
            "annotations": {
                "filebelt.dev/catalog-entry": entry.name,
                "filebelt.dev/catalog-image-digest": entry.image,
                "filebelt.dev/catalog-signature-verified": "true",
                "filebelt.dev/egress-profile": entry.egress_profile,
            },
        },
        "spec": {
            "activeDeadlineSeconds": 130,
            "automountServiceAccountToken": false,
            "enableServiceLinks": false,
            "restartPolicy": "Never",
            "serviceAccountName": settings.runner_service_account,
            "shareProcessNamespace": false,
            "terminationGracePeriodSeconds": 10,
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 10001,
                "runAsGroup": 10001,
                "fsGroup": 10001,
                "fsGroupChangePolicy": "OnRootMismatch",
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "affinity": {
                "nodeAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": {
                        "nodeSelectorTerms": [{
                            "matchExpressions": [{
                                "key": "kubernetes.io/arch",
                                "operator": "In",
                                "values": architectures,
                            }]
                        }]
                    }
                }
            },
            "initContainers": [{
                "name": "install-runner",
                "image": settings.runner_image,
                "imagePullPolicy": "IfNotPresent",
                "args": ["install", "--destination", "/filebelt/bin/filebelt-mcp-runner"],
                "securityContext": restricted_security_context(),
                "resources": {
                    "requests": {"cpu": "10m", "memory": "8Mi", "ephemeral-storage": "8Mi"},
                    "limits": {"cpu": "100m", "memory": "32Mi", "ephemeral-storage": "16Mi"},
                },
                "volumeMounts": [{"name": "runner-bin", "mountPath": "/filebelt/bin"}],
            }],
            "containers": [
                {
                    "name": "relay",
                    "image": settings.runner_image,
                    "imagePullPolicy": "IfNotPresent",
                    "args": relay_arguments,
                    "ports": [{"name": "proxy", "containerPort": 7777, "protocol": "TCP"}],
                    "securityContext": restricted_security_context(),
                    "resources": {
                        "requests": {"cpu": "25m", "memory": "32Mi", "ephemeral-storage": "16Mi"},
                        "limits": {"cpu": "250m", "memory": "128Mi", "ephemeral-storage": "32Mi"},
                    },
                    "volumeMounts": [
                        {"name": "runner-socket", "mountPath": "/run/filebelt-mcp"},
                        {"name": "bootstrap", "mountPath": "/run/secrets/bootstrap", "readOnly": true},
                        {"name": "broker-tls", "mountPath": "/run/secrets/broker-tls", "readOnly": true},
                        {"name": "gateway-tls", "mountPath": "/run/secrets/gateway-tls", "readOnly": true},
                        {"name": "tmp-relay", "mountPath": "/tmp"},
                    ],
                },
                {
                    "name": "server",
                    "image": server_image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["/filebelt/bin/filebelt-mcp-runner"],
                    "args": child_arguments,
                    "env": [
                        {"name": "HTTP_PROXY", "value": "http://127.0.0.1:7777"},
                        {"name": "HTTPS_PROXY", "value": "http://127.0.0.1:7777"},
                        {"name": "ALL_PROXY", "value": ""},
                        {"name": "NO_PROXY", "value": "127.0.0.1,localhost"},
                    ],
                    "securityContext": restricted_security_context(),
                    "resources": {
                        "requests": {
                            "cpu": entry.resources.cpu_request,
                            "memory": entry.resources.memory_request,
                            "ephemeral-storage": "16Mi"
                        },
                        "limits": {
                            "cpu": entry.resources.cpu_limit,
                            "memory": entry.resources.memory_limit,
                            "ephemeral-storage": entry.resources.ephemeral_storage_limit
                        }
                    },
                    "volumeMounts": [
                        {"name": "runner-bin", "mountPath": "/filebelt/bin", "readOnly": true},
                        {"name": "runner-socket", "mountPath": "/run/filebelt-mcp"},
                        {"name": "tmp-server", "mountPath": "/tmp"},
                    ],
                }
            ],
            "volumes": [
                {"name": "runner-bin", "emptyDir": {"sizeLimit": "16Mi"}},
                {"name": "runner-socket", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
                {"name": "tmp-relay", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                {"name": "tmp-server", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
                {"name": "bootstrap", "secret": {"secretName": name, "defaultMode": 288}},
                {"name": "broker-tls", "secret": {"secretName": settings.broker_client_tls_secret, "defaultMode": 288}},
                {"name": "gateway-tls", "secret": {"secretName": settings.gateway_client_tls_secret, "defaultMode": 288}},
            ]
        }
    }))
}

fn validate_numeric_addresses(addresses: &[String], role: &str) -> Result<(), String> {
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(format!("{role} address count is outside the allowed range"));
    }
    if addresses
        .iter()
        .any(|address| address.parse::<SocketAddr>().is_err())
    {
        return Err(format!("{role} address must be a numeric socket address"));
    }
    Ok(())
}

fn runner_labels(request: &RunnerPodRequest, release_name: Option<&str>) -> Value {
    let mut labels = json!({
        "app.kubernetes.io/name": "filebelt",
        "app.kubernetes.io/component": "mcp-runner",
        "app.kubernetes.io/managed-by": "filebelt-controller",
        "filebelt.dev/mcp-invocation": request.invocation_id.to_string(),
        "filebelt.dev/mcp-catalog-entry": request.catalog_entry,
        "filebelt.dev/mcp-tenant": request.tenant_id.to_string(),
        "filebelt.dev/mcp-principal": request.principal_id.to_string(),
    });
    if let Some(release_name) = release_name {
        labels["app.kubernetes.io/instance"] = json!(release_name);
    }
    labels
}

fn restricted_security_context() -> Value {
    json!({
        "allowPrivilegeEscalation": false,
        "capabilities": {"drop": ["ALL"]},
        "privileged": false,
        "readOnlyRootFilesystem": true,
        "runAsNonRoot": true,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    })
}

#[cfg(test)]
mod tests {
    use super::{RunnerPodRequest, RunnerPodSettings, build_runner_pod, build_runner_secret};
    use crate::catalog::{CatalogEntry, CatalogResources, CatalogSignature};
    use std::collections::BTreeSet;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn fixture() -> (RunnerPodRequest, CatalogEntry) {
        let request = RunnerPodRequest {
            invocation_id: Uuid::parse_str("00000000-0000-4000-8000-000000000123").unwrap(),
            tenant_id: Uuid::parse_str("00000000-0000-4000-8000-000000000124").unwrap(),
            principal_id: Uuid::parse_str("00000000-0000-4000-8000-000000000125").unwrap(),
            catalog_entry: "fixture".into(),
            bootstrap_token: Zeroizing::new(vec![b'a'; 48]),
        };
        let entry = CatalogEntry {
            name: "fixture".into(),
            repository: "ghcr.io/example/mcp-server".into(),
            image: format!("sha256:{}", "b".repeat(64)),
            source: "https://example.invalid/mcp-server".into(),
            license: "Apache-2.0".into(),
            command: "/server".into(),
            arguments: vec!["--stdio".into()],
            architectures: BTreeSet::from(["amd64".into(), "riscv64".into()]),
            egress_profile: "public-web".into(),
            signature: CatalogSignature {
                bundle_file: "fixture.json".into(),
                identity: "release".into(),
                issuer: "issuer".into(),
            },
            resources: CatalogResources {
                cpu_request: "50m".into(),
                cpu_limit: "500m".into(),
                memory_request: "64Mi".into(),
                memory_limit: "256Mi".into(),
                ephemeral_storage_limit: "64Mi".into(),
            },
        };
        (request, entry)
    }

    #[test]
    fn pod_is_digest_pinned_and_keeps_secrets_out_of_server() {
        let (request, entry) = fixture();
        let settings = RunnerPodSettings {
            namespace: "filebelt",
            release_name: "example",
            runner_image: &format!(
                "ghcr.io/oxibelt/filebelt-mcp-runner@sha256:{}",
                "c".repeat(64)
            ),
            runner_service_account: "filebelt-mcp-runner",
            broker_addresses: &["10.96.0.21:8084".into(), "[fd00::21]:8084".into()],
            broker_server_name: "filebelt-mcp-broker",
            broker_client_tls_secret: "runner-broker-tls",
            gateway_addresses: &["10.96.0.22:8443".into()],
            gateway_server_name: "mcp-egress.filebelt-egress.svc",
            gateway_client_tls_secret: "runner-gateway-tls",
            gateway_egress_profile: "public-web",
        };
        let pod = build_runner_pod(&request, &entry, &settings).expect("pod");
        let spec = &pod["spec"];
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(
            spec["containers"][1]["image"],
            format!("{}@{}", entry.repository, entry.image)
        );
        assert!(
            spec["containers"][1]["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| !mount["name"].as_str().unwrap().contains("secret")
                    && mount["name"] != "bootstrap"
                    && mount["name"] != "broker-tls"
                    && mount["name"] != "gateway-tls")
        );
        assert_eq!(
            spec["containers"][1]["securityContext"]["readOnlyRootFilesystem"],
            true
        );
        assert!(spec.get("hostNetwork").is_none());
        assert!(spec.get("hostPID").is_none());
        let relay_arguments = spec["containers"][0]["args"].as_array().unwrap();
        assert!(
            relay_arguments
                .iter()
                .any(|value| value == "10.96.0.21:8084")
        );
        assert!(
            relay_arguments
                .iter()
                .any(|value| value == "[fd00::21]:8084")
        );
        assert!(relay_arguments.iter().all(|value| {
            value != "filebelt-mcp-broker:8084"
                && value != "filebelt-mcp-egress.filebelt-egress.svc:8443"
        }));

        let mut mismatched = settings.clone();
        mismatched.gateway_egress_profile = "internal-services";
        assert!(build_runner_pod(&request, &entry, &mismatched).is_err());

        let dns_address = ["filebelt-mcp-broker:8084".into()];
        let mut unsafe_settings = settings;
        unsafe_settings.broker_addresses = &dns_address;
        assert!(build_runner_pod(&request, &entry, &unsafe_settings).is_err());
    }

    #[test]
    fn bootstrap_secret_is_bounded_and_immutable() {
        let (request, _) = fixture();
        let secret = build_runner_secret(&request, "filebelt").expect("secret");
        assert_eq!(secret["immutable"], true);
        let mut short = request;
        short.bootstrap_token = Zeroizing::new(b"too-short".to_vec());
        assert!(build_runner_secret(&short, "filebelt").is_err());
    }
}
