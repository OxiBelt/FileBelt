// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn production_chart_has_the_role_and_disabled_document_contract() {
    let root = repository_root();
    let chart = root.join("deploy/helm/filebelt");
    let metadata = fs::read_to_string(chart.join("Chart.yaml")).expect("chart metadata");
    let schema_source =
        fs::read_to_string(chart.join("values.schema.json")).expect("values schema");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_source).expect("valid schema JSON");
    let catalog_schema_source =
        fs::read_to_string(chart.join("examples/mcp-runner-catalog.schema.json"))
            .expect("MCP runner catalog schema");
    let catalog_schema: serde_json::Value =
        serde_json::from_str(&catalog_schema_source).expect("valid catalog schema JSON");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("values");
    let templates = fs::read_dir(chart.join("templates"))
        .expect("templates")
        .map(|entry| {
            entry
                .expect("template entry")
                .file_name()
                .into_string()
                .expect("UTF-8 template name")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        templates,
        [
            "NOTES.txt",
            "_helpers.tpl",
            "collaboration-deployment.yaml",
            "configmaps.yaml",
            "deployments.yaml",
            "documents.yaml",
            "monitoring.yaml",
            "mcp-deployments.yaml",
            "mcp-rbac.yaml",
            "mounts.yaml",
            "networkpolicies.yaml",
            "operation-job.yaml",
            "pdbs.yaml",
            "revisions.yaml",
            "serviceaccounts.yaml",
            "services.yaml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(metadata.contains("filebelt.dev/phase: \"9\""));
    assert_eq!(schema["title"], "FileBelt Phase 9 Kubernetes deployment");
    assert!(metadata.contains("kubeVersion: \">=1.34.0-0 <1.37.0-0\""));
    for role in [
        "filebelt-api",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-tools",
        "filebelt-web",
        "filebelt-collaboration",
        "filebelt-mcp-broker",
        "filebelt-controller",
        "filebelt-mcp-runner",
        "filebelt-vfs",
        "filebelt-headscale-sync",
        "filebelt-document",
        "filebelt-revision",
        "filebelt-smb-gateway",
        "filebelt-ftp-ftps-gateway",
        "tailscaled",
    ] {
        assert!(
            schema["properties"]["images"]["properties"]
                .get(role)
                .is_some()
        );
        assert!(values.contains(&format!("  {role}:")));
    }
    let inactive_role = "filebelt-media-controller";
    assert!(
        schema["properties"]["images"]["properties"]
            .get(inactive_role)
            .is_none()
    );
    assert!(!values.contains(&format!("  {inactive_role}:")));
    assert_eq!(
        schema["properties"]["global"]["properties"]["runAsUser"]["const"],
        10001
    );
    assert!(
        schema["properties"]["operation"]["properties"]["type"]["enum"]
            .as_array()
            .is_some_and(|operations| {
                operations.len() == 16
                    && operations.iter().any(|operation| operation == "keys-audit")
                    && operations
                        .iter()
                        .any(|operation| operation == "security-descendant-shares-activate")
            })
    );
    assert!(values.contains("linux/riscv64"));
    assert_eq!(catalog_schema["properties"]["schemaVersion"]["const"], 1);
    assert_eq!(catalog_schema["properties"]["entries"]["maxItems"], 128);
    assert_eq!(
        catalog_schema["$defs"]["entry"]["properties"]["image"]["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    assert_eq!(
        schema["properties"]["mcp"]["properties"]["runners"]["properties"]["namespace"]["$ref"],
        "#/definitions/dnsLabel"
    );
    assert!(values.contains("    namespace: filebelt-mcp-runners"));
    assert_eq!(
        schema["properties"]["documents"]["properties"]["enabled"]["type"],
        "boolean"
    );
    assert_eq!(
        schema["properties"]["documents"]["properties"]["providerOrigin"]["pattern"],
        "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"
    );
    assert_eq!(
        schema["properties"]["documents"]["properties"]["launchAction"]["pattern"],
        "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?/onlyoffice/launch$"
    );
    assert!(
        values.contains("launchAction: https://filebelt-editor.example.invalid/onlyoffice/launch")
    );
    let mount_properties = &schema["properties"]["mounts"]["properties"];
    assert!(mount_properties.get("enabled").is_none());
    assert_eq!(
        schema["definitions"]["tailnetStatefulSet"]["properties"]["enabled"]["type"],
        "boolean"
    );
    for protocol in ["ftpFtps", "nfs"] {
        assert_eq!(
            mount_properties[protocol]["properties"]["enabled"]["type"],
            "boolean"
        );
    }
}

#[test]
fn onlyoffice_chart_is_an_isolated_agpl_adapter_delivery_contract() {
    let root = repository_root();
    let chart = root.join("deploy/helm/filebelt-onlyoffice");
    let metadata = fs::read_to_string(chart.join("Chart.yaml")).expect("chart metadata");
    let schema_source =
        fs::read_to_string(chart.join("values.schema.json")).expect("values schema");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_source).expect("valid schema JSON");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("values");
    let templates = fs::read_dir(chart.join("templates"))
        .expect("templates")
        .map(|entry| {
            entry
                .expect("template entry")
                .file_name()
                .into_string()
                .expect("UTF-8 template name")
        })
        .collect::<BTreeSet<_>>();

    assert!(metadata.contains("name: filebelt-onlyoffice"));
    assert!(metadata.contains("artifacthub.io/license: AGPL-3.0-only"));
    assert!(metadata.contains("adapters/onlyoffice"));
    assert_eq!(
        schema["definitions"]["adapterImage"]["properties"]["repository"]["const"],
        "oxibelt/filebelt-onlyoffice-adapter"
    );
    assert_eq!(
        schema["definitions"]["adapterImage"]["properties"]["license"]["const"],
        "AGPL-3.0-only"
    );
    assert_eq!(
        schema["definitions"]["adapterImage"]["properties"]["correspondingSource"]["const"],
        "https://github.com/OxiBelt/FileBelt/releases/download/0.1.0/filebelt-onlyoffice-adapter-source-0.1.0.tar.gz"
    );
    assert_eq!(
        schema["definitions"]["workload"]["properties"]["replicas"]["const"],
        2
    );
    assert_eq!(
        schema["properties"]["providerConfig"]["properties"]["file"]["const"],
        "/etc/filebelt-onlyoffice/provider/provider.toml"
    );
    assert!(values.contains("coreNamespace: filebelt-core"));
    assert!(values.contains("integrationNamespace: filebelt-integrations"));
    assert_eq!(
        templates,
        [
            "_helpers.tpl",
            "deployment.yaml",
            "networkpolicies.yaml",
            "pdb.yaml",
            "service.yaml",
            "serviceaccount.yaml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let rendered = templates
        .iter()
        .map(|name| fs::read_to_string(chart.join("templates").join(name)).expect("template"))
        .collect::<String>();
    let contract = format!("{values}\n{rendered}");
    for required in [
        "automountServiceAccountToken: false",
        "readOnlyRootFilesystem: true",
        "runAsUser: {{ .Values.global.runAsUser }}",
        "browser-jwt",
        "outbox-jwt",
        "core-client-tls",
        "io-client-tls",
        "egress-client-tls",
        "filebelt-onlyoffice-egress",
        "kind: PodDisruptionBudget",
    ] {
        assert!(contract.contains(required), "missing {required}");
    }
    for forbidden in [
        "kind: Namespace",
        "kind: Secret",
        "persistentVolumeClaim",
        "name: payloads",
        "adapter-database",
    ] {
        assert!(!contract.contains(forbidden), "forbidden {forbidden}");
    }
}
