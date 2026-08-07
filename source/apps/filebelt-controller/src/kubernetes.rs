// SPDX-License-Identifier: Apache-2.0

//! Minimal namespace-scoped Kubernetes API client with optimistic fencing.

use std::fs;
use std::time::Duration;

use http::StatusCode;
use jiff::Timestamp;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde_json::{Value, json};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct KubernetesClient {
    client: reqwest::Client,
    api: String,
    namespace: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Leader,
    Follower,
}

impl KubernetesClient {
    pub fn in_cluster(namespace: String) -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is required")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
            .map_err(|_| "KUBERNETES_SERVICE_PORT_HTTPS is required")?;
        let api = if host.contains(':') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        Self::new(
            api,
            namespace,
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        )
    }

    pub fn new(
        api: String,
        namespace: String,
        ca_file: &str,
        token_file: &str,
    ) -> Result<Self, String> {
        if !is_dns_label(&namespace) {
            return Err("runner namespace is invalid".into());
        }
        let ca =
            fs::read(ca_file).map_err(|error| format!("cannot read Kubernetes CA: {error}"))?;
        let certificate = reqwest::Certificate::from_pem(&ca)
            .map_err(|error| format!("Kubernetes CA is invalid: {error}"))?;
        let token = fs::read_to_string(token_file)
            .map_err(|error| format!("cannot read Kubernetes service account token: {error}"))?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
            .map_err(|_| "Kubernetes service account token is invalid")?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        let client = reqwest::Client::builder()
            .https_only(true)
            .add_root_certificate(certificate)
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(3))
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("cannot build Kubernetes client: {error}"))?;
        Ok(Self {
            client,
            api,
            namespace,
        })
    }

    pub async fn try_acquire_lease(
        &self,
        lease_name: &str,
        holder: &str,
        duration_seconds: u64,
    ) -> Result<LeaseState, String> {
        let url = self.namespaced("coordination.k8s.io/v1", "leases", Some(lease_name));
        let response = self.client.get(&url).send().await.map_err(request_error)?;
        let now = Timestamp::now();
        if response.status() == StatusCode::NOT_FOUND {
            let lease = lease_document(
                &self.namespace,
                lease_name,
                holder,
                duration_seconds,
                now,
                None,
            );
            let create_url = self.namespaced("coordination.k8s.io/v1", "leases", None);
            let response = self
                .client
                .post(create_url)
                .json(&lease)
                .send()
                .await
                .map_err(request_error)?;
            return match response.status() {
                StatusCode::CREATED => Ok(LeaseState::Leader),
                StatusCode::CONFLICT => Ok(LeaseState::Follower),
                status => Err(response_error("create controller Lease", status, response).await),
            };
        }
        let status = response.status();
        if !status.is_success() {
            return Err(response_error("read controller Lease", status, response).await);
        }
        let lease: Value = response.json().await.map_err(request_error)?;
        let current_holder = lease["spec"]["holderIdentity"].as_str().unwrap_or("");
        let renewed = lease["spec"]["renewTime"]
            .as_str()
            .and_then(|value| value.parse::<Timestamp>().ok());
        if current_holder != holder
            && renewed.is_some_and(|renewed| {
                now.duration_since(renewed).as_secs() <= duration_seconds as i64
            })
        {
            return Ok(LeaseState::Follower);
        }
        let resource_version = lease["metadata"]["resourceVersion"]
            .as_str()
            .ok_or("controller Lease is missing resourceVersion")?;
        let updated = lease_document(
            &self.namespace,
            lease_name,
            holder,
            duration_seconds,
            now,
            Some(resource_version),
        );
        let response = self
            .client
            .put(url)
            .json(&updated)
            .send()
            .await
            .map_err(request_error)?;
        match response.status() {
            StatusCode::OK => Ok(LeaseState::Leader),
            StatusCode::CONFLICT => Ok(LeaseState::Follower),
            status => Err(response_error("renew controller Lease", status, response).await),
        }
    }

    pub async fn create_runner(&self, secret: &Value, pod: &Value) -> Result<(), String> {
        let name = pod["metadata"]["name"]
            .as_str()
            .ok_or("runner Pod is missing metadata.name")?;
        let labels = pod["metadata"]["labels"]
            .as_object()
            .ok_or("runner Pod is missing metadata.labels")?;
        let pod_url = self.namespaced("v1", "pods", None);
        let response = self
            .client
            .post(pod_url)
            .json(pod)
            .send()
            .await
            .map_err(request_error)?;
        let pod_created = response.status() == StatusCode::CREATED;
        let pod_document = if pod_created {
            response.json().await.map_err(request_error)?
        } else if response.status() == StatusCode::CONFLICT {
            let existing = self
                .read_namespaced("pods", name)
                .await?
                .ok_or("conflicting runner Pod disappeared")?;
            if !resource_labels_match(&existing, labels) {
                return Err("conflicting runner Pod has a different identity".into());
            }
            existing
        } else {
            let status = response.status();
            return Err(response_error("create runner Pod", status, response).await);
        };
        let pod_uid = pod_document["metadata"]["uid"]
            .as_str()
            .ok_or("runner Pod is missing metadata.uid")?;
        let mut owned_secret = secret.clone();
        owned_secret["metadata"]["ownerReferences"] = json!([{
            "apiVersion": "v1",
            "kind": "Pod",
            "name": name,
            "uid": pod_uid,
            "controller": true,
            "blockOwnerDeletion": false,
        }]);
        let secret_url = self.namespaced("v1", "secrets", None);
        let response = self
            .client
            .post(secret_url)
            .json(&owned_secret)
            .send()
            .await
            .map_err(request_error)?;
        let result = if response.status() == StatusCode::CREATED {
            Ok(())
        } else if response.status() == StatusCode::CONFLICT {
            let existing = self
                .read_namespaced("secrets", name)
                .await?
                .ok_or("conflicting runner Secret disappeared")?;
            let owner_matches = existing["metadata"]["ownerReferences"]
                .as_array()
                .is_some_and(|owners| owners.iter().any(|owner| owner["uid"] == pod_uid));
            let token_matches =
                existing["data"]["bootstrap-token"] == owned_secret["data"]["bootstrap-token"];
            if owner_matches && token_matches && existing["immutable"] == true {
                Ok(())
            } else {
                Err("conflicting runner Secret has a different owner or token".into())
            }
        } else {
            let status = response.status();
            Err(response_error("create runner bootstrap Secret", status, response).await)
        };
        if result.is_err() && pod_created {
            let _ = self.delete_namespaced("pods", name, 0).await;
        }
        result
    }

    pub async fn existing_runner_matches(
        &self,
        name: &str,
        expected_labels: &serde_json::Map<String, Value>,
    ) -> Result<bool, String> {
        Ok(self
            .read_namespaced("pods", name)
            .await?
            .is_some_and(|pod| resource_labels_match(&pod, expected_labels)))
    }

    pub async fn active_runner_counts(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<(u32, u32), String> {
        let url = format!(
            "{}?labelSelector={}",
            self.namespaced("v1", "pods", None),
            "app.kubernetes.io%2Fmanaged-by%3Dfilebelt-controller"
        );
        let response = self.client.get(url).send().await.map_err(request_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(response_error("count active runner Pods", status, response).await);
        }
        let list: Value = response.json().await.map_err(request_error)?;
        let mut tenant = 0_u32;
        let mut principal = 0_u32;
        for pod in list["items"].as_array().into_iter().flatten() {
            if matches!(
                pod["status"]["phase"].as_str(),
                Some("Succeeded" | "Failed")
            ) {
                continue;
            }
            let labels = &pod["metadata"]["labels"];
            if labels["filebelt.dev/mcp-tenant"].as_str() == Some(tenant_id) {
                tenant = tenant.saturating_add(1);
                if labels["filebelt.dev/mcp-principal"].as_str() == Some(principal_id) {
                    principal = principal.saturating_add(1);
                }
            }
        }
        Ok((tenant, principal))
    }

    pub async fn delete_runner(&self, name: &str) -> Result<(), String> {
        for resource in ["pods", "secrets"] {
            self.delete_namespaced(resource, name, if resource == "pods" { 10 } else { 0 })
                .await?;
        }
        Ok(())
    }

    pub async fn reconcile_finished_runners(&self) -> Result<usize, String> {
        let url = format!(
            "{}?labelSelector={}",
            self.namespaced("v1", "pods", None),
            "app.kubernetes.io%2Fmanaged-by%3Dfilebelt-controller"
        );
        let response = self.client.get(url).send().await.map_err(request_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(response_error("list runner Pods", status, response).await);
        }
        let list: Value = response.json().await.map_err(request_error)?;
        let mut deleted = 0;
        for pod in list["items"].as_array().into_iter().flatten() {
            if matches!(
                pod["status"]["phase"].as_str(),
                Some("Succeeded" | "Failed")
            ) && let Some(name) = pod["metadata"]["name"].as_str()
            {
                self.delete_runner(name).await?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    fn namespaced(&self, api_version: &str, resource: &str, name: Option<&str>) -> String {
        let prefix = if api_version == "v1" {
            format!("{}/api/v1", self.api)
        } else {
            format!("{}/apis/{api_version}", self.api)
        };
        match name {
            Some(name) => format!("{prefix}/namespaces/{}/{resource}/{name}", self.namespace),
            None => format!("{prefix}/namespaces/{}/{resource}", self.namespace),
        }
    }

    async fn read_namespaced(&self, resource: &str, name: &str) -> Result<Option<Value>, String> {
        let url = self.namespaced("v1", resource, Some(name));
        let response = self.client.get(url).send().await.map_err(request_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = response.status();
        if !status.is_success() {
            return Err(response_error("read runner resource", status, response).await);
        }
        response.json().await.map(Some).map_err(request_error)
    }

    async fn delete_namespaced(
        &self,
        resource: &str,
        name: &str,
        grace_period_seconds: u64,
    ) -> Result<(), String> {
        let url = self.namespaced("v1", resource, Some(name));
        let response = self
            .client
            .delete(url)
            .json(&json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "gracePeriodSeconds": grace_period_seconds,
                "propagationPolicy": "Background",
            }))
            .send()
            .await
            .map_err(request_error)?;
        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            let status = response.status();
            return Err(response_error("delete runner resource", status, response).await);
        }
        Ok(())
    }
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index > 0 && index + 1 < value.len(),
            _ => false,
        })
}

fn resource_labels_match(resource: &Value, expected: &serde_json::Map<String, Value>) -> bool {
    let Some(actual) = resource["metadata"]["labels"].as_object() else {
        return false;
    };
    [
        "app.kubernetes.io/managed-by",
        "filebelt.dev/mcp-invocation",
        "filebelt.dev/mcp-catalog-entry",
        "filebelt.dev/mcp-tenant",
        "filebelt.dev/mcp-principal",
    ]
    .into_iter()
    .all(|key| actual.get(key) == expected.get(key))
}

fn lease_document(
    namespace: &str,
    name: &str,
    holder: &str,
    duration_seconds: u64,
    now: Timestamp,
    resource_version: Option<&str>,
) -> Value {
    let mut metadata = json!({
        "name": name,
        "namespace": namespace,
        "labels": {
            "app.kubernetes.io/name": "filebelt",
            "app.kubernetes.io/component": "controller",
        },
    });
    if let Some(resource_version) = resource_version {
        metadata["resourceVersion"] = json!(resource_version);
    }
    json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": metadata,
        "spec": {
            "holderIdentity": holder,
            "leaseDurationSeconds": duration_seconds,
            "acquireTime": now.to_string(),
            "renewTime": now.to_string(),
        },
    })
}

fn request_error(error: reqwest::Error) -> String {
    format!("Kubernetes API request failed: {error}")
}

async fn response_error(action: &str, status: StatusCode, response: reqwest::Response) -> String {
    let body = response.text().await.unwrap_or_default();
    let bounded = body.chars().take(1024).collect::<String>();
    format!("cannot {action}: Kubernetes returned {status}: {bounded}")
}

#[cfg(test)]
mod tests {
    use super::{is_dns_label, lease_document};

    #[test]
    fn namespace_is_a_dns_label() {
        assert!(is_dns_label("filebelt-system"));
        assert!(!is_dns_label("filebelt/system"));
        assert!(!is_dns_label("-filebelt"));
        assert!(!is_dns_label("filebelt-"));
    }

    #[test]
    fn lease_carries_optimistic_resource_version_and_fencing_clock() {
        let now: jiff::Timestamp = "2026-08-07T01:02:03Z".parse().unwrap();
        let lease = lease_document("filebelt", "controller", "pod-a", 15, now, Some("17"));
        assert_eq!(lease["metadata"]["resourceVersion"], "17");
        assert_eq!(lease["spec"]["renewTime"], "2026-08-07T01:02:03Z");
        assert_eq!(lease["spec"]["holderIdentity"], "pod-a");
        assert_eq!(lease["spec"]["leaseDurationSeconds"], 15);
    }
}
