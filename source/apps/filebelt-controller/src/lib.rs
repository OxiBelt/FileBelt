// SPDX-License-Identifier: Apache-2.0

//! Fail-closed Kubernetes runner orchestration for curated MCP stdio servers.

#![deny(unsafe_code)]

pub mod catalog;
pub mod kubernetes;
pub mod pod;

pub use catalog::{Catalog, CatalogEntry, VerifiedCatalog};
pub use kubernetes::{KubernetesClient, LeaseState};
pub use pod::{RunnerPodRequest, build_runner_pod, build_runner_secret};
