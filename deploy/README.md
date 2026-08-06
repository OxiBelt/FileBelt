<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment assets

Phase 1 adds the [`filebelt` Helm chart](helm/filebelt/README.md) as a strict
image-values contract. It intentionally renders no Kubernetes object and is
not a usable deployment. Kubernetes workloads and observability assets begin
in later phases. Everything under `deploy/` remains in the Apache-2.0 license
region.
