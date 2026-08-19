<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes acceptance

Phase 3 acceptance has two independent live-cluster checks.

`run-kubernetes-kind-compatibility.sh` creates a uniquely named Kind cluster
from one reviewed `kindest/node` digest. It installs the chart quiesced in a
namespace enforcing restricted Pod Security, submits every rendered object to
server-side dry-run, changes the FileBelt configuration, proves that the
Deployment selects a new immutable content-addressed ConfigMap, and verifies
that Helm rollback restores the prior identity. Every administrative Job type
is also submitted to the live API server under restricted admission without
executing it. The same cluster creates separate restricted namespaces and
submits qualified `filebelt-onlyoffice` and `filebelt-git` renders to
server-side dry-run, validating their release-evidence annotations without
pulling or executing either adapter image.

`run-kubernetes-network-policy.sh` creates a uniquely named Minikube profile
with either Calico or Cilium. It runs digest-pinned `agnhost` servers and curl
clients under restricted Pod Security, applies only the chart's standard
`NetworkPolicy` resources, and proves both sides of each intended trust edge.
Negative assertions have a live positive control and require three consecutive
drops so an unavailable fixture cannot be misreported as policy enforcement.

Both scripts delete only their exact run-owned cluster/profile and a temporary
directory whose generated prefix they validate. They never prune shared Docker
or Kubernetes resources. Set `FILEBELT_KUBERNETES_TIMEOUT_SECONDS` to a value
from `120` through `900` when a slower test host needs a larger deadline.

`check-acceptance-contract.sh` is the fast CI guard for executable/script
syntax, immutable fixture and node references, tool checksums, supported
versions, workflow tiers, and the complete trust-edge assertion set.

The shared [`values-ci.yaml`](values-ci.yaml) fixes selectors and external
dependency identities for these checks. It contains no credential material and
must not be used as a production values file.
