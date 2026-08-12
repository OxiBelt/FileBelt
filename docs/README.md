<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt documentation

FileBelt documents its current architecture as living specifications. A
specification describes the contract implemented by the same Git revision; Git
history and reviewed pull requests preserve the rationale for earlier states.
When code changes a documented boundary, update the relevant specification in
the same change.

## Architecture specifications

- [Namespace and authorization](NamespaceAndAuthorization.md) defines tenant,
  identity, session, logical namespace, Virtual ACL, sharing, retention, and
  Markdown collaboration, external document sessions, MCP principal, approval,
  data-grant, mount policy, credential/device fencing, and revocation behavior.
- [Interfaces and capabilities](InterfacesAndCapabilities.md) defines the HTTP,
  OpenAPI, Protobuf, edge, storage-worker, collaboration, external-document,
  MCP-broker, and VFS/gateway/runner authorization boundaries.
- [Storage and durability](StorageAndDurability.md) defines PostgreSQL,
  migrations, payload state, collaboration manifests, document revisions,
  MCP/mount vault state, jobs, Iggy, reconciliation, and recovery.
- [Runtime and deployment](RuntimeAndDeployment.md) defines process and image
  roles, supported platforms, Kubernetes collaboration, document integration,
  and one-shot runner topology, transport/egress security, observability, and
  release promotion.

These documents state cross-component behavior. More specialized sources own
their respective details:

- [Dependency Boundaries](DependencyBoundaries.md) and
  [License Map](LicenseMap.md) define source, dependency, process, and license
  direction.
- [Supply Chain](SupplyChain.md) defines dependency and release evidence.
- [Threat Model](ThreatModel.md) defines assets, trust boundaries, required
  controls, and residual risk.
- [Protocol documentation](../protocol/README.md) defines schema layout and
  deterministic generation.
- [UI documentation](../ui/README.md) defines browser security, accessibility,
  design, dependency, and test requirements.
- [Kubernetes operations](operations/kubernetes.md),
  [ONLYOFFICE integration operations](operations/onlyoffice.md),
  [revision storage operations](operations/revisions.md),
  [NFS release qualification](operations/nfs-qualification.md), and the
  neighboring operations guides define deployment-specific procedures and
  rollback steps.

## Maintaining the specifications

Treat the specification at the checked-out revision as authoritative for that
revision. A change to persistence, authorization, namespace semantics, a public
contract, an external process boundary, an image, deployment trust, or a
license boundary must update all affected specifications, threat-model entries,
operator procedures, compatibility notes, and rollback instructions together.

Record difficult-to-reverse choices and rejected alternatives in the
implementing pull request. Keep specifications focused on the resulting
current contract rather than retaining a second historical decision log.
