<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported versions

Before FileBelt 1.0, security fixes are provided for the latest released minor
line. Older lines should upgrade to that line. The repository currently has no
production release.

| Version | Supported |
| --- | --- |
| latest `0.x` minor | Yes |
| older `0.x` minors | No |
| unreleased source | Best effort |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not file a
public issue or pull request containing exploitable details. Include affected
versions, deployment assumptions, reproduction steps, impact, and any proposed
mitigation. The project does not promise a contractual response SLA.

The maintainer will validate the report, coordinate a fix and advisory when
appropriate, and credit reporters who request attribution. Security fixes must
include regression coverage and upgrade or mitigation guidance.

## Review scope

Security review covers repository and release supply chain, identity and
Virtual ACL, tenant separation, storage integrity, protocol adapters, browser
rendering, integrations, secrets, Kubernetes isolation, and recovery behavior.
The current Phase 0 implementation exposes no runtime service or user data.
