<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0003: License regions and dependency direction

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: mixed

## Context

FileBelt preserves a reusable Apache-2.0 center while integrating with upstream
projects whose in-process adapters or distributions use copyleft licenses.

## Decision

The license map in `docs/LicenseMap.md` is adopted. Core, UI, generic protocol,
deployment, test, documentation, and tooling regions use Apache-2.0. SMB and
FTP/FTPS use GPL-3.0-or-later, ONLYOFFICE uses AGPL-3.0-only, and the reserved
NFS region uses LGPL-3.0-or-later. Transcode implementation remains prohibited
until the exact FFmpeg build and license expression are accepted.

The project adopts REUSE/SPDX. Source files carry SPDX identifiers when their
format supports comments; generated or non-commentable files use REUSE
annotations. Each adapter has its own license, notices, guidance, build root,
process, image, and corresponding-source evidence.

An adapter may consume Apache protocol definitions. No Apache package may
import, link, or path-depend on adapter implementation code. A container or Pod
boundary alone is not treated as license analysis; RPC must be generic and the
programs replaceable.

## Alternatives considered

Deferring all adapter licenses would leave top-level paths ambiguous. Treating
the complete monorepo or a combined image as Apache-2.0 would be inaccurate.

## Consequences and verification

Dependency admission, REUSE, resolved workspace, path dependency, source map,
SBOM, and image-label checks enforce the boundary. Moving code across regions
requires contributor relicensing authority and a new review.

## Rollback

License-region changes require a superseding ADR and cannot retroactively
relicense third-party or contributor work without authorization.

## Open questions

None.
