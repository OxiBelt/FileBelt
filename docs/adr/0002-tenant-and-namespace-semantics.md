<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0002: Tenant and namespace semantics

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0 and protocol consumers

## Context

Web, SMB, FTP/FTPS, Markdown, office editing, and future NFS must resolve the
same logical namespace. Names that compare differently between clients create
data-loss and authorization risks.

## Decision

Identifiers and future tables are tenant-scoped. The initial supported mode is
one tenant per deployment. A drive may be owned by a user, group,
organization, or service principal; transient device, session, and share-link
principals cannot own a drive.

The namespace is a strict rooted tree. Every node except a drive root has one
parent. Hard links, symbolic links, devices, sockets, and FIFOs are unsupported.
Logical names never become physical storage paths.

For each component:

1. require valid UTF-8 and normalize the display value to NFC;
2. reject empty names, `.`/`..`, NUL, ASCII controls, `/`, `\\`,
   `<`, `>`, `:`, `"`, `|`, `?`, and `*`;
3. reject trailing space or dot and Windows device basenames `CON`, `PRN`,
   `AUX`, `NUL`, `COM1` through `COM9`, and `LPT1` through `LPT9`, including
   those basenames followed by an extension, without regard to case;
4. derive the comparison key using full Unicode default case folding of the
   NFC value and enforce one active key per tenant, drive, and parent;
5. reject any normalization or case-fold collision rather than rewriting the
   requested display name.

Limits after normalization are 255 UTF-8 bytes per component, 4096 UTF-8 bytes
for the complete logical path, and 128 components. A protocol with a stricter
limit must report that before accepting a write.

Rename and move are permitted only within a drive. Cross-drive moves return a
stable unsupported-operation error; copy-and-delete requires a future contract.

Clients discover non-persisted `My Drive`, `Shared with me`, and `Shared drives`
collections backed by stable drive and node UUIDs. A label is used unchanged
when unique under the same comparison rules. A collision appends a parenthesized
lowercase UUID prefix of eight hexadecimal characters, extended in four-character
increments until unique and to the full UUID if necessary.

The Unicode data version used to build comparison keys is pinned. Changing it
requires an ADR, collision analysis, and a data migration.

## Alternatives considered

Case-sensitive web-native names were rejected because later mount adapters
would need lossy aliases. Per-protocol normalization was rejected because it
would make authorization and rename behavior client-dependent.

## Consequences and verification

The policy excludes some valid POSIX names but provides stable cross-protocol
behavior. Future namespace code requires example, property, and fuzz tests for
normalization, collision, reserved-name, depth, and cross-tenant cases.

## Rollback

No schema or names exist in Phase 0. Once persisted, this decision may change
only through a collision-safe expand/migrate/contract migration.

## Open questions

None.
