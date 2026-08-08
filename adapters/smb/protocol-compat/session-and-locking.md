<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Mount-session and lock contract draft

This adapter-local document is a compatibility target for the future Apache VFS
v1 contract, not a replacement for its authority.

`SmbMountSession` binds an internal user principal, SMB credential ID and
generation, optional Headscale node ID/source address, Samba session ID,
permitted roots, ACL/membership/namespace generation snapshot, creation/expiry,
and last activity. Samba password material and session keys never enter the
bridge frame, logs, metrics, or audit descriptions.

`SmbHandleBinding` binds an opaque Samba cookie to FileBelt handle and object
IDs, base version, granted actions, ACL/object generations, gateway epoch, and
expiry. Before mutation, flush, close, or lock release, the core must recheck
the session credential generation, ACL projection, expected head, and owner
epoch in its PostgreSQL transaction. A stale session or epoch must fail rather
than commit.

The initial compatible lock vocabulary is share-mode read/write/delete intent,
byte-range lock/unlock, delete-pending, rename exclusion, write-session owner,
and lease-break notification. The adapter records no lock authority locally:
the future common coordinator must fence the owner epoch and serialize an
approved conflict policy across web, collaboration, and SMB. Iggy can prompt a
recheck but never grants a lock or authorizes a stale handle.
