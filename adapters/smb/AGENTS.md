<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# SMB adapter guidance

This directory is a GPL-3.0-or-later region for a future Samba VFS adapter and
bridge. It must remain outside root workspaces and use only a generic FileBelt
VFS protocol across the process boundary. Do not add Samba-derived code,
dependencies, Dockerfiles, or generated artifacts without Plan Mode, exact
upstream review, notices, source instructions, and protocol integration tests.
