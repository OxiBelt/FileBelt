<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# NFS automated-agent overlay

This file applies only to automated agents. Follow the
[root agent guidance](../../AGENTS.md), [contributor workflow](../../CONTRIBUTING.md),
[shared adapter policy](../README.md), and
[living specifications](../../docs/README.md).

Enter Plan Mode before changing this region. Stop and ask the
maintainer if the exact NFS-Ganesha version and ABI, linkage, LGPL replacement
and relinking path, generic protocol boundary, image composition, source
obligations, or integration tests are unresolved. Phase 8 selects Ubuntu 26.04
NFS-Ganesha 6.5-8, a dynamically loaded thin FSAL, and a separate Rust bridge
over the generic VFS protocol. Any departure repeats the shared adapter review.
