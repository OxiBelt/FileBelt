<!-- SPDX-License-Identifier: Apache-2.0 -->

# Git revision adapter automated-agent overlay

This Apache-2.0 wrapper is a separate workspace and process distributed in an
aggregate image with a separate GPL-2.0-only Git executable. It may link the
Apache-2.0 `filebelt-revision-protocol`; Apache core packages must never import
the adapter implementation. Keep the system-Git invocation local,
non-interactive, ref-scoped, and free of network transport, user refs, hooks,
filters, external diff, alternates, and replace refs. Never link Git, libgit2,
Git headers, Git object code, or another Git implementation into the wrapper.
Stop for any change to the Git version, process contract, storage/PVC, TLS
identity, aggregate image composition, or source-distribution obligation.
