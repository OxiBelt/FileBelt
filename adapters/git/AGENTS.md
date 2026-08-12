<!-- SPDX-License-Identifier: GPL-2.0-only -->

# Git revision adapter automated-agent overlay

This GPL-2.0-only adapter is a separate workspace, process, image, and source
distribution region. It may consume `filebelt-revision-protocol` through the
documented process boundary; Apache packages must never import it. Keep the
system-Git invocation local, non-interactive, ref-scoped, and free of network
transport, user refs, hooks, filters, external diff, alternates, and replace
refs. Stop for any change to the Git version, process contract, storage/PVC,
TLS identity, or source-distribution obligation.
