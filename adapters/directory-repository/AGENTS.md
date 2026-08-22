<!-- SPDX-License-Identifier: Apache-2.0 -->

# Directory-repository adapter automated-agent overlay

This Apache-2.0 wrapper is an independent workspace and private process. It
may invoke only the exact separately distributed GPL Git executable through the
Apache `filebelt-directory-repository-protocol` process boundary; it must never
link Git, libgit2, Git headers, or another Git implementation. Apache core may
not import this adapter implementation.

Enter Plan Mode before changing the Git version, private mTLS identity,
repository storage, object-format policy, source-distribution obligation, image
composition, or promotion/recovery semantics. Keep system-Git execution local,
non-interactive, ref-scoped, and free of remotes, user configuration, hooks
other than the immutable adapter-owned receive bridge, alternates, replace refs,
worktrees, external filters, protocols, and prompts.
