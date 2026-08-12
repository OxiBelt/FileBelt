<!-- SPDX-License-Identifier: Apache-2.0 -->

# NFS release qualification

NFS remains disabled and non-publishable at this revision. The adapter image
still carries `filebelt.dev.qualification=abi-probe-only`, the repository has no
configured native RISC-V runner or six-platform NFS client fleet, and the
read-only qualification workflow deliberately ends at a failing publication
boundary. Do not use a successful contract test or native image build as NFS
delivery evidence. Database and API tests for target-approved identity bindings
also do not qualify the Ganesha ABI, image, KDC, client matrix, or live protocol
path.

The manual workflow must be dispatched from the exact release tag, never from
a branch plus a tag-name input. The executable contract is split among:

- [the read-only workflow](../../.github/workflows/nfs-qualification.yml),
  which accepts exact runner labels only for an explicit manual run;
- [the native image probe](../../tests/scripts/run-nfs-native-build.sh), which
  requires a signed release tag, native `amd64`, `arm64`, and `riscv64`
  machines, the exact Ganesha `6.5-8` / FSAL `13.0` labels, a genuinely linked
  dynamic FSAL, and embedded source/relinking material;
- [the client suite](../../tests/scripts/run-nfs-client-qualification.py),
  which performs real NFSv4.2 `krb5p` operations and negative authentication
  tests; and
- [the evidence validator](../../tests/scripts/validate-nfs-qualification.py),
  which is the final immutable qualification contract for a future independent
  NFS promotion job.

## Inputs that must be admitted

Before the manual workflow can become a release gate, a maintainer must review
and record all of these external inputs in tracked supply-chain and runner
configuration:

1. The repository-configured label and immutable host/toolchain identity of a
   native RISC-V runner. QEMU system, user-mode, and `binfmt_misc` execution do
   not satisfy this gate.
2. Native Ubuntu and Debian client versions on both AMD64 and ARM64, plus RHEL
   10 on both architectures. Record an immutable root-filesystem digest for
   every client; a mutable distribution tag is insufficient.
3. An isolated external KDC/realm fixture, exact AES SHA-2 configuration,
   service principal, an ordinary principal exercised in unapproved,
   target-approved, and revoked states, `root@REALM` principal, and a principal
   in a second realm. The KDC is test infrastructure, not an NFS Pod dependency,
   and the deployed gateway must retain no KDC egress.
4. A root-owned administrative driver for the chosen qualification cluster.
   Its revision and digest must be reviewed with the fixture. The driver owns
   only deterministic setup, Ganesha restart, admission drain/resume, gateway
   fence, and exact run-owned cleanup.
5. A read-only evidence assembler that binds native archives, normalized
   rebuild comparisons, ABI/link logs, per-platform CycloneDX SBOMs, Trivy
   reports, complete corresponding source, notices, source offer, relinking
   instructions, tag verification, and provenance to one candidate image-index
   digest. No checked-in assembler or NFS promotion path exists yet.

These are material infrastructure and supply-chain choices. Do not replace
them with a hosted AMD64 runner, an emulated architecture, an unpinned client
container, a mock KDC, an `AUTH_SYS` mount, or a self-reported passing JSON
document.

## Isolated client-runner contract

Each client runner must be disposable, native, root-controlled, and dedicated
to one qualification run. It must already contain the distribution's NFSv4,
Kerberos, extended-attribute, and NFSv4 ACL tools. A root-owned JSON file,
outside the checkout and retained-artifact directory, supplies only public
fixture coordinates and absolute paths to separately projected keytabs:

```json
{
  "schemaVersion": 1,
  "server": "nfs-gateway.qualification.example",
  "exportPath": "/filebelt/00000000-0000-0000-0000-000000000001",
  "realm": "QUALIFICATION.EXAMPLE",
  "userPrincipal": "user@QUALIFICATION.EXAMPLE",
  "userKeytab": "/run/filebelt-nfs-qualification/user.keytab",
  "rootPrincipal": "root@QUALIFICATION.EXAMPLE",
  "rootKeytab": "/run/filebelt-nfs-qualification/root.keytab",
  "crossRealmPrincipal": "user@OTHER.EXAMPLE",
  "crossRealmKeytab": "/run/filebelt-nfs-qualification/cross-realm.keytab",
  "fixtureRelativePath": "qualification/read-fixture.bin",
  "fixtureSha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "adminDriver": "/usr/local/libexec/filebelt-nfs-qualification-admin",
  "rootfsDigestFile": "/etc/filebelt-nfs-rootfs-digest",
  "rootfsDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "imageIndexDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "releaseRevision": "0000000000000000000000000000000000000000",
  "fenceTimeoutSeconds": 300
}
```

Replace every all-zero example value. The config and keytabs must be root-owned
regular files with mode `0600` and `0400` respectively; no path may traverse a
symlink or group/world-writable parent. Keytabs must never be below the checkout
or evidence directory and must be removed with the disposable runner. The
rootfs marker is provisioned with the admitted client image and its exact value
must match `rootfsDigest`. The Ganesha container alone
receives its acceptor keytab. The bridge, Unix IPC, logs, uploaded artifacts,
and evidence JSON receive no ticket, keytab, private key, cookie, capability,
or credential bytes.

The administrative driver receives exactly:

```text
<driver> <prepare|attest|restart|drain|resume|fence|cleanup|assert-clean> \
  <filebelt-nfs-qualification-run-id> <absolute-config-path>
```

It and every parent path must be root-owned and not group/world writable or a
symlink. `attest` prints only the exact observed client rootfs digest,
server-image digest/revision equality, and Ganesha/bridge keytab-isolation JSON
checked by the client harness. `assert-clean` prints only
`{"leftovers": []}` after verifying the exact run-owned cluster resources are
gone. The driver must never echo configuration, ticket, keytab, Kubernetes
Secret, or fault/restore contents.

## Required behavior

Every Ubuntu, Debian, and RHEL 10 client on AMD64 and ARM64 performs the same
suite against the same image-index digest. The positive path authenticates with
`krb5p` through an exact target-approved alias and covers list, immutable read,
write plus `fsync` commit, rename with an open handle, user extended attributes,
NFSv4 ACLs, sparse data/hole preservation, restart lock reclaim, admission
drain, gateway fence, and stale handle rejection. Negative controls require
failed mounts for a pending or quarantined alias, a target-revoked alias,
`AUTH_SYS`, `root@REALM`, and the cross-realm principal. Alias-scope attenuation
must close affected sessions without widening a sibling alias. The complete
label also requires create/mkdir/symlink/readlink, projected mode and
prohibited-bit/chown checks,
xattr list/remove and namespace rejection, conflicting/unlock/to-EOF/LOCKT
locks, open-unlinked completion, truncate/allocate/punch/SEEK_DATA/SEEK_HOLE,
readdir-cookie resume, ACL deny/attenuation, Web-versus-NFS conflict-copy, and
induced replay/retransmit evidence. Cases not yet executable stay in the
required-case manifest, so the current scaffold fails rather than omitting
them. A negative result is counted only
after the fixture's positive `krb5p` path succeeds.

Qualification must use the exact patched Ganesha 6.5 source and prove both
MDCACHE delegation to FileBelt authorization and authoritative owner/group
encoding without host idmapper substitution. Patch digest/application or
warning-clean header compilation is only source evidence, not a substitute for
the configured ABI/link and live `krb5p` cases above.

Hard-mount execution is wrapped in a 40-minute external watchdog, followed by
an independent five-minute, always-run reconciler. Before a stale-handle read,
the disposable client drops its page cache so a cached byte cannot count as a
server result. The suite uses a `filebelt-nfs-qualification-<digest>` prefix and cleans only
that run's directory and driver-owned resources. An unmount, driver cleanup, or
leftover assertion failure fails the run. Fault/recovery logs remain sensitive
runner-local output and are not uploaded.

## Evidence and publication boundary

Run the fast, non-networked contract checks with:

```sh
python3 tests/scripts/test_validate_nfs_qualification.py
tests/scripts/check-nfs-qualification-contract.sh
```

For an admitted evidence directory, the final gate is:

```sh
python3 tests/scripts/validate-nfs-qualification.py \
  --input artifacts/nfs/qualification.json \
  --artifact-root artifacts/nfs
```

The validator rejects missing or duplicate platforms, emulation, mixed
Ganesha/bridge digest or revision, an unauthorized release signer, the
`abi-probe-only` label, incomplete ABI/link/rebuild/SBOM/source evidence,
missing cases, secret-shaped artifact paths, checksum drift, nondeterministic
resource names, and cleanup leftovers.

The current core release workflow contains no `filebelt-nfs-gateway` subject,
and the NFS scaffold has only `contents: read`. A later promotion change must
consume an already accepted immutable evidence package without rebuilding,
receive separately reviewed package/attestation authority only in its
promotion job, read back the published index digest, and keep the core Apache
release independent. Rollback fences admission and selects an earlier verified
digest; it never moves a published tag or deletes retained recovery state.
