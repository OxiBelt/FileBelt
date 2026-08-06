<!-- SPDX-License-Identifier: Apache-2.0 -->

# Authorized release-tag signers

`../release-tag-signers.txt` is the fail-closed allowlist of primary OpenPGP
fingerprints authorized to sign FileBelt release tags. Each fingerprint has one
matching armored public key in this directory. Release validation creates an
empty temporary keyring, verifies that every tracked key has its allowlisted
fingerprint, and accepts only a valid tag signature certified by an allowlisted
primary key.

The initial key is publicly registered to `PiQuark6046` through the
[GitHub GPG-key API](https://api.github.com/users/PiQuark6046/gpg_keys). Its
fingerprint also matches the verified signatures on the repository's current
maintainer commits as of 2026-08-06.

Adding, rotating, or revoking a signer changes release authority. Update the
allowlist and matching public key together through a reviewed, signed commit;
verify the fingerprint against the maintainer's independently published GitHub
identity, and explain the trust transition in the change.
