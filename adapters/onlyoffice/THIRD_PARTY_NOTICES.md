<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ONLYOFFICE Adapter Third-Party Notices

The adapter's direct Rust dependencies are pinned in its adapter-local
`Cargo.lock`: `base64`, `hmac`, `prost`, `reqwest`, `rustls`, `serde`,
`serde_json`, `sha2`, `subtle`, `tokio`, `toml`, and `url`. The Apache-2.0
`filebelt-document-protocol` schema is consumed through the documented mTLS
process boundary only; it has no reverse dependency on this AGPL adapter.
Release SBOM
and provenance evidence must include the complete resolved transitive graph and
the applicable license texts before image promotion.

ONLYOFFICE Document Server `9.4.0`, its connector, `api.js`, assets, image,
and source are operator-supplied external components. They are not included in
this directory or any FileBelt adapter image. Before deployment, operators must
review and publish the third-party notices and source obligations applicable to
their exact provider distribution.
