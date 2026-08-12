<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# FileBelt ONLYOFFICE adapter

This is a standalone AGPL-3.0-only workspace and browser launcher for one
external deployment: ONLYOFFICE Document Server `9.4.0`. It does not contain,
copy, download, build, or redistribute the provider's connector, `api.js`,
assets, image, or source. The browser runtime loads exactly
`https://<document-server>/web-apps/apps/api/documents/api.js` after the
adapter's one-use launch endpoint has redeemed a Core-issued launch ID.

## Security and process boundary

- The adapter has no payload mount, host-path access, browser session
  authority, general PostgreSQL credential, or direct Internet client.
- The runtime uses private TLS 1.3 mutual-TLS clients for the documented Core
  protobuf envelope, scoped I/O, and egress gateway. It has no FileBelt
  database connection, payload mount, generic API credential, or direct
  DocumentServer/Internet socket.
- The browser signing secret and the current/optional-retiring provider outbox
  verification secrets are separately file-mounted. A retiring outbox key is
  accepted for at most 30 minutes; malformed or unreadable inputs fail closed.
  The verifier accepts only `HS256` with `typ: JWT`, rejects `none`, `kid`,
  malformed Base64, and algorithm confusion, and treats the signed ONLYOFFICE
  payload—not custom FileBelt claims—as authoritative.
- `GET /onlyoffice/source`, `GET /onlyoffice/about`, inputs, and callbacks are
  accepted only on `public_origin`. The one-use `POST /onlyoffice/launch` and
  `GET /onlyoffice/launcher.js` are accepted only on a distinct
  `launch_origin`, and launch requires the exact `public_origin` `Origin`
  header. The adapter issues no launch-correlation cookie.
- `GET /onlyoffice/input/{session}/{participant}` requires a provider JWT that
  binds the exact URL and a newly issued scoped Core read capability. It
  accepts a full download without `Range` and valid single ranges, hiding
  denied input as 404.
- Callback handling maps ONLYOFFICE 9.4 status `1` to Core editing; `2` and
  `6` to output-required; `3` to corrupted provider-save-error; `4` to
  closed-without-changes; and `7` to force-save-error. Error callbacks never
  fetch an output URL, though any supplied URL must still be the exact provider
  origin and is included in the authenticated callback fingerprint. Force-save
  types `0`, `1`, `2`, or `3` are required for statuses `6`/`7`.
- Status-1 callbacks must contain exactly one signed `actions` object for the
  route-bound participant UUID: type `1` is connected and type `0` is
  disconnected. Missing, multiple, mismatched-user, or unsupported actions
  are rejected. All other statuses send Core activity `UNSPECIFIED`.
  Canonical SHA-256 fingerprints use the legacy `callback.v1` unambiguous
  length-delimited field set and are recorded by Core before output
  processing. The later-added signed `filetype` is intentionally omitted from
  that v1 digest so an in-flight retry remains idempotent across a rolling
  deployment. JWT/body matching and Core's immutable media binding still
  validate `filetype` independently.
- Save output may be fetched only through the mTLS egress gateway, with no
  redirects, exactly the configured provider origin, and a 100 MiB ceiling.
  DOCX, XLSX, PPTX, ODT, ODS, and ODP are admitted only when the source name
  has the exact lower-case extension for its media type. The signed callback
  `filetype`, the authenticated callback body, and Core's immutable source
  media binding must agree.
  The adapter sets `assemblyFormatAsOrigin=true`, so save-back preserves that
  admitted format rather than accepting a provider conversion.
- Before scoped publication, save output is boundedly spooled to private
  adapter tmpfs and structurally inspected as a ZIP package. It rejects
  encryption, unsafe or duplicate paths, macros, unsupported compression, a
  format mismatch, more than 10,000 entries, more than 1 GiB uncompressed,
  and required metadata larger than 1 MiB. ODF `content.xml` has a separate
  100 MiB uncompressed ceiling and a streaming, namespace-aware XML gate that
  rejects trees deeper than 256 elements, DTDs, malformed XML, undeclared
  prefixes, `office:scripts`,
  `office:script`, `office:event-listeners`, `script:event-listener`,
  `text:execute-macro`, and `table:error-macro`. Ordinary external links and
  embedded office objects remain supported residual content. Failed
  inspection leaves the Core receipt retryable and does not commit a FileBelt
  version.
- The per-tab TypeScript launcher has isolated `idle`, `loading-api`,
  `launching`, `ready`, and `error` states. It uses no browser storage. Its
  embedding view must expose progress in an `aria-live` region and errors with
  `role="alert"`, and must disable the launch control while launching.

`20` active tabs is the enforced maximum for any one Core launch subject. The
Core transport must atomically count/redeem launches and bind each grant to its
principal, tenant, document version, and authorization generations.

The adapter makes no direct PostgreSQL write. It redeems launches and refreshes
the exact 60-second source capability through Core mTLS; provider callbacks are
durably received by Core before the adapter asks its sole egress gateway for
bytes. It then obtains a provider-neutral revision admission, writes and
finalizes only through scoped I/O capabilities, and commits idempotently. A
replica retains at most 1,024 fingerprint-to-revision retry contexts in FIFO
order. Eviction loses no durable state: retrying the same callback makes Core
replay its authoritative revision ID and repopulates the local context. The
adapter retains no callback or version authority.

The package validator is a bounded adapter-side gate, not a production
compatibility qualification. Operators must still run the documented real
ONLYOFFICE Community `9.4.0` browser matrix before enabling ODF traffic.

## Per-replica availability limits

Private request execution runs on the blocking pool, never the Tokio socket
workers. The mTLS listener admits at most 16 in-flight private connections and
returns `429` when full. It permits at most 4 concurrent input transfers
(each capped at 100 MiB, so at most 400 MiB of input buffers) and 2 concurrent
callback output spools (at most 200 MiB of the chart's 256 MiB tmpfs). These
limits fail fast with `429`; health probes on the separate operations listener
are not subject to them. Chunked request bodies are unsupported and any
`Transfer-Encoding` header is rejected.

## Operator inputs

The process receives only these role-specific strict-TOML inputs:

- fixed, pairwise-distinct public, launch, and Document Server bare HTTPS
  origins and the literal `9.4.0` provider version;
- a read-only browser signing secret and current outbox-verification secret,
  plus an optional read-only retiring outbox verifier with an expiry no more
  than 30 minutes ahead;
- the fixed FileBelt tenant ID and distinct browser-signing and provider-outbox
  verification secrets;
- separate mTLS endpoint/certificate/key/CA tuples for Core, scoped I/O, and
  the egress gateway; and
- an egress gateway with the reviewed `POST /v1/fetch` contract that performs
  DocumentServer DNS/IP validation, no-redirect retrieval, and bounded output
  streaming.

Do not provide a database URL, general Core/API credential, payload claim,
provider private source, or general egress proxy. Invoke the process as
`filebelt-onlyoffice-adapter serve --config /path/provider.toml`. Its listener
requires TLS 1.3 client authentication and accepts only
`spiffe://filebelt/oxibelt/onlyoffice`; DocumentServer reaches it through that
OxiBelt identity. The Service exposes only that HTTPS listener. The process
also binds a low-information, unadvertised HTTP operations listener on port
`9090` for kubelet-only `/health/live` and `/health/ready` probes; it accepts
no editor, grant, callback, document, or source routes.

```toml
provider = "onlyoffice_document_server_9_4_0"
document_server_version = "9.4.0"
public_origin = "https://files.example.invalid"
launch_origin = "https://launch.files.example.invalid"
document_server_origin = "https://office.example.invalid"
document_server_api_js = "https://office.example.invalid/web-apps/apps/api/documents/api.js"
tenant_id = "00000000-0000-4000-8000-000000000001"
browser_jwt_file = "/run/secrets/browser-jwt/current"
outbox_jwt_current_file = "/run/secrets/outbox-jwt/current"
# Omit both settings when no retiring verifier key is active. The overlap may
# not exceed 30 minutes.
outbox_jwt_retiring_file = "/run/secrets/outbox-jwt/retiring"
outbox_jwt_retiring_until_unix_seconds = 1735689600

[server_tls]
certificate_chain_file = "/run/secrets/server-tls/tls.crt"
private_key_file = "/run/secrets/server-tls/tls.key"
client_ca_file = "/run/secrets/server-tls/client-ca.crt"
allowed_client_uri_san = "spiffe://filebelt/oxibelt/onlyoffice"

[core]
url = "https://filebelt-document.filebelt-core.svc:8090/"
certificate_chain_file = "/run/secrets/core-client-tls/tls.crt"
private_key_file = "/run/secrets/core-client-tls/tls.key"
server_ca_file = "/run/secrets/core-client-tls/server-ca.crt"

[io]
url = "https://filebelt-worker-io.filebelt-core.svc:8081/"
certificate_chain_file = "/run/secrets/io-client-tls/tls.crt"
private_key_file = "/run/secrets/io-client-tls/tls.key"
server_ca_file = "/run/secrets/io-client-tls/server-ca.crt"

[egress_gateway]
url = "https://filebelt-onlyoffice-egress.filebelt-egress.svc:8443/"
certificate_chain_file = "/run/secrets/egress-client-tls/tls.crt"
private_key_file = "/run/secrets/egress-client-tls/tls.key"
server_ca_file = "/run/secrets/egress-client-tls/server-ca.crt"
```

`browser_jwt_file` signs the exact `documentType`, `document`, and
`editorConfig` supplied to DocEditor. It is never accepted inbound.
`outbox_jwt_*` verifies Document Server callbacks and input downloads using
HS256, with an optional retiring verifier key only during the bounded overlap.
The mounted Secrets are therefore named `browser-jwt` and `outbox-jwt`, never a
shared callback/browser secret.

Configure the operator-supplied Document Server 9.4 `local.json` to use the
same browser signing secret and outbox verification secret, and to emit/accept
tokens in the documented locations:

```json
{
  "services": {"CoAuthoring": {"token": {
    "enable": {"browser": true, "request": {"inbox": true, "outbox": true}},
    "inbox": {"header": "Authorization", "inBody": false},
    "outbox": {"header": "Authorization", "inBody": true}
  }}}
}
```

The browser submits the one-use launch form to `launch_origin`; that isolated
top-level response loads `api.js` from the Document Server. The browser uses
`public_origin/onlyoffice/input/{session}/{participant}` and callbacks use
`public_origin/onlyoffice/callback/{session}/{participant}`. Both values are
UUIDs minted by Core during launch redemption; the outbox JWT must bind the
exact input URL, and its signed callback payload must match the received
callback fields.

## Local checks

```sh
cargo fmt --check --manifest-path Cargo.toml
cargo test --manifest-path Cargo.toml --locked --offline
pnpm --dir . test
pnpm --dir . typecheck
```

## Image and network source

The Dockerfile is source-first and not a publishable artifact until an exact,
digest-pinned image plan, provider source/distribution terms, notices, SBOM,
vulnerability evidence, supported-platform tests, and corresponding-source
publication are reviewed. Once those inputs are admitted, invoke it from the
repository root with `docker build -f adapters/onlyoffice/Dockerfile .` so the
linked Apache protocol source and generated protobuf source are in the build
context. See [SOURCE_OFFER.md](SOURCE_OFFER.md).
