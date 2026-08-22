<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt browser UI

The browser UI is an Apache-2.0 React workspace that consumes FileBelt's
generated OpenAPI contract. It presents authenticated drive and administration
workflows but is never an authorization boundary.

## Packages and contracts

- `@filebelt/web` is the SPA and OxiBelt-served web image.
- `@filebelt/design-system` owns shared themes, layout primitives, icons, and
  accessibility behavior.
- `@filebelt/admin` is the lazy-loaded tenant administration display surface;
  current mutation controls are unavailable until backed by a public API, and
  loading it never grants administrator authority.
- `@filebelt/markdown` and `@filebelt/mcp-settings` are reserved UI packages for
  their focused surfaces.
- `design-assets/` contains FileBelt-owned source and generated SVG assets with
  provenance in `design-assets/MANIFEST.md`.

The web client is generated from
[`protocol/http/v1/openapi.yaml`](../protocol/http/v1/openapi.yaml) and follows
the [Interfaces and Capabilities](../docs/InterfacesAndCapabilities.md)
contract. Regenerate it with:

```sh
python3 protocol/generate-openapi-client.py --repo-root .
```

Visibility, disabled controls, and route guards improve usability only. The API
must resolve the session to an internal principal and enforce the common
[Virtual ACL](../docs/NamespaceAndAuthorization.md) for every operation.

## Browser security

- Never place session, CSRF, share, capability, OIDC, signing, or payload
  secrets in `localStorage`, `sessionStorage`, IndexedDB, service workers,
  telemetry, logs, or URLs. `localStorage` currently holds appearance
  preferences only. IndexedDB may hold only expiring, non-secret resumable
  upload metadata and must clear it on logout or expiry.
- Render filenames, identity labels, API values, and other user content as text.
  Do not use direct HTML/SVG insertion or create feature-local Trusted Types
  policies. Any rich-content boundary requires a centralized reviewed sanitizer
  and policy.
- Treat origin checks, CSRF, cookie attributes, capability scope, CSP, referrer
  policy, and API authorization as server/edge controls. Client checks do not
  substitute for them.
- Externalize English strings, redact credentials from errors and diagnostics,
  and avoid URL state that can cross a referrer boundary.

Anonymous links are unavailable. `/public/share` is a reserved fail-closed UI
shell: it removes a fragment token from history immediately, but the production
HTTP client implements neither token exchange nor public download and reports
the feature as unavailable. The in-memory mock implementation is test/demo data,
not a public product contract. Do not expose this route to authenticated session
cookies or add group/link controls without the corresponding API, edge,
security, privacy, rate-limit, revocation, and audit contracts.

## Design and accessibility

Use the pinned Fluent UI React primitives with FileBelt-owned themes and Lucide
icons; do not copy Fluent product branding. FileBelt-specific concepts and brand
marks use reviewed original SVGs. Shared semantic tokens, stable command
locations, and explicit loading, error, denied, disabled, selected, and offline
states keep behavior consistent.

First-party surfaces target WCAG 2.2 AA. Preserve semantic HTML, visible focus,
logical tab order, keyboard and touch alternatives, screen-reader
announcements, forced colors, reduced motion, text scaling, bidirectional text,
and layouts down to 320 CSS pixels. Do not communicate selection or status with
color or icon fill alone, and do not hide required actions behind hover.

Security-sensitive views show their exact scope: ACL editors identify the
resource and inheritance boundary; session and credential views show expiry and
revocation; destructive multi-resource operations require explicit impact
confirmation. Administrative UI never implies content access that the
administrator lacks under Virtual ACL.

## Dependency and license admission

All UI packages are in the root Apache-2.0 pnpm workspace. A new dependency,
asset, font, copied example, generated runtime, or build plugin requires an
exact version, compatible license and notice review, lockfile evidence, and the
normal Node license and vulnerability checks. Apache UI packages must not
import adapter implementation code. Generated files retain their schema,
generator, command, and license provenance; do not hand-edit them.

Use FileBelt-owned assets or record upstream provenance and license in the
nearest manifest. SVGs must not contain scripts, event handlers, external
references, or unreviewed embedded raster content. The final `filebelt-web`
image license expression and notices must reflect the bundled runtime and
assets; see the [License Map](../docs/LicenseMap.md) and
[Supply Chain](../docs/SupplyChain.md).

## Verification

Run the root pnpm format check, lint, typecheck, tests, build,
dependency-license, and audit gates. Add regression coverage at the lowest
useful layer for state changes,
permission-dependent actions, keyboard and screen-reader semantics, browser
storage, Trusted Types, forced colors, and reduced motion. Browser behavior is
covered in Chromium and Firefox where the artifact exists, and the production
bundle is exercised through OxiBelt-compatible routing.

`pnpm --filter @filebelt/web test:browser` starts the ordinary Vite preview and
excludes `docker-integration.spec.mjs`. The Docker-only browser contract has an
explicit `pnpm --filter @filebelt/web test:browser:docker` entry point and
requires the prepared, running collaboration integration topology; the Docker
unit runner remains the normal owner of that lifecycle and cleanup.
