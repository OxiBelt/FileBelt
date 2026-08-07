<!-- SPDX-License-Identifier: Apache-2.0 -->

# Browser UI automated-agent overlay

This file applies only to automated agents. Follow the
[root agent guidance](../AGENTS.md), [contributor workflow](../CONTRIBUTING.md),
[living specifications](../docs/README.md), and
[interfaces and capabilities contract](../docs/InterfacesAndCapabilities.md).

Enter Plan Mode before changing authentication or secret handling, public
routes, browser persistence, untrusted-content rendering, CSP or Trusted Types,
accessibility interaction contracts, or generated API consumption.
Stop and ask the maintainer whenever the security boundary, compatibility
behavior, or supported interaction is unresolved.

This tree is Apache-2.0.

- Consume the generated OpenAPI client. UI visibility, disabled controls, and
  route guards are usability features, never authorization controls.
- Do not store session, CSRF, share, capability, OIDC, signing, or payload
  secrets in local storage, session storage, IndexedDB, service workers, logs,
  telemetry, or URLs. IndexedDB may hold only expiring non-secret resumable
  upload metadata and must clear it on logout/expiry.
- Keep the anonymous-share route isolated: fragment token exchange by `POST`,
  immediate history clearing, no referrer, restrictive CSP, and no
  authenticated session cookie on its path.
- Use `@fluentui/react-components` with FileBelt-owned themes and Lucide icons;
  do not reproduce Fluent branding. Preserve keyboard, touch, forced-color,
  reduced-motion, bidi, 320 px, and WCAG 2.2 AA behavior.
- Externalize English strings and render user content as text unless the living
  interfaces and capabilities contract explicitly defines another reviewed
  rendering boundary.
- Add behavior and accessibility regression coverage at the component or
  supported-browser layer nearest the change.
