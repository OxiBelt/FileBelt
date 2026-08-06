<!-- SPDX-License-Identifier: Apache-2.0 -->

# Browser UI guidance

This tree is Apache-2.0 and inherits the root dependency and security policy.

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
- Externalize English strings and render user content as text unless a later
  accepted rendering boundary says otherwise.
- Add Chromium and Firefox behavior/accessibility regression coverage at the
  component or browser layer nearest the change. Do not add WebKit CI in Phase
  2.
