// SPDX-License-Identifier: Apache-2.0

import { dirname } from "node:path";

// Vite 8 SSR does not resolve Fluent Icons' exact `./contexts/index` import.
// Remove this when `@fluentui/react-icons` ships that import with its `.js` suffix.
export function ResolveFluentIconsContext() {
  return {
    apply: "serve" as const,
    name: "filebelt-resolve-fluent-icons-context",
    resolveId: ResolveFluentIconsContextId,
  };
}

export function ResolveFluentIconsContextId(Source: string, Importer: string | undefined): string | null {
  if (
    Source !== "./contexts/index" ||
    Importer === undefined ||
    !Importer.endsWith("/@fluentui/react-icons/lib/providers.js")
  ) {
    return null;
  }
  return `${dirname(Importer)}/contexts/index.js`;
}
