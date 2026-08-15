// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vitest/config";
import { ResolveFluentIconsContext } from "../vitest-fluent-icons-resolver.ts";

export default defineConfig({
  plugins: [ResolveFluentIconsContext()],
  test: {
    server: {
      deps: { inline: [/@fluentui/] },
    },
  },
});
