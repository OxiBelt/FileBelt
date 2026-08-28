// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitest/config'
import { URL, fileURLToPath } from 'node:url'

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  test: { environment: 'node', include: ['source/**/*.test.ts', 'source/**/*.test.tsx'] },
})
