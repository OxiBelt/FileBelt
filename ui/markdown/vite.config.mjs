// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vite'
import { URL, fileURLToPath } from 'node:url'

export default defineConfig({
  base: '/markdown-preview/',
  build: {
    emptyOutDir: false,
    outDir: fileURLToPath(new URL('dist/preview', import.meta.url)),
  },
  root: fileURLToPath(new URL('preview', import.meta.url)),
})
