// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from "@playwright/test";
import process from "node:process";

const Diagnostics = process.env.FILEBELT_DOCKER_DIAGNOSTICS_DIR ?? "artifacts/docker/collaboration";

export default defineConfig({
  expect: { timeout: 15_000 },
  fullyParallel: false,
  outputDir: Diagnostics,
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  reporter: [["line"]],
  testDir: "browser",
  testMatch: "docker-integration.spec.mjs",
  tsconfig: "./playwright.tsconfig.json",
  timeout: 120_000,
  // Both projects exercise the same intentionally shared room and revocation
  // state. Serialize them so one browser cannot freeze another browser's case.
  workers: 1,
  use: {
    baseURL: "https://filebelt.localhost:8443",
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    // Playwright traces can retain ephemeral session cookies. Keep only
    // screenshots; the runner destroys the synthetic tenant state before a
    // workflow may retain diagnostics.
    trace: "off",
  },
});
