import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "**/*.e2e.ts",
  use: { baseURL: "http://127.0.0.1:4173", trace: "retain-on-failure" },
  webServer: { command: "bun run --cwd apps/web dev --host 127.0.0.1", url: "http://127.0.0.1:4173", reuseExistingServer: true },
});
