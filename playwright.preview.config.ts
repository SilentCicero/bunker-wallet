import {defineConfig} from '@playwright/test';
export default defineConfig({
 testDir:'tests/e2e',testMatch:'v3-preview-host.e2e.ts',use:{baseURL:'https://bunker-wallet-pq-sepolia-test.pages.dev/',serviceWorkers:'block',trace:'off'},
 webServer:{command:'VITE_EXPERIMENTAL_PQ=1 bun run --cwd apps/web build && bun run --cwd apps/web preview --host 127.0.0.1 --port 4180',url:'http://127.0.0.1:4180/',reuseExistingServer:false,timeout:60000},
});
