import { defineConfig } from '@playwright/test';
// The harness owns lifecycle: it resets only the orbit_e2e schema and serves
// server+web. When CI is unset an already-running run-server.mjs (which holds
// tests/e2e/.runtime.lock) is reused instead of racing a second reset against
// the same database. CI always starts a fresh, clean deployment.
export default defineConfig({testDir:'../../tests/e2e',fullyParallel:false,workers:1,timeout:120_000,globalSetup:'../../tests/e2e/global-setup.mjs',use:{baseURL:'http://127.0.0.1:18080',trace:'retain-on-failure'},webServer:{command:'node ../../tests/e2e/run-server.mjs',url:'http://127.0.0.1:18080/ready',timeout:600_000,reuseExistingServer:!process.env.CI}});
