import { assertDeployment, compose } from './lifecycle.mjs';
export default async function globalSetup() {
  assertDeployment();
  const token = compose(['exec', '-T', 'server', 'orbit-server', 'bootstrap-token']).trim();
  if (!token || token.includes('\n')) throw new Error('Fresh CLI setup token was not a single nonempty value');
  // Only Playwright child processes inherit it. It is never persisted in reports or URLs.
  process.env.ORBIT_E2E_SETUP_TOKEN = token;
}
