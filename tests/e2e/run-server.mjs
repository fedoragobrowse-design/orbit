import { readFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { root, compose, stopWorkspace, assertDeployment, ready, baseURL } from './lifecycle.mjs';
const lock = path.join(root, 'tests/e2e/.runtime.lock');
const handle = openSync(lock, 'wx', 0o600);
closeSync(handle);
let closing = false;
async function shutdown(code = 0) {
  if (closing) return;
  closing = true;
  try { stopWorkspace(); } catch (error) { console.error(error.message); code = 1; }
  try { unlinkSync(lock); } catch {}
  process.exit(code);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
try {
  assertDeployment();
  stopWorkspace();
  compose(['up', '-d', '--build', '--wait', 'postgres', 'greenmail', 'fixtures']);
  assertDeployment();
  // Literal DB name and verified project make an accidental personal/test reset impossible.
  compose(['exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'orbit_test', '-d', 'orbit_e2e', '-c', 'DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION orbit_test;']);
  compose(['exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'orbit_test', '-d', 'orbit_e2e'], { input: readFileSync(path.join(root, 'deploy/docker/test-runtime-role.sql'), 'utf8') });
  compose(['--profile', 'e2e-maintenance', 'run', '--rm', '--no-deps', 'e2e-reset']);
  await ready('http://127.0.0.1:18090/health');
  const reset = await fetch('http://127.0.0.1:18090/test/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reset: true, available: true, mode: 'normal' }) });
  if (!reset.ok) throw new Error('Protocol fixture reset failed');
  compose(['up', '-d', '--build', '--wait', 'server', 'web']);
  assertDeployment();
  await ready(`${baseURL}/ready`);
  console.log(`Orbit isolated browser deployment ready: ${baseURL}`);
  // A real long-lived process owns teardown; the test deployment is not a reused personal server.
  await new Promise(() => { setInterval(() => {}, 60000); });
} catch (error) {
  console.error(error);
  await shutdown(1);
}
