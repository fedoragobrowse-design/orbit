import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const file = path.join(root, 'deploy/examples/compose.test.yaml');
export const baseURL = 'http://127.0.0.1:18080';
const environment = { ...process.env, COMPOSE_PROJECT_NAME: 'orbit-test' };
delete environment.COMPOSE_FILE;
delete environment.COMPOSE_PROFILES;
delete environment.COMPOSE_ENV_FILES;
export function docker(args, options = {}) {
  return execFileSync('docker', args, { cwd: root, env: environment, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], ...options });
}
export function compose(args, options = {}) {
  return docker(['compose', '--env-file', path.join(root, 'deploy/examples/test.env'), '-p', 'orbit-test', '-f', file, ...args], options);
}
function invariant(ok, message) { if (!ok) throw new Error(`Refusing E2E lifecycle: ${message}`); }
export function assertDeployment() {
  invariant(!process.env.ORBIT_E2E_BASE_URL || process.env.ORBIT_E2E_BASE_URL === baseURL, 'base URL must be isolated loopback18080');
  const config = JSON.parse(compose(['config', '--format', 'json']));
  invariant(config.name === 'orbit-test', 'wrong Compose project');
  invariant(config.services.server.environment.DATABASE_URL === 'postgres://orbit_runtime:orbit_runtime_fixture@postgres:5432/orbit_e2e', 'runtime database must be restricted orbit_e2e');
  invariant(config.services.server.environment.ORBIT_MIGRATION_DATABASE_URL === 'postgres://orbit_test:orbit_test@postgres:5432/orbit_e2e', 'migration database must be orbit_e2e');
  invariant(config.services.server.environment.ORBIT_PUBLIC_ORIGIN === baseURL, 'wrong owner origin');
  invariant(config.services.postgres.environment.POSTGRES_DB === 'orbit_test', 'Rust test DB changed');
  invariant(config.volumes['test-db'].name === 'orbit-test-db', 'wrong PostgreSQL volume');
  invariant(config.networks['orbit-test'].name === 'orbit-test', 'wrong private network');
  for (const [service, port] of [['web', '18080'], ['postgres', '55432']]) {
    invariant(config.services[service].ports.some(p => String(p.published) === port && p.host_ip === '127.0.0.1'), `${service} must publish on loopback${port}`);
  }
  for (const service of ['postgres', 'server', 'web', 'node', 'fixtures', 'greenmail']) {
    const ids = compose(['ps', '-a', '-q', service]).trim().split(/\s+/).filter(Boolean);
    for (const id of ids) {
      const container = JSON.parse(docker(['inspect', id]))[0];
      const labels = container.Config.Labels;
      invariant(labels['com.docker.compose.project'] === 'orbit-test' && labels['com.docker.compose.service'] === service, `wrong ${service} container identity`);
      invariant(labels['com.docker.compose.project.config_files']?.split(',').every(p => path.resolve(p) === file), `${service} uses another deployment`);
      if (service === 'postgres') invariant(container.Mounts.some(m => m.Name === 'orbit-test-db' && m.Destination === '/var/lib/postgresql/data'), 'database container has foreign storage');
    }
  }
  return config;
}
export function stopWorkspace() {
  assertDeployment();
  compose(['--profile', 'node', 'stop', 'node', 'web', 'server']);
}
export async function ready(url, timeout = 180000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { if ((await fetch(url, { signal: AbortSignal.timeout(2000) })).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`Readiness deadline exceeded: ${url}`);
}
