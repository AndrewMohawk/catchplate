import { readFileSync, writeFileSync, statSync, realpathSync, existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configuration, childEnvironment, npmConfiguration, reviewedTarball,
  reviewedProject, isInstallation, requireValue, failure, VERSIONS } from './core.mjs';

const directory = dirname(fileURLToPath(import.meta.url));

export function trustedPem(bytes) {
  requireValue(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 262144);
  const text = bytes.toString('ascii');
  const certificates = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  requireValue(certificates?.length > 0 && certificates.length <= 32);
  requireValue(text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() === '');
  for (const certificate of certificates) new X509Certificate(certificate);
  return certificates.join('\n') + '\n';
}

function boundedFile(path, limit) {
  const stat = statSync(path);
  requireValue(stat.isFile() && stat.size > 0 && stat.size <= limit);
  const bytes = readFileSync(path);
  requireValue(bytes.length === stat.size);
  return bytes;
}

export function createInstallationProject(config) {
  requireValue(isInstallation(config.operation)
    && realpathSync(config.project) === config.project && statSync(config.project).isDirectory()
    && realpathSync(dirname(config.output)) === dirname(config.output));
  const lockPath = join(config.project, 'package-lock.json');
  const project = reviewedProject(config, boundedFile(join(config.project, 'package.json'), 65536),
    existsSync(lockPath) ? boundedFile(lockPath, 4 * 1024 * 1024) : null);
  // Exclusive mkdir: never reuse a project or allow npm ci to remove the
  // caller's node_modules. Only these two reviewed inputs are copied.
  mkdirSync(config.output, { mode: 0o700 });
  writeFileSync(join(config.output, 'package.json'), project.manifestBytes, { flag: 'wx', mode: 0o600 });
  if (project.lockBytes) writeFileSync(join(config.output, 'package-lock.json'), project.lockBytes, { flag: 'wx', mode: 0o600 });
  return project;
}

export function verifyVersions(readFile = readFileSync) {
  for (const [name, version] of Object.entries(VERSIONS)) {
    const value = JSON.parse(readFile(join(directory, 'node_modules', name, 'package.json'), 'utf8'));
    requireValue(value.name === name && value.version === version);
  }
  // npm's own bundled libraries must match the independently installed API too.
  for (const name of ['pacote', 'npm-registry-fetch']) {
    const value = JSON.parse(readFile(join(directory, 'node_modules/npm/node_modules', name, 'package.json'), 'utf8'));
    requireValue(value.name === name && value.version === VERSIONS[name]);
  }
}

// A separate POSIX process group lets the deadline also stop a nested npm CLI.
// Killing only the worker could otherwise leave a publish child running.
export function invokeWorker(command, args, options, launch = spawn, timeoutMs = 15000) {
  requireValue(Number.isInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 65000);
  return new Promise((accept, reject) => {
    const child = launch(command, args, { ...options, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', refused = false;
    const stop = () => {
      refused = true;
      try { process.kill(-child.pid, 'SIGKILL'); }
      catch { try { child.kill('SIGKILL'); } catch { /* The exit/error handler still refuses. */ } }
    };
    const timer = setTimeout(stop, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; if (Buffer.byteLength(stdout) > 16384) stop(); });
    child.stderr.on('data', chunk => { stderr += chunk; if (Buffer.byteLength(stderr) > 16384) stop(); });
    child.once('error', () => { clearTimeout(timer); reject(new Error('npm worker unavailable')); });
    child.once('close', (status, signal) => {
      clearTimeout(timer);
      if (refused) reject(new Error('npm worker bounded operation refused'));
      else accept({ status, signal, stdout, stderr });
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('node client.mjs [view|manifest|publish|install|ci]\nDefault: read-only view. Installation needs a reviewed project and a new output directory; publication needs explicit confirmation. See README.md.');
    return;
  }
  const operation = args[0] ?? 'view';
  let taskRoot, installationDirectory;
  try {
    requireValue(args.length <= 1 && process.version === 'v25.5.0' && process.platform !== 'win32');
    const config = configuration(process.env, operation);
    verifyVersions();
    const trust = (config.proxyCaFile ? trustedPem(boundedFile(config.proxyCaFile, 262144)) : '')
      + trustedPem(boundedFile(config.caFile, 262144));
    const tarball = operation === 'publish'
      ? reviewedTarball(config, boundedFile(resolve(config.tarball), 8 * 1024 * 1024)) : null;
    let project;
    if (isInstallation(operation)) {
      project = createInstallationProject(config);
      installationDirectory = config.output;
    }
    taskRoot = mkdtempSync(join(tmpdir(), 'serverware-npm-example-'));
    requireValue((statSync(taskRoot).mode & 0o777) === 0o700);
    const paths = { root: taskRoot, cache: join(taskRoot, 'cache'),
      trust: join(taskRoot, 'trust.pem'), tarball: join(taskRoot, 'reviewed-package.tgz'),
      ...(installationDirectory ? { project: installationDirectory } : {}) };
    mkdirSync(paths.cache, { mode: 0o700 });
    writeFileSync(join(taskRoot, 'package.json'), '{"private":true}\n', { flag: 'wx', mode: 0o600 });
    writeFileSync(paths.trust, trust, { flag: 'wx', mode: 0o600 });
    writeFileSync(join(taskRoot, 'user.npmrc'), npmConfiguration(config), { flag: 'wx', mode: 0o600 });
    writeFileSync(join(taskRoot, 'global.npmrc'), '', { flag: 'wx', mode: 0o600 });
    if (tarball) writeFileSync(paths.tarball, tarball, { flag: 'wx', mode: 0o400 });
    // Extra roots must exist in the environment BEFORE this Node process starts.
    const result = await invokeWorker(process.execPath, [join(directory, 'worker.mjs'), operation], {
      cwd: taskRoot, env: childEnvironment(config, paths),
    }, undefined, isInstallation(operation) ? 65000 : 15000);
    requireValue(!result.error && result.signal === null && result.status === 0 && result.stderr === '');
    const summary = JSON.parse(result.stdout);
    requireValue(summary.ok === true && summary.operation === operation && summary.package === config.packageName);
    if (isInstallation(operation)) {
      requireValue(summary.installed === true && summary.defaultAuditReportedSuccess === true);
      summary.installationDirectory = installationDirectory;
      if (operation === 'ci') requireValue(readFileSync(join(installationDirectory, 'package-lock.json')).equals(project.lockBytes));
    }
    console.log(JSON.stringify(summary));
  } catch {
    console.error(JSON.stringify({ ...failure(operation), ...(installationDirectory ? { installationDirectory,
      warning: 'Partial installation retained. Inspect it and audit logs; choose a new output directory for a deliberate retry.' } : {}) }));
    process.exitCode = 1;
  } finally {
    // Only the exact fresh task directory is removed, never source/CA/tarball inputs.
    if (taskRoot) {
      try { rmSync(taskRoot, { recursive: true, force: false }); }
      catch { console.error(JSON.stringify(failure(operation))); process.exitCode = 1; }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
