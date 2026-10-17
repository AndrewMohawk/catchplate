import { readFileSync, writeFileSync, statSync, realpathSync, existsSync, mkdtempSync, mkdirSync, rmSync,
  openSync, closeSync, fstatSync, readSync, constants } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configuration, childEnvironment, npmConfiguration, reviewedTarball,
  reviewedProject, isInstallation, requireValue, failure, VERSIONS, OPERATIONS } from './core.mjs';
import { sanitizeDiagnostic, caughtDiagnostic, processDiagnostic, workerDiagnostic } from './diagnostics.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const MAX_CONFIG_BYTES = 64 * 1024;

function readConfigurationFile(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    requireValue(before.isFile() && before.size > 0 && before.size <= MAX_CONFIG_BYTES);
    const bytes = Buffer.alloc(MAX_CONFIG_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd);
    requireValue(length === before.size && length <= MAX_CONFIG_BYTES
      && ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(key => before[key] === after[key]));
    return JSON.parse(bytes.subarray(0, length).toString('utf8'));
  } finally { closeSync(fd); }
}

export function loadClientConfig(path, env, operation = 'view', now = Date.now()) {
  try {
    requireValue(typeof path === 'string' && path.length > 0 && path.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(path));
    const filename = resolve(path), value = readConfigurationFile(filename);
    requireValue(value !== null && typeof value === 'object' && !Array.isArray(value)
      && UUID.test(value.application_id) && UUID.test(value.access_rule_id)
      && value.proxy_authentication === 'basic_and_bearer_v1'
      && value.proxy_username === value.application_id
      && Number.isSafeInteger(now) && now >= 0
      && Number.isSafeInteger(value.token_expires_at_epoch_ms) && value.token_expires_at_epoch_ms > now
      && value.upstream_url === 'https://registry.npmjs.org/');
    const profiles = {npm_metadata_read_v1: ['GET'], npm_publish_v1: ['PUT'], npm_install_v1: ['GET', 'POST']};
    requireValue(Object.hasOwn(profiles, value.operation_bundle));
    const methods = profiles[value.operation_bundle];
    requireValue(Array.isArray(value.methods) && value.methods.length === methods.length
      && new Set(value.methods).size === methods.length && methods.every(method => value.methods.includes(method)));
    const publishing = value.operation_bundle === 'npm_publish_v1';
    requireValue(operation !== 'publish' || publishing);
    requireValue(!isInstallation(operation) || value.operation_bundle === 'npm_install_v1');
    requireValue(value.client_recipe === undefined || (value.client_recipe !== null
      && typeof value.client_recipe === 'object' && !Array.isArray(value.client_recipe)));
    const packages = publishing ? [value.package] : value.packages;
    requireValue(Array.isArray(packages) && packages.length > 0 && packages.length <= 512
      && new Set(packages).size === packages.length
      && packages.every(name => typeof name === 'string' && name.length <= 214
        && /^(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*)$/.test(name)));
    const packageName = publishing ? value.package : value.operation_bundle === 'npm_metadata_read_v1'
      ? value.client_recipe?.package : env.CATCHPLATE_NPM_PACKAGE || (packages.length === 1 ? packages[0] : undefined);
    requireValue(packages.includes(packageName));
    const caPath = selected => {
      requireValue(typeof selected === 'string' && selected.length > 0 && selected.length <= 4096
        && !/[\u0000-\u001f\u007f]/.test(selected));
      return resolve(dirname(filename), selected);
    };
    // Only connection and allowed package/tag fields are imported. Operation,
    // version, project/output paths, tarball and publication confirmation stay local.
    return configuration({...env,
      CATCHPLATE_PROXY_URL: value.proxy_url, CATCHPLATE_APP_ID: value.application_id,
      CATCHPLATE_PROXY_TOKEN: value.proxy_password, CATCHPLATE_CA_FILE: caPath(value.ca_file),
      CATCHPLATE_PROXY_CA_FILE: value.proxy_ca_file == null ? undefined : caPath(value.proxy_ca_file),
      CATCHPLATE_NPM_PACKAGE: packageName,
      ...(publishing ? {CATCHPLATE_NPM_TAG: value.tag} : {}),
    }, operation);
  } catch { throw new Error('npm example configuration or operation refused'); }
}

export function parseArguments(args) {
  requireValue(Array.isArray(args) && args.every(value => typeof value === 'string'));
  if (args.length === 1 && args[0] === '--help') return {help: true, operation: 'view', configPath: null};
  let operation = 'view', configPath = null, selected = false;
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--config') {
      requireValue(configPath === null && index + 1 < args.length
        && args[index + 1].length > 0 && !args[index + 1].startsWith('--'));
      configPath = args[++index];
    } else {
      requireValue(!selected && OPERATIONS.has(args[index]));
      operation = args[index]; selected = true;
    }
  }
  return {help: false, operation, configPath};
}

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

// Ordinary CLI jobs own a separate process group. A contained metadata-only MCP
// call instead stays inside its supervisor's group; that supervisor kills the
// whole group on cancellation AND after completion, then removes its scratch.
export function containedMetadataWorker(env, operation) {
  const value = env.CATCHPLATE_MCP_CONTAINED_WORKER;
  requireValue(value === undefined || (value === '1' && operation === 'view'));
  return value === '1';
}

export function invokeWorker(command, args, options, launch = spawn, timeoutMs = 15000, observe = () => {}, contained = false) {
  requireValue(Number.isInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 65000);
  requireValue(typeof contained === 'boolean');
  return new Promise((accept, reject) => {
    const child = launch(command, args, { ...options, detached: !contained, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', refused = false, processError;
    const stop = code => {
      refused = true;
      processError = { code };
      try { if (contained) child.kill('SIGKILL'); else process.kill(-child.pid, 'SIGKILL'); }
      catch { try { child.kill('SIGKILL'); } catch { /* The exit/error handler still refuses. */ } }
    };
    const timer = setTimeout(() => stop('ETIMEDOUT'), timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; if (Buffer.byteLength(stdout) > 16384) stop('ENOBUFS'); });
    child.stderr.on('data', chunk => { stderr += chunk; if (Buffer.byteLength(stderr) > 16384) stop('ENOBUFS'); });
    child.once('error', error => {
      processError = error;
      observe(processDiagnostic('worker', { error, status: null, signal: null }));
      clearTimeout(timer); reject(new Error('npm worker unavailable'));
    });
    child.once('close', (status, signal) => {
      clearTimeout(timer);
      observe(processDiagnostic('worker', { status, signal, error: processError }));
      if (refused) reject(new Error('npm worker bounded operation refused'));
      else accept({ status, signal, stdout, stderr });
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('node client.mjs [--config PATH] [view|manifest|publish|install|ci]\nDefault: read-only view. Use a downloaded private config or environment settings. Installation needs a reviewed project and a new output directory; publication needs explicit confirmation. See README.md.');
    return;
  }
  let operation = 'view';
  let taskRoot, installationDirectory;
  let diagnostic = sanitizeDiagnostic({ launcherStage: 'configuration' });
  const observe = update => { diagnostic = sanitizeDiagnostic({ ...diagnostic, ...update }); };
  try {
    const parsed = parseArguments(args); operation = parsed.operation;
    const contained = containedMetadataWorker(process.env, operation);
    requireValue(process.version === 'v25.5.0' && process.platform !== 'win32');
    const config = parsed.configPath ? loadClientConfig(parsed.configPath, process.env, operation)
      : configuration(process.env, operation);
    observe({ launcherStage: 'versions' });
    verifyVersions();
    observe({ launcherStage: 'trust' });
    const trust = (config.proxyCaFile ? trustedPem(boundedFile(config.proxyCaFile, 262144)) : '')
      + trustedPem(boundedFile(config.caFile, 262144));
    observe({ launcherStage: 'publication_input' });
    const tarball = operation === 'publish'
      ? reviewedTarball(config, boundedFile(resolve(config.tarball), 8 * 1024 * 1024)) : null;
    let project;
    if (isInstallation(operation)) {
      observe({ launcherStage: 'installation_input' });
      project = createInstallationProject(config);
      installationDirectory = config.output;
    }
    observe({ launcherStage: 'runtime_setup' });
    taskRoot = mkdtempSync(join(tmpdir(), 'catchplate-npm-example-'));
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
    observe({ launcherStage: 'worker_process', processRole: 'worker' });
    const result = await invokeWorker(process.execPath, [join(directory, 'worker.mjs'), operation], {
      cwd: taskRoot, env: childEnvironment(config, paths),
    }, undefined, isInstallation(operation) ? 65000 : 15000, observe, contained);
    if (result.status !== 0 || result.signal !== null || result.stderr !== '') {
      const worker = workerDiagnostic(result.stderr);
      if (worker) observe({ ...worker, launcherStage: 'worker_process' });
    }
    requireValue(!result.error && result.signal === null && result.status === 0 && result.stderr === '');
    observe({ launcherStage: 'worker_summary' });
    const summary = JSON.parse(result.stdout);
    requireValue(summary.ok === true && summary.operation === operation && summary.package === config.packageName);
    if (isInstallation(operation)) {
      observe({ launcherStage: 'installation_summary' });
      requireValue(summary.installed === true && summary.defaultAuditReportedSuccess === true);
      summary.installationDirectory = installationDirectory;
      if (operation === 'ci') requireValue(readFileSync(join(installationDirectory, 'package-lock.json')).equals(project.lockBytes));
    }
    console.log(JSON.stringify(summary));
  } catch (error) {
    console.error(JSON.stringify({ ...failure(operation), ...(installationDirectory ? { installationDirectory,
      warning: 'Partial installation retained. Inspect it and audit logs; choose a new output directory for a deliberate retry.' } : {}),
      diagnostic: caughtDiagnostic(diagnostic, error) }));
    process.exitCode = 1;
  } finally {
    // Only the exact fresh task directory is removed, never source/CA/tarball inputs.
    if (taskRoot) {
      try { rmSync(taskRoot, { recursive: true, force: false }); }
      catch (error) {
        console.error(JSON.stringify({ ...failure(operation),
          diagnostic: caughtDiagnostic({ launcherStage: 'cleanup' }, error) }));
        process.exitCode = 1;
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
