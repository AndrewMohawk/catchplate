// Configuration only: stock npm/pacote retain their normal HTTP implementations.
import { createHash } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';

export const REGISTRY = 'https://registry.npmjs.org/';
export const PUBLIC_NPM_DUMMY = 'serverware-npm-placeholder-v1';
export const VERSIONS = Object.freeze({ npm: '11.8.0', pacote: '21.0.4', 'npm-registry-fetch': '19.1.1' });
export const OPERATIONS = new Set(['view', 'manifest', 'publish', 'install', 'ci']);
export const isInstallation = operation => operation === 'install' || operation === 'ci';
const NAME = /^(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*)$/;
// Intentionally narrower than npm: examples select one ordinary release version.
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

export function requireValue(value) {
  if (!value) throw new Error('npm example configuration or operation refused');
}

function required(env, name, max = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= max
    && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}

export function configuration(env, operation = 'view') {
  requireValue(OPERATIONS.has(operation));
  requireValue(env.NODE_TLS_REJECT_UNAUTHORIZED === undefined || env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  const proxy = new URL(required(env, 'SERVERWARE_PROXY_URL'));
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN');
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const packageName = required(env, 'SERVERWARE_NPM_PACKAGE', 214);
  requireValue(NAME.test(packageName));
  const config = { operation, proxyUrl: proxy.origin, applicationId, token, packageName,
    caFile: required(env, 'SERVERWARE_CA_FILE'),
    proxyCaFile: env.SERVERWARE_PROXY_CA_FILE ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null };
  if (operation !== 'view') {
    config.version = required(env, 'SERVERWARE_NPM_VERSION', 128);
    requireValue(VERSION.test(config.version));
  }
  if (operation === 'publish') {
    config.tag = required(env, 'SERVERWARE_NPM_TAG', 64);
    requireValue(/^[a-z][a-z0-9._-]{0,63}$/.test(config.tag));
    config.tarball = required(env, 'SERVERWARE_NPM_TARBALL');
    config.tarballSha256 = required(env, 'SERVERWARE_NPM_TARBALL_SHA256', 64);
    requireValue(/^[0-9a-f]{64}$/.test(config.tarballSha256)
      && env.SERVERWARE_NPM_PUBLISH_CONFIRM === 'publish-publicly');
  }
  if (isInstallation(operation)) {
    config.project = required(env, 'SERVERWARE_NPM_PROJECT');
    config.output = required(env, 'SERVERWARE_NPM_OUTPUT');
    requireValue([config.project, config.output].every(value => isAbsolute(value)
      && resolve(value) === value && value !== '/') && config.project !== config.output
      && !config.output.startsWith(config.project + '/'));
  }
  return config;
}

export function npmConfiguration(config) {
  const authority = new URL(config.proxyUrl).host;
  return [
    'registry=' + REGISTRY,
    '//registry.npmjs.org/:_authToken=' + PUBLIC_NPM_DUMMY,
    'https-proxy=https://' + config.applicationId + ':${SERVERWARE_PROXY_TOKEN}@' + authority,
    'cache=${SERVERWARE_NPM_CACHE}', 'noproxy=', 'strict-ssl=true',
    'fetch-retries=0', 'fetch-timeout=10000', 'update-notifier=false',
    'progress=false', 'logs-max=0', isInstallation(config.operation) ? 'loglevel=error' : 'loglevel=silent', '',
  ].join('\n');
}

export function childEnvironment(config, paths) {
  // No ambient npm/proxy/TLS/Node options, provider credentials or user config.
  // HOME is neither reassigned nor forwarded. npm uses the OS account lookup;
  // explicit user/global config paths and cache control its configuration.
  return { LANG: 'C.UTF-8', PATH: '/usr/bin:/bin',
    NODE_EXTRA_CA_CERTS: paths.trust, SERVERWARE_CA_FILE: paths.trust,
    SERVERWARE_PROXY_URL: config.proxyUrl, SERVERWARE_APP_ID: config.applicationId,
    SERVERWARE_PROXY_TOKEN: config.token, SERVERWARE_NPM_PACKAGE: config.packageName,
    SERVERWARE_NPM_CACHE: paths.cache, SERVERWARE_NPM_WORK: paths.root,
    ...(config.version ? { SERVERWARE_NPM_VERSION: config.version } : {}),
    ...(isInstallation(config.operation) ? {
      SERVERWARE_NPM_PROJECT: config.project, SERVERWARE_NPM_OUTPUT: paths.project,
    } : {}),
    ...(config.operation === 'publish' ? {
      SERVERWARE_NPM_TAG: config.tag, SERVERWARE_NPM_TARBALL: paths.tarball,
      SERVERWARE_NPM_TARBALL_SHA256: config.tarballSha256,
      SERVERWARE_NPM_PUBLISH_CONFIRM: 'publish-publicly',
    } : {}) };
}

export function pacoteOptions(config, cache) {
  const proxy = new URL(config.proxyUrl);
  proxy.username = config.applicationId;
  proxy.password = config.token;
  return { registry: REGISTRY, proxy: proxy.href, strictSSL: true, noProxy: '',
    retry: { retries: 0 }, timeout: 10000, cache, tufCache: cache + '/tuf',
    '//registry.npmjs.org/:_authToken': PUBLIC_NPM_DUMMY };
}

export function reviewedTarball(config, bytes) {
  requireValue(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 8 * 1024 * 1024
    && createHash('sha256').update(bytes).digest('hex') === config.tarballSha256);
  return bytes;
}

export function reviewedManifest(config, manifest) {
  requireValue(manifest && typeof manifest === 'object' && !Array.isArray(manifest)
    && manifest.name === config.packageName && manifest.version === config.version
    && manifest.private !== true && !Object.hasOwn(manifest, 'publishConfig'));
}

export function npmArguments(config, paths) {
  const common = [paths.npmCli, '--userconfig', paths.npmrc, '--globalconfig', paths.globalrc];
  if (config.operation === 'view') return [...common, 'view', config.packageName, '--json'];
  if (isInstallation(config.operation)) return [...common, config.operation,
    '--ignore-scripts=true', '--fund=false', '--workspaces=false', '--json'];
  requireValue(config.operation === 'publish');
  return [...common, 'publish', paths.tarball, '--access=public', '--tag=' + config.tag,
    '--ignore-scripts=true', '--provenance=false', '--force=false', '--dry-run=false',
    '--workspaces=false', '--json'];
}

function registryDependencyMaps(entry) {
  for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
    if (!Object.hasOwn(entry, key)) continue;
    const selected = entry[key];
    requireValue(selected && typeof selected === 'object' && !Array.isArray(selected)
      && Object.keys(selected).length <= 512
      && Object.entries(selected).every(([name, spec]) => NAME.test(name) && typeof spec === 'string'
        && spec.length > 0 && spec.length <= 256 && /[0-9xX*]/.test(spec)
        && /^[0-9xXv*<>=~^|.\-+ \t]+$/.test(spec)));
  }
  if (Object.hasOwn(entry, 'bundleDependencies')) requireValue(Array.isArray(entry.bundleDependencies)
    && entry.bundleDependencies.length <= 512 && entry.bundleDependencies.every(name => typeof name === 'string' && NAME.test(name)));
}

function directlyDeclaredRegistryBundle(location, packages) {
  const separator = location.lastIndexOf('/node_modules/');
  if (separator < 0) return false;
  const parent = packages[location.slice(0, separator)];
  const name = location.slice(separator + '/node_modules/'.length);
  // This small example deliberately refuses inherited/hoisted bundle graphs.
  // An unrelated bundle declaration must not authorize missing fetch fields.
  return parent && parent.inBundle !== true && typeof parent.resolved === 'string'
    && Array.isArray(parent.bundleDependencies) && parent.bundleDependencies.includes(name);
}

// This example copies a reviewed registry-only project into a new output
// directory. npm never runs in, overwrites or removes the caller's project.
export function reviewedProject(config, manifestBytes, lockBytes = null) {
  requireValue(isInstallation(config.operation) && Buffer.isBuffer(manifestBytes)
    && manifestBytes.length > 0 && manifestBytes.length <= 65536);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  requireValue(manifest && !Array.isArray(manifest) && manifest.private === true
    && typeof manifest.name === 'string' && NAME.test(manifest.name)
    && typeof manifest.version === 'string' && VERSION.test(manifest.version)
    && Object.keys(manifest).every(key => ['name', 'version', 'private', 'description', 'license', 'dependencies'].includes(key)));
  const dependencies = manifest.dependencies;
  requireValue(dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies)
    && Object.keys(dependencies).length >= 1 && Object.keys(dependencies).length <= 64
    && Object.entries(dependencies).every(([name, version]) => NAME.test(name)
      && typeof version === 'string' && VERSION.test(version))
    && dependencies[config.packageName] === config.version);
  requireValue(config.operation !== 'ci' || Buffer.isBuffer(lockBytes));
  if (lockBytes !== null) {
    requireValue(Buffer.isBuffer(lockBytes) && lockBytes.length > 0 && lockBytes.length <= 4 * 1024 * 1024);
    const lock = JSON.parse(lockBytes.toString('utf8'));
    requireValue(lock && !Array.isArray(lock) && lock.lockfileVersion === 3
      && lock.name === manifest.name && lock.version === manifest.version
      && lock.packages && typeof lock.packages === 'object' && !Array.isArray(lock.packages)
      && Object.keys(lock.packages).length >= 2 && Object.keys(lock.packages).length <= 512
      && JSON.stringify(Object.entries(lock.packages['']?.dependencies || {}).sort()) === JSON.stringify(Object.entries(dependencies).sort()));
    for (const [location, entry] of Object.entries(lock.packages)) {
      requireValue(entry && typeof entry === 'object' && !Array.isArray(entry));
      registryDependencyMaps(entry);
      if (location === '') continue;
      requireValue(location.length <= 4096 && location.startsWith('node_modules/')
        && location.slice('node_modules/'.length).split('/node_modules/').every(name => NAME.test(name))
        && entry.link !== true && typeof entry.version === 'string' && VERSION.test(entry.version));
      if (entry.inBundle === true && !Object.hasOwn(entry, 'resolved') && !Object.hasOwn(entry, 'integrity')) {
        // These bytes come from the enclosing registry archive. Missing fetch
        // fields alone cannot invent a bundle: require this exact direct child
        // in its independently reviewed registry parent's bundle declaration.
        requireValue(directlyDeclaredRegistryBundle(location, lock.packages));
        continue;
      }
      requireValue(typeof entry.resolved === 'string' && entry.resolved.startsWith(REGISTRY)
        && typeof entry.integrity === 'string' && /^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity));
      const target = new URL(entry.resolved);
      requireValue(target.origin + '/' === REGISTRY && !target.username && !target.password && !target.search && !target.hash
        && target.href === entry.resolved && !/%|\\/.test(target.pathname));
    }
  }
  return { manifestBytes, lockBytes };
}

export function installationSummary(config, value, installedManifestBytes, lockBytes, manifestBytes) {
  requireValue(isInstallation(config.operation) && value && typeof value === 'object'
    && Number.isSafeInteger(value.added) && value.added >= 1
    && Number.isSafeInteger(value.audited) && value.audited >= 2
    && value.audit && typeof value.audit === 'object' && !Array.isArray(value.audit));
  const total = value.audit.dependencies?.total, vulnerabilities = value.audit.vulnerabilities;
  requireValue(Number.isSafeInteger(total) && total >= 1 && value.audited >= total && value.audited <= total + 1
    && vulnerabilities && typeof vulnerabilities === 'object'
    && ['info', 'low', 'moderate', 'high', 'critical', 'total'].every(key =>
      Number.isSafeInteger(vulnerabilities[key]) && vulnerabilities[key] >= 0)
    && vulnerabilities.total === ['info', 'low', 'moderate', 'high', 'critical'].reduce((sum, key) => sum + vulnerabilities[key], 0));
  requireValue(Buffer.isBuffer(installedManifestBytes) && installedManifestBytes.length > 0 && installedManifestBytes.length <= 65536
    && Buffer.isBuffer(lockBytes) && lockBytes.length > 0 && lockBytes.length <= 4 * 1024 * 1024);
  const installed = JSON.parse(installedManifestBytes.toString('utf8'));
  requireValue(installed?.name === config.packageName && installed.version === config.version);
  const lock = JSON.parse(lockBytes.toString('utf8'));
  requireValue(lock?.lockfileVersion === 3 && lock.packages?.['node_modules/' + config.packageName]?.version === config.version);
  // A generated install lock must also be a valid input to the documented ci.
  reviewedProject({...config, operation: 'ci'}, manifestBytes, lockBytes);
  return { ok: true, operation: config.operation, package: config.packageName, version: config.version,
    installed: true, added: value.added, audited: value.audited, defaultAuditReportedSuccess: true,
    vulnerabilities: vulnerabilities.total, lockSha256: createHash('sha256').update(lockBytes).digest('hex') };
}

export function metadataSummary(config, value) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value)
    && value.name === config.packageName && typeof value.version === 'string'
    && value.version.length <= 128 && VERSION.test(value.version)
    && (config.operation !== 'manifest' || value.version === config.version));
  // Only bounded selected metadata is printed; provider errors are never printed.
  return { ok: true, operation: config.operation, package: value.name, version: value.version,
    tarballFetched: false };
}

export function publishSummary(config, value, bytes) {
  reviewedTarball(config, bytes);
  requireValue(value && value.name === config.packageName && value.version === config.version
    && value.id === config.packageName + '@' + config.version && value.size === bytes.length
    && value.integrity === 'sha512-' + createHash('sha512').update(bytes).digest('base64')
    && value.shasum === createHash('sha1').update(bytes).digest('hex'));
  return { ok: true, operation: 'publish', package: config.packageName, version: config.version,
    tag: config.tag, tarballSha256: config.tarballSha256, npmReportedSuccess: true };
}

export function failure(operation) {
  return { ok: false, operation: OPERATIONS.has(operation) ? operation : null,
    error: 'npm example failed; check configuration, permissions and Serverware audit logs.',
    ...(operation === 'publish' ? {
      warning: 'Publication may be unconfirmed. Inspect registry metadata and audit evidence; do not automatically retry.',
    } : {}) };
}
