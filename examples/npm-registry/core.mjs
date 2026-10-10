// Configuration only: stock npm/pacote retain their normal HTTP implementations.
import { createHash } from 'node:crypto';

export const REGISTRY = 'https://registry.npmjs.org/';
export const PUBLIC_NPM_DUMMY = 'serverware-npm-placeholder-v1';
export const VERSIONS = Object.freeze({ npm: '11.8.0', pacote: '21.0.4', 'npm-registry-fetch': '19.1.1' });
export const OPERATIONS = new Set(['view', 'manifest', 'publish']);
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
    'progress=false', 'logs-max=0', 'loglevel=silent', '',
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
  requireValue(config.operation === 'publish');
  return [...common, 'publish', paths.tarball, '--access=public', '--tag=' + config.tag,
    '--ignore-scripts=true', '--provenance=false', '--force=false', '--dry-run=false',
    '--workspaces=false', '--json'];
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
