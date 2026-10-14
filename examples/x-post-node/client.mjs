// Official XDK owns serialization/auth selection; documented Undici hooks own transport.
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PUBLIC_X_DUMMY = 'serverware-x-post-placeholder-v1';
export const X_ORIGIN = 'https://api.x.com';
export const REQUEST_TIMEOUT_MS = 30_000;
export const PROCESS_TIMEOUT_MS = 35_000;
const MAX_CONFIG_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

function requireValue(condition) {
  if (!condition) throw new Error('X posting configuration or response refused');
}

function required(env, name, maximum = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}

export function postText(value) {
  requireValue(typeof value === 'string' && value.isWellFormed() && !value.includes('\0')
    && Buffer.byteLength(value, 'utf8') >= 1 && Buffer.byteLength(value, 'utf8') <= 16384
    && Buffer.byteLength(JSON.stringify({ text: value }), 'utf8') <= 32768);
  return value; // No trimming, normalization, code-point limit or body rewrite.
}

export function configuration(env) {
  requireValue(env.SERVERWARE_X_POST_CONFIRM === 'post-once');
  requireValue(env.NODE_TLS_REJECT_UNAUTHORIZED === undefined || env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  for (const name of ['NODE_OPTIONS', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'SSLKEYLOGFILE']) {
    requireValue(env[name] === undefined || env[name] === '');
  }
  const proxyUrl = required(env, 'SERVERWARE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN');
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const caFile = required(env, 'SERVERWARE_CA_FILE');
  const proxyCaFile = env.SERVERWARE_PROXY_CA_FILE ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null;
  requireValue(isAbsolute(caFile) && (proxyCaFile === null || isAbsolute(proxyCaFile)));
  return { proxyUrl, applicationId, token, caFile, proxyCaFile,
    text: postText(env.SERVERWARE_X_POST_TEXT) };
}

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

export function loadClientConfig(path, env, now = Date.now()) {
  try {
    const filename = resolve(required({ path }, 'path'));
    const value = readConfigurationFile(filename);
    requireValue(value !== null && typeof value === 'object' && !Array.isArray(value));
    requireValue(typeof value.access_rule_id === 'string' && UUID.test(value.access_rule_id)
      && value.proxy_authentication === 'basic_and_bearer_v1'
      && value.proxy_username === value.application_id
      && Number.isSafeInteger(now) && now >= 0
      && Number.isSafeInteger(value.token_expires_at_epoch_ms) && value.token_expires_at_epoch_ms > now);
    requireValue(value.operation_bundle === 'x_text_post_v1' && value.upstream_url === X_ORIGIN + '/2/tweets'
      && Array.isArray(value.methods) && value.methods.length === 1 && value.methods[0] === 'POST'
      && value.credential_input === 'replace_exact' && value.response_mode === 'x_post_json_v1');
    const caPath = value => resolve(dirname(filename), required({ path: value }, 'path'));
    // Only connection fields are imported. Post text and post-once confirmation
    // MUST come from the caller's environment, never this file or its recipe.
    return configuration({ ...env,
      SERVERWARE_PROXY_URL: value.proxy_url,
      SERVERWARE_APP_ID: value.application_id,
      SERVERWARE_PROXY_TOKEN: value.proxy_password,
      SERVERWARE_CA_FILE: caPath(value.ca_file),
      SERVERWARE_PROXY_CA_FILE: value.proxy_ca_file === undefined || value.proxy_ca_file === null
        ? undefined : caPath(value.proxy_ca_file),
    });
  } catch { throw new Error('X posting configuration or response refused'); }
}

export function parseArguments(args) {
  requireValue(Array.isArray(args) && args.every(value => typeof value === 'string'));
  if (args.length === 0) return { help: false, configPath: null };
  if (args.length === 1 && args[0] === '--help') return { help: true, configPath: null };
  requireValue(args.length === 2 && args[0] === '--config'
    && args[1].length > 0 && !args[1].startsWith('--'));
  return { help: false, configPath: required({ path: args[1] }, 'path') };
}

function certificate(path, readFile) {
  const value = readFile(path);
  requireValue(Buffer.isBuffer(value) && value.length > 0 && value.length <= 256 * 1024
    && value.includes(Buffer.from('-----BEGIN CERTIFICATE-----'))
    && !value.includes(Buffer.from('PRIVATE KEY')));
  return value;
}

export function proxyOptions(config, readFile = readFileSync) {
  return { uri: config.proxyUrl,
    token: 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'),
    proxyTls: { rejectUnauthorized: true,
      ...(config.proxyCaFile ? { ca: certificate(config.proxyCaFile, readFile) } : {}) },
    requestTls: { ca: certificate(config.caFile, readFile), rejectUnauthorized: true },
    connections: 1 };
}

// Extra example restriction, not stock SDK behavior. It never rewrites a request
// or response. Handler methods retain their original receiver and arguments.
export function onePostInterceptor(observation) {
  let attempted = false;
  return dispatch => (options, handler) => {
    requireValue(!attempted);
    attempted = true;
    requireValue(new URL(String(options.origin)).href === X_ORIGIN + '/'
      && options.method === 'POST' && options.path === '/2/tweets');
    return dispatch(options, new Proxy(handler, { get(target, key) {
      const value = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args) => {
        if (key === 'onResponseStart' && Number.isInteger(args[1]) && args[1] >= 200) {
          observation.httpStatus = args[1];
        }
        return Reflect.apply(value, target, args);
      };
    } }));
  };
}

export function installTransport(config, observation, {
  ProxyAgent, getGlobalDispatcher, setGlobalDispatcher, readFile = readFileSync,
}) {
  const proxy = new ProxyAgent(proxyOptions(config, readFile));
  const previous = getGlobalDispatcher();
  const dispatcher = proxy.compose(onePostInterceptor(observation));
  setGlobalDispatcher(dispatcher);
  return { proxy, dispatcher, async close() {
    try { setGlobalDispatcher(previous); } finally { await proxy.destroy(); }
  } };
}

export function createSdk(Client) {
  // User-context selection is required by posts.create. This is still a PUBLIC
  // dummy; the account's real access/refresh tokens belong only to Serverware.
  return new Client({ baseUrl: X_ORIGIN, accessToken: PUBLIC_X_DUMMY,
    retry: false, timeout: REQUEST_TIMEOUT_MS });
}

export async function perform(config, sdk, observation) {
  const text = postText(config.text);
  requireValue(observation.invoked !== true);
  observation.invoked = true;
  const response = await sdk.posts.create({ text }); // Exactly one stock call.
  requireValue(observation.httpStatus === 201 && response && typeof response === 'object'
    && (response.errors === undefined || (Array.isArray(response.errors) && response.errors.length === 0))
    && typeof response.data?.id === 'string' && /^[0-9]{1,20}$/.test(response.data.id));
  return { status: 201, id: response.data.id };
}

export function failure(error, observation = {}) {
  const code = observation.httpStatus ?? error?.status;
  const attempted = observation.invoked === true;
  return { ok: false, operation: 'create-post', outcome: attempted ? 'unknown' : 'not_attempted',
    mayHaveBeenPosted: attempted, automaticRetryAllowed: false,
    httpStatus: Number.isInteger(code) && code >= 100 && code <= 599 ? code : null,
    error: attempted
      ? 'Posting was not confirmed. It may have completed, including when HTTP 409 withholds a response. Do not resubmit automatically; inspect Serverware audit and the account.'
      : 'Posting configuration was refused before the SDK call. No post was attempted.' };
}

async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--help') {
    console.log('node client.mjs [--config PATH]\nExplicit local text and SERVERWARE_X_POST_CONFIRM=post-once required; see README.md.');
    return;
  }
  const observation = { invoked: false, httpStatus: null };
  let transport;
  // The SDK clears its timeout after headers. This dedicated-process watchdog
  // additionally bounds body consumption and cleanup; it cannot undo a post.
  const timer = setTimeout(() => {
    console.error(JSON.stringify(failure(null, observation)));
    process.exit(observation.invoked ? 2 : 1);
  }, PROCESS_TIMEOUT_MS);
  try {
    const args = parseArguments(process.argv.slice(2));
    const config = args.configPath === null ? configuration(process.env) : loadClientConfig(args.configPath, process.env);
    const undici = await import('undici');
    transport = installTransport(config, observation, undici);
    const { Client } = await import('@xdevplatform/xdk');
    console.log(JSON.stringify(await perform(config, createSdk(Client), observation)));
  } catch (error) {
    console.error(JSON.stringify(failure(error, observation)));
    process.exitCode = observation.invoked ? 2 : 1;
  } finally {
    if (transport) {
      try { await transport.close(); }
      catch { console.error(JSON.stringify(failure(null, observation))); process.exitCode = observation.invoked ? 2 : 1; }
    }
    clearTimeout(timer);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
