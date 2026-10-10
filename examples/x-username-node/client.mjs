// Official XDK generates the request. Documented Undici configuration routes it.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PUBLIC_X_DUMMY = 'serverware-x-placeholder-v1';
export const X_ORIGIN = 'https://api.x.com';
const DEADLINE_MS = 30_000;

function requireValue(condition) {
  if (!condition) throw new Error('X example configuration or request refused');
}

function required(env, name, maximum = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}

export function configuration(env) {
  requireValue(env.NODE_TLS_REJECT_UNAUTHORIZED === undefined || env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  // Do not run with ambient preload/transport overrides. HTTP[S]_PROXY/NO_PROXY
  // are not consulted by this explicitly installed ProxyAgent.
  requireValue(env.NODE_OPTIONS === undefined || env.NODE_OPTIONS === '');
  const proxyUrl = required(env, 'SERVERWARE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN');
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const username = required(env, 'SERVERWARE_X_USERNAME', 15);
  requireValue(/^[a-z0-9_]{1,15}$/.test(username));
  return { proxyUrl, applicationId, token, username,
    caFile: required(env, 'SERVERWARE_CA_FILE'),
    proxyCaFile: env.SERVERWARE_PROXY_CA_FILE ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null };
}

function certificate(path, readFile) {
  const value = readFile(path);
  requireValue(Buffer.isBuffer(value) && value.length > 0 && value.length <= 256 * 1024
    && value.includes(Buffer.from('-----BEGIN CERTIFICATE-----')));
  return value;
}

export function proxyOptions(config, readFile = readFileSync) {
  return {
    uri: config.proxyUrl,
    token: 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'),
    proxyTls: { rejectUnauthorized: true,
      ...(config.proxyCaFile ? { ca: certificate(config.proxyCaFile, readFile) } : {}) },
    requestTls: { ca: certificate(config.caFile, readFile), rejectUnauthorized: true },
    connections: 1,
  };
}

// Additional example restriction, NOT a claim about stock SDK defaults. The
// documented interceptor forwards admitted options/headers/body unchanged.
export function oneLookupInterceptor(config) {
  let attempted = false;
  return (dispatch) => (options, handler) => {
    requireValue(!attempted);
    attempted = true;
    const origin = new URL(String(options.origin));
    requireValue(origin.href === X_ORIGIN + '/' && options.method === 'GET'
      && options.path === '/2/users/by/username/' + config.username
      && (options.body === undefined || options.body === null));
    return dispatch(options, handler);
  };
}

export function installTransport(config, {
  ProxyAgent, getGlobalDispatcher, setGlobalDispatcher, readFile = readFileSync,
}) {
  const proxy = new ProxyAgent(proxyOptions(config, readFile));
  const previous = getGlobalDispatcher();
  const dispatcher = proxy.compose(oneLookupInterceptor(config));
  setGlobalDispatcher(dispatcher);
  return { proxy, dispatcher, async close() {
    // This example owns its dedicated CLI process, not a shared application.
    try { setGlobalDispatcher(previous); } finally { await proxy.destroy(); }
  } };
}

export function createSdk(Client) {
  return new Client({ baseUrl: X_ORIGIN, bearerToken: PUBLIC_X_DUMMY,
    retry: false, timeout: DEADLINE_MS });
}

export async function perform(config, sdk) {
  // A documented per-request signal also bounds consumption of the JSON body.
  const response = await sdk.users.getByUsername(config.username, {
    requestOptions: { signal: AbortSignal.timeout(DEADLINE_MS) },
  });
  requireValue(response && typeof response === 'object'
    && (response.errors === undefined || (Array.isArray(response.errors) && response.errors.length === 0)));
  const data = response.data;
  requireValue(data && typeof data.id === 'string' && /^[1-9][0-9]{0,19}$/.test(data.id)
    && typeof data.username === 'string' && /^[A-Za-z0-9_]{1,15}$/.test(data.username)
    && data.username.toLowerCase() === config.username);
  // Do not print the response body, provider errors, request or credentials.
  return { operation: 'lookup-username', username: data.username, id: data.id };
}

export function failure(error) {
  return { ok: false, operation: 'lookup-username',
    httpStatus: Number.isInteger(error?.status) && error.status >= 100 && error.status <= 599 ? error.status : null,
    error: 'X lookup failed; inspect configuration, saved permission and service audit logs. No automatic retry.' };
}

async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--help') {
    console.log('node client.mjs\nOne read-only X username lookup. Explicit environment configuration: see README.md.');
    return;
  }
  let transport;
  try {
    requireValue(process.argv.length === 2);
    const config = configuration(process.env);
    const undici = await import('undici');
    transport = installTransport(config, undici);
    // XDK captures native fetch during import; no fetch/header monkey patch.
    const { Client } = await import('@xdevplatform/xdk');
    console.log(JSON.stringify({ ok: true, ...await perform(config, createSdk(Client)) }));
  } catch (error) {
    console.error(JSON.stringify(failure(error)));
    process.exitCode = 1;
  } finally {
    if (transport) {
      try { await transport.close(); }
      catch { console.error(JSON.stringify(failure(null))); process.exitCode = 1; }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
