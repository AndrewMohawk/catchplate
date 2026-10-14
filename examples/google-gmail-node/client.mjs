// Official generated Gmail SDK; explicit, bounded Gaxios fetch implementation.
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { rootCertificates } from 'node:tls';
import { pathToFileURL } from 'node:url';

export const PUBLIC_GMAIL_DUMMY = 'serverware-gmail-placeholder-v1';
export const GMAIL_ORIGIN = 'https://gmail.googleapis.com';
export const FAILURE = 'Gmail example failed; check configuration, permissions and service audit logs.';
const LIST_PATH = '/gmail/v1/users/me/messages';
const MAX_RESPONSE = 1024 * 1024;
const TIMEOUT_MS = 30_000;
const DEADLINE_MS = 120_000;
const MAX_REQUESTS = 12;
const MAX_CONFIG_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

function requireValue(condition) {
  if (!condition) throw new Error(FAILURE);
}

function required(env, name, maximum = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}

export function configuration(env) {
  requireValue(!env.NODE_TLS_REJECT_UNAUTHORIZED || env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  // Debugging hooks can log request options, including proxy credentials.
  for (const name of ['DEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_OPTIONS',
    'GOOGLE_SDK_NODE_LOGGING', 'GOOGLE_APPLICATION_CREDENTIALS']) requireValue(!env[name]);
  const proxyUrl = required(env, 'SERVERWARE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash
    && proxy.hostname !== 'gmail.googleapis.com' && !isIP(proxy.hostname)
    && proxy.hostname.length <= 253 && proxy.hostname.includes('.')
    && proxy.hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    && !proxyUrl.includes('\\') && !/:[/]?$/.test(proxyUrl));
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(UUID.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN', 43);
  requireValue(/^[A-Za-z0-9_-]{43}$/.test(token)
    && Buffer.from(token, 'base64url').length === 32
    && Buffer.from(token, 'base64url').toString('base64url') === token);
  return { proxyUrl, applicationId, token,
    caFile: required(env, 'SERVERWARE_CA_FILE'),
    proxyCaFile: env.SERVERWARE_PROXY_CA_FILE ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null };
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
    const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    requireValue(object(value) && object(value.client_recipe));
    const recipe = value.client_recipe;
    requireValue(['serverware.gmailSdkClient/v1', 'serverware.gmailSdkClient/v2'].includes(recipe.schema)
      && object(recipe.environment));
    requireValue(value.operation_bundle === 'gmail_read_v1'
      && value.upstream_url === GMAIL_ORIGIN + LIST_PATH
      && Array.isArray(value.methods) && value.methods.length === 1 && value.methods[0] === 'GET'
      && value.query_mode === 'orderedFormV1' && value.credential_input === 'replace_exact'
      && value.proxy_authentication === 'basic_and_bearer_v1'
      && value.proxy_username === value.application_id
      && typeof value.access_rule_id === 'string' && UUID.test(value.access_rule_id)
      && Number.isSafeInteger(now) && now > 0
      && Number.isSafeInteger(value.token_expires_at_epoch_ms) && value.token_expires_at_epoch_ms > now);
    const connection = recipe.environment;
    requireValue(recipe.access_rule_id === value.access_rule_id
      && recipe.token_expires_at_epoch_ms === value.token_expires_at_epoch_ms
      && connection.SERVERWARE_APP_ID === value.application_id
      && connection.SERVERWARE_PROXY_URL === value.proxy_url
      && connection.SERVERWARE_PROXY_TOKEN === value.proxy_password
      && connection.SERVERWARE_CA_FILE === value.ca_file
      && (connection.SERVERWARE_PROXY_CA_FILE ?? null) === (value.proxy_ca_file ?? null));
    const caPath = value => resolve(dirname(filename), required({ path: value }, 'path'));
    // Language, entrypoint, commands and arbitrary environment entries are inert.
    // Import only connection values, clearing an absent outer CA from the caller.
    return configuration({ ...env,
      SERVERWARE_PROXY_URL: value.proxy_url,
      SERVERWARE_APP_ID: value.application_id,
      SERVERWARE_PROXY_TOKEN: value.proxy_password,
      SERVERWARE_CA_FILE: caPath(value.ca_file),
      SERVERWARE_PROXY_CA_FILE: value.proxy_ca_file === undefined || value.proxy_ca_file === null
        ? undefined : caPath(value.proxy_ca_file),
    });
  } catch { throw new Error(FAILURE); }
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
  requireValue(Buffer.isBuffer(value) && value.length > 0 && value.length <= MAX_RESPONSE
    && value.includes(Buffer.from('-----BEGIN CERTIFICATE-----')));
  return value;
}

export function proxyOptions(config, readFile = readFileSync) {
  return {
    uri: config.proxyUrl,
    token: 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'),
    proxyTls: { rejectUnauthorized: true,
      ca: config.proxyCaFile ? [...rootCertificates, certificate(config.proxyCaFile, readFile)] : rootCertificates },
    requestTls: { rejectUnauthorized: true, ca: certificate(config.caFile, readFile) },
    connections: 1, pipelining: 0, connectTimeout: TIMEOUT_MS,
  };
}

function exactRequest(url, options) {
  const target = new URL(url);
  requireValue(target.origin === GMAIL_ORIGIN && !target.username && !target.password && !target.hash
    && (target.pathname === LIST_PATH || /^\/gmail\/v1\/users\/me\/messages\/[A-Za-z0-9_-]{1,512}$/.test(target.pathname))
    && options.method === 'GET' && options.body === undefined);
  const headers = new Headers(options.headers);
  requireValue(headers.get('authorization') === 'Bearer ' + PUBLIC_GMAIL_DUMMY);
  for (const name of headers.keys()) requireValue([
    'accept', 'accept-encoding', 'authorization', 'user-agent', 'x-goog-api-client',
  ].includes(name));
  return { target, headers };
}

// This is the documented Gaxios fetchImplementation seam, not a replacement
// Gmail API. Undici.request preserves SDK headers without fetch's browser-only
// sec-fetch-mode/accept-language additions, which this grant does not allow.
export function createTransport(config, { ProxyAgent, request, readFile = readFileSync }) {
  const proxy = new ProxyAgent(proxyOptions(config, readFile));
  const deadline = AbortSignal.timeout(DEADLINE_MS);
  let requests = 0;
  return { proxy, async fetchImplementation(url, options) {
    const { target, headers } = exactRequest(url, options);
    requireValue(++requests <= MAX_REQUESTS);
    const signal = AbortSignal.any([deadline, AbortSignal.timeout(TIMEOUT_MS),
      ...(options.signal ? [options.signal] : [])]);
    signal.throwIfAborted();
    const response = await request(target, {
      method: options.method, headers: Object.fromEntries(headers), dispatcher: proxy,
      signal, maxRedirections: 0, headersTimeout: TIMEOUT_MS, bodyTimeout: TIMEOUT_MS,
    });
    try {
      // The Serverware Gmail response envelope is uncompressed JSON. Refuse
      // redirects or another representation instead of following or decoding it.
      requireValue(response.statusCode < 300 || response.statusCode >= 400);
      requireValue(!response.headers['content-encoding'] || response.headers['content-encoding'] === 'identity');
      const limit = response.statusCode === 200 ? MAX_RESPONSE : 64 * 1024;
      const chunks = [];
      let length = 0;
      for await (const chunk of response.body) {
        signal.throwIfAborted();
        length += chunk.length;
        requireValue(length <= limit);
        chunks.push(chunk);
      }
      const responseHeaders = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        if (Array.isArray(value)) value.forEach(item => responseHeaders.append(name, item));
        else if (value !== undefined) responseHeaders.set(name, value);
      }
      return new Response(Buffer.concat(chunks), { status: response.statusCode, headers: responseHeaders });
    } finally {
      response.body.destroy();
    }
  } };
}

export function createClient(config, { gmail, auth, ...transportDependencies }) {
  const transport = createTransport(config, transportDependencies);
  try {
    // A constant dummy, not ADC or a Google token: Serverware owns real OAuth
    // credentials and refresh. No refresh token/handler exists in this client.
    const oauth = new auth.OAuth2();
    oauth.setCredentials({ access_token: PUBLIC_GMAIL_DUMMY });
    const sdk = gmail({ version: 'v1', auth: oauth, universeDomain: 'googleapis.com',
      retry: false, maxRedirects: 0, timeout: TIMEOUT_MS, responseType: 'json',
      // Skip Gaxios's unused environment-proxy discovery; the explicit
      // Undici dispatcher below is mandatory, including when NO_PROXY is set.
      noProxy: [GMAIL_ORIGIN],
      validateStatus: status => status === 200,
      fetchImplementation: transport.fetchImplementation });
    return { sdk, proxy: transport.proxy };
  } catch (error) {
    Promise.resolve(transport.proxy.destroy()).catch(() => {});
    throw error;
  }
}

function validPageToken(value) {
  return typeof value === 'string' && Buffer.byteLength(value) <= 4096
    && !/[\u0000-\u001f\u007f-\u009f\\]/.test(value);
}

export async function perform(sdk) {
  const summary = { pages: 0, messages_read: 0, more_pages: false };
  const seenIds = new Set();
  const seenPages = new Set();
  let pageToken;
  for (let page = 0; page < 2; page++) {
    const result = await sdk.users.messages.list({ userId: 'me', maxResults: 5,
      labelIds: ['INBOX'], ...(pageToken ? { pageToken } : {}) });
    requireValue(result.status === 200 && result.data && typeof result.data === 'object'
      && !Array.isArray(result.data));
    const { messages = [], nextPageToken = '' } = result.data;
    requireValue(Array.isArray(messages) && messages.length <= 5 && validPageToken(nextPageToken)
      && (!nextPageToken || !seenPages.has(nextPageToken)));
    // Validate the entire page before fetching any returned message.
    for (const message of messages) {
      requireValue(message && typeof message.id === 'string'
        && /^[A-Za-z0-9_-]{1,512}$/.test(message.id) && !seenIds.has(message.id));
      seenIds.add(message.id);
    }
    for (const { id } of messages) {
      const detail = await sdk.users.messages.get({ userId: 'me', id, format: 'metadata',
        metadataHeaders: ['From', 'Subject', 'Date'] });
      requireValue(detail.status === 200 && detail.data?.id === id);
      summary.messages_read++;
    }
    summary.pages++;
    summary.more_pages = nextPageToken !== '';
    if (!nextPageToken) break;
    seenPages.add(nextPageToken);
    pageToken = nextPageToken;
  }
  return summary;
}

async function main() {
  let proxy;
  try {
    const args = parseArguments(process.argv.slice(2));
    if (args.help) {
      console.log('Usage: node client.mjs [--config PATH]');
      return;
    }
    const config = args.configPath ? loadClientConfig(args.configPath, process.env) : configuration(process.env);
    const [{ gmail, auth }, { ProxyAgent, request }] = await Promise.all([
      import('@googleapis/gmail'), import('undici'),
    ]);
    const client = createClient(config, { gmail, auth, ProxyAgent, request });
    proxy = client.proxy;
    const summary = await perform(client.sdk);
    await proxy.destroy();
    proxy = null;
    console.log(JSON.stringify(summary));
  } catch {
    // Google and transport errors may contain mail data or request secrets.
    console.error(FAILURE);
    process.exitCode = 1;
  } finally {
    if (proxy) try { await proxy.destroy(); } catch { process.exitCode = 1; }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
