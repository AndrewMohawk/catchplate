// Stock Octokit + documented Undici proxy configuration; no provider token here.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PUBLIC_GITHUB_DUMMY = 'serverware-github-placeholder-v1';
const OPERATIONS = new Set(['list', 'create-issue', 'create-comment']);
const MAX_REQUESTS = 20;
const DEADLINE_MS = 90_000;

function requireValue(condition) {
  if (!condition) throw new Error('Example configuration or operation refused');
}

function required(env, name, maximum = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
}

function body(env, name) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.trim().length > 0
    && Buffer.byteLength(value) <= 60 * 1024 && !value.includes('\0'));
  return value;
}

export function configuration(env, operation = 'list') {
  requireValue(OPERATIONS.has(operation));
  requireValue(env.NODE_TLS_REJECT_UNAUTHORIZED === undefined || env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  const proxyUrl = required(env, 'SERVERWARE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN', 4096);
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const owner = required(env, 'SERVERWARE_GITHUB_OWNER', 39);
  const repo = required(env, 'SERVERWARE_GITHUB_REPO', 100);
  requireValue(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner)
    && /^[A-Za-z0-9._-]{1,100}$/.test(repo) && !['.', '..'].includes(repo));
  const config = { operation, proxyUrl, applicationId, token, owner, repo,
    caFile: required(env, 'SERVERWARE_CA_FILE'),
    proxyCaFile: env.SERVERWARE_PROXY_CA_FILE
      ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null };
  if (operation === 'create-issue') {
    config.title = required(env, 'SERVERWARE_ISSUE_TITLE', 256);
    config.body = body(env, 'SERVERWARE_ISSUE_BODY');
  } else if (operation === 'create-comment') {
    const number = required(env, 'SERVERWARE_ISSUE_NUMBER', 16);
    requireValue(/^[1-9][0-9]*$/.test(number) && Number.isSafeInteger(Number(number)));
    config.issueNumber = Number(number);
    config.body = body(env, 'SERVERWARE_COMMENT_BODY');
  }
  if (operation !== 'list') requireValue(Buffer.byteLength(JSON.stringify({
    ...(config.title ? { title: config.title } : {}), body: config.body,
  })) <= 65536);
  return config;
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

function exactTarget(url, config) {
  requireValue(typeof url === 'string');
  const target = new URL(url);
  const prefix = '/repos/' + config.owner + '/' + config.repo + '/issues';
  requireValue(target.origin === 'https://api.github.com' && !target.username && !target.password
    && !target.hash && (target.pathname === prefix
      || new RegExp('^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/[1-9][0-9]*/comments$').test(target.pathname)));
}

export function createClient(config, { Octokit, ProxyAgent, fetch, readFile = readFileSync }) {
  const proxy = new ProxyAgent(proxyOptions(config, readFile));
  const deadline = AbortSignal.timeout(DEADLINE_MS);
  let requests = 0;
  try {
    const sdk = new Octokit({
      auth: PUBLIC_GITHUB_DUMMY,
      // SDK errors can retain Authorization/request options. Never print them.
      log: { debug() {}, info() {}, warn() {}, error() {} },
      request: { fetch: (url, options) => {
        exactTarget(url, config);
        requireValue(++requests <= MAX_REQUESTS);
        return fetch(url, { ...options, dispatcher: proxy, redirect: 'error',
          signal: options.signal ? AbortSignal.any([deadline, options.signal]) : deadline });
      } },
    });
    return { sdk, proxy };
  } catch (error) {
    try { Promise.resolve(proxy.destroy()).catch(() => {}); } catch { /* Fixed CLI error only. */ }
    throw error;
  }
}

export async function perform(config, sdk) {
  const scope = { owner: config.owner, repo: config.repo };
  if (config.operation === 'list') {
    const issues = await sdk.paginate(sdk.rest.issues.listForRepo, { ...scope, per_page: 100 });
    return { operation: 'list', issueCount: issues.length,
      issues: issues.map(({ number, title }) => ({ number, title })) };
  }
  const result = config.operation === 'create-issue'
    ? await sdk.rest.issues.create({ ...scope, title: config.title, body: config.body })
    : await sdk.rest.issues.createComment({ ...scope, issue_number: config.issueNumber, body: config.body });
  requireValue(result.status === 201);
  return config.operation === 'create-issue'
    ? { operation: config.operation, issueNumber: result.data.number }
    : { operation: config.operation, issueNumber: config.issueNumber, commentId: result.data.id };
}

export function failure(error, operation) {
  return { ok: false, operation: OPERATIONS.has(operation) ? operation : null,
    httpStatus: Number.isInteger(error?.status) && error.status >= 100 && error.status <= 599 ? error.status : null,
    error: 'GitHub example failed; check configuration, permissions and service audit logs.',
    ...(operation === 'create-issue' || operation === 'create-comment'
      ? { warning: 'Creation may be unconfirmed. Inspect GitHub before deciding whether to retry.' } : {}) };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('node client.mjs [list|create-issue|create-comment]\nDefault: list. Configuration and write content come from environment variables; see README.md.');
    return;
  }
  const operation = args[0] ?? 'list';
  let proxy;
  try {
    requireValue(args.length <= 1);
    const config = configuration(process.env, operation);
    const [{ Octokit }, { ProxyAgent, fetch }] = await Promise.all([import('@octokit/rest'), import('undici')]);
    const client = createClient(config, { Octokit, ProxyAgent, fetch });
    proxy = client.proxy;
    console.log(JSON.stringify({ ok: true, ...await perform(config, client.sdk) }));
  } catch (error) {
    console.error(JSON.stringify(failure(error, operation)));
    process.exitCode = 1;
  } finally {
    if (proxy) {
      try { await proxy.destroy(); }
      catch {
        console.error(JSON.stringify(failure(null, operation)));
        process.exitCode = 1;
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
