// Dedicated-process launcher. Never copy an SDK error, child stderr, or a
// credential-bearing proxy URL to output. No provider credentials are accepted.
import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const DEADLINE_MS = 30_000;
export const CHAINS = Object.freeze({ 'eth-mainnet': '0x1', 'eth-sepolia': '0xaa36a7' });
export const OUTPUT_KEYS = ['blockNumber', 'chain', 'chainId', 'ok', 'operation'];
const MAX_CONFIG_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

function requireValue(condition) {
  if (!condition) throw new Error('Alchemy example configuration or response refused');
}

function required(env, name, maximum = 4096) {
  const value = env[name];
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value === value.trim() && !/[\u0000-\u0020\u007f]/.test(value));
  return value;
}

export function configuration(env) {
  requireValue(!env.NODE_OPTIONS && !env.NODE_DEBUG && !env.NODE_DEBUG_NATIVE
    && (!env.NODE_TLS_REJECT_UNAUTHORIZED || env.NODE_TLS_REJECT_UNAUTHORIZED === '1'));
  const proxyUrl = required(env, 'CATCHPLATE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'CATCHPLATE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'CATCHPLATE_PROXY_TOKEN');
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const chain = required(env, 'CATCHPLATE_ALCHEMY_CHAIN', 11);
  requireValue(Object.hasOwn(CHAINS, chain));
  const caFile = required(env, 'CATCHPLATE_CA_FILE');
  const proxyCaFile = env.CATCHPLATE_PROXY_CA_FILE ? required(env, 'CATCHPLATE_PROXY_CA_FILE') : null;
  requireValue(isAbsolute(caFile) && (!proxyCaFile || isAbsolute(proxyCaFile)));
  return { proxyUrl, applicationId, token, chain, caFile, proxyCaFile };
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
    requireValue(value.operation_bundle === 'alchemy_chain_status_read_v1'
      && typeof value.chain === 'string' && Object.hasOwn(CHAINS, value.chain)
      && value.upstream_url === 'https://' + value.chain + '.g.alchemy.com/v2'
      && Array.isArray(value.methods) && value.methods.length === 1 && value.methods[0] === 'POST'
      && value.credential_input === 'replace_exact' && value.response_mode === 'alchemy_rpc_read_json_v1'
      && Array.isArray(value.rpc_methods) && value.rpc_methods.length === 2
      && value.rpc_methods[0] === 'eth_chainId' && value.rpc_methods[1] === 'eth_blockNumber');
    const caPath = value => resolve(dirname(filename), required({ path: value }, 'path'));
    // JSON selects only connection and saved chain. Commands, headers, request
    // bodies and environment entries are inert; the child still makes two fixed reads.
    return configuration({ ...env,
      CATCHPLATE_PROXY_URL: value.proxy_url,
      CATCHPLATE_APP_ID: value.application_id,
      CATCHPLATE_PROXY_TOKEN: value.proxy_password,
      CATCHPLATE_CA_FILE: caPath(value.ca_file),
      CATCHPLATE_PROXY_CA_FILE: value.proxy_ca_file === undefined || value.proxy_ca_file === null
        ? undefined : caPath(value.proxy_ca_file),
      CATCHPLATE_ALCHEMY_CHAIN: value.chain,
    });
  } catch { throw new Error('Alchemy example configuration or response refused'); }
}

export function parseArguments(args) {
  requireValue(Array.isArray(args) && args.every(value => typeof value === 'string'));
  if (args.length === 0) return { help: false, configPath: null };
  if (args.length === 1 && args[0] === '--help') return { help: true, configPath: null };
  requireValue(args.length === 2 && args[0] === '--config'
    && args[1].length > 0 && !args[1].startsWith('--'));
  return { help: false, configPath: required({ path: args[1] }, 'path') };
}

export function certificate(path, readFile = readFileSync) {
  const bytes = readFile(path);
  requireValue(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 262144);
  const text = bytes.toString('ascii');
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  requireValue(blocks && blocks.length <= 32
    && text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() === '');
  for (const block of blocks) new X509Certificate(block);
  return bytes;
}

export function childEnvironment(config) {
  // Explicit allowlist: no ambient Alchemy keys, HOME/netrc, proxy bypass,
  // NODE_OPTIONS/debugging/preloads, or inherited extra CA configuration.
  return {
    CATCHPLATE_PROXY_URL: config.proxyUrl,
    CATCHPLATE_APP_ID: config.applicationId,
    CATCHPLATE_PROXY_TOKEN: config.token,
    CATCHPLATE_ALCHEMY_CHAIN: config.chain,
    CATCHPLATE_CA_FILE: config.caFile,
    ...(config.proxyCaFile ? {
      CATCHPLATE_PROXY_CA_FILE: config.proxyCaFile,
      NODE_EXTRA_CA_CERTS: config.proxyCaFile,
    } : {}),
  };
}

export function summary(value, chain) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === OUTPUT_KEYS.join(',')
    && value.ok === true && value.operation === 'chain-status' && value.chain === chain
    && Object.hasOwn(CHAINS, chain) && value.chainId === CHAINS[chain]
    && typeof value.blockNumber === 'string' && /^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(value.blockNumber));
  return { ok: true, operation: 'chain-status', chain, chainId: value.chainId, blockNumber: value.blockNumber };
}

export function failure() {
  return { ok: false, operation: 'chain-status',
    error: 'Alchemy chain status failed; inspect configuration, saved permission and service audit logs. No automatic retry.' };
}

export function run(env, { spawn = spawnSync, readFile = readFileSync, configPath = null } = {}) {
  const config = configPath === null ? configuration(env) : loadClientConfig(configPath, env);
  certificate(config.caFile, readFile);
  if (config.proxyCaFile) certificate(config.proxyCaFile, readFile);
  const child = spawn(process.execPath, [fileURLToPath(new URL('./request.mjs', import.meta.url))], {
    env: childEnvironment(config), stdio: ['ignore', 'pipe', 'pipe'],
    timeout: DEADLINE_MS, killSignal: 'SIGKILL', maxBuffer: 65536, encoding: 'utf8',
  });
  requireValue(!child.error && child.status === 0 && child.signal === null
    && typeof child.stdout === 'string' && Buffer.byteLength(child.stdout) <= 4096);
  return summary(JSON.parse(child.stdout), config.chain);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === '--help') {
    console.log('node client.mjs [--config PATH]\nTwo read-only Alchemy RPC calls through Catchplate. Configuration: see README.md.');
  } else {
    try {
      const args = parseArguments(process.argv.slice(2));
      requireValue(process.versions.node === '25.5.0');
      console.log(JSON.stringify(run(process.env, { configPath: args.configPath })));
    } catch {
      console.error(JSON.stringify(failure()));
      process.exitCode = 1;
    }
  }
}
