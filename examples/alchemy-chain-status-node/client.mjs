// Dedicated-process launcher. Never copy an SDK error, child stderr, or a
// credential-bearing proxy URL to output. No provider credentials are accepted.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const DEADLINE_MS = 30_000;
export const CHAINS = Object.freeze({ 'eth-mainnet': '0x1', 'eth-sepolia': '0xaa36a7' });
export const OUTPUT_KEYS = ['blockNumber', 'chain', 'chainId', 'ok', 'operation'];

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
  const proxyUrl = required(env, 'SERVERWARE_PROXY_URL');
  const proxy = new URL(proxyUrl);
  requireValue(proxy.protocol === 'https:' && proxy.hostname && !proxy.username && !proxy.password
    && proxy.pathname === '/' && !proxy.search && !proxy.hash);
  const applicationId = required(env, 'SERVERWARE_APP_ID', 36);
  requireValue(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(applicationId));
  const token = required(env, 'SERVERWARE_PROXY_TOKEN');
  requireValue(/^[A-Za-z0-9_-]+$/.test(token));
  const chain = required(env, 'SERVERWARE_ALCHEMY_CHAIN', 11);
  requireValue(Object.hasOwn(CHAINS, chain));
  const caFile = required(env, 'SERVERWARE_CA_FILE');
  const proxyCaFile = env.SERVERWARE_PROXY_CA_FILE ? required(env, 'SERVERWARE_PROXY_CA_FILE') : null;
  requireValue(isAbsolute(caFile) && (!proxyCaFile || isAbsolute(proxyCaFile)));
  return { proxyUrl, applicationId, token, chain, caFile, proxyCaFile };
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
    SERVERWARE_PROXY_URL: config.proxyUrl,
    SERVERWARE_APP_ID: config.applicationId,
    SERVERWARE_PROXY_TOKEN: config.token,
    SERVERWARE_ALCHEMY_CHAIN: config.chain,
    SERVERWARE_CA_FILE: config.caFile,
    ...(config.proxyCaFile ? {
      SERVERWARE_PROXY_CA_FILE: config.proxyCaFile,
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

export function run(env, { spawn = spawnSync, readFile = readFileSync } = {}) {
  const config = configuration(env);
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
    console.log('node client.mjs\nTwo read-only Alchemy RPC calls through Serverware. Explicit configuration: see README.md.');
  } else {
    try {
      requireValue(process.argv.length === 2 && process.versions.node === '25.5.0');
      console.log(JSON.stringify(run(process.env)));
    } catch {
      console.error(JSON.stringify(failure()));
      process.exitCode = 1;
    }
  }
}
