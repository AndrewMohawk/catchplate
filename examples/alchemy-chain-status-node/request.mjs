// Internal dedicated child, launched by client.mjs. Stock Viem owns JSON-RPC;
// its public fetch options select Undici's supported authenticated ProxyAgent.
// No global agent, request implementation or SDK method is monkey patched.
import { resolve } from 'node:path';
import { rootCertificates } from 'node:tls';
import { pathToFileURL } from 'node:url';
import { certificate, CHAINS, configuration, failure, summary } from './client.mjs';

export const SDK_VERSION = '2.57.6';
export const UNDICI_VERSION = '8.12.1';
export const PUBLIC_ALCHEMY_DUMMY = 'serverware-alchemy-placeholder-v1';
export const REQUEST_TIMEOUT_MS = 15_000;
export const RESPONSE_LIMIT = 65_536;

export function sdkSettings(config, dispatcher, fetch) {
  if (!dispatcher || typeof dispatcher.dispatch !== 'function' || typeof fetch !== 'function') {
    throw new Error('Explicit proxy transport required');
  }
  return {
    batch: false,
    retryCount: 0,
    timeout: REQUEST_TIMEOUT_MS,
    maxResponseBodySize: RESPONSE_LIMIT,
    methods: { include: ['eth_chainId', 'eth_blockNumber'] },
    fetchFn: fetch,
    fetchOptions: {
      dispatcher,
      redirect: 'error',
      headers: { Authorization: 'Bearer ' + PUBLIC_ALCHEMY_DUMMY,
        Accept: 'application/json', 'Accept-Encoding': 'identity' },
    },
  };
}

export function createSdk(config, dispatcher, { createPublicClient, http, fetch }) {
  return createPublicClient({
    cacheTime: 0,
    ccipRead: false,
    transport: http(`https://${config.chain}.g.alchemy.com/v2`, sdkSettings(config, dispatcher, fetch)),
  });
}

export function agentOptions(config, readCertificate = certificate) {
  return {
    uri: config.proxyUrl,
    // Application login belongs only to CONNECT, never provider headers or URL.
    token: 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'),
    requestTls: { ca: readCertificate(config.caFile), rejectUnauthorized: true,
      servername: `${config.chain}.g.alchemy.com`, allowH2: false, maxCachedSessions: 0 },
    proxyTls: { ca: [...rootCertificates, ...(config.proxyCaFile ? [readCertificate(config.proxyCaFile)] : [])],
      rejectUnauthorized: true, allowH2: false, maxCachedSessions: 0 },
    proxyTunnel: true,
    connections: 1,
    pipelining: 0,
    allowH2: false,
    maxHeaderSize: 16_384,
    maxResponseSize: RESPONSE_LIMIT,
    connectTimeout: REQUEST_TIMEOUT_MS,
    headersTimeout: REQUEST_TIMEOUT_MS,
    bodyTimeout: REQUEST_TIMEOUT_MS,
  };
}

export function boundedDispatcher(agent, { responseError }) {
  // Fetch otherwise replays HTTP 421 even with Viem retries disabled. Reject
  // HTTP errors before fetch can inspect them, retaining at most 64 KiB.
  return agent.compose(responseError({ maxSize: RESPONSE_LIMIT }));
}

export function installTransport(config, { ProxyAgent, interceptors, readCertificate = certificate }) {
  const agent = new ProxyAgent(agentOptions(config, readCertificate));
  return { agent, dispatcher: boundedDispatcher(agent, interceptors),
    async close() { await agent.destroy(); } };
}

export async function perform(config, client) {
  const chainId = await client.request({ method: 'eth_chainId', params: [] }, { retryCount: 0, dedupe: false });
  if (chainId !== CHAINS[config.chain]) throw new Error('Unexpected chain');
  const blockNumber = await client.request({ method: 'eth_blockNumber', params: [] }, { retryCount: 0, dedupe: false });
  return summary({ ok: true, operation: 'chain-status', chain: config.chain, chainId, blockNumber }, config.chain);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let transport;
  try {
    if (process.argv.length !== 2 || process.versions.node !== '25.5.0') throw new Error('Unsupported invocation');
    const config = configuration(process.env);
    if ((process.env.NODE_EXTRA_CA_CERTS ?? null) !== config.proxyCaFile) throw new Error('Unexpected outer trust');
    const { createPublicClient, http } = await import('viem');
    const { ProxyAgent, fetch, interceptors } = await import('undici');
    transport = installTransport(config, { ProxyAgent, interceptors });
    const client = createSdk(config, transport.dispatcher, { createPublicClient, http, fetch });
    const result = await perform(config, client);
    await transport.close(); transport = null;
    console.log(JSON.stringify(result));
  } catch {
    console.error(JSON.stringify(failure()));
    process.exitCode = 1;
  } finally {
    if (transport) {
      try { await transport.close(); } catch { process.exitCode = 1; }
    }
  }
}
