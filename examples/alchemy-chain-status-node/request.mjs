// Internal dedicated child, launched by client.mjs. Ordinary Alchemy SDK calls
// use Node's documented global HTTPS Agent; no request or SDK monkey patch.
import https from 'node:https';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { certificate, CHAINS, configuration, failure, summary } from './client.mjs';

export const SDK_VERSION = '3.6.5';
export const PUBLIC_ALCHEMY_DUMMY = 'serverware-alchemy-placeholder-v1';
export const REQUEST_TIMEOUT_MS = 15_000;

export function sdkSettings(config) {
  return {
    apiKey: PUBLIC_ALCHEMY_DUMMY,
    network: config.chain,
    url: `https://${config.chain}.g.alchemy.com/v2`,
    batchRequests: false,
    maxRetries: 1,
    connectionInfoOverrides: {
      // This replaces the SDK headers object, so retain its actual version.
      headers: { Authorization: 'Bearer ' + PUBLIC_ALCHEMY_DUMMY,
        'Alchemy-Ethers-Sdk-Version': SDK_VERSION },
      allowGzip: false,
      throttleLimit: 1,
      throttleCallback: async () => false,
      timeout: REQUEST_TIMEOUT_MS,
    },
  };
}

export function agentOptions(config, readCertificate = certificate) {
  const proxy = new URL(config.proxyUrl);
  proxy.username = config.applicationId;
  proxy.password = config.token;
  return {
    // Only this in-memory Agent option contains a credential-bearing URL.
    // Never print it, put it in argv/environment/files, or enable NODE_DEBUG.
    proxyEnv: { HTTPS_PROXY: proxy.href, NO_PROXY: '' },
    ca: readCertificate(config.caFile), rejectUnauthorized: true,
    keepAlive: false, maxSockets: 1, maxTotalSockets: 1, maxCachedSessions: 0,
    timeout: REQUEST_TIMEOUT_MS,
  };
}

export function installTransport(config, { module = https, readCertificate = certificate } = {}) {
  const previous = module.globalAgent;
  const agent = new module.Agent(agentOptions(config, readCertificate));
  module.globalAgent = agent;
  return { agent, close() { module.globalAgent = previous; agent.destroy(); } };
}

export async function perform(config, alchemy) {
  const provider = await alchemy.config.getProvider();
  const chainId = await provider.send('eth_chainId', []);
  if (chainId !== CHAINS[config.chain]) throw new Error('Unexpected chain');
  const blockNumber = await provider.send('eth_blockNumber', []);
  return summary({ ok: true, operation: 'chain-status', chain: config.chain, chainId, blockNumber }, config.chain);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let transport;
  try {
    if (process.argv.length !== 2 || process.versions.node !== '25.5.0') throw new Error('Unsupported invocation');
    const config = configuration(process.env);
    if ((process.env.NODE_EXTRA_CA_CERTS ?? null) !== config.proxyCaFile) throw new Error('Unexpected outer trust');
    transport = installTransport(config);
    const { Alchemy } = await import('alchemy-sdk');
    console.log(JSON.stringify(await perform(config, new Alchemy(sdkSettings(config)))));
  } catch {
    console.error(JSON.stringify(failure()));
    process.exitCode = 1;
  } finally {
    if (transport) transport.close();
  }
}
