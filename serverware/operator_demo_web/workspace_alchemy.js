// Alchemy is a closed JSON-RPC read permission, never a generic POST or key URL.
const operatorAlchemy = Object.freeze({connection: 'alchemy_key_v1', bundle: 'alchemy_chain_status_read_v1',
  response: 'alchemy_rpc_read_json_v1', token: 'serverware-alchemy-placeholder-v1',
  placeholder: 'Bearer serverware-alchemy-placeholder-v1', chains: ['eth-mainnet', 'eth-sepolia'],
  rpcMethods: ['eth_chainId', 'eth_blockNumber'],
  headers: ['accept', 'accept-language', 'alchemy-ethers-sdk-method', 'alchemy-ethers-sdk-version', 'sec-fetch-mode', 'user-agent']});
function alchemyOrigin(chain) {
  if (!operatorAlchemy.chains.includes(chain)) throw operatorError('Choose Ethereum mainnet or Sepolia. No arbitrary chain or URL is supported.');
  return 'https://' + chain + '.g.alchemy.com';
}
function alchemyCapabilityDescriptor(destinations) {
  return {schema: 'serverware.operatorAlchemyRpcRead/v1', connection_type: operatorAlchemy.connection,
    create_credential_path: '/api/operator-demo/credentials/alchemy-key',
    create_rule_path: '/api/operator-demo/access-rules/alchemy-chain-status',
    chains: operatorAlchemy.chains.map((chain, index) => ({chain, api_origin: alchemyOrigin(chain), destination_allowed: destinations[index]})),
    operation_bundles: [operatorAlchemy.bundle], rpc_methods: [...operatorAlchemy.rpcMethods],
    sdk_auth_token: operatorAlchemy.token, placeholder: operatorAlchemy.placeholder,
    response_mode: operatorAlchemy.response, source_pair_required: true};
}
function projectAlchemyCapability(value) {
  if (!Array.isArray(value?.chains) || value.chains.length !== 2 ||
      value.chains.some(item => typeof item?.destination_allowed !== 'boolean')) return null;
  const expected = alchemyCapabilityDescriptor(value.chains.map(item => item.destination_allowed));
  return operatorExact(value, expected) ? expected : null;
}
function alchemyDestinationAvailable(catalog, chain) {
  const capability = projectAlchemyCapability(catalog?.capabilities?.alchemy);
  return Boolean(capability && capability.chains.some(item => (chain === undefined || item.chain === chain) &&
    item.destination_allowed && catalog.allowed_upstreams.includes(item.api_origin)));
}
function alchemyCredentialValid(credential) {
  return isAlchemyCredential(credential) && credential.provider_id === 'alchemy' && credential.auth_type === 'bearer' &&
    credential.header_name === 'Authorization' && !credential.legacy_upstream_origin;
}
function alchemyAvailable(catalog, credential, chain) {
  return alchemyCredentialValid(credential) && credential.status === 'active' && alchemyDestinationAvailable(catalog, chain);
}
function alchemyRuleFields(chain) {
  return {operation_bundle: operatorAlchemy.bundle, chain, upstream_url: alchemyOrigin(chain) + '/v2', methods: ['POST'],
    request_fields: [], response_fields: [], query_keys: [], allowed_headers: [...operatorAlchemy.headers],
    response_mode: operatorAlchemy.response, credential_input: 'replace_exact', placeholder: operatorAlchemy.placeholder};
}
function alchemyRuleValid(rule, credential) {
  try {
    return alchemyCredentialValid(credential) && !['query_mode', 'request_body_mode', 'age_policy', 'repository',
      'packages', 'package', 'tag', 'publishing_window', 'username'].some(key => Object.hasOwn(rule, key)) &&
      Object.entries(alchemyRuleFields(rule.chain)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function alchemyRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorAlchemy.bundle, chain: rule.chain};
}
function alchemyCredentialReceipt(credential, expectedName) {
  if (!alchemyCredentialValid(credential) || credential.status !== 'active' || credential.name !== expectedName ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(credential.id || '') ||
      !Number.isSafeInteger(credential.credential_generation) || credential.credential_generation < 1 ||
      typeof credential.created_at !== 'string' || !Number.isFinite(Date.parse(credential.created_at)))
    throw operatorError('The exact saved Alchemy connection was not confirmed. Inspect saved state; do not submit again.');
  return Object.fromEntries(['id', 'name', 'status', 'created_at', 'auth_type', 'header_name',
    'connection_type', 'provider_id', 'credential_generation'].map(key => [key, credential[key]]));
}
function alchemyCredentialReceiptMatches(credential, expected) {
  try { return operatorExact(alchemyCredentialReceipt(credential, expected.name), expected); }
  catch (_) { return false; }
}
function alchemyRpcRequest(method) {
  if (!operatorAlchemy.rpcMethods.includes(method)) throw operatorError('Choose eth_chainId or eth_blockNumber. No arbitrary RPC request is available.');
  return {jsonrpc: '2.0', id: 1, method, params: []};
}
function buildAlchemyClientRecipe({proxyUrl, applicationId, proxyAuthentication, chain, method, caPath, proxyCaPath = ''}) {
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  if (typeof proxyCaPath !== 'string' || proxyCaPath.length > 512 || /[\x00-\x1f\x7f]/.test(proxyCaPath))
    throw operatorError('Use a local outer proxy CA path, or leave it empty for system trust.');
  const body = JSON.stringify(alchemyRpcRequest(method));
  const lines = buildCurlCommand({proxyUrl, applicationId, proxyAuthentication, upstreamUrl: alchemyOrigin(chain) + '/v2',
    method: 'POST', caPath, allowedHeaders: operatorAlchemy.headers, credentialInput: 'replace_exact',
    placeholder: operatorAlchemy.placeholder, credential: {auth_type: 'bearer', header_name: 'Authorization'}}).split(' \\\n');
  const target = lines.pop();
  if (proxyCaPath) lines.push('  --proxy-cacert ' + quote(proxyCaPath));
  lines.push("  --header 'Content-Type: application/json'", '  --data-raw ' + quote(body), target);
  return lines.join(' \\\n');
}
function alchemyRuleRestrictions(rule) {
  return [['Permission', 'Read Alchemy chain status'], ['Chain', rule.chain], ['Destination', alchemyOrigin(rule.chain) + '/v2'],
    ['Allowed use', 'POST JSON-RPC: eth_chainId and eth_blockNumber only, with params: [] and no URL query.'],
    ['Excluded use', 'No transactions, wallets, arbitrary RPC, batches, notifications, WebSockets, NFT or Notify APIs.'],
    ['Response', 'Full bounded JSON with the same request ID. HTTP 200 can still contain an RPC error. No response-field setup.'],
    ['Client authentication', operatorAlchemy.placeholder + ' (public dummy); the separate Serverware app token logs in to the proxy.']];
}
function renderAlchemyCompatibility(id) {
  element(id).replaceChildren(...[
    'Select Ethereum mainnet or Sepolia only. Each exact origin must be approved separately in Proxy setup. This page never adds destinations, restarts services or sends a provider request.',
    'POST to the keyless /v2 endpoint with Authorization: Bearer serverware-alchemy-placeholder-v1. Only Serverware stores the real API or access key; never put it in a URL or client configuration. Saving does not test or renew the key.',
    'One JSON-RPC request up to 64 KiB: jsonrpc 2.0, an ID, eth_chainId or eth_blockNumber, and params: []. IDs are integers 0–9007199254740991 or nonempty printable ASCII strings up to 64 bytes. No batches, notifications, arbitrary methods or parameters.',
    'Full strict JSON responses up to 64 KiB. HTTP 200 must contain the same typed request ID and exactly one result or error. An RPC error is not a successful method result. Supported HTTP errors: 400, 401, 403, 404, 429, 500, 502, 503 and 504.',
    'No response-field setup. Bounded response metadata is checked and discarded; no response headers are forwarded. Redirects, compression, empty 204/304 and streaming are unsupported. Keep both proxy and destination TLS verification enabled.',
    'Ordinary Alchemy SDK verification is pending; this page has not run a client or verified provider access. No transactions, wallets, WebSockets, NFT or Notify APIs are granted.'
  ].map(value => textNode('p', value, 'small muted')));
}
