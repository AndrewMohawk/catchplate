// X app-only username reads are a typed preset, never generic or user OAuth.
// These public descriptors contain no provider secret or authorization proof.
const operatorX = Object.freeze({origin: 'https://api.x.com', connection: 'x_app_bearer_v1',
  bundle: 'x_username_read_v1', response: 'x_app_read_json_v1', token: 'serverware-x-placeholder-v1',
  placeholder: 'Bearer serverware-x-placeholder-v1', headers: ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent']});
function xCapabilityDescriptor(destinationAllowed) {
  return {schema: 'serverware.operatorXAppRead/v1', connection_type: operatorX.connection,
    create_credential_path: '/api/operator-demo/credentials/x-app-bearer',
    create_rule_path: '/api/operator-demo/access-rules/x-username', api_origin: operatorX.origin,
    destination_allowed: destinationAllowed, operation_bundles: [operatorX.bundle],
    sdk_auth_token: operatorX.token, placeholder: operatorX.placeholder,
    response_mode: operatorX.response, source_pair_required: true};
}
function projectXCapability(value) {
  return typeof value?.destination_allowed === 'boolean' && operatorExact(value, xCapabilityDescriptor(value.destination_allowed)) ?
    xCapabilityDescriptor(value.destination_allowed) : null;
}
function xDestinationAvailable(catalog) {
  return projectXCapability(catalog?.capabilities?.x)?.destination_allowed === true &&
    catalog.allowed_upstreams.includes(operatorX.origin);
}
function xCredentialValid(credential) {
  return isXCredential(credential) && credential.provider_id === 'x' && credential.auth_type === 'bearer' &&
    credential.header_name === 'Authorization' && !credential.legacy_upstream_origin;
}
function xAvailable(catalog, credential) {
  return xCredentialValid(credential) && credential.status === 'active' && xDestinationAvailable(catalog);
}
function xUsernameValid(username) { return typeof username === 'string' && /^[a-z0-9_]{1,15}$/.test(username); }
function xRuleFields(username) {
  if (!xUsernameValid(username)) throw operatorError('Enter one exact lowercase X username, 1–15 letters, digits or underscores. No @, URL or whitespace.');
  return {operation_bundle: operatorX.bundle, username,
    upstream_url: operatorX.origin + '/2/users/by/username/' + username, methods: ['GET'],
    request_fields: [], response_fields: [], query_keys: [], allowed_headers: [...operatorX.headers],
    response_mode: operatorX.response, credential_input: 'replace_exact', placeholder: operatorX.placeholder};
}
function xRuleValid(rule, credential) {
  try {
    return xCredentialValid(credential) && !['query_mode', 'request_body_mode', 'age_policy', 'repository',
      'packages', 'package', 'tag', 'publishing_window'].some(key => Object.hasOwn(rule, key)) &&
      Object.entries(xRuleFields(rule.username)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function xRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorX.bundle, username: rule.username};
}
function xCredentialReceipt(credential, expectedName) {
  if (!xCredentialValid(credential) || credential.status !== 'active' || credential.name !== expectedName ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(credential.id || '') ||
      !Number.isSafeInteger(credential.credential_generation) || credential.credential_generation < 1 ||
      typeof credential.created_at !== 'string' || !Number.isFinite(Date.parse(credential.created_at)))
    throw operatorError('The exact saved X connection was not confirmed. Inspect saved state; do not submit again.');
  return Object.fromEntries(['id', 'name', 'status', 'created_at', 'auth_type', 'header_name',
    'connection_type', 'provider_id', 'credential_generation'].map(key => [key, credential[key]]));
}
function xCredentialReceiptMatches(credential, expected) {
  try { return operatorExact(xCredentialReceipt(credential, expected.name), expected); }
  catch (_) { return false; }
}
function xRuleRestrictions(rule) {
  return [['Permission', 'Look up one X username'], ['Username', rule.username || 'Choose one exact username'],
    ['Destination', operatorX.origin + '/2/users/by/username/' + (rule.username || '<username>')],
    ['Allowed use', 'GET only; no query parameters or request body.'],
    ['Excluded use', 'No posting, search, pagination, /users/me, DMs, media, streams or user OAuth.'],
    ['Response', 'Full bounded JSON, without response-field setup. HTTP 200 is not proof of a successful lookup.'],
    ['Client authentication', operatorX.placeholder + ' (public dummy); the separate Serverware app token logs in to the proxy.']];
}
function renderXCompatibility(id) {
  element(id).replaceChildren(...[
    'X app-only lookup permits one exact lowercase username at api.x.com. GET only, with no query parameters or body. This is not user OAuth and does not grant posting, search, pagination, /users/me, DMs, media or streams.',
    'The client sends the fixed public dummy Bearer serverware-x-placeholder-v1. Only Serverware holds the real app-only bearer token. Saving a token does not test its validity or provider entitlement; it is not automatically renewed.',
    'No response-field setup. HTTP 200 JSON is bounded to 1 MiB; supported errors 400, 401, 403, 404, 429, 500, 502, 503 and 504 are bounded to 64 KiB. Provider error bodies remain errors, not evidence of a successful lookup.',
    'Standard response metadata is checked and discarded; no response headers are forwarded. Client compression offers are removed before forwarding. Compressed responses, redirects, empty 204/304 and streaming are unsupported.',
    'A GET may omit Content-Type or use the admitted JSON/UTF-8 Content-Type while still sending zero body bytes. Keep both proxy and destination TLS verification enabled with the downloaded CA and the required outer proxy trust.',
    'A saved or loaded policy is not provider acceptance. Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. This page has not tested your X credentials or provider entitlement. The GitHub Actions recipe is inactive and has not been run. Alchemy uses a separate JSON-RPC permission; an X token never grants Alchemy access.'
  ].map(value => textNode('p', value, 'small muted')));
}
