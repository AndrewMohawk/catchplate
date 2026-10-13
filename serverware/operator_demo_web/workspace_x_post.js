// User-consented posting is separate from the app-only username lookup preset.
// These helpers validate public configuration; they never send a post.
const operatorXPost = Object.freeze({connection: 'x_user_oauth_v1', bundle: 'x_text_post_v1',
  origin: 'https://api.x.com', token: 'serverware-x-post-placeholder-v1',
  placeholder: 'Bearer serverware-x-post-placeholder-v1', response: 'x_post_json_v1',
  scopes: ['offline.access', 'tweet.read', 'tweet.write', 'users.read'],
  headers: ['accept', 'accept-language', 'content-type', 'sec-fetch-mode', 'user-agent']});
function xPostQuotaDescriptor() {
  return {schema: 'serverware.operatorXPostAttemptQuota/v1', field: 'daily_post_attempt_limit',
    period: 'utc_day', scope: 'verified_x_account', unit: 'posting_attempt', minimum: 1, maximum: 1000000000};
}
function xPostCapabilityDescriptor(destinationAllowed, quota = false) {
  return {schema: 'serverware.operatorXPost/v1', connection_type: operatorXPost.connection,
    create_rule_path: '/api/operator-demo/access-rules/x-post', api_origin: operatorXPost.origin,
    destination_allowed: destinationAllowed, operation_bundles: [operatorXPost.bundle],
    sdk_auth_token: operatorXPost.token, placeholder: operatorXPost.placeholder,
    response_mode: operatorXPost.response, source_pair_required: true, daily_quota_available: quota,
    ...(quota ? {daily_quota: xPostQuotaDescriptor()} : {})};
}
function projectXPostCapability(value) {
  return typeof value?.destination_allowed === 'boolean' && typeof value.daily_quota_available === 'boolean' &&
    operatorExact(value, xPostCapabilityDescriptor(value.destination_allowed, value.daily_quota_available)) ?
    xPostCapabilityDescriptor(value.destination_allowed, value.daily_quota_available) : null;
}
function xPostCredentialValid(credential) {
  return isXOAuthCredential(credential) && credential.auth_type === 'x_oauth' &&
    credential.provider_id === 'x' && credential.header_name === 'Authorization' &&
    credential.permission_preset === operatorXPost.bundle &&
    typeof credential.provider_subject === 'string' && /^[1-9][0-9]{0,19}$/.test(credential.provider_subject) &&
    typeof credential.provider_account === 'string' && /^@[A-Za-z0-9_]{1,15}$/.test(credential.provider_account) &&
    typeof credential.oauth_client_id === 'string' && /^[\x21-\x7e]{1,256}$/.test(credential.oauth_client_id) &&
    operatorExact(credential.scopes, operatorXPost.scopes);
}
function xPostAvailable(catalog, credential) {
  return xPostCredentialValid(credential) && credential.status === 'active' &&
    projectXPostCapability(catalog?.capabilities?.x_post)?.destination_allowed === true &&
    catalog.allowed_upstreams.includes(operatorXPost.origin);
}
function xPostQuotaAvailable(catalog, credential) {
  return xPostAvailable(catalog, credential) && projectXPostCapability(catalog.capabilities.x_post).daily_quota_available;
}
function xPostQuotaValid(rule) {
  return !Object.hasOwn(rule, 'daily_post_attempt_limit') || Number.isSafeInteger(rule.daily_post_attempt_limit) &&
    rule.daily_post_attempt_limit >= 1 && rule.daily_post_attempt_limit <= 1000000000;
}
function xPostQuotaInput(mode, value, catalog, credential) {
  if (mode === 'none') return {};
  if (mode !== 'daily' || !xPostQuotaAvailable(catalog, credential))
    throw operatorError('The selected daily posting-attempt limit is unavailable. Refresh and review; no unlimited fallback is sent.');
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,9}$/.test(value) || Number(value) > 1000000000)
    throw operatorError('Enter a whole number from 1 to 1,000,000,000 for posting attempts per UTC day.');
  return {daily_post_attempt_limit: Number(value)};
}
function xPostQuotaSummary(rule) {
  if (!xPostQuotaValid(rule)) return 'Invalid saved daily posting-attempt limit; do not use this permission.';
  return Object.hasOwn(rule, 'daily_post_attempt_limit') ?
    String(rule.daily_post_attempt_limit) + ' posting attempts per UTC day across all apps using this X account, including other connections to the same verified account. Uncertain attempts still count.' :
    'No daily posting-attempt limit is set on this permission.';
}
function renderXPostQuotaForm(catalog, credential, active) {
  const available = active && xPostQuotaAvailable(catalog, credential);
  const mode = element('connect-x-post-quota').value;
  const limited = mode === 'daily';
  element('connect-x-post-quota-group').hidden = !active || !available && mode === 'none';
  element('connect-x-post-quota').disabled = !available;
  element('connect-x-post-limit-group').hidden = !active || !limited;
  const input = element('connect-x-post-limit'); input.disabled = !available || !limited; input.required = active && limited;
  let problem = '';
  if (active) try { xPostQuotaInput(mode, input.value, catalog, credential); } catch (error) { problem = operatorMessage(error); }
  input.setCustomValidity(available && limited ? problem : '');
  element('connect-x-post-quota-status').textContent = problem;
  return problem;
}
function xPostRuleFields() {
  return {operation_bundle: operatorXPost.bundle, upstream_url: operatorXPost.origin + '/2/tweets',
    methods: ['POST'], request_fields: [], response_fields: [], query_keys: [],
    allowed_headers: [...operatorXPost.headers], response_mode: operatorXPost.response,
    credential_input: 'replace_exact', placeholder: operatorXPost.placeholder};
}
function xPostRuleValid(rule, credential) {
  return xPostCredentialValid(credential) && rule && xPostQuotaValid(rule) &&
    !['request_body_mode', 'query_mode', 'age_policy', 'repository', 'packages', 'package', 'tag',
      'publishing_window', 'username', 'chain', 'quota', 'daily_quota'].some(key => Object.hasOwn(rule, key)) &&
    Object.entries(xPostRuleFields()).every(([key, value]) => operatorExact(rule[key], value));
}
function xPostRulePayload(rule) {
  if (!xPostQuotaValid(rule) || !Object.entries(xPostRuleFields()).every(([key, value]) => operatorExact(rule[key], value)))
    throw operatorError('Review the fixed X text-post permission again.');
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorXPost.bundle,
    ...(Object.hasOwn(rule, 'daily_post_attempt_limit') ? {daily_post_attempt_limit: rule.daily_post_attempt_limit} : {})};
}
function xPostRuleRestrictions(rule = {}) {
  return [['Permission', 'Publish text as the connected X account'], ['Endpoint', operatorXPost.origin + '/2/tweets'],
    ['Content', 'Text only. No media, replies, quotes or threads. Text is supplied by your client, not stored in this permission.'],
    ['Daily posting-attempt limit', xPostQuotaSummary(rule)],
    ['Shared account', 'All active posting permissions for the same verified X account must agree on this restriction, even across OAuth clients. Existing permissions are not changed automatically.'],
    ['Client authentication', 'Public X dummy token plus a separate Serverware proxy app token. No X token goes to the client.']];
}
function renderXPostCompatibility(id) {
  element(id).replaceChildren(...[
    'Publish one text-only post per explicit client invocation as the connected X account. The fixed endpoint accepts only text; no media, replies, quotes, threads or response-field editor.',
    'An optional daily limit counts posting attempts, not successful posts, across all apps using the same verified X account. An uncertain attempt still counts. Review the exact restriction before granting. Usage and reset observations are not available on this page. Account consent, app-token expiry, loaded policy and X provider entitlement remain separate.',
    'Use the linked SDK example with the public dummy token and HTTPS proxy login. Verify both TLS roots. The page does not execute a post or prove provider access.',
    'Posting is not idempotent. A lost or uncertain reply must be inspected; never automatically retry it. The example requires an explicit local post-once confirmation.'
  ].map(text => textNode('p', text, 'small muted')));
}
function buildXPostClientRecipe({proxyUrl, applicationId, proxyAuthentication, caPath = './serverware-ca.pem', proxyCaPath = ''}) {
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId) ||
      proxyAuthentication !== 'basic_and_bearer_v1' || [caPath, proxyCaPath].some(value =>
        typeof value !== 'string' || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)))
    throw operatorError('The X SDK recipe requires standard proxy login and valid CA paths.');
  const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
  return ['# Run from the reviewed examples/x-post-node project after installing its pinned dependencies.',
    '# This command publishes. Set your reviewed text locally; never put provider credentials here.',
    ': "${SERVERWARE_PROXY_TOKEN:?Set your Serverware app token locally}"',
    ': "${SERVERWARE_X_POST_TEXT:?Set the exact text you intend to publish locally}"',
    'export SERVERWARE_PROXY_TOKEN SERVERWARE_X_POST_TEXT',
    'export SERVERWARE_PROXY_URL=' + quote(proxy.origin), 'export SERVERWARE_APP_ID=' + quote(applicationId),
    'export SERVERWARE_CA_FILE="$(realpath ' + quote(caPath || './serverware-ca.pem') + ')"',
    ...(proxyCaPath ? ['export SERVERWARE_PROXY_CA_FILE="$(realpath ' + quote(proxyCaPath) + ')"'] : ['unset SERVERWARE_PROXY_CA_FILE']),
    '# Explicit local confirmation; this page has not sent or tested a post.',
    'SERVERWARE_X_POST_CONFIRM=post-once node client.mjs',
    '# If the reply is uncertain, inspect the account before doing anything else. Do not repeat automatically.',
    'unset SERVERWARE_PROXY_TOKEN SERVERWARE_X_POST_TEXT SERVERWARE_X_POST_CONFIRM'].join('\n');
}
