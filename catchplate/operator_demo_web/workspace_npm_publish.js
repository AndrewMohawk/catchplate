// Publishing is a separate, explicitly advertised contract. Metadata grants
// never become publishing grants, and these helpers perform no provider I/O.
const operatorNpmPublish = Object.freeze({bundle: 'npm_publish_v1', response: 'npm_publish_json_v1',
  headers: ['accept', 'content-type', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'user-agent']});
function npmPublishCapabilityDescriptor(destinationAllowed) {
  return {schema: 'catchplate.operatorNpmPublish/v1', connection_type: operatorNpm.connection,
    create_rule_path: '/api/operator-demo/access-rules/npm-publish', registry_origin: operatorNpm.origin,
    destination_allowed: destinationAllowed, operation_bundles: [operatorNpmPublish.bundle],
    sdk_auth_token: operatorNpm.token, placeholder: operatorNpm.placeholder, response_mode: operatorNpmPublish.response,
    source_pair_required: true, max_active_rules_per_application: 1, default_tag: 'latest',
    publishing_window_timezone: 'UTC', read_metadata_included: true,
    max_request_body_bytes: 16777216, max_tarball_bytes: 8388608};
}
function projectNpmPublishCapability(value) {
  return typeof value?.destination_allowed === 'boolean' && operatorExact(value, npmPublishCapabilityDescriptor(value.destination_allowed)) ?
    npmPublishCapabilityDescriptor(value.destination_allowed) : null;
}
function npmPublishAvailable(catalog, credential) {
  return isNpmCredential(credential) && credential.status === 'active' &&
    projectNpmPublishCapability(catalog?.capabilities?.npm_publish)?.destination_allowed === true &&
    catalog.allowed_upstreams.includes(operatorNpm.origin);
}
function npmPublishNewRuleAvailable(catalog, applicationId) {
  return !catalog?.access_rules.some(rule => {
    if (rule.status !== 'active' || rule.application_id !== applicationId) return false;
    if (isNpmRule(rule) || isNpmPublishRule(rule)) return true;
    if (!rule.methods?.some(method => ['GET', 'PUT'].includes(method))) return false;
    try { const url = new URL(rule.upstream_url); return url.origin === operatorNpm.origin && /^\/[^/]+$/.test(url.pathname); }
    catch (_) { return true; }
  });
}
function npmPublishWindowValid(value) {
  return value === null || value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === 'end,start' && ['start', 'end'].every(key =>
      typeof value[key] === 'string' && /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(value[key])) && value.start < value.end;
}
function npmPublishRuleFields(packageName, tag, publishingWindow) {
  if (!npmPackagesValid([packageName]) || typeof tag !== 'string' || !/^[a-z][a-z0-9._-]{0,63}$/.test(tag) ||
      !npmPublishWindowValid(publishingWindow))
    throw operatorError('Choose one exact lowercase package name, a lowercase tag, and optional same-day UTC hours (start before end; no 24:00).');
  return {operation_bundle: operatorNpmPublish.bundle, package: packageName, tag,
    publishing_window: publishingWindow === null ? null : {...publishingWindow}, upstream_url: operatorNpm.origin + '/',
    methods: ['PUT'], request_fields: [], response_fields: [], query_keys: [], allowed_headers: [...operatorNpmPublish.headers],
    response_mode: operatorNpmPublish.response, credential_input: 'replace_exact', placeholder: operatorNpm.placeholder};
}
function npmPublishRuleValid(rule, credential) {
  try {
    return isNpmCredential(credential) && credential.provider_id === 'npm' && credential.auth_type === 'bearer' &&
      credential.header_name === 'Authorization' &&
      !['query_mode', 'request_body_mode', 'age_policy', 'repository', 'packages'].some(key => Object.hasOwn(rule, key)) &&
      Object.entries(npmPublishRuleFields(rule.package, rule.tag, rule.publishing_window)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function npmPublishRulePayload(rule) {
  npmPublishRuleFields(rule.package, rule.tag, rule.publishing_window);
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorNpmPublish.bundle, package: rule.package, tag: rule.tag,
    publishing_window: rule.publishing_window === null ? null : {...rule.publishing_window}};
}
function npmPublishHours(rule) {
  return rule.publishing_window ? 'daily ' + rule.publishing_window.start + '–' + rule.publishing_window.end + ' UTC (end exclusive)' : 'at any time';
}
function npmPublishReview(rule) {
  return 'Publish new versions of ' + rule.package + ' with tag ' + rule.tag + ' ' + npmPublishHours(rule) +
    '; read that package’s metadata at any time.';
}
function npmPublishRuleRestrictions(rule) {
  return [['Permission', 'Publish package'], ['Effective access', npmPublishReview(rule)], ['Registry', operatorNpm.origin],
    ['Limits', 'No install, unpublish, tag administration, provenance, staged publishing or provider 2FA flow.'],
    ['Client authentication', 'Public npm dummy token; separate Catchplate app token for HTTPS proxy login. The stored npm token must permit publishing.']];
}
function renderNpmPublishCompatibility(id) {
  element(id).replaceChildren(...[
    'Publish one exact package and tag. The permission includes package metadata GETs, even outside optional UTC publishing hours. Publishing hours apply to PUT requests and are checked again before forwarding; this is not a scheduler or approval workflow.',
    'One active npm metadata or publishing permission per app. No automatic upgrade, merging or revocation. Reuse a saved permission, or explicitly revoke it before changing the package, tag or hours.',
    'No install, unpublish, standalone tag administration, provenance, staged publishing, npm audit or provider 2FA flow. Use a least-privilege npm token whose provider policy permits noninteractive publishing. Catchplate does not renew or verify it here.',
    'Bounded publish JSON up to 16 MiB containing one tarball up to 8 MiB. Package/version/tag and attachment integrity are validated, not the safety of archive contents. No response-field setup.',
    'Use stock npm with verified HTTPS proxy and destination TLS, a dedicated npmrc and fresh private cache, and zero automatic retries. Review the package before explicitly running publish. A lost or uncertain publish reply is not permission to republish; inspect registry metadata first.',
    'NODE_EXTRA_CA_CERTS is loaded before npm starts and retains Node default roots. For a private outer proxy CA, use a scoped extra-CA file containing both required roots. Keep strict-ssl enabled and do not override cafile.',
    'Proxy app-token validity, loaded policy and provider publishing rights are separate. This page sends no npm requests; a configured permission is not proof of successful publication.'
  ].map(text => textNode('p', text, 'small muted')));
}
function buildNpmPublishClientRecipe({proxyUrl, applicationId, proxyAuthentication, packageName, tag, publishingWindow = null, caPath = './catchplate-ca.pem'}) {
  npmPublishRuleFields(packageName, tag, publishingWindow);
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId) ||
      proxyAuthentication !== 'basic_and_bearer_v1' || typeof caPath !== 'string' || caPath.length > 512 || /[\u0000-\u001f\u007f]/.test(caPath))
    throw new Error('An exact publishing permission and standard proxy login are required');
  const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
  return ['# npm ' + operatorNpm.versions.npm + ' / Node.js ' + operatorNpm.nodeVersion + '. Publishing changes the registry.',
    '# Save this section as a dedicated catchplate-npm.npmrc; keep environment references literal.',
    '# Never put the real npm token here. Use the existing app token only in CATCHPLATE_PROXY_TOKEN.',
    'registry=' + operatorNpm.origin + '/',
    'https-proxy=https://' + applicationId + ':${CATCHPLATE_PROXY_TOKEN}@' + proxy.host,
    '//registry.npmjs.org/:_authToken=' + operatorNpm.token,
    'strict-ssl=true', 'noproxy=', 'fetch-retries=0', 'update-notifier=false', 'cache=${CATCHPLATE_NPM_CACHE}',
    '', '# Public-publishing example: place your reviewed ./package.tgz in an empty test directory.',
    '# Explicitly run only after reviewing the tarball contents, package name and new version.',
    '# Its package.json name must be ' + packageName + '; tag ' + tag + '; publishing ' + npmPublishHours({publishing_window: publishingWindow}) + '.',
    '# Use a clean npm environment and a fresh private CATCHPLATE_NPM_CACHE; remove conflicting proxy/npm/TLS config.',
    '# No cafile or TLS-verification override. Extra CA is loaded before Node startup.',
    'NODE_EXTRA_CA_CERTS="$(realpath ' + quote(caPath || './catchplate-ca.pem') + ')" npm --userconfig ./catchplate-npm.npmrc --globalconfig /dev/null publish ./package.tgz --access=public --tag=' + quote(tag) + ' --ignore-scripts=true --provenance=false --force=false --dry-run=false --workspaces=false --json',
    '', '# No request was run by this page. If publication is uncertain, inspect metadata; do not automatically repeat publish.'
  ].join('\n');
}
