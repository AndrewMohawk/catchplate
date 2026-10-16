// Explicit metadata-only npm connection. Neither a generic Bearer key nor a
// registry URL grants this preset implicitly; source support is not live proof.
const operatorNpm = Object.freeze({origin: 'https://registry.npmjs.org', connection: 'npm_token_v1',
  // Joined to examples/npm-registry package/core/lock pins by the UI regression suite.
  versions: Object.freeze({npm: '11.21.1', pacote: '21.5.1', 'npm-registry-fetch': '19.1.1'}), nodeVersion: '25.5.0',
  bundle: 'npm_metadata_read_v1', response: 'npm_metadata_json_v1', token: 'serverware-npm-placeholder-v1',
  placeholder: 'Bearer serverware-npm-placeholder-v1', headers: ['accept', 'npm-auth-type', 'npm-command',
    'npm-in-ci', 'npm-scope', 'pacote-pkg-id', 'pacote-req-type', 'pacote-version', 'user-agent']});
function npmCapabilityDescriptor(destinationAllowed) {
  return {schema: 'serverware.operatorNpmMetadata/v1', connection_type: operatorNpm.connection,
    create_credential_path: '/api/operator-demo/credentials/npm-token', create_rule_path: '/api/operator-demo/access-rules/npm-metadata',
    registry_origin: operatorNpm.origin, destination_allowed: destinationAllowed,
    operation_bundles: [operatorNpm.bundle], sdk_auth_token: operatorNpm.token, placeholder: operatorNpm.placeholder,
    response_mode: operatorNpm.response, source_pair_required: true, metadata_only: true, max_active_rules_per_application: 1};
}
function projectNpmCapability(value) {
  return typeof value?.destination_allowed === 'boolean' && operatorExact(value, npmCapabilityDescriptor(value.destination_allowed)) ?
    npmCapabilityDescriptor(value.destination_allowed) : null;
}
function npmAvailable(catalog, credential) {
  return isNpmCredential(credential) && credential.status === 'active' &&
    projectNpmCapability(catalog?.capabilities.npm)?.destination_allowed === true && catalog.allowed_upstreams.includes(operatorNpm.origin);
}
function npmNewRuleAvailable(catalog, applicationId) {
  return !catalog?.access_rules.some(rule => {
    if (rule.status !== 'active' || rule.application_id !== applicationId) return false;
    if (isNpmRule(rule) || isNpmInstallRule(rule)) return true;
    if (!rule.methods?.includes('GET')) return false;
    try { const target = new URL(rule.upstream_url); return target.origin === operatorNpm.origin && /^\/[^/]+$/.test(target.pathname); }
    catch (_) { return true; }
  });
}

// Installation is an additive typed bundle, never inferred from metadata access.
const operatorNpmInstall = Object.freeze({bundle: 'npm_install_v1', response: 'npm_install_v1',
  headers: ['accept', 'content-type', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope',
    'pacote-integrity', 'pacote-pkg-id', 'pacote-req-type', 'pacote-version', 'user-agent']});
function npmInstallCapabilityDescriptor() {
  return {schema: 'serverware.operatorNpmInstall/v1', connection_type: operatorNpm.connection,
    create_rule_path: '/api/operator-demo/access-rules/npm-install', registry_origin: operatorNpm.origin,
    destination_allowed: true, operation_bundles: [operatorNpmInstall.bundle], sdk_auth_token: operatorNpm.token,
    placeholder: operatorNpm.placeholder, response_mode: operatorNpmInstall.response, source_pair_required: true,
    max_active_rules_per_application: 1, max_packages: 64, modes: ['metadata', 'tarball', 'audit'],
    dependencies_require_explicit_grant: true};
}
function projectNpmInstallCapability(value) {
  return operatorExact(value, npmInstallCapabilityDescriptor()) ? npmInstallCapabilityDescriptor() : null;
}
function npmInstallAvailable(catalog, credential) {
  return isNpmCredential(credential) && credential.status === 'active' &&
    Boolean(projectNpmInstallCapability(catalog?.capabilities?.npm_install)) && catalog.allowed_upstreams.includes(operatorNpm.origin);
}
function npmInstallNewRuleAvailable(catalog, applicationId) {
  return !catalog?.access_rules.some(rule => {
    if (rule.status !== 'active' || rule.application_id !== applicationId) return false;
    try { return new URL(rule.upstream_url).origin === operatorNpm.origin; }
    catch (_) { return true; }
  });
}
function npmInstallRuleFields(packages) {
  if (!npmPackagesValid(packages)) throw operatorError('List every intended npm package and dependency explicitly (1–64 exact names).');
  return {operation_bundle: operatorNpmInstall.bundle, packages: [...packages], upstream_url: operatorNpm.origin + '/',
    methods: ['GET', 'POST'], request_fields: [], response_fields: [], query_keys: [], allowed_headers: [...operatorNpmInstall.headers],
    response_mode: operatorNpmInstall.response, credential_input: 'replace_exact', placeholder: operatorNpm.placeholder};
}
function npmInstallRuleValid(rule, credential) {
  try {
    return isNpmCredential(credential) && credential.provider_id === 'npm' && credential.auth_type === 'bearer' &&
      credential.header_name === 'Authorization' &&
      !['query_mode', 'request_body_mode', 'age_policy', 'repository', 'package', 'tag', 'publishing_window'].some(key => Object.hasOwn(rule, key)) &&
      Object.entries(npmInstallRuleFields(rule.packages)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function npmInstallRulePayload(rule) {
  npmInstallRuleFields(rule.packages);
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorNpmInstall.bundle, packages: [...rule.packages]};
}
function npmInstallRuleRestrictions(rule) {
  return [['Permission', 'Install packages and run npm audit'], ['Registry', operatorNpm.origin],
    ['Explicit package and dependency allowlist', rule.packages.join(', ')],
    ['Allowed use', 'Metadata GET, package tarball GET and fixed bulk advisory POST for these exact packages only.'],
    ['Excluded use', 'No publish, arbitrary registry writes, URLs, git dependencies or automatic dependency grants.'],
    ['Local client', 'Use the reviewed install/ci example with lifecycle scripts disabled; default audit remains enabled.'],
    ['Verification', 'Permission and client setup only. Stock-client proxy verification and provider access are not proven by this page.']];
}
function renderNpmInstallCompatibility(id) {
  element(id).replaceChildren(...npmInstallRuleRestrictions({packages: ['every intended package, including each dependency']})
    .map(([label, value]) => textNode('p', label + ': ' + value, 'small muted')));
}
function buildNpmInstallClientRecipe({proxyUrl, applicationId, proxyAuthentication, packages, caPath = './serverware-ca.pem'}) {
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId) ||
      proxyAuthentication !== 'basic_and_bearer_v1' || !npmPackagesValid(packages) ||
      typeof caPath !== 'string' || caPath.length > 512 || /[\u0000-\u001f\u007f]/.test(caPath))
    throw new Error('An exact npm installation permission and standard proxy login are required');
  const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
  return ['# From the reviewed examples/npm-registry project; no command runs in this page.',
    '# Explicitly permitted package names (including dependencies): ' + packages.join(', '),
    '# Set SERVERWARE_PROXY_TOKEN privately to this app token, never a provider token.',
    '# Set SERVERWARE_NPM_PACKAGE and SERVERWARE_NPM_VERSION to the intended exact package/version.',
    '# Set SERVERWARE_NPM_PROJECT to an absolute reviewed source directory (package.json).',
    '# Set SERVERWARE_NPM_OUTPUT to a new absolute directory that does not exist; output is retained.',
    '# ci additionally requires the original package-lock.json v3. Only manifests/lock are copied.',
    'export SERVERWARE_PROXY_URL=' + quote(proxyUrl), 'export SERVERWARE_APP_ID=' + quote(applicationId),
    'export SERVERWARE_CA_FILE=' + quote(caPath || './serverware-ca.pem'),
    '# Both TLS legs stay verified. The public npm dummy is supplied by the example.',
    '# Lifecycle scripts are disabled; default npm audit remains on. Never hide an audit failure.',
    'node client.mjs install', '# Or explicitly use the reviewed lockfile instead:', '# node client.mjs ci',
    '# No package or provider entitlement was verified by generating this recipe.'].join('\n');
}
function npmPackagesValid(packages) {
  return Array.isArray(packages) && packages.length >= 1 && packages.length <= 64 &&
    packages.every((name, index) => typeof name === 'string' && name.length <= 214 &&
      /^(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*)$/.test(name) &&
      (index === 0 || packages[index - 1] < name));
}
function npmPackageInput(text) {
  const packages = text.split(/\r?\n/).map(name => name.trim()).filter(Boolean).sort();
  if (!npmPackagesValid(packages)) throw operatorError('Enter 1–64 unique, exact lowercase package names, one per line. No wildcards, URLs or version suffixes.');
  return packages;
}
function npmRuleFields(packages) {
  if (!npmPackagesValid(packages)) throw operatorError('Choose an explicit sorted list of 1–64 unique npm packages.');
  return {operation_bundle: operatorNpm.bundle, packages: [...packages], upstream_url: operatorNpm.origin + '/',
    methods: ['GET'], request_fields: [], response_fields: [], query_keys: [], allowed_headers: [...operatorNpm.headers],
    response_mode: operatorNpm.response, credential_input: 'replace_exact', placeholder: operatorNpm.placeholder};
}
function npmRuleValid(rule, credential) {
  try {
    return isNpmCredential(credential) && credential.provider_id === 'npm' && credential.auth_type === 'bearer' &&
      credential.header_name === 'Authorization' && !['query_mode', 'request_body_mode', 'age_policy', 'repository'].some(key => Object.hasOwn(rule, key)) &&
      Object.entries(npmRuleFields(rule.packages)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function npmRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorNpm.bundle, packages: [...rule.packages]};
}
function npmRuleRestrictions(rule) {
  return [['Permission', 'Read package metadata'], ['Registry', operatorNpm.origin],
    ['Packages', Array.isArray(rule.packages) ? rule.packages.join(', ') : 'Choose explicit package names'],
    ['Allowed use', 'npm view and pacote.manifest metadata lookups only. GET, no body or query parameters.'],
    ['Excluded use', 'No install, publish, tarball downloads, npm audit, search, login or other registry operations.'],
    ['Response', 'Bounded metadata JSON, without field filtering. No binary content, redirects or streaming.'],
    ['Client authentication', 'Fixed public dummy npm token; a separate Serverware app token authenticates to the HTTPS proxy.']];
}
function renderNpmCompatibility(id) {
  element(id).replaceChildren(...[
    'Read package metadata supports npm view and pacote.manifest for only the explicitly named packages. Scoped names are supported. Package authority does not include dependencies automatically.',
    'No install, publish, tarball downloads, npm audit, search, account login or other registry operations. GET only, without request bodies or query parameters. No cache-validation or empty 304 response path.',
    'Whole metadata JSON responses: HTTP 200 up to 1 MiB; supported provider errors up to 64 KiB. No response-field setup. Standard metadata is checked and discarded; no response headers are forwarded.',
    'Use a dedicated fresh client cache and zero automatic retries. Ordinary npm/pacote metadata headers are supported; compression offers are removed before forwarding. Compressed responses, redirects and streaming remain unsupported.',
    'One active npm metadata permission per application. Include every intended package in that one explicit list. Changing it requires explicit revocation and a new grant; this page never broadens an existing permission.',
    'The stock npm recipe requires standard username/password proxy login. The public application ID is the username and its Serverware token is the password, never the real npm token.',
    'Set NODE_EXTRA_CA_CERTS before starting npm or Node. It adds the downloaded interception CA to Node default public roots for both outer proxy and destination TLS. If the outer proxy has a private CA, use a deliberately scoped additional-CA file containing both required roots; do not disable TLS or override cafile.',
    'A loaded policy is not a successful package lookup or proof of a valid npm token. The recipe targets the pinned npm/pacote versions; source configuration alone is not runtime acceptance. This page performs no provider request.'
  ].map(text => textNode('p', text, 'small muted')));
}
function buildNpmClientRecipe({proxyUrl, applicationId, proxyAuthentication, packages, packageName, caPath = './serverware-ca.pem'}) {
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId) ||
      proxyAuthentication !== 'basic_and_bearer_v1' || !npmPackagesValid(packages) || !packages.includes(packageName) ||
      typeof caPath !== 'string' || caPath.length > 512 || /[\u0000-\u001f\u007f]/.test(caPath))
    throw new Error('An exact npm metadata permission and standard proxy login are required');
  const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
  return ['# npm ' + operatorNpm.versions.npm + ' / Node.js ' + operatorNpm.nodeVersion + '; metadata only, not install or publish.',
    '# Save these settings in a dedicated serverware-npm.npmrc in an empty test directory.',
    '# Keep environment references literal. The real npm token never belongs here.',
    'registry=' + operatorNpm.origin + '/',
    'https-proxy=https://' + applicationId + ':${SERVERWARE_PROXY_TOKEN}@' + proxy.host,
    '//registry.npmjs.org/:_authToken=' + operatorNpm.token,
    'strict-ssl=true', 'noproxy=', 'fetch-retries=0', 'update-notifier=false',
    'cache=${SERVERWARE_NPM_CACHE}',
    '', '# Then run from that empty directory in a clean npm environment.',
    '# SERVERWARE_PROXY_TOKEN: existing app token; SERVERWARE_NPM_CACHE: fresh private cache path.',
    '# Remove conflicting proxy/npm/TLS configuration. No cafile or TLS-verification override.',
    '# Extra CA is loaded at process startup; Node default public roots remain trusted.',
    'NODE_EXTRA_CA_CERTS="$(realpath ' + quote(caPath || './serverware-ca.pem') + ')" npm --userconfig ./serverware-npm.npmrc --globalconfig /dev/null view ' + quote(packageName) + ' --json',
    '', '# This page has not executed the recipe or verified this package/token.'
  ].join('\n');
}
