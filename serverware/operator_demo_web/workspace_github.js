// Explicit GitHub connection and named-job contracts. A generic Bearer key is
// never upgraded implicitly, and a source capability is not a runtime receipt.
const operatorGithub = Object.freeze({origin: 'https://api.github.com', connection: 'github_token_v1',
  read: 'github_issues_read_v1', write: 'github_issues_write_v1',
  token: 'serverware-github-placeholder-v1', placeholder: 'token serverware-github-placeholder-v1'});
function githubCapabilityDescriptor(destinationAllowed) {
  return {schema: 'serverware.operatorGithub/v1', connection_type: operatorGithub.connection,
    create_credential_path: '/api/operator-demo/credentials/github-token', create_rule_path: '/api/operator-demo/access-rules/github',
    api_origin: operatorGithub.origin, destination_allowed: destinationAllowed,
    operation_bundles: [operatorGithub.read, operatorGithub.write], sdk_auth_token: operatorGithub.token,
    placeholder: operatorGithub.placeholder, query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2',
    source_pair_required: true};
}
function projectGithubCapability(value) {
  if (typeof value?.destination_allowed !== 'boolean' || !operatorExact(value, githubCapabilityDescriptor(value.destination_allowed))) return null;
  return githubCapabilityDescriptor(value.destination_allowed);
}
function githubAppCapabilityDescriptor(destinationAllowed) {
  return {...githubCapabilityDescriptor(destinationAllowed), schema: 'serverware.operatorGithubApp/v1',
    connection_type: 'github_app_v1', create_credential_path: '/api/operator-demo/credentials/github-app'};
}
function projectGithubAppCapability(value) {
  return typeof value?.destination_allowed === 'boolean' && operatorExact(value, githubAppCapabilityDescriptor(value.destination_allowed)) ?
    githubAppCapabilityDescriptor(value.destination_allowed) : null;
}
function projectGithubAppKeyReplacementCapability(value) {
  const expected = {schema: 'serverware.operatorGithubAppKeyReplacement/v1',
    path: '/api/operator-demo/credentials/github-app/replace-key'};
  return operatorExact(value, expected) ? {...expected} : null;
}
function projectGithubAppKeyMetadata(credential) {
  if (!isGithubAppCredential(credential)) return {};
  // Historical inventories may omit this metadata; they cannot offer replacement.
  if (!Object.hasOwn(credential, 'credential_generation') && !Object.hasOwn(credential, 'key_replaced_at')) return {};
  const generation = credential.credential_generation, time = credential.key_replaced_at;
  const hasTime = Object.hasOwn(credential, 'key_replaced_at');
  if (!(credential.status === 'active' ? Number.isSafeInteger(generation) && generation > 0 :
      credential.status === 'revoked' && generation === null) || hasTime && (typeof time !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(time) ||
      !Number.isFinite(Date.parse(time)) || new Date(time).toISOString().slice(0, 19) !== time.slice(0, 19)))
    throw operatorError('Saved GitHub App key metadata is incomplete. Refresh before making changes.');
  return {credential_generation: generation, ...(hasTime ? {key_replaced_at: time} : {})};
}
function githubAppKeyReplacementAvailable(catalog, credential) {
  try {
    if (!projectGithubAppKeyReplacementCapability(catalog?.capabilities?.github_app_key_replacement) ||
        !githubAppDestinationAvailable(catalog) || !isGithubAppCredential(credential) || credential.status !== 'active') return false;
    projectGithubAppMetadata(credential);
    const generation = projectGithubAppKeyMetadata(credential).credential_generation;
    return Number.isSafeInteger(generation) && generation > 0 && generation < Number.MAX_SAFE_INTEGER;
  } catch (_) { return false; }
}
function githubAppDestinationAvailable(catalog) {
  return projectGithubAppCapability(catalog?.capabilities?.github_app)?.destination_allowed === true &&
    catalog.allowed_upstreams.includes(operatorGithub.origin);
}
function githubIdValid(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value) &&
    (value.length < 16 || value <= '9007199254740991');
}
function projectGithubAppMetadata(credential) {
  const value = credential?.github_app;
  if (!isGithubAppCredential(credential) || credential.provider_id !== 'github' || credential.auth_type !== 'bearer' ||
      credential.header_name !== 'Authorization' || credential.legacy_upstream_origin || !value ||
      !operatorExact(Object.keys(value).sort(), ['account_id', 'app_id', 'installation_id', 'issues_permission', 'repository', 'repository_id', 'token_refresh']) ||
      !['app_id', 'installation_id', 'account_id', 'repository_id'].every(key => githubIdValid(value[key])) ||
      !githubRepositoryValid(value.repository) || !['read', 'write'].includes(value.issues_permission) || value.token_refresh !== 'automatic')
    throw operatorError('Saved GitHub App binding is unsupported. Refresh before making changes.');
  return {github_app: {app_id: value.app_id, installation_id: value.installation_id, account_id: value.account_id,
    repository_id: value.repository_id, repository: {owner: value.repository.owner, name: value.repository.name},
    issues_permission: value.issues_permission, token_refresh: 'automatic'}};
}
function githubPermissionBundles(credential) {
  if (!isGithubAppCredential(credential)) return [operatorGithub.read, operatorGithub.write];
  try { return projectGithubAppMetadata(credential).github_app.issues_permission === 'write' ?
    [operatorGithub.read, operatorGithub.write] : [operatorGithub.read]; }
  catch (_) { return []; }
}
function githubAppCredentialReceipt(credential, submitted) {
  const binding = projectGithubAppMetadata(credential).github_app;
  if (credential.status !== 'active' || credential.name !== submitted?.name ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(credential.id || '') ||
      typeof credential.created_at !== 'string' || !Number.isFinite(Date.parse(credential.created_at)) ||
      !['app_id', 'installation_id', 'repository', 'issues_permission'].every(key => operatorExact(binding[key], submitted[key])))
    throw operatorError('The exact saved GitHub App connection was not confirmed. Inspect saved state; do not submit again.');
  return {id: credential.id, name: credential.name, status: credential.status, created_at: credential.created_at,
    auth_type: credential.auth_type, header_name: credential.header_name, connection_type: credential.connection_type,
    provider_id: credential.provider_id, github_app: binding};
}
function githubAppCredentialReceiptMatches(credential, expected) {
  try { return operatorExact(githubAppCredentialReceipt(credential, {name: expected.name, ...expected.github_app}), expected); }
  catch (_) { return false; }
}
function githubAvailable(catalog, credential) {
  const capability = isGithubAppCredential(credential) ? projectGithubAppCapability(catalog?.capabilities?.github_app) :
    projectGithubCapability(catalog?.capabilities?.github);
  return isGithubCredential(credential) && credential.status === 'active' && githubPermissionBundles(credential).length > 0 &&
    capability?.destination_allowed === true && catalog.allowed_upstreams.includes(operatorGithub.origin);
}
function githubRepositoryValid(repository) {
  return repository && operatorExact(Object.keys(repository).sort(), ['name', 'owner']) &&
    typeof repository.owner === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(repository.owner) &&
    typeof repository.name === 'string' && /^[A-Za-z0-9._-]{1,100}$/.test(repository.name) && !['.', '..'].includes(repository.name);
}
function githubPermissionName(bundle) {
  return bundle === operatorGithub.read ? 'Read issues and comments' : bundle === operatorGithub.write ?
    'Read and create issues/comments' : 'Unsupported GitHub permission';
}
function githubRuleFields(bundle, repository) {
  if (![operatorGithub.read, operatorGithub.write].includes(bundle) || !githubRepositoryValid(repository))
    throw operatorError('Choose a supported GitHub permission and exact repository owner/name.');
  return {operation_bundle: bundle, repository: {owner: repository.owner, name: repository.name},
    upstream_url: operatorGithub.origin + '/repos/' + repository.owner + '/' + repository.name + '/issues',
    methods: bundle === operatorGithub.write ? ['GET', 'POST'] : ['GET'],
    request_fields: [], response_fields: [], request_body_mode: 'preserve_json_v1',
    query_keys: ['assignee', 'creator', 'direction', 'labels', 'mentioned', 'milestone', 'page', 'per_page', 'since', 'sort', 'state'],
    allowed_headers: ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent', 'x-github-api-version'],
    credential_input: 'replace_exact', placeholder: operatorGithub.placeholder,
    query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2'};
}
function githubRuleValid(rule, credential) {
  try {
    return isGithubCredential(credential) && credential.provider_id === 'github' &&
      credential.auth_type === 'bearer' && credential.header_name === 'Authorization' && !Object.hasOwn(rule, 'age_policy') &&
      (isGithubAppCredential(credential) ? githubPermissionBundles(credential).includes(rule.operation_bundle) &&
        operatorExact(rule.repository, projectGithubAppMetadata(credential).github_app.repository) : !Object.hasOwn(credential, 'github_app')) &&
      Object.entries(githubRuleFields(rule.operation_bundle, rule.repository)).every(([key, value]) => operatorExact(rule[key], value));
  } catch (_) { return false; }
}
function githubRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: rule.operation_bundle, repository: {owner: rule.repository.owner, name: rule.repository.name}};
}
function buildGithubClientRecipe({proxyUrl, applicationId, proxyAuthentication, repository, bundle, operation = 'read',
    caPath = './serverware-ca.pem', proxyCaPath = ''}) {
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId) ||
      !['bearer', 'basic_and_bearer_v1'].includes(proxyAuthentication) || !githubRepositoryValid(repository) ||
      ![operatorGithub.read, operatorGithub.write].includes(bundle) || !['read', 'create'].includes(operation) ||
      operation === 'create' && bundle !== operatorGithub.write)
    throw new Error('A supported saved GitHub permission and proxy application are required');
  for (const value of [caPath, proxyCaPath]) if (typeof value !== 'string' || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value))
    throw new Error('CA file paths must be printable text');
  const literal = value => JSON.stringify(value);
  const lines = [
    '// Node.js >=22.19, ESM. Install @octokit/rest@22.0.1 and undici@8.11.2.',
    '// SERVERWARE_PROXY_TOKEN is the app token, NOT the GitHub token.',
    "import { readFileSync } from 'node:fs';",
    "import { Octokit } from '@octokit/rest';",
    "import { ProxyAgent, fetch as undiciFetch } from 'undici';",
    "const appToken = process.env.SERVERWARE_PROXY_TOKEN;",
    "if (!appToken) throw new Error('Set the Serverware application token in the environment');",
    'const proxy = new ProxyAgent({',
    '  uri: ' + literal(proxyUrl) + ',',
    proxyAuthentication === 'basic_and_bearer_v1' ?
      '  token: \'Basic \' + Buffer.from(' + literal(applicationId + ':') + ' + appToken).toString(\'base64\'),' :
      "  token: 'Bearer ' + appToken,",
    proxyCaPath ? '  proxyTls: { ca: readFileSync(' + literal(proxyCaPath) + '), rejectUnauthorized: true },' :
      '  proxyTls: { rejectUnauthorized: true }, // outer proxy: Node default trust',
    '  requestTls: { ca: readFileSync(' + literal(caPath || './serverware-ca.pem') + '), rejectUnauthorized: true },',
    '});',
    'const octokit = new Octokit({',
    '  auth: ' + literal(operatorGithub.token) + ', // public dummy; never replace with the real GitHub token',
    '  request: { fetch: (url, options) => undiciFetch(url, { ...options, dispatcher: proxy }) },',
    '});',
    'const repository = { owner: ' + literal(repository.owner) + ', repo: ' + literal(repository.name) + ' };',
    '// No retry/throttling plugins. Do not retry an uncertain creation automatically.',
    'try {'
  ];
  if (operation === 'read') lines.push(
    '  const issues = await octokit.paginate(octokit.rest.issues.listForRepo, { ...repository, per_page: 100 });',
    '  console.log({ issueCount: issues.length });',
    '  if (issues.length) {',
    '    const issue_number = issues[0].number;',
    '    const issue = await octokit.rest.issues.get({ ...repository, issue_number });',
    '    const comments = await octokit.paginate(octokit.rest.issues.listComments, { ...repository, issue_number, per_page: 100 });',
    '    console.log({ issueNumber: issue.data.number, commentCount: comments.length });',
    '  }');
  else lines.push(
    '  // This example performs two writes. Set their content explicitly before running.',
    '  const title = process.env.SERVERWARE_ISSUE_TITLE;',
    '  const body = process.env.SERVERWARE_COMMENT_BODY;',
    "  if (!title || !body) throw new Error('Set an issue title and comment body before creating anything');",
    '  const issue = await octokit.rest.issues.create({ ...repository, title });',
    '  const comment = await octokit.rest.issues.createComment({ ...repository, issue_number: issue.data.number, body });',
    '  console.log({ issueNumber: issue.data.number, commentId: comment.data.id });');
  lines.push('} finally {', '  await proxy.close();', '}');
  return lines.join('\n');
}
function githubRuleRestrictions(rule) {
  return [['Permission', githubPermissionName(rule.operation_bundle)],
    ['Repository', rule.repository.owner + '/' + rule.repository.name + ' · api.github.com'],
    ['Allowed use', 'Read issue and comment lists, individual issues/comments and pagination.' +
      (rule.operation_bundle === operatorGithub.write ? ' Also create issues and comments.' : ' No writes.')],
    ['Excluded use', 'No edits, deletes, merges, repository changes or other GitHub APIs.'],
    ['Response', 'Supported JSON content and errors are retained without field filtering. Pagination and retry metadata remain bounded.'],
    ['Client authentication', 'Octokit uses a fixed public dummy token; Serverware supplies the stored GitHub token only after authorization.']];
}
function renderGithubCompatibility(id, rule) {
  element(id).replaceChildren(...[
    'This named-repository permission permits issue/comment reads and pagination' +
      (rule.operation_bundle === operatorGithub.write ? ', plus issue/comment creation.' : '. It does not permit writes.'),
    'No manual response-field list. Supported provider JSON errors and selected pagination/rate-limit metadata are preserved, not a claim that every GitHub endpoint or SDK operation is supported.',
    'GET requests have no body. Creation accepts bounded JSON up to 64 KiB. Responses: JSON up to 1 MiB success / 64 KiB error, or a strictly empty HTTP 204. No forms, binary content or streaming.',
    'Selected response metadata: Link, Retry-After, X-GitHub-Request-Id and the supported X-RateLimit fields. Values are bounded and checked; retry guidance does not authorize replay of an uncertain write.',
    'Pagination is checked against this permission and normalized back to the signed named repository; it does not grant direct numeric-repository URLs or another origin.',
    'Use the pinned Octokit/Undici recipe. Compression offers are removed before forwarding; compressed responses, streaming, redirects and arbitrary request headers are not supported.',
    'A loaded policy confirms publication, not a successful GitHub request or valid provider token. A denied request and an uncertain post-dispatch outcome are different: do not automatically retry creation after a lost response.'
  ].map(value => textNode('p', value, 'small muted')));
}
function createGithubAppKeyReplacementView(workspace) {
  const panel = element('github-app-replace-panel'), form = element('github-app-replace-form');
  const secret = element('github-app-replace-private-key'); let draft = null;
  const caveat = 'Existing installation tokens, proxy leases and in-flight requests are not recalled. ' +
    'Delete the old private key separately in GitHub after reviewing the replacement. Application proxy tokens and their expiry are unchanged.';
  const message = value => { element('github-app-replace-status').textContent = value; };
  const writable = () => Boolean(workspace.state.catalog && !workspace.state.busy && !workspace.state.uncertain);
  function identity(credential) {
    return JSON.stringify({resource: keyReplacementIdentity(credential),
      app: githubAppCredentialReceipt(credential, {name: credential.name, ...projectGithubAppMetadata(credential).github_app})});
  }
  function review(id) {
    const catalog = workspace.state.catalog, credential = catalog?.credentials.find(item => item.id === id);
    if (!githubAppKeyReplacementAvailable(catalog, credential) ||
        !Number.isSafeInteger(catalog.policy.sequence) || catalog.policy.sequence < 1) return null;
    let boundIdentity;
    try { boundIdentity = identity(credential); } catch (_) { return null; }
    return {id, generation: credential.credential_generation, revision: catalog.revision,
      policyHash: catalog.policy.policy_hash, sequence: catalog.policy.sequence, identity: boundIdentity,
      bindings: keyReplacementBindings(catalog), replacedAt: credential.key_replaced_at,
      capability: catalog.capabilities.github_app_key_replacement};
  }
  function close() {
    secret.value = ''; draft = null; panel.hidden = true; element('github-app-replace-fields').disabled = true;
  }
  function render() {
    if (draft && (!writable() || !operatorExact(review(draft.id), draft))) {
      close(); message('Saved state changed or became unavailable. The private key was cleared. Review the connection and open replacement again; no request was retried.');
    }
    element('github-app-replace-fields').disabled = !draft || !writable();
  }
  function open(id) {
    close(); if (!writable()) return;
    draft = review(id); if (!draft) return;
    const catalog = workspace.state.catalog, credential = catalog.credentials.find(item => item.id === id);
    element('github-app-replace-title').textContent = 'Replace GitHub App private key · ' + credential.name;
    element('github-app-replace-binding').textContent = 'GitHub App ' + credential.github_app.app_id + ' · installation ' +
      credential.github_app.installation_id + ' · ' + credential.github_app.repository.owner + '/' + credential.github_app.repository.name +
      ' · ' + githubPermissionName(credential.github_app.issues_permission === 'write' ? operatorGithub.write : operatorGithub.read);
    const rules = catalog.access_rules.filter(item => item.status === 'active' && item.credential_id === id);
    const ids = new Set(rules.map(item => item.application_id));
    const apps = operatorConnectResourceChoices(catalog.applications.filter(item => ids.has(item.id)));
    element('github-app-replace-count').textContent = apps.length + ' affected app' + (apps.length === 1 ? '' : 's') +
      ' · ' + rules.length + ' active access rule' + (rules.length === 1 ? '' : 's') + '. Existing permissions stay unchanged.';
    element('github-app-replace-apps').replaceChildren(...(apps.length ? apps.map(item => {
      const row = textNode('li', item.name); row.dataset.applicationId = item.id; return row;
    }) : [textNode('li', 'No apps currently have access through this connection.')]));
    message(''); panel.hidden = false; render(); secret.focus();
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!draft || !writable()) { secret.value = ''; return; }
    if (!operatorExact(review(draft.id), draft)) { render(); return; }
    if (!form.reportValidity() || !secret.value || new TextEncoder().encode(secret.value).length > 8192) {
      secret.value = ''; message('Enter the new GitHub App private key PEM, up to 8192 UTF-8 bytes. The value was cleared.'); return;
    }
    const reviewed = draft, body = {id: draft.id, expected_credential_generation: draft.generation, private_key_pem: secret.value};
    close(); // Both DOM and request object are cleared before awaiting the response.
    let receipt = null;
    const accepted = await workspace.mutate('credentials/github-app/replace-key', body, 'github-app-replace-status', result => {
      const credential = result.credential, replacement = result.key_replacement;
      const metadata = projectGithubAppKeyMetadata(credential);
      if (!credential || identity(credential) !== reviewed.identity || metadata.credential_generation !== reviewed.generation + 1 ||
          !metadata.key_replaced_at || result.revision !== reviewed.revision + 1 ||
          result.policy?.policy_hash !== reviewed.policyHash || result.policy.sequence !== reviewed.sequence ||
          !operatorExact(replacement, {previous_credential_generation: reviewed.generation, credential_generation: reviewed.generation + 1,
            cache_invalidation: replacement?.cache_invalidation, in_flight_requests: 'not_recalled'}) ||
          !['local_completed', 'local_unconfirmed'].includes(replacement.cache_invalidation))
        throw operatorError('The GitHub App replacement receipt could not be confirmed. Review saved state; do not assume rollback or repeat the request.');
      receipt = {generation: metadata.credential_generation, replacedAt: metadata.key_replaced_at, cache: replacement.cache_invalidation};
    }).finally(() => { body.private_key_pem = ''; });
    if (!accepted) return;
    const catalog = workspace.state.catalog, current = catalog?.credentials.find(item => item.id === reviewed.id);
    const confirmed = receipt && current?.status === 'active' && isGithubAppCredential(current) && catalog.revision === reviewed.revision + 1 &&
      catalog.policy.policy_hash === reviewed.policyHash && catalog.policy.sequence === reviewed.sequence &&
      identity(current) === reviewed.identity && keyReplacementBindings(catalog) === reviewed.bindings &&
      current.credential_generation === receipt.generation && current.key_replaced_at === receipt.replacedAt;
    const notice = (confirmed ? 'GitHub App private-key replacement saved in Serverware. App identities, repository binding and access rules are unchanged. ' :
      'Replacement acknowledged, but refreshed saved state could not be confirmed. Refresh and review before another replacement; do not assume rollback. ') +
      (receipt?.cache === 'local_unconfirmed' ? 'Local cache invalidation was not confirmed. ' : '') + caveat;
    if (!confirmed) workspace.requireReview(notice);
    message(notice);
  });
  form.addEventListener('invalid', () => { secret.value = ''; }, true);
  element('github-app-replace-cancel').addEventListener('click', () => { close(); message('Replacement cancelled. No private key was submitted.'); });
  window.addEventListener('hashchange', close); window.addEventListener('pagehide', close);
  return {open, render};
}
