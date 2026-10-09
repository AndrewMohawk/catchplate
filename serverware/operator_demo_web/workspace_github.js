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
function githubAvailable(catalog, credential) {
  return isGithubCredential(credential) && credential.status === 'active' &&
    projectGithubCapability(catalog?.capabilities.github)?.destination_allowed === true &&
    catalog.allowed_upstreams.includes(operatorGithub.origin);
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
