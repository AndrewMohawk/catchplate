#!/usr/bin/env node
// Synthetic rendered UI/DTO controls only. No backend, provider, proxy, CA
// download, SDK import or generated client recipe is executed by this suite.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const vm = require('node:vm');
const {ready, view, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest, pair, step, review, grant} = require('./test_operator_ordinary_modes_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const API = 'https://api.github.com';
const CREATE = '/api/operator-demo/credentials/github-token';
const GRANT = '/api/operator-demo/access-rules/github';
const READ = 'github_issues_read_v1';
const WRITE = 'github_issues_write_v1';
const DUMMY = 'serverware-github-placeholder-v1';
const PRIVATE = 'synthetic_github_provider_secret_NEVER_RENDER';
const ERROR = 'synthetic_private_provider_error_NEVER_RENDER';
const REPOSITORY = {owner: 'Example-Owner', name: 'Example.Repo'};
const QUERY = ['assignee', 'creator', 'direction', 'labels', 'mentioned', 'milestone', 'page', 'per_page', 'since', 'sort', 'state'];
const HEADERS = ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent', 'x-github-api-version'];
const AUTH = {schema: 'serverware.operatorProxyAuthentication/v1', modes: ['bearer', 'basic_and_bearer_v1'],
  path: '/api/operator-demo/applications/proxy-authentication'};
const clone = value => JSON.parse(JSON.stringify(value));
const capability = (destination = true) => ({schema: 'serverware.operatorGithub/v1', connection_type: 'github_token_v1',
  create_credential_path: CREATE, create_rule_path: GRANT, api_origin: API, destination_allowed: destination,
  operation_bundles: [READ, WRITE], sdk_auth_token: DUMMY, placeholder: 'token ' + DUMMY,
  query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2', source_pair_required: true});
const githubCredential = (changes = {}) => credential({name: 'Saved GitHub token', version: 1,
  credential_generation: 1, connection_type: 'github_token_v1', provider_id: 'github', ...changes});
// Independent closed server-field oracle: do not call the UI's rule generator.
const githubRule = (bundle = READ, changes = {}) => rule({name: 'Saved GitHub issues permission', version: 1,
  upstream_url: API + '/repos/' + REPOSITORY.owner + '/' + REPOSITORY.name + '/issues',
  operation_bundle: bundle, repository: clone(REPOSITORY), query_mode: 'githubRestV1',
  methods: bundle === WRITE ? ['GET', 'POST'] : ['GET'], request_fields: [], response_fields: [],
  request_body_mode: 'preserve_json_v1', query_keys: [...QUERY], allowed_headers: [...HEADERS],
  response_mode: 'unfiltered_json_or_empty_v2', credential_input: 'replace_exact', placeholder: 'token ' + DUMMY, ...changes});
const options = (changes = {}) => ({credentials: [githubCredential({secret: PRIVATE})],
  applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules: [],
  allowedUpstreams: [API], requestBodyModes: ['preserve_json_v1'],
  responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'], ...changes});
function catalog(state) {
  const value = publicCatalog(state);
  value.capabilities.application_proxy_authentication = clone(AUTH);
  if (state.githubCapability !== undefined) value.capabilities.github = clone(state.githubCapability);
  return value;
}
function exactCAS(state, body) {
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
}
function createCredential(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
  exactCAS(state, body); assert.equal(body.name, 'My GitHub token'); assert.equal(body.secret, PRIVATE);
  assert.deepEqual(state.githubCapability, capability(state.githubCapability.destination_allowed));
  assert.equal(state.credentials.length, 0);
  const saved = githubCredential({name: body.name}); state.credentials.push(saved); state.revision++;
  // Keep secret bytes out of fixture receipts and assertion summaries.
  body.secret = '';
  return {credential: catalog(state).credentials[0], revision: state.revision, policy: catalog(state).policy};
}
function createRule(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
    'expected_revision', 'name', 'operation_bundle', 'repository']);
  exactCAS(state, body); assert.deepEqual(state.githubCapability, capability(true));
  assert(state.allowedUpstreams.includes(API)); assert.deepEqual(body.repository, REPOSITORY);
  assert([READ, WRITE].includes(body.operation_bundle));
  assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
  assert.equal(body.name, (body.operation_bundle === READ ? 'Read issues and comments' : 'Read and create issues/comments') +
    ' · ' + REPOSITORY.owner + '/' + REPOSITORY.name);
  assert(state.credentials.some(item => item.id === body.credential_id && item.status === 'active' && item.connection_type === 'github_token_v1'));
  assert(state.applications.some(item => item.id === body.application_id && item.status === 'active'));
  assert.equal(state.rules.length, 0);
  const saved = githubRule(body.operation_bundle, {name: body.name}); state.rules.push(saved);
  state.revision++; state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
  return {access_rule: catalog(state).access_rules[0], revision: state.revision, policy: catalog(state).policy};
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => JSON.stringify({html: document.documentElement.outerHTML,
    inputs: [...document.querySelectorAll('input,textarea')].map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const value of [PRIVATE, ERROR]) assert(!surfaces.includes(value), 'provider material/raw errors must not remain in public surfaces or storage');
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.githubCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
    const observed = {creates: [], grants: [], requests: 0};
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(++observed.requests <= 40);
        let result; let status = 200;
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++;
          result = catalog(state);
        } else {
          assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= 16384);
          assert(request.headers()['content-type']?.startsWith('application/json'));
          const body = JSON.parse(bytes.toString()); status = 201;
          if (url.pathname === CREATE) {
            assert.equal(observed.creates.length, 0, 'never automatically repeat credential submission');
            result = createCredential(state, body);
            observed.creates.push({name: body.name, secretMatched: true, expected_revision: body.expected_revision,
              expected_policy_hash: body.expected_policy_hash});
          } else {
            assert.equal(url.pathname, GRANT); assert.equal(observed.grants.length, 0, 'never automatically repeat a grant');
            observed.grants.push(clone(body)); result = createRule(state, body);
            if (config.loseReceipt) { state.expectedFailures.add(GRANT); await route.abort('failed'); return; }
          }
        }
        await route.fulfill({status, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (_) { state.errors.push('GitHub fixture DTO/CAS boundary failed'); await route.abort(); }
    };
    for (const path of ['/api/operator-demo/catalog', CREATE, GRANT]) await controls.context.route(ORIGIN + path, handler);
    await page.reload({waitUntil: 'networkidle'});
    await exercise(page, state, observed);
    assert.deepEqual(state.posts, [], 'no unrelated creation, token rotation, consent, revoke or generic grant');
    assert(observed.creates.length <= 1 && observed.grants.length <= 1); await privateAbsent(page);
  });
}
async function refresh(page) {
  const response = page.waitForResponse(value => value.url() === ORIGIN + '/api/operator-demo/catalog' && value.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function form(page, bundle = READ) {
  await pair(page); await page.locator('#connect-operation').selectOption(bundle);
  await page.locator('#connect-github-owner').fill(REPOSITORY.owner); await page.locator('#connect-github-repo').fill(REPOSITORY.name);
  for (const id of ['connect-path', 'connect-response-mode', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
  }
  assert(await page.locator('#connect-github-repository').isVisible());
}
async function recipe(page, create = false, basic = true) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#github-client-controls').isVisible());
  const text = await page.locator('#client-command').innerText();
  assert(text.includes('@octokit/rest@22.0.1') && text.includes('undici@8.11.2'));
  assert(text.includes('process.env.SERVERWARE_PROXY_TOKEN') && text.includes('new ProxyAgent'));
  assert(text.includes('auth: "' + DUMMY + '"'));
  assert.equal(text.includes("token: 'Basic ' + Buffer.from"), basic);
  assert.equal(text.includes("token: 'Bearer ' + appToken"), !basic);
  assert(text.includes('proxyTls: { rejectUnauthorized: true }') && text.includes('requestTls: { ca: readFileSync'));
  assert(text.includes('rejectUnauthorized: true')); assert(!/rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|https:\/\/[^\s]+@/.test(text));
  assert.equal(text.includes('octokit.rest.issues.create('), create);
  assert.equal(text.includes('octokit.rest.issues.createComment('), create);
  if (!create) assert(text.includes('octokit.paginate(octokit.rest.issues.listForRepo') && text.includes('octokit.rest.issues.get('));
  assert.match(await page.locator('#client-guidance').innerText(), /No GitHub request was tested here/);
  return text;
}

const INPUTS = ['scripts/test_operator_github_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'workspace_core.js', 'workspace_github.js', 'workspace_google.js',
    'workspace_google_reauthorization.js', 'workspace_resources.js', 'workspace_applications.js',
    'workspace_proxy_audit.js', 'workspace_connect.js', 'app.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) { await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true,
  mask: [page.locator('#client-token'), page.locator('#connect-credential-secret')]}); }
function pureChecks() {
  const source = ['workspace_core.js', 'workspace_github.js'].map(name => readFileSync(join(ROOT, 'serverware/operator_demo_web', name), 'utf8')).join('\n');
  const state = {...options(), revision: 1, sequence: 1, active: digest(1), loaded: digest(1), githubCapability: capability(), rules: [githubRule()]};
  const evaluate = (expression, input) => vm.runInNewContext(source + '\n' + expression,
    {input, clientCredentialInput, credentialHeaderTarget, location: {origin: ORIGIN}, URL}, {timeout: 1000});
  const project = input => JSON.parse(JSON.stringify(evaluate('projectCatalog(input)', input)));
  assert.equal(project(catalog(state)).access_rules[0].operation_bundle, READ);
  for (const mutation of [{repository: {...REPOSITORY, extra: true}}, {query_mode: 'orderedFormV1'}, {methods: ['DELETE']},
    {placeholder: 'Bearer ' + DUMMY}, {response_fields: ['title']}, {allowed_headers: ['accept']}, {operation_bundle: 'future'}]) {
    const value = catalog(state); Object.assign(value.access_rules[0], mutation); assert.throws(() => project(value));
  }
  const generic = catalog(state); delete generic.credentials[0].connection_type; delete generic.credentials[0].provider_id;
  assert.throws(() => project(generic), 'a generic bearer never acquires GitHub authority implicitly');
  const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application, proxyAuthentication: 'basic_and_bearer_v1',
    repository: clone(REPOSITORY), bundle: READ};
  const text = evaluate('buildGithubClientRecipe(input)', input);
  assert(text.includes('"./serverware-ca.pem"')); assert(text.includes('22.19'));
  for (const key of ['caPath', 'proxyCaPath']) for (const value of ['bad\npath', 'bad\rpath'])
    assert.throws(() => evaluate('buildGithubClientRecipe(input)', {...input, [key]: value}));
  assert.throws(() => evaluate('buildGithubClientRecipe(input)', {...input, operation: 'create'}));
  return {ok: true, pureGroups: 1, scope: 'closed projection and recipe text only; no SDK or transport execution'};
}

const tests = [
  ['missing or malformed GitHub capability disables its entry without disabling generic credentials', async browser => {
    for (const cap of [undefined, {...capability(), create_rule_path: '/other'}, {...capability(), source_pair_required: false}])
      await fixture(browser, {capability: cap}, async (page, state, observed) => {
        await ready(page); await view(page, 'connect'); assert(await page.locator('#connect-use-github').isDisabled());
        assert(!await page.locator('#connect-use-key').isDisabled()); assert.match(await page.locator('#connect-github-status').innerText(), /not advertised/);
        assert.equal(observed.creates.length + observed.grants.length, 0);
      });
  }],
  ['GitHub token save is separate from permissions and never tests or echoes the provider token', browser => fixture(browser,
    {credentials: [], capability: capability(false), allowedUpstreams: []}, async (page, state, observed) => {
      await ready(page); await view(page, 'connect'); assert(!await page.locator('#connect-use-github').isDisabled());
      assert.match(await page.locator('#connect-github-status').innerText(), /can be saved.*cannot be granted/i);
      await page.locator('#connect-use-github').click(); assert(await page.locator('#connect-credential-auth-group').isHidden());
      await page.locator('#connect-credential-name').fill('My GitHub token'); await page.locator('#connect-credential-secret').fill(PRIVATE);
      await page.locator('#connect-credential-next').click(); await step(page, 'application');
      assert.equal(observed.creates.length, 1); assert.equal(observed.grants.length, 0); assert.equal(state.rules.length, 0);
      assert.equal(await page.locator('#connect-credential-secret').inputValue(), ''); assert.equal(state.active, digest(1));
      await privateAbsent(page);
    })],
  ['read permission sends only repository DTO and waits for exact policy before SDK setup', browser => fixture(browser,
    {autoLoad: false}, async (page, state, observed) => {
      await form(page); await review(page); assert.equal(observed.grants.length, 0);
      assert.match(await page.locator('#connect-review-details').innerText(), /Read issues.*Example-Owner\/Example.Repo/s);
      await grant(page); assert.equal(observed.grants.length, 1); assert(await page.locator('#connect-setup-slot').isHidden());
      assert.match(await page.locator('#connect-activation').innerText(), /Waiting/);
      state.loaded = state.active; await refresh(page); const text = await recipe(page);
      assert(await page.locator('#github-client-operation option[value="create"]').isDisabled());
      await page.locator('#copy-command').click(); assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
      await screenshot(page, 'github-read-desktop'); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await screenshot(page, 'github-read-mobile');
      assert.equal(observed.creates.length, 0);
    })],
  ['write permission permits only explicit creation recipe with separate TLS trust and no implicit request', browser => fixture(browser,
    {}, async (page, state, observed) => {
      await form(page, WRITE); await review(page); await grant(page); await recipe(page);
      await page.locator('#github-client-operation').selectOption('create'); await recipe(page, true);
      await page.locator('#github-proxy-ca-path').fill('./outer-proxy.pem');
      const text = await page.locator('#client-command').innerText();
      assert(text.includes('proxyTls: { ca: readFileSync("./outer-proxy.pem"), rejectUnauthorized: true }'));
      assert(text.includes('SERVERWARE_ISSUE_TITLE') && text.includes('SERVERWARE_COMMENT_BODY'));
      assert.equal(observed.grants.length, 1); assert.equal(observed.creates.length, 0);
      assert.equal(state.rules[0].operation_bundle, WRITE); assert.deepEqual(state.rules[0].methods, ['GET', 'POST']);
    })],
  ['saved permission reuse preserves bearer app mode and never resends a token or grant', browser => fixture(browser,
    {applications: [application()], rules: [githubRule()]}, async (page, state, observed) => {
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      await recipe(page, false, false); assert.equal(observed.creates.length + observed.grants.length, 0);
      assert(!Object.hasOwn(state.applications[0], 'proxy_authentication')); assert.equal(state.credentials.length, 1);
    })],
  ['stale review or withdrawn destination blocks grant while preserving the reviewed repository', async browser => {
    for (const withdrawal of [false, true]) await fixture(browser, {}, async (page, state, observed) => {
      await form(page); await review(page);
      if (withdrawal) { state.githubCapability = capability(false); state.allowedUpstreams = []; } else state.revision++;
      await refresh(page); assert(await page.locator('#connect-grant').isDisabled()); assert.equal(observed.grants.length, 0);
      await page.locator('#connect-back').click(); assert.equal(await page.locator('#connect-github-owner').inputValue(), REPOSITORY.owner);
      assert.equal(await page.locator('#connect-github-repo').inputValue(), REPOSITORY.name);
      if (withdrawal) assert.match(await page.locator('#connect-github-summary').innerText(), /unavailable/);
    });
  }],
  ['lost committed grant receipt is uncertain and never automatically resubmitted', browser => fixture(browser,
    {loseReceipt: true}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(observed.grants.length, 1); assert.equal(state.rules.length, 1); assert(await page.locator('#connect-grant').isDisabled());
      assert(await page.locator('#connect-setup-step').isHidden()); await refresh(page); assert.equal(observed.grants.length, 1);
    })],
  ['denied destination retains token inventory but cannot become a generic or ready GitHub permission', browser => fixture(browser,
    {capability: capability(false), allowedUpstreams: [], rules: [githubRule()]}, async (page, state, observed) => {
      await ready(page); await view(page, 'credentials'); assert.match(await page.locator('#credentials-list').innerText(), /Saved GitHub token/);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled()); assert.equal(observed.grants.length + observed.creates.length, 0);
      assert.equal(state.rules[0].operation_bundle, READ);
    })],
];
async function main() {
  assert.equal(process.argv.length, 2, 'No live target, selector or execution arguments are accepted');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify(pureChecks()));
  const directory = '/srv/catchplate-fast/projects/serverware-operator-artifacts'; assert((await stat(directory)).isDirectory());
  artifacts = await mkdtemp(join(directory, 'github-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, pureGroups: 1, renderedGroups: tests.length}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline; let attempted = 0; let passed = 0;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { attempted++; await run(browser); passed++; console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, pureGroups: 1, renderedGroups: tests.length, passed,
        backendAcceptance: false, sdkExecuted: false, providerRequests: 0, proxyRequests: 0,
        nativeHttpDownloads: 0, generatedCommandsExecuted: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('GitHub browser fixture deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after, attempted, passed,
      failed: attempted - passed, unattempted: tests.length - attempted})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {fixture, githubRule, capability};
