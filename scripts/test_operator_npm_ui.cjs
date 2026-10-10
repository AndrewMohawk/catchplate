#!/usr/bin/env node
// Pure catalog/form/recipe controls with an inert DOM. No browser, application,
// provider, HTTP, package manager, SDK or generated recipe is executed.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');
const ASSETS = resolve(__dirname, '../serverware/operator_demo_web');
const FILES = ['workspace_core.js', 'workspace_github.js', 'workspace_npm.js', 'workspace_npm_publish.js',
  'workspace_x.js', 'workspace_alchemy.js', 'workspace_resources.js', 'workspace_connect.js'];
const SOURCE = FILES.map(name => readFileSync(resolve(ASSETS, name), 'utf8')).join('\n');
const HTML = readFileSync(resolve(ASSETS, 'index.html'), 'utf8');
const ORIGIN = 'https://registry.npmjs.org';
const BUNDLE = 'npm_metadata_read_v1';
const DUMMY = 'serverware-npm-placeholder-v1';
const PRIVATE = 'synthetic-npm-token-NEVER-RENDER';
const PACKAGES = ['@example/fixture', 'example-package'];
const HEADERS = ['accept', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'pacote-pkg-id', 'pacote-req-type', 'pacote-version', 'user-agent'];
const clone = value => JSON.parse(JSON.stringify(value));
const cap = (allowed = true) => ({schema: 'serverware.operatorNpmMetadata/v1', connection_type: 'npm_token_v1',
  create_credential_path: '/api/operator-demo/credentials/npm-token', create_rule_path: '/api/operator-demo/access-rules/npm-metadata',
  registry_origin: ORIGIN, destination_allowed: allowed, operation_bundles: [BUNDLE], sdk_auth_token: DUMMY,
  placeholder: 'Bearer ' + DUMMY, response_mode: 'npm_metadata_json_v1', source_pair_required: true,
  metadata_only: true, max_active_rules_per_application: 1});
const npmCredential = (changes = {}) => credential({name: 'npm test token', connection_type: 'npm_token_v1', provider_id: 'npm', ...changes});
// Independent server-field oracle, never derived from the UI generator.
const npmRule = (changes = {}) => rule({name: 'Read package metadata', operation_bundle: BUNDLE, packages: [...PACKAGES],
  upstream_url: ORIGIN + '/', methods: ['GET'], request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: [...HEADERS], response_mode: 'npm_metadata_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer ' + DUMMY, ...changes});
function rawCatalog({credentials = [npmCredential()], rules = [npmRule()], capability = cap(), allowed = [ORIGIN]} = {}) {
  const value = publicCatalog({revision: 1, sequence: 1, active: digest(1), loaded: digest(1), credentials,
    applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules, allowedUpstreams: allowed,
    responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], requestBodyModes: ['preserve_json_v1'], credentialInputModes: ['insert', 'replace_exact']});
  value.capabilities.npm = capability;
  value.capabilities.application_proxy_authentication = {schema: 'serverware.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  return value;
}
class Node {
  constructor(tag = 'div', attrs = {}) {
    this.tag = tag; this.children = []; this.attrs = {...attrs}; this.dataset = {}; this.events = {};
    this.value = attrs.value || ''; this.hidden = Object.hasOwn(attrs, 'hidden'); this.disabled = Object.hasOwn(attrs, 'disabled');
    this.checked = Object.hasOwn(attrs, 'checked'); this.textContent = ''; this.id = attrs.id || ''; this.open = false;
  }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  get firstElementChild() { return this.children[0]; }
  after() {}
  setAttribute(name, value) { this.attrs[name] = String(value); }
  removeAttribute(name) { delete this.attrs[name]; }
  addEventListener(name, callback) { this.events[name] = callback; }
  reportValidity() { return true; } // Field validation is NOT browser acceptance.
  setCustomValidity(message) { this.invalid = message; }
  scrollIntoView() {}
  descendants() { return this.children.flatMap(node => [node, ...node.descendants()]); }
  querySelectorAll(selector) {
    const tags = selector.split(',');
    return this.descendants().filter(node => tags.includes(node.tag) || selector === 'details' && node.tag === 'details');
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function inertDom() {
  const root = new Node(); const nodes = new Map(); const stack = [root];
  const empty = new Set(['input', 'meta', 'link', 'br', 'hr']);
  for (const match of HTML.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)([^>]*)>/g)) {
    const tag = match[1].toLowerCase();
    if (match[0].startsWith('</')) {
      const index = stack.findLastIndex(node => node.tag === tag);
      if (index > 0) stack.length = index;
      continue;
    }
    const attrs = Object.fromEntries([...match[2].matchAll(/([A-Za-z][A-Za-z0-9-]*)(?:="([^"]*)")?/g)].map(item => [item[1], item[2] || '']));
    const node = new Node(tag, attrs); stack.at(-1).append(node);
    if (node.id) nodes.set(node.id, node);
    if (!empty.has(tag)) stack.push(node);
  }
  return {nodes, getElementById: id => { assert(nodes.has(id), 'known inert element ' + id); return nodes.get(id); },
    createElement: tag => new Node(tag), querySelectorAll: selector => selector === 'input[name="connect-method"]:checked' ?
      root.descendants().filter(node => node.tag === 'input' && node.attrs.name === 'connect-method' && node.checked) : []};
}
function context(dom = inertDom()) {
  class Clock extends Date { static now() { return NOW; } }
  const value = vm.createContext({document: dom, URL, Date: Clock, location: {origin: 'https://operator.example.test', hash: ''},
    window: {addEventListener() {}, confirm: () => true}, clientCredentialInput, credentialHeaderTarget,
    fetch: () => { throw new Error('No network'); }, setTimeout: () => { throw new Error('No timers'); }});
  vm.runInContext(SOURCE, value, {timeout: 2000});
  return {value, dom, run: (expression, input) => { value.input = input; return vm.runInContext(expression, value, {timeout: 1000}); }};
}
const pure = context();
const project = input => clone(pure.run('projectCatalog(input)', input));
const fixture = (changes = {}) => {
  const current = context(); const raw = rawCatalog(changes); const posts = [];
  const workspace = {state: {catalog: project(raw), busy: false, uncertain: false}, ready: () => true, loaded: () => true,
    subscribe(callback) { this.render = callback; callback(); }, refresh() { this.render(); },
    async mutate(path, body, status, receipt) {
      posts.push({path, body: clone(body)});
      if (path === 'credentials/npm-token') {
        assert.deepEqual(Object.keys(body).sort(), ['name', 'secret']);
        assert.equal(body.secret, PRIVATE); raw.credentials = [npmCredential({name: body.name})];
        body.secret = ''; posts.at(-1).body.secret = '';
      } else {
        assert.equal(path, 'access-rules/npm-metadata');
        assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'name', 'operation_bundle', 'packages']);
        assert.deepEqual(clone(body.packages), PACKAGES);
        raw.access_rules = [npmRule({name: body.name})];
      }
      raw.revision++; this.state.catalog = project(raw);
      const key = path.startsWith('credentials') ? 'credential' : 'access_rule';
      receipt({revision: raw.revision, [key]: this.state.catalog[key === 'credential' ? 'credentials' : 'access_rules'][0]});
      this.render(); return true;
    }};
  current.value.workspaceFixture = workspace;
  const view = current.run('createConnectView(workspaceFixture, {mount(){},tokenFor(){return null;}}, {mount(){},select(){}})');
  const node = id => current.dom.getElementById(id);
  const event = async (id, type = 'click') => { const target = node(id); assert.equal(typeof target.events[type], 'function');
    await target.events[type]({preventDefault() {}, currentTarget: target}); };
  return {...current, raw, workspace, posts, view, node, event};
};
async function existingPair(f) {
  await f.event('connect-use-saved'); f.node('connect-credential-choice').value = IDS.credential;
  await f.event('connect-credential-form', 'submit'); f.node('connect-application-choice').value = IDS.application;
  await f.event('connect-application-form', 'submit');
}
const tests = [
  ['exact capability and public catalog projection never retain secret fields', () => {
    const raw = rawCatalog({credentials: [npmCredential({secret: PRIVATE, token: PRIVATE})]});
    const value = project(raw); assert.equal(value.credentials[0].provider_id, 'npm');
    assert.equal(value.access_rules[0].operation_bundle, BUNDLE); assert(!JSON.stringify(value).includes(PRIVATE));
    assert.deepEqual(value.capabilities.npm, cap());
  }],
  ['missing, malformed or withdrawn capability never grants a fallback', () => {
    for (const capability of [null, {...cap(), metadata_only: false}, {...cap(), max_active_rules_per_application: 2},
      {...cap(), registry_origin: 'https://other.example.test'}, {...cap(), create_rule_path: '/other'}]) {
      const value = project(rawCatalog({capability})); assert.equal(value.capabilities.npm, null);
      assert.equal(pure.run('operatorRuleSupported(input.access_rules[0], input)', value), false);
    }
    for (const options of [{capability: cap(false)}, {allowed: []}]) {
      const value = project(rawCatalog(options)); assert.equal(pure.run('operatorRuleSupported(input.access_rules[0], input)', value), false);
    }
  }],
  ['explicit package grammar, bounds, duplicates and sorted authority', () => {
    assert.deepEqual(clone(pure.run('npmPackageInput(input)', 'example-package\n@example/fixture\n')), PACKAGES);
    for (const names of [[], ['pkg', 'pkg'], ['z', 'a'], ['*'], ['Pkg'], ['pkg@1.0.0'], ['https://registry.npmjs.org/pkg'],
      ['@scope%2fname'], ['@scope/name/child'], ['_name'], ['.name'], ['x'.repeat(215)], Array.from({length: 65}, (_, index) => 'x' + index).sort()])
      assert.equal(pure.run('npmPackagesValid(input)', names), false);
    assert.equal(pure.run('npmPackagesValid(input)', ['x'.repeat(214)]), true);
    assert.throws(() => pure.run('npmPackageInput(input)', 'pkg\npkg'));
  }],
  ['public npm rule exactly matches independent metadata-only server oracle', () => {
    const fields = clone(pure.run('npmRuleFields(input)', PACKAGES));
    for (const [name, value] of Object.entries(fields)) assert.deepEqual(value, npmRule()[name]);
    for (const changes of [{methods: ['POST']}, {query_keys: ['query']}, {query_mode: 'orderedFormV1'}, {request_body_mode: 'preserve_json_v1'},
      {allowed_headers: ['accept']}, {response_fields: ['name']}, {response_mode: 'unfiltered_json'}, {upstream_url: ORIGIN + '/pkg'},
      {placeholder: 'token ' + DUMMY}, {packages: ['*']}, {operation_bundle: 'npm_install_v1'}])
      assert.throws(() => project(rawCatalog({rules: [npmRule(changes)]})));
  }],
  ['no implicit upgrade from generic, GitHub, or legacy exact rule', () => {
    for (const saved of [credential(), npmCredential({provider_id: 'github'}), npmCredential({connection_type: 'github_token_v1', provider_id: 'github'})])
      assert.throws(() => project(rawCatalog({credentials: [saved]})));
    assert.throws(() => project(rawCatalog({rules: [rule()]})));
    assert.throws(() => project(rawCatalog({rules: [npmRule(), npmRule({id: 'second'})]})));
  }],
  ['rule submission contains only package grant DTO, never hidden generic controls', () => {
    const value = clone(pure.run('npmRulePayload(input)', npmRule()));
    assert.deepEqual(Object.keys(value).sort(), ['application_id', 'credential_id', 'name', 'operation_bundle', 'packages']);
    assert.deepEqual(value.packages, PACKAGES); assert.equal(value.operation_bundle, BUNDLE);
    assert.equal(pure.run('npmNewRuleAvailable(input, "' + IDS.application + '")',
      {access_rules: [rule({upstream_url: ORIGIN + '/other-package'})]}), false);
    assert.equal(pure.run('npmNewRuleAvailable(input, "' + IDS.application + '")',
      {access_rules: [rule({upstream_url: 'https://different.example.test/pkg'})]}), true);
  }],
  ['recipe uses stock npm, fixed dummy, environment-only app token and verified TLS', () => {
    const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application, proxyAuthentication: 'basic_and_bearer_v1', packages: PACKAGES, packageName: PACKAGES[0]};
    const text = pure.run('buildNpmClientRecipe(input)', input);
    for (const expected of ['npm 11.8.0', 'strict-ssl=true', 'NODE_EXTRA_CA_CERTS=', 'https-proxy=https://' + IDS.application + ':${SERVERWARE_PROXY_TOKEN}@proxy.example.test',
      '//registry.npmjs.org/:_authToken=' + DUMMY, "view '@example/fixture' --json", 'fetch-retries=0', 'cache=${SERVERWARE_NPM_CACHE}', '--globalconfig /dev/null']) assert(text.includes(expected), expected);
    assert(!text.includes(PRIVATE)); assert(!text.includes('strict-ssl=false'));
    for (const change of [{proxyAuthentication: 'bearer'}, {packageName: 'outside-grant'}, {proxyUrl: 'http://proxy.example.test'},
      {proxyUrl: 'https://user:secret@proxy.example.test'}, {caPath: 'bad\npath'}, {applicationId: 'not-uuid'}])
      assert.throws(() => pure.run('buildNpmClientRecipe(input)', {...input, ...change}));
  }],
  ['missing npm capability leaves ordinary credentials available', async () => {
    const f = fixture({rules: [], capability: null});
    assert(f.node('connect-use-npm').disabled); assert(!f.node('connect-use-key').disabled);
    await f.event('connect-use-npm'); assert(f.node('connect-credential-form').hidden); assert.equal(f.posts.length, 0);
  }],
  ['npm token save is separate, uses its endpoint and clears the secret', async () => {
    const f = fixture({credentials: [], rules: [], capability: cap(false), allowed: []});
    assert(!f.node('connect-use-npm').disabled); await f.event('connect-use-npm');
    assert(f.node('connect-credential-auth-group').hidden); assert(!f.node('connect-npm-token-note').hidden);
    f.node('connect-credential-name').value = 'My npm token'; f.node('connect-credential-secret').value = PRIVATE;
    await f.event('connect-credential-form', 'submit');
    assert.equal(f.posts[0].path, 'credentials/npm-token'); assert.equal(f.posts.length, 1);
    assert.equal(f.node('connect-credential-secret').value, ''); assert.equal(f.raw.access_rules.length, 0);
    assert(!f.node('connect-application-step').hidden);
  }],
  ['actual connect handlers review exact packages then send one small npm grant', async () => {
    const f = fixture({rules: []}); await existingPair(f);
    assert(!f.node('connect-npm-packages-group').hidden); assert(f.node('connect-exact-destination').hidden);
    assert(f.node('connect-exact-content').hidden); assert(f.node('connect-credential-input-group').hidden);
    assert(f.node('connect-path').disabled); assert(f.node('connect-response-mode').disabled);
    f.node('connect-npm-packages').value = 'example-package\n@example/fixture';
    await f.event('connect-access-form', 'submit'); assert(!f.node('connect-review-step').hidden, f.node('connect-status').textContent); assert.equal(f.posts.length, 0);
    await f.event('connect-grant'); assert.equal(f.posts.length, 1); assert.equal(f.posts[0].path, 'access-rules/npm-metadata');
    assert.deepEqual(f.posts[0].body.packages, PACKAGES); assert(!f.node('connect-setup-step').hidden);
  }],
  ['existing npm grant blocks a second new permission but is reusable without POST', async () => {
    const f = fixture(); await existingPair(f);
    assert(f.node('connect-review').disabled); assert.match(f.node('connect-npm-summary').textContent, /already has/);
    f.node('connect-rule-choice').value = IDS.rule; await f.event('connect-rule-choice', 'change');
    await f.event('connect-access-form', 'submit'); await f.event('connect-grant');
    assert.equal(f.posts.length, 0); assert(!f.node('connect-setup-step').hidden);
  }],
  ['capability withdrawal or changed catalog blocks reviewed grant', async () => {
    const f = fixture({rules: []}); await existingPair(f); f.node('connect-npm-packages').value = PACKAGES.join('\n');
    await f.event('connect-access-form', 'submit');
    f.raw.capabilities.npm = cap(false); f.raw.revision++; f.workspace.state.catalog = project(f.raw); f.workspace.render();
    assert(f.node('connect-grant').disabled); await f.event('connect-grant'); assert.equal(f.posts.length, 0);
  }],
];
async function main() {
  assert.equal(process.argv.length, 2, 'No browser/live target or execution arguments accepted');
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, generated_recipe_executed: false,
    scope: 'public catalog, inert DOM connect handlers, metadata-only recipe text; not browser or provider acceptance'}));
}
module.exports = {context, rawCatalog, npmCredential, npmRule, cap, existingPair, IDS, clone};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
