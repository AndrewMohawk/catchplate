#!/usr/bin/env node
// Pure catalog/form/recipe controls with an inert DOM. No browser, application,
// provider, HTTP, package manager, SDK or generated recipe is executed.
const assert = require('node:assert/strict');
const {mutationReviewStorage} = require('./operator_mutation_recovery_test_helpers.cjs');
const {readFileSync} = require('node:fs');
const {mkdtemp, writeFile, rm} = require('node:fs/promises');
const {tmpdir} = require('node:os');
const {resolve} = require('node:path');
const {pathToFileURL} = require('node:url');
const vm = require('node:vm');
const {credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../catchplate/operator_demo_web/app.js');
const ASSETS = resolve(__dirname, '../catchplate/operator_demo_web');
const FILES = ['workspace_core.js', 'workspace_github.js', 'workspace_npm.js', 'workspace_npm_publish.js',
  'workspace_x.js', 'workspace_alchemy.js', 'workspace_aws.js', 'workspace_ecr.js', 'workspace_resources.js', 'workspace_connect.js'];
const SOURCE = FILES.map(name => readFileSync(resolve(ASSETS, name), 'utf8')).join('\n');
const HTML = readFileSync(resolve(ASSETS, 'index.html'), 'utf8');
const NPM_EXAMPLE = resolve(__dirname, '../examples/npm-registry');
const NPM_PACKAGE = JSON.parse(readFileSync(resolve(NPM_EXAMPLE, 'package.json'), 'utf8'));
const ORIGIN = 'https://registry.npmjs.org';
const BUNDLE = 'npm_metadata_read_v1';
const DUMMY = 'catchplate-npm-placeholder-v1';
const PRIVATE = 'synthetic-npm-token-NEVER-RENDER';
const PACKAGES = ['@example/fixture', 'example-package'];
const HEADERS = ['accept', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'pacote-pkg-id', 'pacote-req-type', 'pacote-version', 'user-agent'];
const clone = value => JSON.parse(JSON.stringify(value));
const cap = (allowed = true) => ({schema: 'catchplate.operatorNpmMetadata/v1', connection_type: 'npm_token_v1',
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
  value.capabilities.application_proxy_authentication = {schema: 'catchplate.operatorProxyAuthentication/v1',
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
  // Connect reads HTMLSelectElement.options when updating provider choices.
  // Resolve the current option descendants; other inert elements do not gain it.
  get options() { return this.tag === 'select' ? this.descendants().filter(node => node.tag === 'option') : undefined; }
  after() {}
  setAttribute(name, value) { this.attrs[name] = String(value); }
  removeAttribute(name) { delete this.attrs[name]; }
  addEventListener(name, callback) { this.events[name] = callback; }
  reportValidity() { return true; } // Field validation is NOT browser acceptance.
  reset() {
    assert.equal(this.tag, 'form', 'only an inert form can reset its input defaults');
    for (const node of this.descendants()) {
      if (['input', 'textarea'].includes(node.tag)) {
        node.value = node.attrs.value || ''; node.checked = Object.hasOwn(node.attrs, 'checked');
      } else if (node.tag === 'select') {
        node.value = (node.options.find(option => Object.hasOwn(option.attrs, 'selected')) || node.options[0])?.value || '';
      }
    }
  }
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
// Run the actual proxy view and private-download click handler with in-memory
// browser download primitives. This is not a rendered browser or SDK check.
function npmDownloadFixture(raw, token = 'synthetic-app-token-for-private-download') {
  const current = context(); const blobs = [], downloads = [], revoked = [];
  const node = id => current.dom.getElementById(id);
  const createElement = current.dom.createElement;
  current.dom.createElement = tag => {
    const result = createElement(tag);
    if (tag === 'a') {
      result.click = () => downloads.push({href: result.href, filename: result.download});
      result.remove = () => {};
    }
    return result;
  };
  current.dom.body = {append(anchor) { assert.equal(anchor.tag, 'a'); }};
  const methodLabel = createElement('label');
  current.dom.querySelector = selector => {
    assert.equal(selector, 'label[for="proxy-method"]'); return methodLabel;
  };
  node('github-client-operation').querySelector = selector => {
    assert.equal(selector, 'option[value="create"]');
    return node('github-client-operation').options.find(option => option.value === 'create');
  };
  class DownloadURL extends URL {
    static createObjectURL(blob) { blobs.push(blob); return 'blob:inert-npm/' + blobs.length; }
    static revokeObjectURL(url) { revoked.push(url); }
  }
  Object.assign(current.value, {URL: DownloadURL, Blob,
    setTimeout(callback, delay) { assert.equal(delay, 1000); callback(); }});
  vm.runInContext(readFileSync(resolve(ASSETS, 'workspace_proxy_audit.js'), 'utf8'), current.value, {timeout: 1000});
  const catalog = clone(current.run('projectCatalog(input)', raw));
  node('proxy-application').value = IDS.application; node('proxy-rule').value = IDS.rule;
  node('npm-client-package').value = catalog.access_rules[0].packages?.[0] || '';
  current.value.workspaceFixture = {state: {catalog, busy: false, uncertain: false}, loaded: () => true,
    subscribe(callback) { callback(); }};
  current.value.applicationsFixture = {tokenFor(id) { assert.equal(id, IDS.application); return token; }};
  current.run('createProxyView(workspaceFixture, applicationsFixture)');
  return {node, blobs, downloads, revoked, token};
}
const pure = context();
const project = input => clone(pure.run('projectCatalog(input)', input));
const fixture = (changes = {}) => {
  const current = context(); const raw = rawCatalog(changes); const posts = []; const clientCreations = [];
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
        raw.access_rules = [npmRule({name: body.name, credential_id: body.credential_id, application_id: body.application_id})];
      }
      raw.revision++; const refreshed = project(raw);
      const key = path.startsWith('credentials') ? 'credential' : 'access_rule';
      receipt({revision: raw.revision, policy: clone(raw.policy), [key]: refreshed[key === 'credential' ? 'credentials' : 'access_rules'][0]});
      this.state.catalog = refreshed;
      this.render(); return true;
    }};
  current.value.workspaceFixture = workspace;
  current.value.applicationsFixture = {mount(){}, tokenFor(){return null;}, create(...args) {
    clientCreations.push(args); throw new Error('Unexpected client creation in credential-only fixture');
  }};
  const view = current.run('createConnectView(workspaceFixture, applicationsFixture, {mount(){},select(){}})');
  const node = id => current.dom.getElementById(id);
  const event = async (id, type = 'click') => { const target = node(id); assert.equal(typeof target.events[type], 'function');
    await target.events[type]({preventDefault() {}, currentTarget: target}); };
  return {...current, raw, workspace, posts, clientCreations, view, node, event};
};
async function existingPair(f) {
  await f.event('connect-use-saved'); f.node('connect-credential-choice').value = IDS.credential;
  await f.event('connect-credential-form', 'submit'); f.node('connect-application-choice').value = IDS.application;
  await f.event('connect-application-form', 'submit');
}

// Creation-receipt tests use the actual core transport/uncertainty controller,
// not the smaller provider-form stub above. Only this in-memory fetch exists.
async function credentialSaveFixture(method, options = {}) {
  const current = context(); const requests = [], bodies = [], forbidden = [];
  const priorId = '77777777-7777-4777-8777-777777777777';
  const raw = rawCatalog({credentials: [credential({id: priorId, name: 'Previously saved credential'})], rules: []});
  const originalApplications = clone(raw.applications);
  raw.capabilities.github = {schema: 'catchplate.operatorGithub/v1', connection_type: 'github_token_v1',
    create_credential_path: '/api/operator-demo/credentials/github-token', create_rule_path: '/api/operator-demo/access-rules/github',
    api_origin: 'https://api.github.com', destination_allowed: true,
    operation_bundles: ['github_issues_read_v1', 'github_issues_write_v1'], sdk_auth_token: 'catchplate-github-placeholder-v1',
    placeholder: 'token catchplate-github-placeholder-v1', query_mode: 'githubRestV1',
    response_mode: 'unfiltered_json_or_empty_v2', source_pair_required: true};
  raw.allowed_upstreams.push('https://api.github.com');
  const name = 'Reviewed ' + method + ' credential';
  const selected = credential({name, ...(method === 'key' ? {auth_type: 'header', header_name: 'X-Reviewed-Key'} :
    {connection_type: method === 'npm' ? 'npm_token_v1' : 'github_token_v1', provider_id: method === 'npm' ? 'npm' : 'github'})});
  const response = body => ({ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => clone(body)});
  Object.assign(current.value, {TextEncoder, clearTimeout() {}, AbortSignal: {timeout: () => undefined}});
  current.value.sessionStorage = mutationReviewStorage();
  Object.defineProperty(current.value, 'localStorage',
    {get() { forbidden.push('localStorage'); throw new Error('Storage is forbidden'); }});
  current.value.fetch = async (path, init) => {
    assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
    if (!init.method) {
      assert.equal(path, '/api/operator-demo/catalog'); requests.push({method: 'GET', path}); return response(raw);
    }
    assert.equal(init.method, 'POST'); assert.equal(path, '/api/operator-demo/credentials' +
      (method === 'key' ? '' : method === 'npm' ? '/npm-token' : '/github-token'));
    const payload = JSON.parse(init.body);
    assert.equal(payload.secret, PRIVATE); assert.equal(payload.name, name);
    assert.equal(payload.expected_revision, 1); assert.equal(payload.expected_policy_hash, digest(1));
    const fields = ['expected_policy_hash', 'expected_revision', 'name', 'secret'];
    if (method === 'key') {
      fields.push('auth_type', 'header_name'); assert.equal(payload.auth_type, 'header'); assert.equal(payload.header_name, 'X-Reviewed-Key');
    }
    assert.deepEqual(Object.keys(payload).sort(), fields.sort()); delete payload.secret;
    requests.push({method: 'POST', path, payload}); raw.revision = 2; raw.credentials.push(clone(selected));
    const result = {revision: 2, policy: clone(raw.policy), credential: clone(selected)};
    options.receipt?.(result, priorId); options.refreshed?.(raw, priorId);
    return response(result);
  };
  const workspace = current.run('createOperatorWorkspace()'); const mutate = workspace.mutate;
  workspace.mutate = (...args) => { bodies.push(args[1]); return mutate(...args); };
  assert.equal(await workspace.refresh(), true); current.value.workspaceFixture = workspace;
  current.value.clientFixture = {mount(){}, tokenFor(){return null;}, create() { forbidden.push('client'); throw new Error('Client creation is forbidden'); }};
  const view = current.run('createConnectView(workspaceFixture, clientFixture, {mount(){},select(){}})'); view.show(true);
  const node = id => current.dom.getElementById(id);
  const event = async (id, kind = 'click') => {
    const target = node(id); assert.equal(typeof target.events[kind], 'function');
    await target.events[kind]({preventDefault(){}, currentTarget: target});
  };
  const save = async () => {
    assert.equal(view.addCredential(), true); await event('connect-use-' + method);
    node('connect-credential-name').value = name; node('connect-credential-secret').value = PRIVATE;
    if (method === 'key') { node('connect-credential-auth-type').value = 'header'; node('connect-credential-header-name').value = 'X-Reviewed-Key'; }
    await event('connect-credential-form', 'submit');
  };
  const clean = () => {
    assert.deepEqual(forbidden, []); assert.equal(node('connect-credential-secret').value, '');
    assert(!JSON.stringify([workspace.state, requests, bodies,
      [...current.dom.nodes.values()].map(value => [value.value, value.textContent])]).includes(PRIVATE));
    assert.equal(requests.filter(value => value.method === 'POST').length, 1); assert.deepEqual(raw.access_rules, []);
    assert.deepEqual(raw.applications, originalApplications);
  };
  return {...current, raw, workspace, view, node, event, save, clean, requests};
}

const tests = [
  ['diagnostic grouping is exact and conservative and preserves manageable retained cards', () => {
    const current = context(), fixture = 'https://demo-upstream:8443/echo';
    const raw = {credentials: [credential({id: 'fixture'}), credential({id: 'mixed'}), npmCredential({id: 'provider'}),
      credential({id: 'unassigned'}), credential({id: 'legacy', legacy_upstream_origin: 'https://real.example.test'}),
      credential({id: 'ambiguous'})], applications: [application({id: 'fixture-app'}), application({id: 'mixed-app'}), application({id: 'unassigned-app'})],
      access_rules: [rule({id: 'fixture-rule', credential_id: 'fixture', application_id: 'fixture-app', upstream_url: fixture}),
        rule({id: 'fixture-history', credential_id: 'fixture', application_id: 'fixture-app', upstream_url: fixture, status: 'revoked'}),
        rule({id: 'mixed-fixture', credential_id: 'mixed', application_id: 'mixed-app', upstream_url: fixture}),
        rule({id: 'mixed-history', credential_id: 'mixed', application_id: 'mixed-app', upstream_url: fixture + '?other=1', status: 'revoked'}),
        rule({id: 'provider-fixture', credential_id: 'provider', application_id: 'fixture-app', upstream_url: fixture}),
        rule({id: 'legacy-fixture', credential_id: 'legacy', application_id: 'fixture-app', upstream_url: fixture}),
        rule({id: 'ambiguous-fixture', credential_id: 'ambiguous', application_id: 'missing-app', upstream_url: fixture})]};
    const before = JSON.stringify(raw);
    const classify = value => clone(current.run('Object.fromEntries(Object.entries(operatorDiagnosticResources(input)).map(([key, ids]) => [key, [...ids].sort()]))', value));
    const grouped = classify(raw);
    assert.deepEqual(grouped.credentials, ['fixture']); assert.deepEqual(grouped.applications, ['fixture-app']);
    assert(!grouped.access_rules.includes('mixed-history')); assert(grouped.access_rules.includes('fixture-history'));
    const renamed = clone(raw); renamed.credentials.forEach(item => { item.name = 'Unrelated production-looking name'; });
    assert.deepEqual(classify(renamed), grouped); assert.equal(JSON.stringify(raw), before);
    const entries = ['current', 'expired', 'diagnostic', 'revoked'].map(group => {
      const card = new Node('article'); card.dataset.resourceId = group;
      const button = new Node('button'); button.addEventListener('click', () => { button.clicked = true; }); card.append(button);
      return {card, group};
    });
    current.value.entries = entries;
    const render = () => current.run('renderResourceGroups("credentials-list", entries, "No current credentials in the main list.")');
    render(); const list = current.dom.getElementById('credentials-list');
    assert.equal(list.children[0], entries[0].card);
    const groups = () => list.children.filter(node => node.tag === 'details');
    assert.deepEqual(groups().map(node => node.dataset.resourceGroup), ['expired', 'diagnostic', 'revoked']);
    assert(groups().every(node => node.open === false)); assert(Object.hasOwn(groups()[0].dataset, 'expiredAppAccess'));
    assert(groups()[1].children.some(node => node.textContent.includes('does not disable active permissions')));
    groups()[1].open = true; render(); assert.equal(groups()[1].open, true);
    assert.equal(groups()[1].children.at(-1).children[0], entries[2].card);
    entries[2].card.children[0].events.click(); assert(entries[2].card.children[0].clicked);
    current.value.entries = entries.slice(1); render();
    assert.equal(list.children[0].textContent, 'No current credentials in the main list.');
    assert.equal(groups().length, 3); assert.equal(groups()[1].open, true);
  }],
  ['inert select options reflect parsed and replaced option descendants only', () => {
    const dom = inertDom(); const select = dom.getElementById('connect-github-type');
    assert.deepEqual(select.options.map(option => option.value), ['github_token_v1', 'github_app_v1']);
    const group = new Node('optgroup'); const nested = new Node('option', {value: 'fixture-nested'});
    group.append(nested); select.append(group);
    assert.deepEqual(select.options.map(option => option.value), ['github_token_v1', 'github_app_v1', 'fixture-nested']);
    assert.equal(select.options[2], nested);
    select.replaceChildren(new Node('option', {value: 'fixture-replacement'}));
    assert.deepEqual(select.options.map(option => option.value), ['fixture-replacement']);
    assert.equal(new Node('div').options, undefined);
  }],
  ['inert form reset restores declared defaults without executing any browser effects', () => {
    const form = new Node('form'); const input = new Node('input', {value: 'default'});
    const choice = new Node('select'); choice.append(new Node('option', {value: 'first'}), new Node('option', {value: 'second', selected: ''}));
    const checked = new Node('input', {checked: ''}); const unchecked = new Node('input');
    form.append(input, choice, checked, unchecked); input.value = 'changed'; choice.value = 'first'; checked.checked = false; unchecked.checked = true;
    form.reset(); assert.equal(input.value, 'default'); assert.equal(choice.value, 'second'); assert(checked.checked); assert(!unchecked.checked);
  }],
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
    for (const expected of ['npm ' + NPM_PACKAGE.dependencies.npm, 'strict-ssl=true', 'NODE_EXTRA_CA_CERTS=', 'https-proxy=https://' + IDS.application + ':${CATCHPLATE_PROXY_TOKEN}@proxy.example.test',
      '//registry.npmjs.org/:_authToken=' + DUMMY, "view '@example/fixture' --json", 'fetch-retries=0', 'cache=${CATCHPLATE_NPM_CACHE}', '--globalconfig /dev/null']) assert(text.includes(expected), expected);
    assert(!text.includes(PRIVATE)); assert(!text.includes('strict-ssl=false'));
    for (const change of [{proxyAuthentication: 'bearer'}, {packageName: 'outside-grant'}, {proxyUrl: 'http://proxy.example.test'},
      {proxyUrl: 'https://user:secret@proxy.example.test'}, {caPath: 'bad\npath'}, {applicationId: 'not-uuid'}])
      assert.throws(() => pure.run('buildNpmClientRecipe(input)', {...input, ...change}));
  }],
  ['generated npm guidance joins the maintained package, launcher core and lock pins', async () => {
    const {VERSIONS} = await import(pathToFileURL(resolve(NPM_EXAMPLE, 'core.mjs')).href);
    const lock = JSON.parse(readFileSync(resolve(NPM_EXAMPLE, 'package-lock.json'), 'utf8'));
    assert.deepEqual(VERSIONS, NPM_PACKAGE.dependencies);
    assert.deepEqual(lock.packages[''].dependencies, VERSIONS);
    assert.deepEqual(clone(pure.run('operatorNpm.versions')), VERSIONS);
    assert.equal(pure.run('operatorNpm.nodeVersion'), NPM_PACKAGE.engines.node);
    assert.equal(lock.packages[''].engines.node, NPM_PACKAGE.engines.node);
    for (const [name, version] of Object.entries(VERSIONS)) {
      assert.equal(lock.packages['node_modules/' + name].version, version, name);
      if (name !== 'npm') assert.equal(lock.packages['node_modules/npm/node_modules/' + name].version, version, 'npm bundled ' + name);
    }
    const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application,
      proxyAuthentication: 'basic_and_bearer_v1', packages: PACKAGES, packageName: PACKAGES[0], tag: 'latest'};
    for (const builder of ['buildNpmClientRecipe', 'buildNpmPublishClientRecipe']) {
      const recipe = pure.run(builder + '(input)', input);
      assert(recipe.startsWith('# npm ' + VERSIONS.npm + ' / Node.js ' + NPM_PACKAGE.engines.node), builder);
      assert(!/11\.8\.0|21\.0\.4/.test(recipe), builder + ' must not advertise retired pins');
    }
    assert(pure.run('buildNpmInstallClientRecipe(input)', input).includes('node client.mjs install'));
  }],
  ['actual npm private downloads use the maintained pins without changing token or TLS handling', async () => {
    const {capability: publishCapability, publishRule} = require('./test_operator_npm_publish_ui.cjs');
    const publishing = rawCatalog({rules: [publishRule()]}); publishing.capabilities.npm_publish = publishCapability();
    for (const raw of [rawCatalog(), publishing]) {
      const f = npmDownloadFixture(raw);
      assert.equal(f.node('download-config').disabled, false);
      f.node('download-config').events.click();
      assert.equal(f.blobs.length, 1); assert.equal(f.blobs[0].type, 'application/json');
      assert.deepEqual(f.downloads, [{href: 'blob:inert-npm/1', filename: 'catchplate-client.private.json'}]);
      assert.deepEqual(f.revoked, ['blob:inert-npm/1']);
      const text = await f.blobs[0].text(); const config = JSON.parse(text);
      assert.equal(config.client_recipe.npm_version, NPM_PACKAGE.dependencies.npm);
      assert.equal(config.client_recipe.node_version, NPM_PACKAGE.engines.node);
      if (raw.access_rules[0].operation_bundle === BUNDLE)
        assert.equal(config.client_recipe.pacote_version, NPM_PACKAGE.dependencies.pacote);
      assert.equal(config.proxy_username, IDS.application); assert.equal(config.proxy_password, f.token);
      assert.equal(config.client_recipe.sdk_auth_token, DUMMY); assert.equal(config.client_recipe.strict_ssl, true);
      assert.equal(config.client_recipe.fresh_cache_required, true); assert.equal(config.client_recipe.automatic_retries, 0);
      assert(!text.includes(PRIVATE)); assert(!/11\.8\.0|21\.0\.4/.test(text));
      assert.equal(f.node('client-copy-status').textContent, 'Downloaded private client configuration. Keep it out of source control.');
      assert.equal(f.node('provider-config-handoff').hidden, false);
      assert.equal(f.node('provider-config-command').textContent, 'node client.mjs --config ./catchplate-client.private.json');
      const directory = await mkdtemp(resolve(tmpdir(), 'catchplate-npm-download-'));
      try {
        const path = resolve(directory, 'catchplate-client.private.json');
        await writeFile(path, text, {mode: 0o600});
        const {loadClientConfig} = await import(pathToFileURL(resolve(NPM_EXAMPLE, 'client.mjs')).href);
        const loaded = loadClientConfig(path, {CATCHPLATE_PROXY_TOKEN: 'wrong-ambient'}, 'view', NOW);
        assert.equal(loaded.operation, 'view'); assert.equal(loaded.token, f.token);
        assert.equal(loaded.applicationId, IDS.application);
        assert.equal(loaded.packageName, config.package || config.client_recipe.package);
        assert.equal(loaded.caFile, resolve(directory, 'catchplate-ca.pem'));
        assert.throws(() => loadClientConfig(path, {}, 'publish', NOW), 'no implicit publication confirmation');
      } finally { await rm(directory, {recursive: true, force: true}); }
    }
  }],
  ['actual GitHub private download loads directly in the stock-client configuration path', async () => {
    const {githubRule, capability} = require('./test_operator_github_browser.cjs');
    const raw = rawCatalog({credentials: [credential({connection_type: 'github_token_v1', provider_id: 'github'})],
      rules: [githubRule()], allowed: ['https://api.github.com'], capability: null});
    raw.capabilities.github = capability();
    const f = npmDownloadFixture(raw, 'A'.repeat(43));
    assert.equal(f.node('download-config').disabled, false);
    f.node('download-config').events.click();
    assert.equal(f.blobs.length, 1);
    const text = await f.blobs[0].text();
    assert(!text.includes(PRIVATE));
    assert(f.node('client-guidance').textContent.includes('--config'));
    const directory = await mkdtemp(resolve(tmpdir(), 'catchplate-github-config-'));
    try {
      const path = resolve(directory, 'catchplate-client.private.json');
      await writeFile(path, text, {mode: 0o600});
      const {loadClientConfig} = await import(pathToFileURL(resolve(__dirname, '../examples/github-issues-node/client.mjs')).href);
      const loaded = loadClientConfig(path, {CATCHPLATE_PROXY_TOKEN: 'wrong-ambient-token',
        CATCHPLATE_GITHUB_OWNER: 'wrong-owner', CATCHPLATE_PROXY_CA_FILE: '/wrong/ambient.pem'}, 'list', NOW);
      assert.equal(loaded.operation, 'list'); assert.equal(loaded.token, f.token);
      assert.equal(loaded.applicationId, IDS.application); assert.equal(loaded.proxyUrl, raw.proxy_url);
      assert.equal(loaded.owner, raw.access_rules[0].repository.owner); assert.equal(loaded.repo, raw.access_rules[0].repository.name);
      assert.equal(loaded.caFile, resolve(directory, 'catchplate-ca.pem')); assert.equal(loaded.proxyCaFile, null);
      assert.throws(() => loadClientConfig(path, {}, 'create-issue', NOW));
    } finally { await rm(directory, {recursive: true, force: true}); }
  }],
  ['setup labels distinguish reusable credentials from consuming clients', async () => {
    const f = fixture({rules: []});
    await f.event('connect-use-saved');
    assert.equal(f.node('connect-credential-heading').textContent, 'Use a saved credential');
    assert(HTML.includes('>Choose another credential type</button>'));
    assert(HTML.includes('>Use this credential for a client</button>'));
    assert(!/Connect an app|Accounts (?:and|&amp;|&) keys|Use a saved connection/.test(HTML + SOURCE));
    assert.equal(f.posts.length, 0); assert.equal(f.clientCreations.length, 0);
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
  ['Add credential saves once and cannot create a client or permission without a separate action', async () => {
    const f = fixture({credentials: [], rules: []}); const clientsBefore = clone(f.raw.applications);
    assert.equal(f.view.addCredential(), true); assert.equal(f.node('connect-title').textContent, 'Add credential');
    await f.event('connect-use-npm'); f.node('connect-credential-name').value = 'Saved npm credential';
    f.node('connect-credential-secret').value = PRIVATE; await f.event('connect-credential-form', 'submit');
    assert.equal(f.posts.length, 1); assert.equal(f.posts[0].path, 'credentials/npm-token');
    assert.equal(f.node('connect-credential-secret').value, ''); assert(!f.node('connect-credential-saved').hidden);
    for (const step of ['application', 'access', 'review', 'setup']) assert(f.node('connect-' + step + '-step').hidden);
    f.node('connect-application-choice').value = 'new'; f.node('connect-application-name').value = 'Must not be created';
    f.node('connect-token-ttl').value = '3600';
    await f.event('connect-application-form', 'submit'); await f.event('connect-access-form', 'submit'); await f.event('connect-grant');
    f.workspace.refresh(); assert.equal(f.posts.length, 1); assert.equal(f.clientCreations.length, 0);
    assert.deepEqual(f.raw.applications, clientsBefore); assert.deepEqual(f.raw.access_rules, []);
    await f.event('connect-saved-done'); assert.equal(f.value.location.hash, 'credentials');
    assert.equal(f.posts.length, 1); assert.equal(f.clientCreations.length, 0);
  }],
  ['the saved credential receipt enters client setup only after explicit Set up access', async () => {
    const f = fixture({credentials: [], rules: []}); assert.equal(f.view.addCredential(), true);
    await f.event('connect-use-npm'); f.node('connect-credential-name').value = 'Saved npm credential';
    f.node('connect-credential-secret').value = PRIVATE; await f.event('connect-credential-form', 'submit');
    await f.event('connect-saved-use'); assert(f.node('connect-credential-saved').hidden);
    assert(!f.node('connect-application-step').hidden); assert.equal(f.node('connect-credential-choice').value, IDS.credential);
    assert.equal(f.posts.length, 1); assert.equal(f.clientCreations.length, 0); assert.deepEqual(f.raw.access_rules, []);
  }],
  ['saved credential action binds the exact selected ID even when names are identical', async () => {
    const other = '66666666-6666-4666-8666-666666666666';
    const f = fixture({credentials: [npmCredential({name: 'Same label'}), npmCredential({id: other, name: 'Same label'})], rules: []});
    assert.equal(f.view.selectCredential(other), true); assert.equal(f.node('connect-credential-choice').value, other);
    assert(!f.node('connect-application-step').hidden); assert.equal(f.posts.length, 0);
    f.node('connect-application-choice').value = IDS.application; await f.event('connect-application-form', 'submit');
    f.node('connect-npm-packages').value = PACKAGES.join('\n'); await f.event('connect-access-form', 'submit');
    await f.event('connect-grant'); assert.equal(f.posts.length, 1); assert.equal(f.posts[0].path, 'access-rules/npm-metadata');
    assert.equal(f.posts[0].body.credential_id, other); assert.equal(f.posts[0].body.application_id, IDS.application);
    assert.equal(f.raw.credentials.length, 2); assert.equal(f.clientCreations.length, 0);
  }],
  ['unavailable selected credential never falls back to another saved credential', async () => {
    const other = '66666666-6666-4666-8666-666666666666';
    const f = fixture({credentials: [npmCredential(), npmCredential({id: other})], rules: []});
    assert.equal(f.view.selectCredential(other), true);
    f.raw.credentials = [npmCredential()]; f.raw.revision++; f.workspace.state.catalog = project(f.raw); f.workspace.render();
    f.node('connect-application-choice').value = IDS.application; await f.event('connect-application-form', 'submit');
    assert(f.node('connect-access-step').hidden); assert.equal(f.posts.length, 0); assert.equal(f.clientCreations.length, 0);
    assert.equal(f.view.selectCredential(other), false); assert.equal(f.posts.length, 0);
  }],
  ['new setup entrypoints preserve unresolved mutation and busy-state write holds', () => {
    for (const held of ['busy', 'uncertain']) {
      const f = fixture({rules: []}); assert.equal(f.view.addCredential(), true);
      f.workspace.state[held] = true; f.workspace.render();
      assert.equal(f.view.addCredential(), false); assert.equal(f.view.selectCredential(IDS.credential), false);
      assert.equal(f.view.startSetup(), false);
      assert.equal(f.posts.length, 0); assert.equal(f.clientCreations.length, 0);
    }
  }],
  ['unconfirmed save receipt cannot be discarded by switching setup entrypoints', async () => {
    const f = fixture({credentials: [], rules: []}); let saves = 0;
    f.workspace.mutate = async (path, body, status, receipt) => {
      assert.equal(path, 'credentials/npm-token'); saves++;
      receipt({revision: 2, policy: clone(f.raw.policy), credential: npmCredential({name: body.name})}); f.workspace.render(); return true;
    };
    assert.equal(f.view.addCredential(), true); await f.event('connect-use-npm');
    f.node('connect-credential-name').value = 'Awaiting catalog'; f.node('connect-credential-secret').value = PRIVATE;
    await f.event('connect-credential-form', 'submit'); assert.equal(saves, 1);
    assert(f.node('connect-credential-saved').hidden); assert(f.node('connect-application-step').hidden);
    assert.equal(f.view.addCredential(), false); assert.equal(f.view.selectCredential(IDS.credential), false);
    assert.equal(f.view.startSetup(), false);
    await f.event('connect-credential-form', 'submit'); f.workspace.refresh(); assert.equal(saves, 1);
    assert.equal(f.clientCreations.length, 0); assert.equal(f.node('connect-credential-secret').value, '');
  }],
  ...['key', 'github', 'npm'].map(method => [method + ' save-only creation uses actual core CAS transport and exact refreshed identity', async () => {
    const f = await credentialSaveFixture(method, {receipt: result => { result.credential.secret = PRIVATE; }});
    await f.save(); assert.equal(f.workspace.state.uncertain, false); assert(!f.node('connect-credential-saved').hidden);
    assert(f.node('connect-application-step').hidden); f.clean();
    await f.event('connect-saved-use'); assert(!f.node('connect-application-step').hidden);
    assert.equal(f.node('connect-credential-choice').value, IDS.credential); f.clean();
  }]),
  ...['key', 'github', 'npm'].map(method => [method + ' mismatched creation receipts hold writes and never replay or select a different credential', async () => {
    const changes = [
      (result, prior) => { result.credential.id = prior; },
      result => { result.credential.id = 'not-a-uuid'; },
      result => { result.credential.name = 'Unreviewed name'; },
      result => { result.credential.auth_type = method === 'key' ? 'bearer' : 'header'; },
      result => { result.credential.header_name = 'X-Unreviewed-Header'; },
      result => { result.credential.connection_type = method === 'key' ? 'github_token_v1' : null; },
      result => { result.credential.provider_id = method === 'key' ? 'github' : 'unreviewed-provider'; },
      result => { result.credential.active_rule_count = 1; },
      result => { result.credential.created_at = 'not-a-date'; },
      result => { result.credential.credential_generation = 2; },
      result => { result.revision = 1; },
      result => { result.revision = 3; },
      result => { result.policy.policy_hash = digest(2); },
      result => { result.policy.sequence = 2; },
      result => { delete result.policy; },
      result => { result.client_token = 'unexpected-client-token'; },
    ];
    for (const receipt of changes) {
      const f = await credentialSaveFixture(method, {receipt}); await f.save();
      assert.equal(f.workspace.state.uncertain, true); assert(f.node('connect-credential-saved').hidden);
      assert(f.node('connect-application-step').hidden); assert.equal(f.view.selectCredential(IDS.credential), false);
      await f.event('connect-credential-form', 'submit'); await f.workspace.refresh(); f.clean();
    }
  }]),
  ...['key', 'github', 'npm'].map(method => [method + ' refreshed identity drift never confirms the saved credential or repeats creation', async () => {
    const changes = [
      raw => { raw.credentials.at(-1).name = 'Changed after receipt'; },
      raw => { raw.credentials.at(-1).header_name = 'X-Changed-After-Receipt'; },
      raw => { raw.credentials.at(-1).credential_generation = 2; },
      raw => { raw.credentials.at(-1).created_at = new Date(NOW + 1000).toISOString(); },
      raw => { raw.credentials.at(-1).status = 'revoked'; },
      raw => { raw.credentials.pop(); },
      raw => { raw.policy.policy_hash = raw.policy.loaded_policy_hash = digest(2); raw.policy.sequence = 2; },
    ];
    for (const refreshed of changes) {
      const f = await credentialSaveFixture(method, {refreshed}); await f.save();
      assert(f.node('connect-credential-saved').hidden); assert(f.node('connect-application-step').hidden);
      assert.equal(f.view.addCredential(), false); assert.equal(f.view.selectCredential(IDS.credential), false);
      await f.event('connect-credential-form', 'submit'); await f.workspace.refresh(); f.clean();
    }
  }]),
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
    scope: 'public catalog, inert DOM connect/download handlers, npm recipe and source-pin joins; not browser or provider acceptance'}));
}
module.exports = {context, rawCatalog, npmCredential, npmRule, cap, existingPair, IDS, clone};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
