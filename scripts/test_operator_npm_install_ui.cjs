#!/usr/bin/env node
// Actual catalog/Connect functions in the existing inert DOM. No browser,
// request, npm command, provider call or generated recipe is executed.
const assert = require('node:assert/strict');
const {context, rawCatalog, npmRule, cap, existingPair, IDS, clone} = require('./test_operator_npm_ui.cjs');
const {publishRule} = require('./test_operator_npm_publish_ui.cjs');
const BUNDLE = 'npm_install_v1';
const PACKAGES = ['@example/fixture', 'example-package'];
const capability = () => ({schema: 'serverware.operatorNpmInstall/v1', connection_type: 'npm_token_v1',
  create_rule_path: '/api/operator-demo/access-rules/npm-install', registry_origin: 'https://registry.npmjs.org',
  destination_allowed: true, operation_bundles: [BUNDLE], sdk_auth_token: 'serverware-npm-placeholder-v1',
  placeholder: 'Bearer serverware-npm-placeholder-v1', response_mode: 'npm_install_v1', source_pair_required: true,
  max_active_rules_per_application: 1, max_packages: 64, modes: ['metadata', 'tarball', 'audit'],
  dependencies_require_explicit_grant: true});
// Independent public DTO oracle, not generated with npmInstallRuleFields.
function installRule(changes = {}) {
  return npmRule({name: 'Install packages and run npm audit', operation_bundle: BUNDLE, packages: [...PACKAGES],
    methods: ['GET', 'POST'], response_mode: 'npm_install_v1', allowed_headers: ['accept', 'content-type',
      'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'pacote-integrity', 'pacote-pkg-id',
      'pacote-req-type', 'pacote-version', 'user-agent'], ...changes});
}
function catalog({rules = [], installCapability = capability(), ...rest} = {}) {
  const result = rawCatalog({rules, ...rest}); result.capabilities.npm_install = installCapability; return result;
}
const pure = context();
const project = value => clone(pure.run('projectCatalog(input)', value));
function fixture(options = {}) {
  const current = context(); const raw = catalog(options); const posts = [];
  const workspace = {state: {catalog: project(raw), busy: false, uncertain: false}, ready: () => true, loaded: () => true,
    subscribe(callback) { this.render = callback; callback(); }, refresh() { this.render(); },
    async mutate(path, body, status, receipt) {
      posts.push({path, body: clone(body)}); assert.equal(path, 'access-rules/npm-install');
      assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'name', 'operation_bundle', 'packages']);
      if (options.uncertain) { this.state.uncertain = true; this.render(); return false; }
      raw.access_rules = [installRule({...body, ...(options.receiptChange || {})})]; raw.revision++;
      this.state.catalog = project(raw);
      receipt({revision: raw.revision, access_rule: this.state.catalog.access_rules[0]}); this.render(); return true;
    }};
  current.value.workspaceFixture = workspace;
  const view = current.run('createConnectView(workspaceFixture, {mount(){},tokenFor(){return null;}}, {mount(){},select(){}})');
  const node = id => current.dom.getElementById(id);
  const event = async (id, type = 'click') => { const target = node(id); assert.equal(typeof target.events[type], 'function');
    await target.events[type]({preventDefault() {}, currentTarget: target}); };
  return {...current, raw, workspace, posts, view, node, event};
}
async function chooseInstall(f) {
  await existingPair(f); f.node('connect-operation').value = BUNDLE; await f.event('connect-operation', 'change');
  f.node('connect-npm-packages').value = [...PACKAGES].reverse().join('\n');
}
const tests = [
  ['closed paired capability, separate unchanged metadata grant, no secret projection', () => {
    const raw = catalog({rules: [installRule()]}); raw.credentials[0].secret = 'PRIVATE_INSTALL_CANARY';
    const value = project(raw); assert.deepEqual(value.capabilities.npm_install, capability());
    assert.deepEqual(value.capabilities.npm, cap()); assert(!JSON.stringify(value).includes('PRIVATE_INSTALL_CANARY'));
    assert.equal(pure.run('operatorRuleSupported(input.access_rules[0],input)', value), true);
    for (const changed of [null, {...capability(), extra: true}, {...capability(), destination_allowed: false},
      {...capability(), modes: ['audit', 'metadata', 'tarball']}, {...capability(), max_packages: 65},
      {...capability(), dependencies_require_explicit_grant: false}, {...capability(), create_rule_path: '/other'}]) {
      const retained = project(catalog({rules: [installRule()], installCapability: changed}));
      assert.equal(retained.capabilities.npm_install, null); assert.equal(retained.access_rules[0].operation_bundle, BUNDLE);
      assert.equal(pure.run('operatorRuleSupported(input.access_rules[0],input)', retained), false);
    }
    assert.equal(pure.run('operatorRuleSupported(input.access_rules[0],input)', project(catalog({rules: [installRule()], allowed: []}))), false);
  }],
  ['closed install rules cannot smuggle generic authority or implicit dependencies', () => {
    for (const changes of [{methods: ['GET', 'PUT']}, {allowed_headers: ['content-encoding']}, {query_keys: ['x']},
      {request_body_mode: 'preserve_json_v1'}, {query_mode: 'orderedFormV1'}, {response_fields: ['ok']},
      {package: 'example-package'}, {packages: ['*']}, {packages: ['pkg', 'pkg']}, {packages: ['z', 'a']},
      {placeholder: 'Bearer REAL'}, {response_mode: 'npm_metadata_json_v1'}])
      assert.throws(() => project(catalog({rules: [installRule(changes)]})));
    assert.throws(() => project(catalog({rules: [npmRule({operation_bundle: BUNDLE})]})));
  }],
  ['all same-app registry grants conflict without changing old permissions', () => {
    for (const sibling of [npmRule(), publishRule()]) {
      const existing = project(catalog({rules: [sibling]}));
      assert.equal(pure.run('npmInstallNewRuleAvailable(input,"' + IDS.application + '")', existing), false);
      for (const rules of [[installRule(), {...sibling, id: 'second'}], [{...sibling, id: 'second'}, installRule()]])
        assert.throws(() => project(catalog({rules})));
    }
    const installed = project(catalog({rules: [installRule()]}));
    assert.equal(pure.run('npmNewRuleAvailable(input,"' + IDS.application + '")', installed), false);
    assert.equal(project(catalog({rules: [npmRule()]})).access_rules[0].operation_bundle, 'npm_metadata_read_v1');
  }],
  ['public recipe separates app token, TLS and reviewed source/output paths', () => {
    const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application,
      proxyAuthentication: 'basic_and_bearer_v1', packages: PACKAGES};
    const text = pure.run('buildNpmInstallClientRecipe(input)', input);
    for (const value of ['SERVERWARE_PROXY_TOKEN', 'SERVERWARE_CA_FILE', 'SERVERWARE_NPM_PROJECT', 'SERVERWARE_NPM_OUTPUT',
      'SERVERWARE_NPM_PACKAGE', 'SERVERWARE_NPM_VERSION', 'node client.mjs install', 'node client.mjs ci',
      'Lifecycle scripts are disabled', 'default npm audit remains on', 'including dependencies', 'does not exist']) assert(text.includes(value), value);
    assert(!text.includes('strict-ssl=false')); assert(!text.includes('curl '));
    for (const changes of [{proxyAuthentication: 'bearer'}, {proxyUrl: 'http://proxy.example.test'},
      {proxyUrl: 'https://user:password@proxy.example.test'}, {applicationId: 'bad'}, {packages: []}, {caPath: 'bad\npath'}])
      assert.throws(() => pure.run('buildNpmInstallClientRecipe(input)', {...input, ...changes}));
  }],
  ['actual form reviews explicit closure then sends exactly one typed DTO', async () => {
    const f = fixture(); await chooseInstall(f);
    assert(!f.node('connect-npm-packages-group').hidden); assert(f.node('connect-npm-publish-group').hidden);
    assert.match(f.node('connect-npm-packages-label').textContent, /dependency/);
    assert.match(f.node('connect-npm-packages-help').textContent, /transitive.*peer/);
    assert(f.node('connect-exact-content').hidden); assert(f.node('connect-response-mode').disabled);
    await f.event('connect-access-form', 'submit'); assert(!f.node('connect-review-step').hidden, f.node('connect-status').textContent);
    assert.equal(f.posts.length, 0); await f.event('connect-grant'); assert.equal(f.posts.length, 1);
    assert.deepEqual(f.posts[0].body.packages, PACKAGES); assert.equal(f.posts[0].body.operation_bundle, BUNDLE);
    assert(!f.node('connect-setup-step').hidden);
  }],
  ['metadata remains default, absent live capability never offers fallback', async () => {
    const f = fixture({installCapability: null}); await existingPair(f);
    assert.equal(f.node('connect-operation').value, 'npm_metadata_read_v1');
    assert(!f.node('connect-operation').children.some(item => item.value === BUNDLE));
    f.node('connect-operation').value = BUNDLE; await f.event('connect-operation', 'change');
    assert(f.node('connect-review').disabled); await f.event('connect-access-form', 'submit'); assert.equal(f.posts.length, 0);
  }],
  ['saved permission remains reusable and does not trigger a new POST', async () => {
    const f = fixture({rules: [installRule()]}); await chooseInstall(f); assert(f.node('connect-review').disabled);
    f.node('connect-rule-choice').value = IDS.rule; await f.event('connect-rule-choice', 'change');
    await f.event('connect-access-form', 'submit'); await f.event('connect-grant'); assert.equal(f.posts.length, 0);
    assert(!f.node('connect-setup-step').hidden);
  }],
  ['capability drift, unknown outcome and changed receipt cannot retry or widen', async () => {
    const changed = fixture(); await chooseInstall(changed); await changed.event('connect-access-form', 'submit');
    changed.raw.capabilities.npm_install = null; changed.raw.revision++;
    changed.workspace.state.catalog = project(changed.raw); changed.workspace.render();
    await changed.event('connect-grant'); assert.equal(changed.posts.length, 0);
    const unknown = fixture({uncertain: true}); await chooseInstall(unknown); await unknown.event('connect-access-form', 'submit');
    await unknown.event('connect-grant'); await unknown.event('connect-grant'); assert.equal(unknown.posts.length, 1);
    const mismatch = fixture({receiptChange: {packages: ['different-package']}}); await chooseInstall(mismatch);
    await mismatch.event('connect-access-form', 'submit'); await mismatch.event('connect-grant'); await mismatch.event('connect-grant');
    assert.equal(mismatch.posts.length, 1); assert(mismatch.node('connect-setup-step').hidden);
    assert.match(mismatch.node('connect-status').textContent, /not yet confirmed.*do not submit again/);
  }],
];
async function main() {
  assert.equal(process.argv.length, 2);
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, generated_recipe_executed: false}));
}
module.exports = {capability, installRule};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
