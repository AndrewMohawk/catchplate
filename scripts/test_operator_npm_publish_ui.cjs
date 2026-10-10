#!/usr/bin/env node
// Pure DTO/recipe and actual Connect handlers against an inert DOM. No provider,
// browser, network, npm command or generated recipe is executed.
const assert = require('node:assert/strict');
const {context, rawCatalog, npmRule, cap, existingPair, IDS, clone} = require('./test_operator_npm_ui.cjs');
const ORIGIN = 'https://registry.npmjs.org';
const PACKAGE = '@example/package';
const BUNDLE = 'npm_publish_v1';
const capability = (allowed = true) => ({schema: 'serverware.operatorNpmPublish/v1', connection_type: 'npm_token_v1',
  create_rule_path: '/api/operator-demo/access-rules/npm-publish', registry_origin: ORIGIN, destination_allowed: allowed,
  operation_bundles: [BUNDLE], sdk_auth_token: 'serverware-npm-placeholder-v1', placeholder: 'Bearer serverware-npm-placeholder-v1',
  response_mode: 'npm_publish_json_v1', source_pair_required: true, max_active_rules_per_application: 1, default_tag: 'latest',
  publishing_window_timezone: 'UTC', read_metadata_included: true, max_request_body_bytes: 16777216, max_tarball_bytes: 8388608});
function publishRule(changes = {}) {
  const result = npmRule({name: 'Publish package · ' + PACKAGE, operation_bundle: BUNDLE, package: PACKAGE, tag: 'latest', publishing_window: null,
    methods: ['PUT'], allowed_headers: ['accept', 'content-type', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'user-agent'],
    response_mode: 'npm_publish_json_v1'});
  delete result.packages; return {...result, ...changes};
}
function catalog({rules = [], publishCapability = capability(), ...rest} = {}) {
  const raw = rawCatalog({rules, ...rest});
  raw.capabilities.npm_publish = publishCapability; return raw;
}
const pure = context();
const project = raw => clone(pure.run('projectCatalog(input)', raw));
function fixture(options = {}) {
  const current = context(); const raw = catalog(options); const posts = [];
  const workspace = {state: {catalog: project(raw), busy: false, uncertain: false}, ready: () => true, loaded: () => true,
    subscribe(callback) { this.render = callback; callback(); }, refresh() { this.render(); },
    async mutate(path, body, status, receipt) {
      posts.push({path, body: clone(body)});
      assert.equal(path, 'access-rules/npm-publish');
      assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'name', 'operation_bundle', 'package', 'publishing_window', 'tag']);
      if (options.uncertain) { this.state.uncertain = true; this.render(); return false; }
      raw.access_rules = [publishRule({...body, ...(options.receiptChange || {})})]; raw.revision++;
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
async function choosePublish(f, window = false) {
  await existingPair(f); f.node('connect-operation').value = BUNDLE; await f.event('connect-operation', 'change');
  f.node('connect-npm-publish-package').value = PACKAGE; f.node('connect-npm-publish-tag').value = 'latest';
  f.node('connect-npm-publish-hours').value = window ? 'window' : 'any'; await f.event('connect-npm-publish-hours', 'change');
}
const tests = [
  ['closed new capability only; metadata capability remains unchanged', () => {
    const raw = catalog({rules: [publishRule()]}); raw.credentials[0].secret = 'PRIVATE_CANARY';
    const value = project(raw); assert.deepEqual(value.capabilities.npm_publish, capability());
    assert.deepEqual(value.capabilities.npm, cap()); assert(!JSON.stringify(value).includes('PRIVATE_CANARY'));
    for (const changed of [null, {...capability(), read_metadata_included: false}, {...capability(), publishing_window_timezone: 'local'},
      {...capability(), max_tarball_bytes: 999}, {...capability(), create_rule_path: '/other'}, {...capability(), extra: true}]) {
      const saved = project(catalog({rules: [publishRule()], publishCapability: changed}));
      assert.equal(saved.capabilities.npm_publish, null);
      assert.equal(pure.run('operatorRuleSupported(input.access_rules[0], input)', saved), false);
    }
    for (const options of [{publishCapability: capability(false)}, {allowed: []}])
      assert.equal(pure.run('operatorRuleSupported(input.access_rules[0], input)', project(catalog({...options, rules: [publishRule()]}))), false);
  }],
  ['exact package/tag and nullable half-open same-day UTC window', () => {
    assert.deepEqual(clone(pure.run('npmPublishRuleFields(input.package,input.tag,input.publishing_window)', publishRule())),
      Object.fromEntries(Object.keys(clone(pure.run('npmPublishRuleFields(input.package,input.tag,input.publishing_window)', publishRule()))).map(key => [key, publishRule()[key]])));
    for (const changes of [{package: 'Pkg'}, {package: '*'}, {package: 'pkg@1.0.0'}, {tag: 'Latest'}, {tag: '1.0.0'}, {tag: 'a'.repeat(65)},
      {publishing_window: {}}, {publishing_window: {start: '24:00', end: '24:01'}}, {publishing_window: {start: '17:00', end: '09:00'}},
      {publishing_window: {start: '09:00', end: '09:00'}}, {publishing_window: {start: '09:00', end: '17:00', timezone: 'UTC'}},
      {publishing_window: {start: '9:00', end: '17:00'}}]) assert.throws(() => project(catalog({rules: [publishRule(changes)]})));
    assert.equal(project(catalog({rules: [publishRule({publishing_window: {start: '00:00', end: '23:59'}})]})).access_rules[0].publishing_window.end, '23:59');
  }],
  ['typed rule cannot gain generic controls or upgrade a metadata grant', () => {
    for (const changes of [{methods: ['GET', 'PUT']}, {request_fields: ['name']}, {response_fields: ['ok']}, {query_keys: ['x']},
      {request_body_mode: 'preserve_json_v1'}, {query_mode: 'orderedFormV1'}, {packages: [PACKAGE]}, {placeholder: 'Bearer REAL'},
      {allowed_headers: ['accept']}, {upstream_url: ORIGIN + '/' + PACKAGE}]) assert.throws(() => project(catalog({rules: [publishRule(changes)]})));
    assert.throws(() => project(catalog({rules: [npmRule({package: PACKAGE})]})));
    assert.throws(() => project(catalog({rules: [npmRule(), publishRule({id: 'second'})]})));
    assert.equal(pure.run('npmPublishNewRuleAvailable(input, "' + IDS.application + '")', project(catalog({rules: [npmRule()]}))), false);
  }],
  ['stock recipe separates npm dummy from app token and preserves verified TLS', () => {
    const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application, proxyAuthentication: 'basic_and_bearer_v1',
      packageName: PACKAGE, tag: 'latest', publishingWindow: {start: '09:00', end: '17:00'}};
    const recipe = pure.run('buildNpmPublishClientRecipe(input)', input);
    for (const expected of ['https-proxy=https://' + IDS.application + ':${SERVERWARE_PROXY_TOKEN}@proxy.example.test',
      '//registry.npmjs.org/:_authToken=serverware-npm-placeholder-v1', 'strict-ssl=true', 'NODE_EXTRA_CA_CERTS=', 'fetch-retries=0',
      'cache=${SERVERWARE_NPM_CACHE}', "publish ./package.tgz --access=public --tag='latest' --ignore-scripts=true --provenance=false",
      '--force=false --dry-run=false --workspaces=false --json', '09:00–17:00 UTC', 'do not automatically repeat'])
      assert(recipe.includes(expected), expected);
    assert(!recipe.includes('strict-ssl=false')); assert(!recipe.includes('curl '));
    for (const changes of [{proxyUrl: 'http://proxy.example.test'}, {proxyUrl: 'https://user:pass@proxy.example.test'},
      {proxyAuthentication: 'bearer'}, {applicationId: 'invalid'}, {caPath: 'bad\npath'}])
      assert.throws(() => pure.run('buildNpmPublishClientRecipe(input)', {...input, ...changes}));
  }],
  ['new form reviews and submits one exact publishing DTO with UTC hours', async () => {
    const f = fixture(); await choosePublish(f, true);
    assert(!f.node('connect-npm-publish-group').hidden); assert(f.node('connect-npm-packages-group').hidden);
    assert(f.node('connect-exact-content').hidden); assert(f.node('connect-response-mode').disabled);
    f.node('connect-npm-publish-start').value = '09:00'; f.node('connect-npm-publish-end').value = '17:00';
    await f.event('connect-access-form', 'submit'); assert(!f.node('connect-review-step').hidden, f.node('connect-status').textContent);
    assert.match(f.node('connect-review-context').textContent, /09:00–17:00 UTC.*metadata at any time/);
    assert.equal(f.posts.length, 0); await f.event('connect-grant'); assert.equal(f.posts.length, 1);
    assert.deepEqual(f.posts[0].body.publishing_window, {start: '09:00', end: '17:00'});
    assert(!f.node('connect-setup-step').hidden);
  }],
  ['unrestricted window remains null and invalid hours send nothing', async () => {
    const f = fixture(); await choosePublish(f); assert(f.node('connect-npm-publish-window').hidden);
    await f.event('connect-access-form', 'submit'); await f.event('connect-grant'); assert.equal(f.posts[0].body.publishing_window, null);
    const bad = fixture(); await choosePublish(bad, true); bad.node('connect-npm-publish-end').value = '08:00';
    await bad.event('connect-access-form', 'submit'); assert(bad.node('connect-review-step').hidden); assert.equal(bad.posts.length, 0);
  }],
  ['metadata remains default and absent publish capability has no fallback', async () => {
    const f = fixture({publishCapability: null}); await existingPair(f);
    assert.equal(f.node('connect-operation').value, 'npm_metadata_read_v1'); assert(f.node('connect-npm-publish-group').hidden);
    assert(!f.node('connect-operation').children.some(item => item.value === BUNDLE));
    f.node('connect-operation').value = BUNDLE; await f.event('connect-operation', 'change');
    assert(f.node('connect-review').disabled); await f.event('connect-access-form', 'submit'); assert.equal(f.posts.length, 0);
  }],
  ['existing metadata/publishing rule blocks another grant without revoking anything', async () => {
    for (const saved of [npmRule(), publishRule()]) {
      const f = fixture({rules: [saved]}); await choosePublish(f); assert(f.node('connect-review').disabled);
      await f.event('connect-access-form', 'submit'); assert.equal(f.posts.length, 0);
      f.node('connect-rule-choice').value = IDS.rule; await f.event('connect-rule-choice', 'change');
      await f.event('connect-access-form', 'submit'); await f.event('connect-grant'); assert.equal(f.posts.length, 0);
    }
  }],
  ['capability withdrawal, uncertain response and mismatched receipt never retry', async () => {
    const changed = fixture(); await choosePublish(changed); await changed.event('connect-access-form', 'submit');
    changed.raw.capabilities.npm_publish = null; changed.raw.revision++;
    changed.workspace.state.catalog = project(changed.raw); changed.workspace.render();
    await changed.event('connect-grant'); assert.equal(changed.posts.length, 0);
    const unknown = fixture({uncertain: true}); await choosePublish(unknown); await unknown.event('connect-access-form', 'submit');
    await unknown.event('connect-grant'); await unknown.event('connect-grant'); unknown.workspace.refresh(); assert.equal(unknown.posts.length, 1);
    const mismatch = fixture({receiptChange: {tag: 'other'}}); await choosePublish(mismatch); await mismatch.event('connect-access-form', 'submit');
    await mismatch.event('connect-grant'); await mismatch.event('connect-grant'); assert.equal(mismatch.posts.length, 1);
    assert(mismatch.node('connect-setup-step').hidden); assert.match(mismatch.node('connect-status').textContent, /not yet confirmed.*do not submit again/);
  }],
];
async function main() {
  assert.equal(process.argv.length, 2);
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, generated_recipe_executed: false}));
}
module.exports = {capability, publishRule, PACKAGE, BUNDLE};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
