#!/usr/bin/env node
'use strict';
// Pure current-source renderer/checker agreement. No browser, app startup,
// Docker, sockets, private files, provider calls, or runtime receipt writes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const ASSETS = path.join(ROOT, 'serverware/operator_demo_web');
const PORTAL = path.join(ROOT, 'serverware/operator_demo_portal.py');
const CHECKER = path.join(__dirname, 'check_operator_runtime_browser.cjs');
const NOW = 1800000000000, FIXTURE = 'https://demo-upstream:8443', GMAIL = 'https://gmail.googleapis.com';
const UPSTREAM_LISTS = [[FIXTURE], [FIXTURE, GMAIL],
  [FIXTURE, 'https://api.github.com', 'https://registry.npmjs.org', GMAIL]];
const CATALOG = '/api/operator-demo/catalog', UPSTREAMS = '/api/operator-demo/proxy/upstreams';
const GOOGLE = '/api/operator-demo/oauth/google/configuration/v2';
const PUBLIC = 'https://serverware-demo.example.com', POLICY = 'sha256:' + 'a'.repeat(64);
const source = fs.readFileSync(CHECKER, 'utf8');
const entrypoint = '\n(async () => {\n';
assert.equal(source.split(entrypoint).length, 2, 'one explicit runtime entrypoint');
const declarations = source.split(entrypoint)[0];

// Invoke the actual standalone Python renderer, not a second JS rendering
// implementation. Its only imports are stdlib; do not import serverware/app.
const reference = JSON.parse(execFileSync(process.env.SERVERWARE_TEST_PYTHON || '/usr/bin/python3',
  ['-I', '-B', '-c', `
import base64, importlib.util, json, pathlib, sys
def deny_runtime(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in {'os.system', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('renderer attempted runtime I/O')
sys.addaudithook(deny_runtime)
spec = importlib.util.spec_from_file_location('public_renderer_only', pathlib.Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
scripts = module.SCRIPT_FILES
variants = []
for omitted in ({'workspace_x.js', 'workspace_alchemy.js', 'workspace_aws.js', 'workspace_gmail_sdk.js'},
                {'workspace_alchemy.js', 'workspace_aws.js', 'workspace_gmail_sdk.js'},
                {'workspace_aws.js', 'workspace_gmail_sdk.js'}, {'workspace_gmail_sdk.js'}, set()):
    module.SCRIPT_FILES = tuple(name for name in scripts if name not in omitted)
    module.render.cache_clear()
    variants.append({'scripts': module.SCRIPT_FILES,
        'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')})
print(json.dumps({'scripts': module.SCRIPT_FILES,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii'), 'variants': variants}))
`, path.join(ROOT, 'serverware/operator_demo_portal.py')],
  {encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024,
    env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'}}));
const expected = Buffer.from(reference.html, 'base64');
assert(expected.length > 0 && expected.length <= 2 * 1024 * 1024);
let forbiddenCalls = 0;
function forbidden() { forbiddenCalls++; throw new Error('pure asset test attempted runtime I/O'); }

function fixture(overrides = {}) {
  const reads = [];
  const context = vm.createContext({Buffer, structuredClone, Date: class extends Date { static now() { return NOW; } }, __dirname, __filename: CHECKER,
    fixtureRoot: ROOT, fixtureReply: null, fixtureRequests: [],
    require(name) {
      if (name === 'node:path') return path;
      if (name === 'node:crypto') return require(name);
      if (name === 'node:fs') return {
        readFileSync(filename, encoding) {
          assert(filename === PORTAL || path.dirname(filename) === ASSETS, 'only selected public renderer/assets may be read');
          assert.equal(encoding, 'utf8');
          const name = path.basename(filename); reads.push(name);
          if (Object.hasOwn(overrides, name)) {
            if (overrides[name] instanceof Error) throw overrides[name];
            return overrides[name];
          }
          return fs.readFileSync(filename, encoding);
        }, realpathSync: forbidden, mkdirSync: forbidden, writeFileSync: forbidden};
      if (name === 'node:child_process') return {execFile: forbidden};
      if (name.endsWith('/lib/node_modules/playwright')) return {chromium: {launch: forbidden}};
      throw new Error('unexpected checker dependency');
    }, setTimeout: forbidden, clearTimeout: forbidden});
  const run = code => vm.runInContext(code, context, {timeout: 1000});
  run(declarations);
  run('source = fixtureRoot; bridge = async payload => { fixtureRequests.push(payload); return fixtureReply; };');
  return {context, reads, run,
    render(managed) { context.mode = managed; return run('managedGoogle = mode; documentBytes()'); },
    async getActual(body) {
      context.fixtureReply = {status: 200, headers: [['content-type', 'text/html']], body_base64: body.toString('base64')};
      return run('get("/")');
    }};
}

function reviewed(origins = UPSTREAM_LISTS[2], revision = 39, managed = true) {
  const f = fixture();
  f.context.origins = [...origins]; f.context.revision = revision; f.context.managed = managed;
  f.run('expectedUpstreams = origins; expectedRevision = revision; managedGoogle = managed');
  const app = (id, status, expiry, token, access, rules) => ({id, status, token_expires_at_epoch_ms: expiry,
    token_generation: 1, token_status: token, access_status: access, active_rule_count: rules});
  const catalog = {schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
    hardwareVerified: false, revision: revision === null ? 13 : revision, allowed_upstreams: [...origins],
    policy: {activation: 'active', policy_hash: POLICY, loaded_policy_hash: POLICY},
    capabilities: {oauth: false, google_oauth: null}, observed_activity: {observed_at_epoch_ms: NOW},
    credentials: [{id: 'credential'}], access_rules: [{id: 'rule'}], applications: [
      app('active', 'active', NOW + 600000, 'valid', 'active', 1),
      app('expired', 'active', NOW - 1000, 'expired', 'pending', 1),
      app('revoked', 'revoked', NOW + 600000, 'revoked', 'revoked', 0)]};
  if (revision === null) catalog.applications = [catalog.applications[1]];
  const settings = {allowed_upstreams: [...origins], fixture_cidrs: ['127.0.0.0/8']};
  // Independent fixed-key canonical input, not the checker's serial/hash helper.
  const digest = 'sha256:' + require('node:crypto').createHash('sha256').update(JSON.stringify(settings)).digest('hex');
  const upstreams = {schema: 'serverware.operatorUpstreamSetupReview/v1', old_settings: settings,
    expected_settings_digest: digest, cold_restart_required: true, eligible: true, pending_operation_id: null,
    blocked_reason: null, expected_revision: catalog.revision, expected_policy_hash: POLICY};
  const google = {schema: 'serverware.operatorGoogleConfiguration/v2', state: 'unconfigured', revision: catalog.revision,
    policy_hash: POLICY, effective_settings: structuredClone(settings), effective_settings_digest: digest,
    public_url: PUBLIC, redirect_uri: PUBLIC + '/api/oauth/callback/google', permission_preset: 'gmail_readonly',
    scopes: ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'], blocked_reason: null, operation: null,
    readiness: {pair_ready: true, consent_ready: false, loaded_policy_hash: POLICY},
    review: {schema: 'serverware.operatorGoogleManagedSetupReview/v2', expected_revision: catalog.revision,
      expected_policy_hash: POLICY, expected_settings_digest: digest, old_settings: structuredClone(settings),
      target_settings: {allowed_upstreams: origins.includes(GMAIL) ? [...origins] : [...origins, GMAIL],
        fixture_cidrs: ['127.0.0.0/8']}, public_url: PUBLIC, redirect_uri: PUBLIC + '/api/oauth/callback/google',
      provider_id: 'google', permission_preset: 'gmail_readonly',
      scopes: ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'], eligible: true}};
  return {f, catalog, upstreams, google};
}
function validate(f, route, value) {
  f.context.fixturePath = route; f.context.fixtureValue = value;
  return f.run('validate(fixturePath, fixtureValue)');
}

const tests = [
  ['actual documentBytes matches all five closed Python renderer rosters in both checker modes', async () => {
    assert.equal(reference.variants.length, 5);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_aws.js')), [false, false, false, true, true]);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_gmail_sdk.js')), [false, false, false, false, true]);
    for (const variant of reference.variants) {
      for (const managed of [false, true]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + variant.scripts.map(JSON.stringify).join(', ') + ')\n'});
      const names = JSON.parse(f.run('JSON.stringify(sourceScriptFiles())'));
      assert.deepEqual(names, variant.scripts);
      assert.equal(new Set(names).size, names.length);
      assert.equal(names[names.indexOf('workspace_npm.js') + 1], 'workspace_npm_publish.js');
      assert.deepEqual(names.slice(-2), ['workspace_google_configuration.js', 'app.js']);
      f.reads.length = 0;
      const actual = f.render(managed);
      const bytes = Buffer.from(variant.html, 'base64');
      assert(actual.equals(bytes), 'exact UTF-8 HTML bytes must match actual renderer');
      assert.deepEqual(f.reads, ['operator_demo_portal.py', 'index.html', ...variant.scripts, 'style.css']);
      f.context.fixtureExpected = actual; f.run('expectedHtml = fixtureExpected');
      const response = await f.getActual(bytes);
      assert(response.body.equals(bytes));
      assert.equal(f.context.fixtureRequests.length, 1);
      assert.equal(f.context.fixtureRequests[0].path, '/');
      assert.equal(f.context.fixtureRequests[0].op, 'get');
      assert.equal(f.context.fixtureRequests[0].managed_google_unconfigured, managed ? true : undefined);
      }
    }
  }],
  ['AWS is admitted only in its exact current roster and position, not mixed historical rosters', () => {
    const names = reference.variants[3].scripts;
    assert.equal(names[names.indexOf('workspace_alchemy.js') + 1], 'workspace_aws.js');
    assert.equal(names[names.indexOf('workspace_aws.js') + 1], 'workspace_google.js');
    for (const changed of [names.filter(name => name !== 'workspace_x.js'),
      names.filter(name => name !== 'workspace_alchemy.js'),
      names.filter(name => !['workspace_x.js', 'workspace_alchemy.js'].includes(name)),
      ['workspace_aws.js', ...names.filter(name => name !== 'workspace_aws.js')],
      [...names, 'workspace_aws.js']]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py'], 'refused roster never reads candidate assets');
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['Gmail SDK is additive only in its exact selected position, never mixed into older rosters', () => {
    const names = reference.scripts;
    assert.equal(names[names.indexOf('workspace_applications.js') + 1], 'workspace_gmail_sdk.js');
    assert.equal(names[names.indexOf('workspace_gmail_sdk.js') + 1], 'workspace_proxy_audit.js');
    for (const changed of [names.filter(name => name !== 'workspace_aws.js'),
      names.filter(name => name !== 'workspace_alchemy.js'), names.filter(name => name !== 'workspace_x.js'),
      ['workspace_gmail_sdk.js', ...names.filter(name => name !== 'workspace_gmail_sdk.js')],
      [...names, 'workspace_gmail_sdk.js']]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py'], 'refused roster never reads candidate assets');
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['missing or reordered modules and any changed response byte fail exact HTML comparison', async () => {
    for (const names of [reference.scripts.filter(name => name !== 'workspace_npm_publish.js'),
      reference.scripts.filter(name => name !== 'workspace_google_configuration.js'),
      [reference.scripts[1], reference.scripts[0], ...reference.scripts.slice(2)],
      [...reference.scripts, 'unknown.js'], [...reference.scripts, reference.scripts[0]],
      ['../private.js', ...reference.scripts.slice(1)]]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + names.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
    }
    for (const portal of ['SCRIPT_FILES = make_scripts()\n', 'SCRIPT_FILES = ("app.js",)\nSCRIPT_FILES = ("app.js",)\n',
      'x'.repeat(65537), 'SCRIPT_FILES = ("app.js", extra)\n'])
      assert.throws(() => fixture({'operator_demo_portal.py': portal}).render(false), error => error.message === 'renderer_roster_refused');
    const f = fixture(); f.context.fixtureExpected = f.render(false); f.run('expectedHtml = fixtureExpected');
    const changed = Buffer.from(expected); changed[changed.length - 1] ^= 1;
    await assert.rejects(f.getActual(changed), error => error.message === 'actual_renderer_mismatch');
  }],
  ['raw-text escapes and missing or duplicated HTML markers still refuse', () => {
    for (const [name, value] of [['workspace_npm_publish.js', '/* </ScRiPt> */'],
      ['workspace_aws.js', '/* </ScRiPt> */'], ['workspace_gmail_sdk.js', '/* </ScRiPt> */'], ['style.css', '/* </StYlE> */']]) {
      for (const managed of [false, true]) assert.throws(() => fixture({[name]: value}).render(managed),
        error => error.message === 'renderer_raw_text_terminator');
    }
    const html = fs.readFileSync(path.join(ASSETS, 'index.html'), 'utf8');
    for (const marker of ['__OPERATOR_DEMO_STYLE__', '__OPERATOR_DEMO_SCRIPT__']) {
      for (const value of [html.replace(marker, ''), html.replace(marker, marker + marker)]) {
        assert.throws(() => fixture({'index.html': value}).render(true), error => error.message === 'renderer_marker');
      }
    }
  }],
  ['a missing selected asset fails closed without fallback or runtime work', () => {
    for (const name of ['workspace_npm_publish.js', 'workspace_aws.js', 'workspace_gmail_sdk.js', 'workspace_google_configuration.js']) {
      const failure = Object.assign(new Error('synthetic missing public asset'), {code: 'ENOENT'});
      for (const managed of [false, true]) assert.throws(() => fixture({[name]: failure}).render(managed),
        error => error === failure);
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['actual navigation helper awaits visibility before view inspection and preserves timeouts', async () => {
    for (const name of ['proxy', 'applications', 'notifications']) {
      const f = fixture(), calls = [];
      let release, entered, visible = false;
      const waiting = new Promise(resolve => { entered = resolve; });
      const visibility = new Promise(resolve => { release = resolve; });
      f.context.navigationName = name;
      f.context.fixturePage = {locator(selector) {
        if (selector === `nav a[href="#${name}"]`) return {
          async click() { calls.push('click'); },
          async getAttribute(attribute) { assert(visible); assert.equal(attribute, 'aria-current'); calls.push('aria'); return 'page'; }};
        if (selector === 'section.page#' + name) return {async waitFor(options) {
          assert.deepEqual(JSON.parse(JSON.stringify(options)), {state: 'visible'});
          calls.push('wait'); entered(); await visibility;
        }};
        assert.equal(selector, 'section.page:visible');
        return {async count() { assert(visible); calls.push('count'); return 1; }};
      }};
      const navigation = f.run('navigateSection(fixturePage, navigationName)');
      try {
        await Promise.race([waiting, navigation.then(() => assert(visible, 'navigation returned before visibility wait'))]);
        assert.deepEqual(calls, ['click', 'wait'], 'no aria/count/view checks before visibility resolves');
      } finally { visible = true; release(); }
      await navigation;
      assert.deepEqual(calls, ['click', 'wait', 'aria', 'count']);

      const timeout = Object.assign(new Error('synthetic navigation timeout'), {name: 'TimeoutError'});
      calls.length = 0; visible = false;
      const locator = f.context.fixturePage.locator;
      f.context.fixturePage.locator = selector => selector === 'section.page#' + name ?
        {async waitFor() { calls.push('wait'); throw timeout; }} : locator(selector);
      await assert.rejects(f.run('navigateSection(fixturePage, navigationName)'), error => error === timeout);
      assert.deepEqual(calls, ['click', 'wait']);
    }
    for (const [current, count] of [[null, 1], ['page', 0], ['page', 2]]) {
      const f = fixture();
      f.context.fixturePage = {locator: () => ({async click() {}, async waitFor() {},
        async getAttribute() { return current; }, async count() { return count; }})};
      await assert.rejects(f.run('navigateSection(fixturePage, "proxy")'), error => error.message === 'navigation_state_mismatch');
    }
    const f = fixture(); f.context.fixturePage = {locator: forbidden};
    await assert.rejects(f.run('navigateSection(fixturePage, "audit")'), error => error.message === 'navigation_section_refused');
  }],
  ['proxy-default refusal records only the five fixed booleans and success adds no diagnostic', async () => {
    const expectedChecks = {panel_visible: true, effective_fixture: true, form_hidden: true,
      no_review_get: true, restart_notice_present: true};
    for (const failed of [null, ...Object.keys(expectedChecks)]) {
      const f = fixture(), canary = 'synthetic-private-DOM-canary';
      f.context.fixturePage = {locator(selector) {
        if (selector === '#proxy-upstreams') return {
          async isVisible() { return failed !== 'panel_visible'; },
          async innerText() { return failed === 'restart_notice_present' ? canary :
            'Apps still need permission. Changes require a controlled restart.'; }};
        if (selector === '#upstreams-effective') return {async innerText() {
          return failed === 'effective_fixture' ? canary : 'https://demo-upstream:8443'; }};
        assert.equal(selector, '#upstreams-form');
        return {async isHidden() { return failed !== 'form_hidden'; }};
      }};
      if (failed === 'no_review_get') f.run('seen[UPSTREAMS] = 1');
      if (failed === null) {
        await f.run('verifyProxyDefault(fixturePage)');
        assert.equal(f.run('Object.hasOwn(receipt, "proxy_default_checks")'), false);
      } else {
        await assert.rejects(f.run('verifyProxyDefault(fixturePage)'), error => error.message === 'proxy_default_mismatch');
        const projection = f.run('JSON.stringify(receipt.proxy_default_checks)');
        assert.deepEqual(JSON.parse(projection), {...expectedChecks, [failed]: false});
        assert(!projection.includes(canary));
      }
      assert.equal(f.context.fixtureRequests.length, 0);
    }
  }],
  ['runtime options accept only the three exact reviewed rosters and positive safe revisions', () => {
    const f = fixture(), base = ['a'.repeat(64), 'b'.repeat(40), '/synthetic/fresh'];
    const parse = args => { f.context.args = args; return JSON.parse(f.run('JSON.stringify(parseRuntimeOptions(args))')); };
    assert.deepEqual(parse(base), {appId: base[0], commit: base[1], output: base[2], managedGoogle: false,
      expectedUpstreams: [FIXTURE], expectedRevision: null, explicitUpstreams: false});
    assert.equal(parse([...base, '--managed-google-unconfigured']).managedGoogle, true);
    for (const origins of UPSTREAM_LISTS) {
      const result = parse([...base, '--expected-catalog-revision', '39', '--expected-upstreams', JSON.stringify(origins),
        '--managed-google-unconfigured']);
      assert.deepEqual(result.expectedUpstreams, origins); assert.equal(result.expectedRevision, 39);
      assert.equal(result.managedGoogle, true); assert.equal(result.explicitUpstreams, true);
    }
    for (const invalid of [[], [GMAIL], [FIXTURE, FIXTURE], [...UPSTREAM_LISTS[2], 'https://extra.invalid'],
      [...UPSTREAM_LISTS[2]].reverse(), ['https://demo-upstream:8443/'], null, {}, 'https://api.github.com'])
      assert.throws(() => parse([...base, '--expected-upstreams', JSON.stringify(invalid)]),
        error => error.message === 'expected_upstreams_refused');
    for (const invalid of ['', '0', '-1', '1.5', '01', '+39', ' 39', '39 ', 'true', '9007199254740992'])
      assert.throws(() => parse([...base, '--expected-catalog-revision', invalid]), error => error.message === 'expected_revision_refused');
    for (const suffix of [['--expected-upstreams'], ['--expected-catalog-revision'], ['--unknown'],
      ['--expected-upstreams', '['], ['--expected-upstreams', 'x'.repeat(1025)],
      ['--managed-google-unconfigured', '--managed-google-unconfigured'],
      ['--expected-catalog-revision', '39', '--expected-catalog-revision', '40']])
      assert.throws(() => parse([...base, ...suffix]));
    assert.equal(f.context.fixtureRequests.length, 0);
  }],
  ['reviewed catalog admits coherent mixed application states and exact badge labels only', () => {
    const {f, catalog} = reviewed(); validate(f, CATALOG, catalog);
    f.context.sampleCatalog = catalog;
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(sampleCatalog.applications.map(app => applicationBadge(app, sampleCatalog)))')),
      ['Active', 'Token expired', 'Revoked · enforced']);
    for (const [patch, policy, expected] of [
      [{active_rule_count: 0, access_status: 'unassigned'}, catalog.policy, 'No access rules'],
      [{access_status: 'pending'}, {...catalog.policy, activation: 'pending', loaded_policy_hash: null}, 'Access pending'],
      [{status: 'revoked', token_status: 'revoked', access_status: 'pending'},
        {...catalog.policy, activation: 'pending', loaded_policy_hash: null}, 'Revoked · enforcement pending'],
      [{token_expires_at_epoch_ms: NOW, token_status: 'expired', access_status: 'pending'}, catalog.policy, 'Token expired']]) {
      f.context.sampleApp = {...catalog.applications[0], ...patch}; f.context.samplePolicy = policy;
      assert.equal(f.run('applicationBadge(sampleApp, {policy: samplePolicy})'), expected);
    }
    for (const patch of [{status: 'expired'}, {token_status: 'expired'}, {token_status: 'revoked'}, {access_status: 'pending'},
      {token_expires_at_epoch_ms: 0}, {token_expires_at_epoch_ms: '1800000600000'}, {token_expires_at_epoch_ms: 1.5},
      {token_expires_at_epoch_ms: null}, {token_generation: 0}, {token_generation: true}, {active_rule_count: -1},
      {active_rule_count: '1'}]) {
      const sample = reviewed(); Object.assign(sample.catalog.applications[0], patch);
      assert.throws(() => validate(sample.f, CATALOG, sample.catalog), error => error.message === 'reviewed_application_state_mismatch');
    }
    for (const mutate of [c => c.revision = 40, c => c.revision = '39', c => c.allowed_upstreams.pop(),
      c => c.allowed_upstreams.push('https://extra.invalid'), c => c.productionReady = true]) {
      const sample = reviewed(); mutate(sample.catalog); assert.throws(() => validate(sample.f, CATALOG, sample.catalog));
    }
    for (const managed of [false, true]) {
      const legacy = reviewed([FIXTURE], null, managed); validate(legacy.f, CATALOG, legacy.catalog);
      const invalid = reviewed([FIXTURE], null, managed); invalid.catalog.applications[0].token_status = 'valid';
      assert.throws(() => validate(invalid.f, CATALOG, invalid.catalog), error => error.message === 'retained_app_not_expired');
    }
    const legacyRevision = reviewed([FIXTURE], null, true); legacyRevision.catalog.revision = 39;
    assert.throws(() => validate(legacyRevision.f, CATALOG, legacyRevision.catalog), error => error.message === 'managed_unconfigured_catalog_mismatch');
  }],
  ['upstream review preserves exact settings digest revision policy and no-pending-operation CAS', () => {
    for (const origins of UPSTREAM_LISTS) {
      const sample = reviewed(origins); validate(sample.f, CATALOG, sample.catalog); validate(sample.f, UPSTREAMS, sample.upstreams);
    }
    for (const mutate of [v => v.old_settings.allowed_upstreams.pop(), v => v.old_settings.fixture_cidrs.push('10.0.0.0/8'),
      v => v.old_settings.extra = true, v => v.expected_settings_digest = 'sha256:' + 'b'.repeat(64),
      v => v.expected_revision = 38, v => v.expected_policy_hash = 'sha256:' + 'b'.repeat(64),
      v => v.eligible = false, v => v.cold_restart_required = false, v => v.pending_operation_id = 'pending',
      v => v.blocked_reason = 'blocked']) {
      const sample = reviewed(); validate(sample.f, CATALOG, sample.catalog); mutate(sample.upstreams);
      assert.throws(() => validate(sample.f, UPSTREAMS, sample.upstreams), error => error.message === 'upstream_review_mismatch');
    }
  }],
  ['managed Google uses reviewed revision and exact current origins plus Gmail only when absent', () => {
    for (const origins of UPSTREAM_LISTS) {
      for (const revision of [null, 39]) {
        const sample = reviewed(origins, revision); validate(sample.f, CATALOG, sample.catalog);
        validate(sample.f, UPSTREAMS, sample.upstreams); validate(sample.f, GOOGLE, sample.google);
        assert.equal(sample.f.run('expectedGoogleAddedOrigin()'), origins.includes(GMAIL) ?
          'None — https://gmail.googleapis.com is already an allowed destination.' : GMAIL);
      }
    }
    for (const mutate of [v => v.revision = 13, v => v.policy_hash = 'sha256:' + 'b'.repeat(64),
      v => v.effective_settings_digest = 'sha256:' + 'b'.repeat(64), v => v.review.expected_revision = 13,
      v => v.review.expected_policy_hash = 'sha256:' + 'b'.repeat(64), v => v.review.expected_settings_digest = 'sha256:' + 'b'.repeat(64),
      v => v.review.target_settings.allowed_upstreams.push(GMAIL), v => v.review.target_settings.allowed_upstreams.shift(),
      v => v.review.target_settings.fixture_cidrs.push('10.0.0.0/8'), v => v.review.eligible = false,
      v => v.readiness.pair_ready = false, v => v.readiness.consent_ready = true, v => v.operation = {},
      v => v.scopes.push('extra'), v => v.review.provider_id = 'unknown']) {
      const sample = reviewed(); validate(sample.f, CATALOG, sample.catalog); validate(sample.f, UPSTREAMS, sample.upstreams);
      mutate(sample.google); assert.throws(() => validate(sample.f, GOOGLE, sample.google));
    }
  }],
  ['before and after snapshots ignore only the original sampling clock and refuse resource drift', () => {
    const sample = reviewed(); validate(sample.f, CATALOG, sample.catalog);
    const clockOnly = structuredClone(sample.catalog); clockOnly.observed_activity.observed_at_epoch_ms++;
    validate(sample.f, CATALOG, clockOnly);
    for (const mutate of [c => c.credentials[0].name = 'changed', c => c.applications[0].token_generation++,
      c => c.access_rules[0].id = 'different', c => c.observed_activity.new_field = true]) {
      const changed = structuredClone(sample.catalog); mutate(changed);
      assert.throws(() => validate(sample.f, CATALOG, changed), error => error.message === 'public_resource_changed_during_read');
    }
    validate(sample.f, UPSTREAMS, sample.upstreams);
    const changedReview = structuredClone(sample.upstreams); changedReview.new_field = true;
    assert.throws(() => validate(sample.f, UPSTREAMS, changedReview), error => error.message === 'public_resource_changed_during_read');
  }],
  ['proxy DOM comparison requires the exact reviewed four-origin display with no extra request', async () => {
    for (const text of [UPSTREAM_LISTS[2].join('\n'), FIXTURE, [...UPSTREAM_LISTS[2]].reverse().join('\n'),
      [...UPSTREAM_LISTS[2], 'https://extra.invalid'].join('\n')]) {
      const {f} = reviewed();
      f.context.fixturePage = {locator(selector) {
        if (selector === '#proxy-upstreams') return {async isVisible() { return true; },
          async innerText() { return 'Apps still need permission. Changes require a controlled restart.'; }};
        if (selector === '#upstreams-effective') return {async innerText() { return text; }};
        assert.equal(selector, '#upstreams-form'); return {async isHidden() { return true; }};
      }};
      if (text === UPSTREAM_LISTS[2].join('\n')) await f.run('verifyProxyDefault(fixturePage)');
      else await assert.rejects(f.run('verifyProxyDefault(fixturePage)'), error => error.message === 'proxy_default_mismatch');
      assert.equal(f.context.fixtureRequests.length, 0);
    }
  }],
];

(async () => {
  for (const [name, test] of tests) { await test(); process.stdout.write('PASS ' + name + '\n'); }
  assert.equal(forbiddenCalls, 0);
  process.stdout.write(`PASS ${tests.length} pure runtime-browser asset groups; no browser or service calls\n`);
})().catch(error => { console.error(error); process.exitCode = 1; });
