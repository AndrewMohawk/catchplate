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
const ASSETS = path.join(ROOT, 'catchplate/operator_demo_web');
const PORTAL = path.join(ROOT, 'catchplate/operator_demo_portal.py');
const CHECKER = path.join(__dirname, 'check_operator_runtime_browser.cjs');
const NOW = 1800000000000, FIXTURE = 'https://demo-upstream:8443', GMAIL = 'https://gmail.googleapis.com';
const UPSTREAM_LISTS = [[FIXTURE], [FIXTURE, GMAIL],
  [FIXTURE, 'https://api.github.com', 'https://registry.npmjs.org', GMAIL]];
const CATALOG = '/api/operator-demo/catalog', UPSTREAMS = '/api/operator-demo/proxy/upstreams';
const GOOGLE = '/api/operator-demo/oauth/google/configuration/v2';
const X_CONFIGURATION = '/api/operator-demo/oauth/x/configuration/v1';
const X_DISABLED = {detail: 'X configuration is not supported by this deployment'};
const PUBLIC = 'https://catchplate-demo.example.com', POLICY = 'sha256:' + 'a'.repeat(64);
const source = fs.readFileSync(CHECKER, 'utf8');
const entrypoint = '\n(async () => {\n';
assert.equal(source.split(entrypoint).length, 2, 'one explicit runtime entrypoint');
const declarations = source.split(entrypoint)[0];

// Invoke the actual standalone Python renderer, not a second JS rendering
// implementation. Its only imports are stdlib; do not import catchplate/app.
const reference = JSON.parse(execFileSync(process.env.CATCHPLATE_TEST_PYTHON || '/usr/bin/python3',
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
historical_scripts = tuple(name for name in scripts if name not in {'workspace_x_accounts.js', 'workspace_x_post.js', 'workspace_workload_renewal.js', 'workspace_pending_actions.js'})
variants = []
for omitted in ({'workspace_x.js', 'workspace_alchemy.js', 'workspace_aws.js', 'workspace_gmail_sdk.js', 'workspace_x_configuration.js'},
                {'workspace_alchemy.js', 'workspace_aws.js', 'workspace_gmail_sdk.js', 'workspace_x_configuration.js'},
                {'workspace_aws.js', 'workspace_gmail_sdk.js', 'workspace_x_configuration.js'},
                {'workspace_gmail_sdk.js', 'workspace_x_configuration.js'}, {'workspace_x_configuration.js'}, set()):
    module.SCRIPT_FILES = tuple(name for name in historical_scripts if name not in omitted)
    module.render.cache_clear()
    variants.append({'scripts': module.SCRIPT_FILES,
        'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')})
module.SCRIPT_FILES = tuple(name for name in scripts if name not in {'workspace_workload_renewal.js', 'workspace_pending_actions.js'})
module.render.cache_clear()
variants.append({'scripts': module.SCRIPT_FILES,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')})
module.SCRIPT_FILES = tuple(name for name in scripts if name != 'workspace_pending_actions.js')
module.render.cache_clear()
variants.append({'scripts': module.SCRIPT_FILES,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')})
module.SCRIPT_FILES = scripts
module.render.cache_clear()
variants.append({'scripts': scripts,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')})
print(json.dumps({'scripts': module.SCRIPT_FILES,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii'), 'variants': variants}))
`, path.join(ROOT, 'catchplate/operator_demo_portal.py')],
  {encoding: 'utf8', timeout: 10000, maxBuffer: 8 * 1024 * 1024,
    env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'}}));
const expected = Buffer.from(reference.html, 'base64');
assert(expected.length > 0 && expected.length <= 2 * 1024 * 1024);
let forbiddenCalls = 0;
function forbidden() { forbiddenCalls++; throw new Error('pure asset test attempted runtime I/O'); }

function fixture(overrides = {}) {
  const reads = [];
  const context = vm.createContext({Buffer, structuredClone, URL, Date: class extends Date { static now() { return NOW; } }, __dirname, __filename: CHECKER,
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
        }, realpathSync: overrides.realpathSync || forbidden, lstatSync: overrides.lstatSync || forbidden,
        mkdirSync: forbidden, writeFileSync: forbidden};
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
  const catalog = {schema: 'catchplate.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
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
  const upstreams = {schema: 'catchplate.operatorUpstreamSetupReview/v1', old_settings: settings,
    expected_settings_digest: digest, cold_restart_required: true, eligible: true, pending_operation_id: null,
    blocked_reason: null, expected_revision: catalog.revision, expected_policy_hash: POLICY};
  const google = {schema: 'catchplate.operatorGoogleConfiguration/v2', state: 'unconfigured', revision: catalog.revision,
    policy_hash: POLICY, effective_settings: structuredClone(settings), effective_settings_digest: digest,
    public_url: PUBLIC, redirect_uri: PUBLIC + '/api/oauth/callback/google', permission_preset: 'gmail_readonly',
    scopes: ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'], blocked_reason: null, operation: null,
    readiness: {pair_ready: true, consent_ready: false, loaded_policy_hash: POLICY},
    review: {schema: 'catchplate.operatorGoogleManagedSetupReview/v2', expected_revision: catalog.revision,
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
function disabledX(managed = false, variantIndex = 5) {
  const scripts = reference.variants[variantIndex].scripts;
  const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + scripts.map(JSON.stringify).join(', ') + ')\n'}); f.context.mode = managed;
  f.run('managedGoogle = mode; xConfigurationDisabled = disabledXConfigurationForSource();');
  assert.equal(f.run('xConfigurationDisabled'), true);
  f.context.fixtureReply = {status: 404, headers: [['content-type', 'application/json'], ['cache-control', 'no-store']],
    body_base64: Buffer.from(JSON.stringify(X_DISABLED)).toString('base64')};
  return f;
}
function enabledX(managed = false) {
  const sample = reviewed(UPSTREAM_LISTS[2], 81, managed), {f, catalog} = sample;
  f.run('managedX = true; PUBLIC = CANONICAL_PUBLIC; selectXConfigurationProfile();');
  Object.assign(catalog.capabilities, {x_oauth: null, x_post: null});
  const configuration = {schema: 'catchplate.operatorXConfiguration/v1', state: 'unconfigured', revision: 81,
    policy_hash: POLICY, redirect_uri: 'https://catchplate.example.com/api/oauth/callback/x',
    permission_preset: 'x_text_post_v1', scopes: ['offline.access', 'tweet.read', 'tweet.write', 'users.read'],
    configuration: null, operation: null, blocked_reason: null, consent_ready: false,
    review: {expected_revision: 81, expected_policy_hash: POLICY}};
  f.context.fixtureReply = {status: 200, headers: [['content-type', 'application/json'], ['cache-control', 'no-store']],
    body_base64: Buffer.from(JSON.stringify(configuration)).toString('base64')};
  return {...sample, configuration};
}

const tests = [
  ['only the exact Docker CLI receives a bounded Go scheduler in its clean child environment', () => {
    const f = fixture();
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(commandEnvironment("/usr/bin/docker"))')),
      {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GOMAXPROCS: '2'});
    for (const binary of ['/usr/bin/python3', '/tmp/docker', 'docker']) {
      f.context.binary = binary;
      assert.deepEqual(JSON.parse(f.run('JSON.stringify(commandEnvironment(binary))')), {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'});
    }
    f.run('const alteredEnvironment = commandEnvironment("/usr/bin/docker"); alteredEnvironment.GOMAXPROCS = "99";');
    assert.equal(f.run('commandEnvironment("/usr/bin/docker").GOMAXPROCS'), '2');
    assert.equal(forbiddenCalls, 0);
  }],
  ['subprocess failure diagnostics contain only fixed categories, never private messages or output', () => {
    const f = fixture();
    f.context.failure = {code: 'EAGAIN', signal: 'SIGKILL', killed: true,
      message: 'private-message-canary', stderr: 'private-stderr-canary'};
    const result = JSON.parse(f.run('JSON.stringify(subprocessFailure("/usr/bin/docker", failure, "private-stdout-canary"))'));
    assert.deepEqual(result, {executable: 'docker', code: 'EAGAIN', signal: 'SIGKILL', killed: true, bridge_refused: false});
    f.context.failure = {code: 'private-code-canary', signal: 'private-signal-canary', killed: 'true'};
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(subprocessFailure("private-path-canary", failure, ""))')),
      {executable: 'other', code: 'other', signal: null, killed: false, bridge_refused: false});
    f.context.failure = {code: 2};
    f.context.fixtureOutput = '{"ok":false,"reason":"runtime_readonly_bridge_refused"}\n';
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(subprocessFailure("/usr/bin/docker", failure, fixtureOutput))')),
      {executable: 'docker', code: 2, signal: null, killed: false, bridge_refused: true});
    assert.equal(f.run('subprocessFailure("/usr/bin/docker", failure, undefined).bridge_refused'), false);
    assert.equal(forbiddenCalls, 0);
  }],
  ['actual documentBytes matches all nine closed Python renderer rosters in both checker modes', async () => {
    assert.equal(reference.variants.length, 9);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_aws.js')), [false, false, false, true, true, true, true, true, true]);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_gmail_sdk.js')), [false, false, false, false, true, true, true, true, true]);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_x_configuration.js')), [false, false, false, false, false, true, true, true, true]);
    for (const name of ['workspace_x_accounts.js', 'workspace_x_post.js'])
      assert.deepEqual(reference.variants.map(variant => variant.scripts.includes(name)), [false, false, false, false, false, false, true, true, true]);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_workload_renewal.js')), [false, false, false, false, false, false, false, true, true]);
    assert.deepEqual(reference.variants.map(variant => variant.scripts.includes('workspace_pending_actions.js')), [false, false, false, false, false, false, false, false, true]);
    for (const variant of reference.variants) {
      for (const managed of [false, true]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + variant.scripts.map(JSON.stringify).join(', ') + ')\n'});
      const names = JSON.parse(f.run('JSON.stringify(sourceScriptFiles())'));
      assert.deepEqual(names, variant.scripts);
      assert.equal(new Set(names).size, names.length);
      assert.equal(names[names.indexOf('workspace_npm.js') + 1], 'workspace_npm_publish.js');
      if (names.includes('workspace_x_configuration.js'))
        assert.deepEqual(names.slice(-3), ['workspace_google_configuration.js', 'workspace_x_configuration.js', 'app.js']);
      else assert.deepEqual(names.slice(-2), ['workspace_google_configuration.js', 'app.js']);
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
    const names = reference.variants[4].scripts;
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
  ['X configuration is additive only after Google configuration in its exact historical roster', () => {
    const names = reference.variants[5].scripts;
    assert.deepEqual(names.slice(-3), ['workspace_google_configuration.js', 'workspace_x_configuration.js', 'app.js']);
    const mixed = reference.variants.slice(0, 4).map(variant =>
      [...variant.scripts.slice(0, -1), 'workspace_x_configuration.js', 'app.js']);
    for (const changed of [...mixed,
      [...names.slice(0, -3), 'workspace_x_configuration.js', 'workspace_google_configuration.js', 'app.js'],
      [...names, 'workspace_x_configuration.js']]) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py'], 'refused roster never reads candidate assets');
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['X accounts and posting are admitted together only in the exact new roster', () => {
    const names = reference.variants[6].scripts;
    assert.deepEqual(names, reference.scripts.filter(name => !['workspace_workload_renewal.js', 'workspace_pending_actions.js'].includes(name)));
    assert.deepEqual(names.slice(names.indexOf('workspace_x.js'), names.indexOf('workspace_x.js') + 4),
      ['workspace_x.js', 'workspace_x_accounts.js', 'workspace_x_post.js', 'workspace_alchemy.js']);
    const changedRosters = [
      names.filter(name => name !== 'workspace_x_accounts.js'), names.filter(name => name !== 'workspace_x_post.js'),
      [...names, 'workspace_x_accounts.js'], [...names, 'workspace_x_post.js'],
      names.map(name => name === 'workspace_x_accounts.js' ? 'workspace_x_post.js' : name === 'workspace_x_post.js' ? 'workspace_x_accounts.js' : name),
      ...reference.variants.slice(0, 5).map(variant => [...variant.scripts.slice(0, -1), 'workspace_x_accounts.js', 'workspace_x_post.js', 'app.js']),
    ];
    for (const changed of changedRosters) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py']);
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['workload renewal is additive only in its exact new renderer roster', () => {
    const names = reference.variants[7].scripts;
    assert.deepEqual(names, reference.scripts.filter(name => name !== 'workspace_pending_actions.js'));
    assert.equal(names[names.indexOf('workspace_workload_renewal.js') + 1], 'workspace_applications.js');
    const changedRosters = [
      [...names, 'workspace_workload_renewal.js'],
      ['workspace_workload_renewal.js', ...names.filter(name => name !== 'workspace_workload_renewal.js')],
      names.filter(name => name !== 'workspace_x_accounts.js'),
      ...reference.variants.slice(0, 6).map(variant => variant.scripts.flatMap(name =>
        name === 'workspace_applications.js' ? ['workspace_workload_renewal.js', name] : [name])),
    ];
    for (const changed of changedRosters) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py']);
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['pending actions is admitted only after notifications in its exact new renderer roster', () => {
    const names = reference.variants[8].scripts;
    assert.deepEqual(names, reference.scripts);
    assert.deepEqual(names.slice(names.indexOf('workspace_notifications.js'), names.indexOf('workspace_notifications.js') + 3),
      ['workspace_notifications.js', 'workspace_pending_actions.js', 'workspace_upstreams.js']);
    const changedRosters = [
      [...names, 'workspace_pending_actions.js'],
      ['workspace_pending_actions.js', ...names.filter(name => name !== 'workspace_pending_actions.js')],
      [...names.filter(name => !['workspace_pending_actions.js', 'app.js'].includes(name)), 'workspace_pending_actions.js', 'app.js'],
      names.filter(name => name !== 'workspace_workload_renewal.js'),
      ...reference.variants.slice(0, 7).map(variant => variant.scripts.flatMap(name =>
        name === 'workspace_notifications.js' ? [name, 'workspace_pending_actions.js'] : [name])),
    ];
    for (const changed of changedRosters) {
      const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + changed.map(JSON.stringify).join(', ') + ')\n'});
      assert.throws(() => f.render(true), error => error.message === 'renderer_roster_refused');
      assert.deepEqual(f.reads, ['operator_demo_portal.py'], 'refused roster never reads candidate assets');
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['only the four exact X configuration rosters opt into the disabled-X GET flag and three additional reads', async () => {
    for (const variant of reference.variants) {
      for (const managed of [false, true]) {
        const f = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + variant.scripts.map(JSON.stringify).join(', ') + ')\n'});
        f.context.mode = managed;
        f.run('managedGoogle = mode; xConfigurationDisabled = disabledXConfigurationForSource();');
        const current = reference.variants.indexOf(variant) >= 5;
        assert.equal(f.run('paths().includes(X_CONFIGURATION)'), current);
        if (!current) {
          await assert.rejects(f.run('get(X_CONFIGURATION)'), error => error.message === 'get_route_or_bound');
          assert.equal(f.context.fixtureRequests.length, 0, 'historical assets never issue X discovery');
        }
      }
    }
    for (const variantIndex of [5, 6, 7, 8]) for (const managed of [false, true]) {
      const f = disabledX(managed, variantIndex);
      for (let index = 0; index < 3; index++) {
        const reply = await f.run('get(X_CONFIGURATION)');
        assert.equal(reply.status, 404); assert.equal(reply.headers['cache-control'], 'no-store');
        assert.deepEqual(JSON.parse(reply.body), X_DISABLED);
      }
      assert.deepEqual(JSON.parse(JSON.stringify(f.context.fixtureRequests)), Array.from({length: 3}, () =>
        ({op: 'get', path: X_CONFIGURATION, x_configuration_disabled: true})));
      await assert.rejects(f.run('get(X_CONFIGURATION)'), error => error.message === 'get_route_or_bound');
      assert.equal(f.context.fixtureRequests.length, 3);
      const bounded = disabledX(managed, variantIndex);
      bounded.context.cap = (managed ? 17 : 16) + 3;
      bounded.run('receipt.gets = Array.from({length: cap - 1}, () => ({path: "/", method: "GET"}));');
      await bounded.run('get(X_CONFIGURATION)');
      await assert.rejects(bounded.run('get(X_CONFIGURATION)'), error => error.message === 'get_route_or_bound');
      assert.equal(bounded.context.fixtureRequests.length, 1, 'total GET bound still enforced');
    }
    const runSource = source.slice(source.indexOf('async function run()'), source.indexOf(entrypoint));
    assert(runSource.indexOf('await identity();') < runSource.indexOf('selectXConfigurationProfile()'));
    assert(runSource.indexOf('xConfigurationBrowserReadComplete = true;') < runSource.indexOf('await route.fulfill(response)'));
    assert(runSource.includes("observesX() && phase === 'proxy' && seen[path] === 1"));
    assert.equal(forbiddenCalls, 0);
  }],
  ['X accounts roster permits no consent, operation, disconnect, posting or alternate configuration requests', async () => {
    const f = disabledX(true, 6);
    for (const route of ['/api/operator-demo/oauth/x/start',
      '/api/operator-demo/oauth/x/operations/11111111-1111-4111-8111-111111111111',
      '/api/operator-demo/oauth/x/accounts/11111111-1111-4111-8111-111111111111/disconnect-review',
      '/api/operator-demo/oauth/x/disconnect', '/api/operator-demo/access-rules/x-post',
      X_CONFIGURATION + '?review=true', X_CONFIGURATION + '/',
      'https://catchplate-demo.example.com' + X_CONFIGURATION]) {
      f.context.fixturePath = route;
      await assert.rejects(f.run('get(fixturePath)'), error => error.message === 'get_route_or_bound');
    }
    assert.equal(f.context.fixtureRequests.length, 0);
    assert.equal(f.run('receipt.gets.length'), 0);
    await f.run('get(X_CONFIGURATION)');
    assert.deepEqual(JSON.parse(JSON.stringify(f.context.fixtureRequests)),
      [{op: 'get', path: X_CONFIGURATION, x_configuration_disabled: true}]);
    assert.equal(forbiddenCalls, 0);
  }],
  ['disabled-X accepts only the fixed 404 detail and one no-store header, not generic errors', async () => {
    for (const mutate of [reply => reply.status = 200, reply => reply.status = 503,
      reply => reply.headers = [['content-type', 'application/json']],
      reply => reply.headers[1][1] = 'private, no-store',
      reply => reply.headers.push(['Cache-Control', 'no-store']),
      reply => reply.body_base64 = Buffer.from(JSON.stringify({detail: 'other unavailable'})).toString('base64'),
      reply => reply.body_base64 = Buffer.from(JSON.stringify({...X_DISABLED, extra: true})).toString('base64'),
      reply => reply.body_base64 = Buffer.from('[]').toString('base64'),
      reply => reply.body_base64 = Buffer.from('{').toString('base64')]) {
      for (const variantIndex of [5, 6, 7, 8]) {
        const f = disabledX(false, variantIndex); mutate(f.context.fixtureReply);
        await assert.rejects(f.run('get(X_CONFIGURATION)'));
        assert.equal(f.run('xConfigurationBrowserReadComplete'), false);
        assert.equal(f.context.fixtureRequests.length, 1, 'no retry after invalid response');
      }
    }
    const f = disabledX(true); await f.run('get(X_CONFIGURATION)');
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(before[X_CONFIGURATION])')), X_DISABLED);
    f.run('before[X_CONFIGURATION].detail = "changed";');
    await assert.rejects(f.run('get(X_CONFIGURATION)'), error => error.message === 'public_resource_changed_during_read');
    const other = disabledX(true);
    await assert.rejects(other.run('get(CATALOG)'), error => error.message === 'response_invalid');
    assert.deepEqual(JSON.parse(JSON.stringify(other.context.fixtureRequests)),
      [{op: 'get', path: CATALOG, managed_google_unconfigured: true}]);
    assert.equal(forbiddenCalls, 0);
  }],
  ['disabled-X requires a completed browser read, hidden panel and no visible global hold', async () => {
    for (const failed of [null, 'completed', 'seen', '#x-configuration-panel', '#x-configuration-form',
      '#credential-fields', '#mutation-review']) {
      const f = disabledX(); f.run('xConfigurationBrowserReadComplete = true; seen[X_CONFIGURATION] = 1;');
      if (failed === 'completed') f.run('xConfigurationBrowserReadComplete = false');
      if (failed === 'seen') f.run('seen[X_CONFIGURATION] = 2');
      const visited = [];
      f.context.fixturePage = {locator(selector) {
        visited.push(selector);
        assert(['#x-configuration-panel', '#x-configuration-form', '#credential-fields', '#mutation-review'].includes(selector));
        return {async isHidden() { return selector !== failed; }, async isDisabled() { return selector === failed; }};
      }};
      if (failed === null) {
        await f.run('verifyXConfigurationDisabled(fixturePage)');
        assert.deepEqual(visited, ['#x-configuration-panel', '#x-configuration-form', '#credential-fields', '#mutation-review']);
      } else await assert.rejects(f.run('verifyXConfigurationDisabled(fixturePage)'),
        error => error.message === 'disabled_x_configuration_panel_or_hold_mismatch');
      assert.equal(f.context.fixtureRequests.length, 0);
    }
    const old = fixture(); old.context.fixturePage = {locator: forbidden};
    await old.run('verifyXConfigurationDisabled(fixturePage)');
    assert.equal(forbiddenCalls, 0);
  }],
  ['only the verified exact disabled-X 404 console event is separated, at most once', () => {
    const message = (url = PUBLIC + X_CONFIGURATION, text = 'Failed to load resource: the server responded with a status of 404 (Not Found)', type = 'error') =>
      ({type: () => type, location: () => ({url}), text: () => text});
    const f = disabledX();
    f.run('xConfigurationBrowserReadComplete = true; seen[X_CONFIGURATION] = 1; receipt.expected_disabled_x_console_errors = 0;');
    f.context.fixtureMessage = message(); f.run('recordConsole(fixtureMessage)');
    assert.equal(f.run('receipt.expected_disabled_x_console_errors'), 1);
    assert.equal(f.run('receipt.console_errors'), 0);
    f.run('recordConsole(fixtureMessage)');
    assert.equal(f.run('receipt.expected_disabled_x_console_errors'), 1);
    assert.equal(f.run('receipt.console_errors'), 1, 'second identical error is not exempt');
    for (const failed of ['historical', 'incomplete', 'unseen', 'duplicate', 'url', 'text']) {
      const sample = disabledX();
      sample.run('xConfigurationBrowserReadComplete = true; seen[X_CONFIGURATION] = 1; receipt.expected_disabled_x_console_errors = 0;');
      if (failed === 'historical') sample.run('xConfigurationDisabled = false');
      if (failed === 'incomplete') sample.run('xConfigurationBrowserReadComplete = false');
      if (failed === 'unseen') sample.run('delete seen[X_CONFIGURATION]');
      if (failed === 'duplicate') sample.run('seen[X_CONFIGURATION] = 2');
      sample.context.fixtureMessage = message(failed === 'url' ? PUBLIC + CATALOG : undefined,
        failed === 'text' ? 'synthetic-private-console-canary' : undefined);
      sample.run('recordConsole(fixtureMessage)');
      assert.equal(sample.run('receipt.expected_disabled_x_console_errors'), 0);
      assert.equal(sample.run('receipt.console_errors'), 1);
      assert(!sample.run('JSON.stringify(receipt)').includes('synthetic-private-console-canary'));
    }
    const info = disabledX(); info.context.fixtureMessage = message(undefined, undefined, 'info');
    info.run('recordConsole(fixtureMessage)'); assert.equal(info.run('receipt.console_errors'), 0);
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
      ['workspace_aws.js', '/* </ScRiPt> */'], ['workspace_gmail_sdk.js', '/* </ScRiPt> */'],
      ['workspace_x_configuration.js', '/* </ScRiPt> */'], ['style.css', '/* </StYlE> */']]) {
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
    for (const name of ['workspace_npm_publish.js', 'workspace_aws.js', 'workspace_gmail_sdk.js', 'workspace_google_configuration.js', 'workspace_x_configuration.js']) {
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
    assert.deepEqual(parse(base), {appId: base[0], commit: base[1], output: base[2], managedGoogle: false, managedX: false,
      expectedUpstreams: [FIXTURE], expectedRevision: null, explicitUpstreams: false, publicOrigin: PUBLIC, sourceDirectory: null});
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
  ['snapshot directory option is explicit and retains the historical default', () => {
    const probes = [], f = fixture({realpathSync(value) { probes.push(['realpath', value]); return value; },
      lstatSync(value) { probes.push(['lstat', value]); return {isDirectory: () => true}; }});
    const base = ['a'.repeat(64), 'b'.repeat(40), '/synthetic/fresh'];
    const selected = '/mnt/immutable/source-' + base[1];
    const parse = args => { f.context.args = args; return JSON.parse(f.run('JSON.stringify(parseRuntimeOptions(args))')); };
    assert.equal(parse(base).sourceDirectory, null);
    f.context.fixtureCommit = base[1];
    assert.equal(f.run('sourceDirectory(fixtureCommit)'),
      path.join(path.dirname(ROOT), 'catchplate-operator-artifacts/source-' + base[1]));
    const all = [...base, '--managed-google-unconfigured', '--expected-upstreams', JSON.stringify(UPSTREAM_LISTS[2]),
      '--expected-catalog-revision', '39', '--canonical-origin', '--source-directory', selected];
    assert.equal(parse(all).sourceDirectory, selected);
    assert.equal(f.run('sourceDirectory(parseRuntimeOptions(args).commit, parseRuntimeOptions(args).sourceDirectory)'), selected);
    assert.deepEqual(probes.slice(-2), [['realpath', selected], ['lstat', selected]]);
    for (const suffix of [['--source-directory'], ['--source-directory', selected, '--source-directory', selected],
      ['--source-directory=' + selected], ['--source-directory', 'x'.repeat(4097)]])
      assert.throws(() => parse([...base, ...suffix]));
    assert.equal(f.context.fixtureRequests.length, 0);
  }],
  ['snapshot directory refuses aliases symlinks non-directories and wrong commit names', () => {
    const commit = 'b'.repeat(40), exact = '/mnt/immutable/source-' + commit;
    for (const invalid of ['', 'source-' + commit, '/mnt/immutable/source-' + 'c'.repeat(40),
      exact + '/', '/mnt/immutable/./source-' + commit, '/mnt/other/../immutable/source-' + commit, '/', true]) {
      const f = fixture(); f.context.fixtureCommit = commit; f.context.fixtureDirectory = invalid;
      assert.throws(() => f.run('sourceDirectory(fixtureCommit, fixtureDirectory)'),
        error => error.message === 'source_directory_not_exact');
    }
    for (const filesystem of [
      {realpathSync: () => '/mnt/other/source-' + commit, lstatSync: () => ({isDirectory: () => true})},
      {realpathSync: value => value, lstatSync: () => ({isDirectory: () => false})},
      {realpathSync() { throw new Error('synthetic missing path'); }}]) {
      const f = fixture(filesystem); f.context.fixtureCommit = commit; f.context.fixtureDirectory = exact;
      assert.throws(() => f.run('sourceDirectory(fixtureCommit, fixtureDirectory)'));
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['identity forwards the exact snapshot path and still binds mount host and container proofs', async () => {
    const selected = '/mnt/immutable/source-' + 'b'.repeat(40), app = 'a'.repeat(64), digest = 'd'.repeat(64);
    for (const mismatch of [null, 'mount', 'host', 'container']) {
      const f = fixture();
      f.context.fixtureSource = selected; f.context.fixtureApp = app; f.context.fixtureCommit = 'b'.repeat(40);
      f.context.fixtureCalls = [];
      f.context.fixtureInspect = {id: app, running: true, health: 'healthy', project: 'catchplate-operator-demo',
        service: 'catchplate', mounts: [{source: mismatch === 'mount' ? selected + '-wrong' : selected, rw: false, type: 'bind'}]};
      f.context.fixtureVerified = {ok: true, commit: 'b'.repeat(40), source: mismatch === 'host' ? selected + '-wrong' : selected,
        git_blob_equality: true, world_readable_and_nonwritable: true, manifest_sha256: digest, files: 2};
      f.context.fixtureReply = {ok: true, manifest_sha256: mismatch === 'container' ? 'e'.repeat(64) : digest, files: 2};
      f.run(`source = fixtureSource; appId = fixtureApp; commit = fixtureCommit;
        command = async (binary, args, input, timeout) => {
          fixtureCalls.push({binary, args, input, timeout});
          return JSON.stringify(binary === '/usr/bin/docker' ? fixtureInspect : fixtureVerified);
        };`);
      if (mismatch === null) await f.run('identity()');
      else await assert.rejects(f.run('identity()'), error => error.message === {
        mount: 'runtime_identity_mismatch', host: 'host_source_mismatch', container: 'container_source_mismatch'}[mismatch]);
      const calls = JSON.parse(f.run('JSON.stringify(fixtureCalls)'));
      assert.equal(calls.length, mismatch === 'mount' ? 1 : 2);
      if (mismatch !== 'mount') assert.deepEqual(calls[1], {binary: '/usr/bin/python3', args: ['-I', '-B',
        path.join(__dirname, 'verify_operator_source_snapshot.py'), '--commit', 'b'.repeat(40), '--source-directory', selected],
        input: '', timeout: 40000});
      assert.equal(f.context.fixtureRequests.length, ['mount', 'host'].includes(mismatch) ? 0 : 1);
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['canonical origin is a closed explicit opt-in with unchanged paths and renderer proof', () => {
    const canonical = 'https://catchplate.example.com', base = ['a'.repeat(64), 'b'.repeat(40), '/synthetic/fresh'];
    const {f, catalog, upstreams, google} = reviewed();
    const parse = args => { f.context.args = args; return JSON.parse(f.run('JSON.stringify(parseRuntimeOptions(args))')); };
    assert.equal(parse(base).publicOrigin, PUBLIC);
    assert.equal(parse([...base, '--canonical-origin']).publicOrigin, canonical);
    const all = [...base, '--managed-google-unconfigured', '--expected-upstreams', JSON.stringify(UPSTREAM_LISTS[2]),
      '--expected-catalog-revision', '39', '--canonical-origin'];
    assert.equal(parse(all).publicOrigin, canonical);
    for (const suffix of [['--canonical-origin', '--canonical-origin'], ['--canonical-origin', canonical],
      ['--canonical-origin=https://catchplate.example.com'], ['--public-origin', canonical],
      ['--canonical-origin', 'https://unreviewed.invalid']]) assert.throws(() => parse([...base, ...suffix]));
    parse(all);
    f.run('PUBLIC = new URL(parseRuntimeOptions(args).publicOrigin).origin');
    assert.equal(f.run('new URL("/", PUBLIC).href'), canonical + '/');
    assert.deepEqual(JSON.parse(f.run('JSON.stringify(paths())')), ['/', CATALOG,
      '/api/operator-demo/notifications', UPSTREAMS, GOOGLE]);
    assert(f.render(true).equals(expected));
    validate(f, CATALOG, catalog);
    validate(f, UPSTREAMS, upstreams);
    assert.throws(() => validate(f, GOOGLE, google));
    for (const value of [google, google.review]) {
      value.public_url = canonical; value.redirect_uri = canonical + '/api/oauth/callback/google';
    }
    validate(f, GOOGLE, google);
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
  ['managed-X selection is explicit canonical and revision-bound, never inferred from source or an enabled response', () => {
    const f = fixture(), base = ['a'.repeat(64), 'b'.repeat(40), '/synthetic/fresh'];
    const parse = args => { f.context.args = args; return JSON.parse(f.run('JSON.stringify(parseRuntimeOptions(args))')); };
    assert.equal(parse(base).managedX, false);
    const selected = [...base, '--managed-x-unconfigured', '--canonical-origin', '--expected-catalog-revision', '81'];
    assert.equal(parse(selected).managedX, true);
    assert.equal(parse([...selected, '--managed-google-unconfigured', '--expected-upstreams', JSON.stringify(UPSTREAM_LISTS[2]),
      '--source-directory', '/immutable/source-' + base[1]]).managedGoogle, true);
    for (const args of [[...base, '--managed-x-unconfigured'], [...base, '--managed-x-unconfigured', '--canonical-origin'],
      [...base, '--managed-x-unconfigured', '--expected-catalog-revision', '81'],
      [...selected, '--managed-x-unconfigured'], [...selected, '--x-configuration-disabled'],
      [...base, '--managed-x-unconfigured=true']]) assert.throws(() => parse(args));
    for (const [index, variant] of reference.variants.entries()) {
      const sample = fixture({'operator_demo_portal.py': 'SCRIPT_FILES = (' + variant.scripts.map(JSON.stringify).join(', ') + ')\n'});
      sample.run('selectXConfigurationProfile()');
      assert.equal(sample.run('managedX'), false);
      assert.equal(sample.run('xConfigurationDisabled'), index >= 5);
      sample.run('managedX = true');
      if (index >= 6) { sample.run('selectXConfigurationProfile()'); assert.equal(sample.run('xConfigurationDisabled'), false); }
      else assert.throws(() => sample.run('selectXConfigurationProfile()'), error => error.message === 'managed_x_source_profile_refused');
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['enabled-X joins exact null catalog capabilities and closed unconfigured configuration to the current policy', async () => {
    for (const managed of [false, true]) {
      const {f, catalog, configuration} = enabledX(managed); validate(f, CATALOG, catalog);
      for (let i = 0; i < 3; i++) {
        const reply = await f.run('get(X_CONFIGURATION)'); assert.equal(reply.status, 200);
        assert.deepEqual(JSON.parse(reply.body), configuration);
      }
      assert.deepEqual(JSON.parse(JSON.stringify(f.context.fixtureRequests)), Array.from({length: 3}, () =>
        ({op: 'get', path: X_CONFIGURATION, managed_x_unconfigured: true})));
      await assert.rejects(f.run('get(X_CONFIGURATION)'), error => error.message === 'get_route_or_bound');
      assert.equal(f.context.fixtureRequests.length, 3);
    }
    for (const mutate of [v => delete v.capabilities.x_oauth, v => delete v.capabilities.x_post,
      v => v.capabilities.x_oauth = {}, v => v.capabilities.x_post = {}, v => v.policy.activation = 'pending',
      v => v.policy.loaded_policy_hash = 'sha256:' + 'b'.repeat(64)]) {
      const sample = enabledX(); mutate(sample.catalog);
      assert.throws(() => validate(sample.f, CATALOG, sample.catalog));
    }
    for (const mutate of [v => v.state = 'configured', v => v.schema = 'other', v => v.extra = true,
      v => v.revision++, v => v.policy_hash = 'sha256:' + 'b'.repeat(64), v => v.redirect_uri = PUBLIC + '/api/oauth/callback/x',
      v => v.permission_preset = 'x_readonly', v => v.scopes.reverse(), v => v.scopes.push('extra'),
      v => v.configuration = {}, v => v.operation = {}, v => v.blocked_reason = 'pending_google_configuration',
      v => v.consent_ready = true, v => v.review.expected_revision++, v => v.review.extra = true,
      v => v.review.expected_policy_hash = 'sha256:' + 'b'.repeat(64)]) {
      const sample = enabledX(); validate(sample.f, CATALOG, sample.catalog); mutate(sample.configuration);
      assert.throws(() => validate(sample.f, X_CONFIGURATION, sample.configuration), error => error.message === 'managed_x_configuration_mismatch');
    }
    for (const mutate of [r => r.status = 404, r => r.status = 503, r => r.headers.pop(),
      r => r.headers.push(['Cache-Control', 'no-store']), r => r.body_base64 = Buffer.from(JSON.stringify(X_DISABLED)).toString('base64')]) {
      const sample = enabledX(); validate(sample.f, CATALOG, sample.catalog); mutate(sample.f.context.fixtureReply);
      await assert.rejects(sample.f.run('get(X_CONFIGURATION)')); assert.equal(sample.f.context.fixtureRequests.length, 1);
    }
    const sample = enabledX(); validate(sample.f, CATALOG, sample.catalog);
    sample.f.run('xConfigurationDisabled = true');
    await assert.rejects(sample.f.run('get(X_CONFIGURATION)'), error => error.message === 'contradictory_x_profile');
    assert.equal(sample.f.context.fixtureRequests.length, 0);
    const historical = disabledX(); historical.context.fixtureReply = enabledX().f.context.fixtureReply;
    await assert.rejects(historical.run('get(X_CONFIGURATION)'), error => error.message === 'response_invalid');
    assert.equal(historical.run('managedX'), false, 'no disabled-to-enabled fallback');
  }],
  ['only successful enabled-X discovery permits its one additional proxy-phase catalog GET', async () => {
    for (const managed of [false, true]) {
      const {f, catalog} = enabledX(managed); validate(f, CATALOG, catalog);
      f.run('phase = "proxy"; seen[CATALOG] = 2; seen[X_CONFIGURATION] = 1;');
      assert.equal(f.run('catalogBrowserReadAllowed()'), false, 'no extra read before successful discovery');
      f.run('xConfigurationBrowserReadComplete = true'); assert.equal(f.run('catalogBrowserReadAllowed()'), true);
      for (const count of [0, 2]) { f.context.count = count; f.run('seen[X_CONFIGURATION] = count'); assert.equal(f.run('catalogBrowserReadAllowed()'), false); }
      f.run('seen[X_CONFIGURATION] = 1; seen[CATALOG] = 3'); assert.equal(f.run('catalogBrowserReadAllowed()'), false);
      f.run('phase = "review"'); assert.equal(f.run('catalogBrowserReadAllowed()'), true);
      f.run('phase = "google_review"; seen[CATALOG] = 4'); assert.equal(f.run('catalogBrowserReadAllowed()'), managed);
      f.context.cap = (managed ? 17 : 16) + 4;
      f.run('receipt.gets = Array.from({length: cap - 1}, () => ({path: "/", method: "GET"}));');
      await f.run('get(X_CONFIGURATION)');
      await assert.rejects(f.run('get(X_CONFIGURATION)'), error => error.message === 'get_route_or_bound');
      assert.equal(f.context.fixtureRequests.length, 1);
      const disabled = disabledX(managed);
      disabled.run('phase = "proxy"; seen[CATALOG] = 2; seen[X_CONFIGURATION] = 1; xConfigurationBrowserReadComplete = true;');
      assert.equal(disabled.run('catalogBrowserReadAllowed()'), false);
      disabled.run('phase = "review"'); assert.equal(disabled.run('catalogBrowserReadAllowed()'), true);
    }
    const runSource = source.slice(source.indexOf('async function run()'), source.indexOf(entrypoint));
    assert(runSource.includes("receipt.gets.length === (managedGoogle ? 17 : 13) + (observesX() ? 3 : 0) + (managedX ? 1 : 0)"));
    assert.equal(forbiddenCalls, 0);
  }],
  ['enabled-X DOM requires empty first-save controls and no consent, mutation hold, or replay', async () => {
    const visible = ['#x-configuration-panel', '#x-configuration-form'];
    const hidden = ['#mutation-review', '#x-configuration-operation', '#x-configuration-account-link'];
    for (const failed of [null, 'completion', 'catalog', ...visible, ...hidden, '#x-configuration-review', '#credential-fields',
      '#x-configuration-save', '#x-configuration-callback', '#x-configuration-status', '#x-configuration-client-id',
      '#x-configuration-client-secret', '#x-configuration-scopes']) {
      const {f} = enabledX();
      f.run('xConfigurationBrowserReadComplete = true; seen[X_CONFIGURATION] = 1; seen[CATALOG] = 2;');
      if (failed === 'completion') f.run('xConfigurationBrowserReadComplete = false');
      if (failed === 'catalog') f.run('seen[CATALOG] = 1');
      f.context.fixturePage = {locator(selector) { return {
        async isVisible() { assert(visible.includes(selector)); return failed !== selector; },
        async isHidden() { assert(hidden.includes(selector)); return failed !== selector; },
        async isDisabled() { return selector === '#x-configuration-save' ? failed !== selector : failed === selector; },
        async inputValue() { return failed === selector ? 'synthetic-input-canary' : ''; },
        async innerText() { return failed === selector ? 'wrong' : selector === '#x-configuration-callback' ?
          'https://catchplate.example.com/api/oauth/callback/x' : 'Not configured. Enter settings.'; },
        async textContent() { return failed === selector ? 'wrong' : ['offline.access', 'tweet.read', 'tweet.write', 'users.read'].join('\n'); }
      }; }};
      if (failed === null) await f.run('verifyXConfigurationUnconfigured(fixturePage)');
      else await assert.rejects(f.run('verifyXConfigurationUnconfigured(fixturePage)'), error => error.message === 'managed_x_panel_or_hold_mismatch');
      assert.equal(f.context.fixtureRequests.length, 0);
    }
    const disabled = disabledX(); disabled.context.fixturePage = {locator: forbidden};
    await disabled.run('verifyXConfigurationUnconfigured(fixturePage)');
    const {f} = enabledX(); f.run('xConfigurationBrowserReadComplete = true; seen[X_CONFIGURATION] = 1;');
    f.context.fixtureMessage = {type: () => 'error', location: () => ({url: 'https://catchplate.example.com' + X_CONFIGURATION}),
      text: () => 'Failed to load resource: the server responded with a status of 404 (Not Found)'};
    f.run('recordConsole(fixtureMessage)'); assert.equal(f.run('receipt.console_errors'), 1, 'enabled mode has no 404 exception');
    assert.equal(forbiddenCalls, 0);
  }],
];

(async () => {
  for (const [name, test] of tests) { await test(); process.stdout.write('PASS ' + name + '\n'); }
  assert.equal(forbiddenCalls, 0);
  process.stdout.write(`PASS ${tests.length} pure runtime-browser asset groups; no browser or service calls\n`);
})().catch(error => { console.error(error); process.exitCode = 1; });
