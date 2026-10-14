#!/usr/bin/env node
// Actual UI functions and core transport with an inert DOM and in-memory API.
// No browser, provider, SDK, HTTP, key parsing or generated recipe is executed.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {mutationReviewStorage} = require('./operator_mutation_recovery_test_helpers.cjs');
const {context, clone, IDS} = require('./test_operator_npm_ui.cjs');
const {credential, application, rule} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const ORIGIN = 'https://api.github.com';
const READ = 'github_issues_read_v1', WRITE = 'github_issues_write_v1';
const REPOSITORY = {owner: 'Example-Owner', name: 'Example.Repo'};
const PEM = '-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY_NEVER_RENDER\n-----END PRIVATE KEY-----';
const PAT = 'synthetic_github_PAT_NEVER_RENDER';
const NAME = 'Fixture GitHub App';
const REPLACE = '/api/operator-demo/credentials/github-app/replace-key';
const REPLACEMENT = {schema: 'serverware.operatorGithubAppKeyReplacement/v1', path: REPLACE};
// Independent literal API fixtures; no production descriptor/receipt generator.
function capability(app = true, allowed = true) {
  return {schema: app ? 'serverware.operatorGithubApp/v1' : 'serverware.operatorGithub/v1',
    connection_type: app ? 'github_app_v1' : 'github_token_v1',
    create_credential_path: '/api/operator-demo/credentials/' + (app ? 'github-app' : 'github-token'),
    create_rule_path: '/api/operator-demo/access-rules/github', api_origin: ORIGIN,
    destination_allowed: allowed, operation_bundles: [READ, WRITE], sdk_auth_token: 'serverware-github-placeholder-v1',
    placeholder: 'token serverware-github-placeholder-v1', query_mode: 'githubRestV1',
    response_mode: 'unfiltered_json_or_empty_v2', source_pair_required: true};
}
function binding(changes = {}) {
  return {app_id: '12345', installation_id: '23456', account_id: '34567', repository_id: '45678',
    repository: {...REPOSITORY}, issues_permission: 'read', token_refresh: 'automatic', ...changes};
}
function appCredential(changes = {}) {
  return credential({name: NAME, connection_type: 'github_app_v1', provider_id: 'github', github_app: binding(), credential_generation: 1, ...changes});
}
function patCredential(changes = {}) {
  return credential({name: 'Fixture PAT', connection_type: 'github_token_v1', provider_id: 'github', credential_generation: 1, ...changes});
}
function githubRule(permission = READ, changes = {}) {
  return rule({name: 'Reviewed GitHub permission', operation_bundle: permission, repository: {...REPOSITORY},
    upstream_url: ORIGIN + '/repos/Example-Owner/Example.Repo/issues', methods: permission === READ ? ['GET'] : ['GET', 'POST'],
    request_fields: [], response_fields: [], request_body_mode: 'preserve_json_v1',
    query_keys: ['assignee', 'creator', 'direction', 'labels', 'mentioned', 'milestone', 'page', 'per_page', 'since', 'sort', 'state'],
    allowed_headers: ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent', 'x-github-api-version'],
    credential_input: 'replace_exact', placeholder: 'token serverware-github-placeholder-v1',
    query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2', ...changes});
}
function catalog({credentials = [appCredential()], rules = [], app = capability(), pat = capability(false), allowed = [ORIGIN], replacement = null} = {}) {
  const value = publicCatalog({revision: 1, sequence: 1, active: digest(1), loaded: digest(1), credentials,
    applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules, allowedUpstreams: allowed,
    responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], requestBodyModes: ['preserve_json_v1'],
    credentialInputModes: ['insert', 'replace_exact']});
  value.capabilities.github = pat; value.capabilities.github_app = app;
  value.capabilities.github_app_key_replacement = replacement;
  value.capabilities.application_proxy_authentication = {schema: 'serverware.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  value.capabilities.static_key_replacement = {schema: 'serverware.operatorStaticKeyReplacement/v1',
    path: '/api/operator-demo/credentials/replace-key', credential_types: ['bearer', 'header']};
  return value;
}
const plain = context();
const project = raw => clone(plain.run('projectCatalog(input)', raw));
const submitted = () => ({name: NAME, app_id: '12345', installation_id: '23456', repository: {...REPOSITORY}, issues_permission: 'read'});
const jsonResponse = (value, status = 200) => ({status, ok: status >= 200 && status < 300,
  headers: {get: key => key === 'content-type' ? 'application/json' : null}, json: async () => clone(value)});

async function fixture(options = {}) {
  const current = context(); const raw = catalog(options); const requests = [], bodies = [], violations = [], events = new Map();
  // Extend only this harness with the native select property the real UI uses.
  for (const node of current.dom.nodes.values()) if (node.tag === 'select')
    Object.defineProperty(node, 'options', {get: () => node.children.filter(child => child.tag === 'option')});
  const created = []; const createElement = current.dom.createElement;
  current.dom.createElement = tag => { const node = createElement(tag); created.push(node); return node; };
  const forbidden = kind => { violations.push(kind); throw new Error('Forbidden test effect'); };
  current.value.sessionStorage = mutationReviewStorage();
  Object.defineProperty(current.value, 'localStorage', {get: () => forbidden('storage')});
  current.value.AbortSignal = {timeout: value => { assert.equal(value, 30000); return undefined; }};
  current.value.TextEncoder = TextEncoder; current.value.clearTimeout = () => {};
  current.value.setTimeout = () => forbidden('timer');
  current.value.window = {addEventListener(name, handler) { events.set(name, [...(events.get(name) || []), handler]); }, confirm: () => true};
  let mode = options.mode || 'success', held = null, receiptChange = options.receiptChange, catalogChange = options.catalogChange;
  current.value.fetch = async (path, init) => {
    try {
      assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
      if (!init.method) { assert.equal(path, '/api/operator-demo/catalog'); requests.push({path, method: 'GET'}); return jsonResponse(raw); }
      assert.equal(init.method, 'POST'); assert.equal(init.headers['Content-Type'], 'application/json');
      const payload = JSON.parse(init.body);
      assert.equal(payload.expected_revision, raw.revision); assert.equal(payload.expected_policy_hash, raw.policy.policy_hash);
      if (path === REPLACE) {
        assert.deepEqual(Object.keys(payload).sort(), ['expected_credential_generation', 'expected_policy_hash', 'expected_revision', 'id', 'private_key_pem']);
        assert.equal(payload.id, IDS.credential); assert.equal(payload.expected_credential_generation, raw.credentials[0].credential_generation);
        assert.equal(payload.private_key_pem, PEM); delete payload.private_key_pem;
      } else if (path === '/api/operator-demo/credentials/github-app') {
        assert.deepEqual(Object.keys(payload).sort(), ['app_id', 'expected_policy_hash', 'expected_revision',
          ...(options.explicitInstallation ? ['installation_id'] : []), 'issues_permission', 'name', 'private_key_pem', 'repository']);
        assert.equal(payload.private_key_pem, PEM); delete payload.private_key_pem;
        const expected = submitted(); if (!options.explicitInstallation) delete expected.installation_id;
        for (const [key, value] of Object.entries(expected)) assert.deepEqual(payload[key], value);
      } else if (path === '/api/operator-demo/credentials/github-token') {
        assert.deepEqual(Object.keys(payload).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
        assert.equal(payload.secret, PAT); delete payload.secret;
      } else {
        assert.equal(path, '/api/operator-demo/access-rules/github');
        assert.deepEqual(Object.keys(payload).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
          'expected_revision', 'name', 'operation_bundle', 'repository']);
        assert.equal(payload.application_id, IDS.application); assert.equal(payload.credential_id, IDS.credential);
        assert.deepEqual(payload.repository, REPOSITORY); assert([READ, WRITE].includes(payload.operation_bundle));
      }
      requests.push({path, method: 'POST', payload});
      const respond = () => {
        if (mode === 'lost') throw new Error(PEM);
        if (typeof mode === 'number') return jsonResponse({detail: PEM}, mode);
        raw.revision++;
        if (path === REPLACE) {
          const item = raw.credentials[0], previous = item.credential_generation;
          item.credential_generation++; item.key_replaced_at = '2026-10-10T12:00:00+00:00';
          const result = {revision: raw.revision, policy: clone(raw.policy), credential: clone(item), key_replacement: {
            previous_credential_generation: previous, credential_generation: item.credential_generation,
            cache_invalidation: 'local_completed', in_flight_requests: 'not_recalled'}};
          receiptChange?.(result); catalogChange?.(raw);
          if (mode === 'lost-after-commit') throw new Error(PEM);
          return jsonResponse(result);
        }
        const kind = path.endsWith('/github') ? 'access_rule' : 'credential';
        const item = kind === 'access_rule' ? githubRule(payload.operation_bundle, {name: payload.name}) :
          path.endsWith('/github-token') ? patCredential({name: payload.name}) : appCredential({name: payload.name});
        raw[kind === 'credential' ? 'credentials' : 'access_rules'] = [clone(item)];
        const result = {revision: raw.revision, policy: clone(raw.policy), [kind]: clone(item)};
        receiptChange?.(result); catalogChange?.(raw); return jsonResponse(result, 201);
      };
      if (mode === 'hold') return await new Promise((resolve, reject) => { held = () => { mode = 'success'; try { resolve(respond()); } catch (error) { reject(error); } }; });
      return respond();
    } catch (error) {
      if (error?.code === 'ERR_ASSERTION') violations.push('fixture API assertion');
      throw error;
    }
  };
  const workspace = current.run('createOperatorWorkspace()');
  const mutate = workspace.mutate;
  workspace.mutate = (...args) => { bodies.push(args[1]); return mutate(...args); };
  assert.equal(await workspace.refresh(), true);
  current.value.workspaceFixture = workspace;
  const view = current.run('createConnectView(workspaceFixture, {mount(){},tokenFor(){return null;}}, {mount(){},select(){}})');
  view.show(true);
  let replacementView;
  if (options.replacement) {
    for (const node of current.dom.nodes.values()) node.focus = () => {};
    replacementView = current.run('createGithubAppKeyReplacementView(workspaceFixture)');
    workspace.subscribe(replacementView.render);
  }
  const node = id => current.dom.getElementById(id);
  const event = async (id, type = 'click') => { const target = node(id); assert.equal(typeof target.events[type], 'function');
    await target.events[type]({preventDefault() {}, currentTarget: target}); };
  const clean = () => {
    assert.deepEqual(violations, []);
    const values = [...current.dom.nodes.values(), ...created].map(node => [node.value, node.textContent, node.attrs, node.dataset]);
    const surfaces = JSON.stringify([values, workspace.state, requests, bodies, current.value.location]);
    for (const secret of [PEM, 'SYNTHETIC_PRIVATE_KEY_NEVER_RENDER', PAT]) assert(!surfaces.includes(secret));
  };
  return {...current, raw, workspace, view, replacementView, requests, bodies, node, event, clean,
    posts: () => requests.filter(row => row.method === 'POST'),
    release: () => { assert(held); held(); },
    fire: async name => { for (const handler of events.get(name) || []) await handler(); }};
}
async function newApp(f, installationId = '') {
  await f.event('connect-use-github'); f.node('connect-github-type').value = 'github_app_v1';
  await f.event('connect-github-type', 'change');
  for (const [id, value] of Object.entries({'connect-credential-name': NAME, 'connect-github-app-id': '12345',
    'connect-github-installation-id': installationId, 'connect-github-app-owner': REPOSITORY.owner,
    'connect-github-app-repo': REPOSITORY.name, 'connect-github-app-permission': 'read', 'connect-github-private-key': PEM})) f.node(id).value = value;
}
async function savedPair(f) {
  await f.event('connect-use-saved'); f.node('connect-credential-choice').value = IDS.credential;
  await f.event('connect-credential-form', 'submit'); f.node('connect-application-choice').value = IDS.application;
  await f.event('connect-application-form', 'submit');
}
const tests = [
  ['literal App capability is closed and independent of PAT', () => {
    for (const allowed of [false, true]) {
      assert.deepEqual(clone(plain.run('githubAppCapabilityDescriptor(input)', allowed)), capability(true, allowed));
      assert.deepEqual(project(catalog({app: capability(true, allowed)})).capabilities.github_app, capability(true, allowed));
    }
    const mutations = [{schema: 'serverware.operatorGithub/v1'}, {connection_type: 'github_token_v1'},
      {create_credential_path: '/api/operator-demo/credentials/github-token'}, {create_rule_path: '/arbitrary'},
      {api_origin: 'https://other.example.test'}, {destination_allowed: 1}, {operation_bundles: [READ]},
      {sdk_auth_token: PEM}, {placeholder: 'Bearer dummy'}, {query_mode: 'orderedFormV1'},
      {response_mode: 'projected_json'}, {source_pair_required: false}, {extra: true}];
    for (const changed of [null, {}, ...mutations.map(change => ({...capability(), ...change}))]) {
      const value = project(catalog({app: changed}));
      assert.equal(value.capabilities.github_app, null); assert.deepEqual(value.capabilities.github, capability(false));
      assert.equal(plain.run('githubAvailable(input, input.credentials[0])', value), false);
    }
    const appOnly = project(catalog({pat: null}));
    assert.equal(plain.run('githubAvailable(input, input.credentials[0])', appOnly), true);
  }],
  ['canonical string IDs and exact public binding reject forged or private metadata', () => {
    const value = project(catalog({credentials: [appCredential({private_key_pem: PEM, secret: PEM, token: PAT, credential_generation: 8})]}));
    assert.deepEqual(value.credentials[0].github_app, binding());
    assert.equal(value.credentials[0].credential_generation, 8);
    assert(!JSON.stringify(value).includes(PEM)); assert(!JSON.stringify(value).includes(PAT));
    for (const key of ['app_id', 'installation_id', 'account_id', 'repository_id']) {
      for (const invalid of [0, 1, true, null, '', '0', '01', '+1', '1.0', '1e2', ' 1', '1 ', '١', '9007199254740992', '10000000000000000'])
        assert.throws(() => project(catalog({credentials: [appCredential({github_app: binding({[key]: invalid})})]})));
      for (const valid of ['1', '9007199254740991'])
        assert.equal(project(catalog({credentials: [appCredential({github_app: binding({[key]: valid})})]})).credentials[0].github_app[key], valid);
    }
    for (const change of [{issues_permission: 'admin'}, {token_refresh: 'manual'}, {private_key_pem: PEM},
      {repository: {...REPOSITORY, id: '1'}}, {repository: {owner: '*', name: '*'}}])
      assert.throws(() => project(catalog({credentials: [appCredential({github_app: binding(change)})]})));
    for (const change of [{provider_id: 'npm'}, {header_name: 'X-API-Key'}, {auth_type: 'header'},
      {legacy_upstream_origin: 'https://other.example.test'}, {connection_type: 'github_token_v1'}])
      assert.throws(() => project(catalog({credentials: [appCredential(change)]})));
  }],
  ['App rules bind exact repository and permission ceiling, never a generic upgrade', () => {
    assert.equal(project(catalog({rules: [githubRule()]})).access_rules[0].operation_bundle, READ);
    assert.throws(() => project(catalog({rules: [githubRule(WRITE)]})));
    for (const change of [{repository: {...REPOSITORY, name: 'Other'}}, {repository: {...REPOSITORY, owner: 'example-owner'}},
      {methods: ['DELETE']}, {placeholder: 'Bearer wrong'}, {query_mode: 'orderedFormV1'}, {response_fields: ['id']}])
      assert.throws(() => project(catalog({rules: [githubRule(READ, change)]})));
    assert.throws(() => project(catalog({rules: [rule()]})));
    for (const permission of [READ, WRITE])
      assert.equal(project(catalog({credentials: [appCredential({github_app: binding({issues_permission: 'write'})})],
        rules: [githubRule(permission)]})).access_rules[0].operation_bundle, permission);
    for (const options of [{app: capability(true, false)}, {allowed: []}, {app: null}]) {
      const value = project(catalog({...options, rules: [githubRule()]}));
      assert.equal(plain.run('operatorRuleSupported(input.access_rules[0], input)', value), false);
    }
  }],
  ['creation and refreshed receipt bind all public App identity fields', () => {
    const receipt = clone(plain.run('githubAppCredentialReceipt(input.row, input.submitted)', {row: appCredential(), submitted: submitted()}));
    assert.deepEqual(Object.keys(receipt).sort(), ['auth_type', 'connection_type', 'created_at', 'github_app', 'header_name', 'id', 'name', 'provider_id', 'status']);
    assert.equal(plain.run('githubAppCredentialReceiptMatches(input.row, input.receipt)', {row: appCredential(), receipt}), true);
    for (const installationId of [undefined, null]) {
      const discovery = submitted();
      if (installationId === undefined) delete discovery.installation_id; else discovery.installation_id = installationId;
      assert.deepEqual(clone(plain.run('githubAppCredentialReceipt(input.row, input.submitted)', {row: appCredential(), submitted: discovery})), receipt);
      for (const invalid of ['', null, undefined, '01', '9007199254740992'])
        assert.throws(() => plain.run('githubAppCredentialReceipt(input.row, input.submitted)',
          {row: appCredential({github_app: binding({installation_id: invalid})}), submitted: discovery}));
    }
    for (const change of [{name: 'Different'}, {app_id: '2'}, {installation_id: '2'}, {issues_permission: 'write'},
      {repository: {...REPOSITORY, name: 'Other'}}])
      assert.throws(() => plain.run('githubAppCredentialReceipt(input.row, input.submitted)', {row: appCredential(), submitted: {...submitted(), ...change}}));
    for (const change of [{account_id: '2'}, {repository_id: '2'}, {app_id: '2'}, {installation_id: '2'}, {issues_permission: 'write'}])
      assert.equal(plain.run('githubAppCredentialReceiptMatches(input.row, input.receipt)',
        {row: appCredential({github_app: binding(change)}), receipt}), false);
  }],
  ['App has no generic Replace key action while PAT retains it', async () => {
    const f = await fixture();
    assert.equal(f.run('staticKeyReplacementAvailable(workspaceFixture.state.catalog, input)', appCredential({credential_generation: 1})), false);
    assert.equal(f.run('staticKeyReplacementAvailable(workspaceFixture.state.catalog, input)', patCredential()), true);
    f.run('createCredentialsView(workspaceFixture).render()');
    const actions = () => f.node('credentials-list').descendants().map(node => node.dataset.action);
    assert(!actions().includes('replace-key')); assert(actions().includes('revoke-credential'));
    f.raw.credentials = [patCredential()]; await f.workspace.refresh();
    assert(actions().includes('replace-key')); f.clean();
  }],
  ['save uses one App POST with exact CAS and clears PEM before held reply', async () => {
    for (const explicitInstallation of [false, true]) {
      const f = await fixture({credentials: [], mode: 'hold', explicitInstallation}); await newApp(f, explicitInstallation ? '23456' : '');
      assert(f.node('connect-provider-secret-group').hidden); assert(f.node('connect-credential-secret').disabled);
      assert(!f.node('connect-github-app-fields').hidden);
      const pending = f.event('connect-credential-form', 'submit');
      assert.equal(f.posts().length, 1); assert.equal(f.node('connect-github-private-key').value, '');
      assert.equal(Object.hasOwn(f.posts()[0].payload, 'installation_id'), explicitInstallation);
      assert.equal(f.bodies[0].private_key_pem, ''); assert.equal(f.workspace.writeInFlight(), true); f.clean();
      await f.event('connect-credential-form', 'submit'); assert.equal(f.posts().length, 1);
      f.release(); await pending;
      assert.equal(f.posts().length, 1); assert.equal(f.raw.access_rules.length, 0);
      assert.equal(f.raw.credentials[0].github_app.installation_id, '23456');
      assert(!f.node('connect-application-step').hidden); assert.equal(f.workspace.state.uncertain, false); f.clean();
    }
  }],
  ['PAT and manual credential choices remain separate and available', async () => {
    const f = await fixture({credentials: [], app: null}); await f.event('connect-use-github');
    assert.equal(f.node('connect-github-type').value, 'github_token_v1');
    assert(f.node('connect-github-app-fields').hidden); assert(!f.node('connect-provider-secret-group').hidden);
    assert(!f.node('connect-github-type').children.some(node => node.value === 'github_app_v1' && !node.disabled));
    f.node('connect-credential-name').value = 'Fixture PAT'; f.node('connect-credential-secret').value = PAT;
    await f.event('connect-credential-form', 'submit');
    assert.equal(f.posts()[0].path, '/api/operator-demo/credentials/github-token'); f.clean();
    const manual = await fixture({credentials: [], app: null, pat: null});
    assert(manual.node('connect-use-github').disabled); assert(!manual.node('connect-use-key').disabled);
    await manual.event('connect-use-key'); assert(!manual.node('connect-credential-auth-group').hidden); manual.clean();
  }],
  ['existing App grant UI fixes the repository and excludes write above ceiling', async () => {
    const f = await fixture(); await savedPair(f);
    for (const [id, value] of [['connect-github-owner', REPOSITORY.owner], ['connect-github-repo', REPOSITORY.name]]) {
      assert.equal(f.node(id).value, value); assert.equal(f.node(id).readOnly, true);
    }
    assert(!f.node('connect-operation').children.some(node => node.value === WRITE && !node.disabled));
    await f.event('connect-access-form', 'submit'); assert(!f.node('connect-review-step').hidden);
    assert.equal(f.posts().length, 0); await f.event('connect-grant');
    assert.equal(f.posts().length, 1); assert.equal(f.posts()[0].payload.operation_bundle, READ);
    assert(!f.node('connect-setup-step').hidden); f.clean();
    const write = await fixture({credentials: [appCredential({github_app: binding({issues_permission: 'write'})})]});
    await savedPair(write); assert(write.node('connect-operation').children.some(node => node.value === WRITE && !node.disabled));
    write.node('connect-operation').value = WRITE; await write.event('connect-access-form', 'submit');
    await write.event('connect-grant'); assert.equal(write.posts()[0].payload.operation_bundle, WRITE); write.clean();
  }],
  ['programmatic scope escalation cannot create a grant', async () => {
    for (const [id, value] of [['connect-operation', WRITE], ['connect-github-owner', 'Other'], ['connect-github-repo', 'Other']]) {
      const f = await fixture(); await savedPair(f); f.node(id).value = value;
      await f.event('connect-access-form', 'submit'); await f.event('connect-grant');
      assert.equal(f.posts().length, 0); assert(f.node('connect-setup-step').hidden); f.clean();
    }
  }],
  ['capability, origin, binding or revision drift invalidates reviewed grant', async () => {
    const changes = [raw => { raw.capabilities.github_app = null; }, raw => { raw.allowed_upstreams = []; },
      raw => { raw.credentials[0].github_app.repository_id = '999'; }, raw => { raw.revision++; }];
    for (const change of changes) {
      const f = await fixture(); await savedPair(f); await f.event('connect-access-form', 'submit');
      change(f.raw); await f.workspace.refresh(); await f.event('connect-grant');
      assert.equal(f.posts().length, 0); assert(f.node('connect-setup-step').hidden); f.clean();
    }
  }],
  ['uncertain, denied and lost saves clear PEM with no automatic replay or raw errors', async () => {
    for (const mode of [401, 409, 422, 503, 'lost']) {
      const f = await fixture({credentials: [], mode}); await newApp(f);
      await f.event('connect-credential-form', 'submit'); assert.equal(f.posts().length, 1);
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.node('connect-github-private-key').value, '');
      await f.event('connect-credential-form', 'submit'); await f.workspace.refresh();
      assert.equal(f.posts().length, 1); f.clean();
    }
  }],
  ['mismatched creation or refreshed identity never advances or repeats save', async () => {
    for (const options of [
      {receiptChange: result => { result.credential.github_app.app_id = '999'; }},
      {catalogChange: raw => { raw.credentials[0].github_app.installation_id = '999'; }},
      {catalogChange: raw => { raw.credentials[0].github_app.repository_id = '999'; }},
      {catalogChange: raw => { raw.credentials[0] = patCredential({name: NAME}); }}
    ]) {
      const f = await fixture({credentials: [], ...options}); await newApp(f);
      await f.event('connect-credential-form', 'submit');
      assert(f.node('connect-application-step').hidden); assert.equal(f.posts().length, 1);
      await f.event('connect-credential-form', 'submit'); assert.equal(f.posts().length, 1); f.clean();
    }
  }],
  ['PEM clears on navigation, type switch and invalid input without storage', async () => {
    for (const action of [f => f.view.show(false), f => f.fire('pagehide'), f => f.fire('hashchange'),
      async f => { f.node('connect-github-type').value = 'github_token_v1'; await f.event('connect-github-type', 'change'); },
      f => f.event('connect-method-change'), f => f.event('connect-credential-form', 'invalid')]) {
      const f = await fixture({credentials: []}); await newApp(f); await action(f);
      assert.equal(f.node('connect-github-private-key').value, ''); assert.equal(f.posts().length, 0); f.clean();
    }
    for (const field of ['connect-github-app-id', 'connect-github-installation-id']) for (const invalid of ['01', '9007199254740992', '+1', ' ']) {
      const f = await fixture({credentials: []}); await newApp(f); f.node(field).value = invalid;
      await f.event('connect-credential-form', 'submit');
      assert.equal(f.posts().length, 0); assert.equal(f.node('connect-github-private-key').value, ''); f.clean();
    }
  }],
  ['App replacement capability and configuration generation are separately closed', () => {
    const value = project(catalog({replacement: REPLACEMENT}));
    assert.deepEqual(value.capabilities.github_app_key_replacement, REPLACEMENT);
    assert.equal(plain.run('githubAppKeyReplacementAvailable(input, input.credentials[0])', value), true);
    assert.equal(plain.run('staticKeyReplacementAvailable(input, input.credentials[0])', value), false);
    for (const options of [{app: null}, {app: capability(true, false)}, {allowed: []},
      {app: {...capability(), api_origin: 'https://other.invalid'}}]) {
      const projected = project(catalog({replacement: REPLACEMENT, ...options}));
      assert.equal(plain.run('githubAppKeyReplacementAvailable(input, input.credentials[0])', projected), false);
    }
    for (const invalid of [null, {}, {...REPLACEMENT, extra: true}, {...REPLACEMENT, schema: 'unknown'},
      {...REPLACEMENT, path: '/api/operator-demo/credentials/replace-key'}]) {
      const projected = project(catalog({replacement: invalid}));
      assert.equal(projected.capabilities.github_app_key_replacement, null);
      assert.equal(plain.run('githubAppKeyReplacementAvailable(input, input.credentials[0])', projected), false);
    }
    for (const generation of [true, '1', 0, -1, 1.5, null, Number.MAX_SAFE_INTEGER + 1])
      assert.throws(() => project(catalog({credentials: [appCredential({credential_generation: generation})]})));
    for (const time of ['', 'not-date', '2026-02-30T00:00:00Z', '2026-10-10T00:00:00+04:00'])
      assert.throws(() => project(catalog({credentials: [appCredential({key_replaced_at: time})]})));
    const legacy = appCredential(); delete legacy.credential_generation;
    for (const row of [legacy, appCredential({credential_generation: Number.MAX_SAFE_INTEGER}),
      appCredential({status: 'revoked', credential_generation: null}), patCredential()]) {
      const projected = project(catalog({credentials: [row], replacement: REPLACEMENT}));
      assert.equal(plain.run('githubAppKeyReplacementAvailable(input, input.credentials[0])', projected), false);
    }
  }],
  ['replacement sends only complete private-key CAS and clears before held reply while retaining all assignments', async () => {
    const f = await fixture({replacement: REPLACEMENT, rules: [githubRule()], mode: 'hold'});
    const before = clone({apps: f.raw.applications, rules: f.raw.access_rules, policy: f.raw.policy, binding: f.raw.credentials[0].github_app});
    f.replacementView.open(IDS.credential); assert(!f.node('github-app-replace-panel').hidden);
    assert.match(f.node('github-app-replace-count').textContent, /^1 affected app · 1 active access rule/);
    f.node('github-app-replace-private-key').value = PEM;
    const pending = f.event('github-app-replace-form', 'submit');
    assert.equal(f.posts().length, 1); assert.equal(f.posts()[0].path, REPLACE);
    assert.equal(f.node('github-app-replace-private-key').value, ''); assert.equal(f.bodies[0].private_key_pem, '');
    assert(f.node('github-app-replace-panel').hidden); assert(f.workspace.writeInFlight()); f.clean();
    await f.event('github-app-replace-form', 'submit'); assert.equal(f.posts().length, 1);
    f.release(); await pending;
    assert.equal(f.raw.credentials[0].credential_generation, 2); assert.equal(f.workspace.state.uncertain, false);
    assert.deepEqual({apps: f.raw.applications, rules: f.raw.access_rules, policy: f.raw.policy, binding: f.raw.credentials[0].github_app}, before);
    assert.match(f.node('github-app-replace-status').textContent, /replacement saved in Serverware/);
    assert.match(f.node('github-app-replace-status').textContent, /Delete the old private key separately in GitHub/); f.clean();
  }],
  ['replacement cancellation navigation invalid input and shared holds clear without writes', async () => {
    for (const action of [f => f.event('github-app-replace-cancel'), f => f.fire('hashchange'), f => f.fire('pagehide'),
      f => f.event('github-app-replace-form', 'invalid'), f => f.workspace.setConsentHold(true, 'independent-owner')]) {
      const f = await fixture({replacement: REPLACEMENT}); f.replacementView.open(IDS.credential);
      f.node('github-app-replace-private-key').value = PEM; await action(f);
      assert.equal(f.posts().length, 0); assert.equal(f.node('github-app-replace-private-key').value, ''); f.clean();
    }
    const f = await fixture({replacement: REPLACEMENT}); f.replacementView.open(IDS.credential);
    f.node('github-app-replace-private-key').value = 'é'.repeat(4097);
    await f.event('github-app-replace-form', 'submit'); assert.equal(f.posts().length, 0);
    assert.equal(f.node('github-app-replace-private-key').value, ''); f.clean();
  }],
  ['replacement review refuses generation capability policy binding and assignment drift before submission', async () => {
    for (const drift of [v => v.credentials[0].credential_generation++, v => v.revision++,
      v => v.capabilities.github_app_key_replacement = null, v => v.capabilities.github_app = null,
      v => v.allowed_upstreams = [], v => v.policy.sequence++,
      v => v.credentials[0].github_app.account_id = '999', v => v.applications[0].token_generation++,
      v => v.access_rules[0].name = 'Changed permission']) {
      const f = await fixture({replacement: REPLACEMENT, rules: [githubRule()]}); f.replacementView.open(IDS.credential);
      f.node('github-app-replace-private-key').value = PEM; drift(f.raw); await f.workspace.refresh();
      assert(f.node('github-app-replace-panel').hidden); assert.equal(f.node('github-app-replace-private-key').value, '');
      await f.event('github-app-replace-form', 'submit'); assert.equal(f.posts().length, 0); f.clean();
    }
  }],
  ['uncertain replacement requires manual auth recovery and explicit review acknowledgement without replay', async () => {
    for (const mode of [401, 403, 409, 422, 503, 'lost', 'lost-after-commit']) {
      const f = await fixture({replacement: REPLACEMENT, mode}); f.replacementView.open(IDS.credential);
      const initialGets = f.requests.filter(row => row.method === 'GET').length;
      f.node('github-app-replace-private-key').value = PEM; await f.event('github-app-replace-form', 'submit');
      assert.equal(f.workspace.state.uncertain, true); assert(f.node('github-app-replace-panel').hidden);
      assert.equal(f.node('github-app-replace-private-key').value, ''); assert.equal(f.bodies[0].private_key_pem, '');
      f.replacementView.open(IDS.credential); assert(f.node('github-app-replace-panel').hidden);
      await f.event('github-app-replace-form', 'submit');
      if ([401, 403].includes(mode)) {
        assert.equal(f.workspace.state.catalog, null); assert.equal(f.node('load-error').hidden, false);
        assert.match(f.node('load-error-text').textContent, /session or request origin could not be verified/);
        assert.equal(f.node('mutation-review-confirm').disabled, true);
        assert.equal(f.requests.filter(row => row.method === 'GET').length, initialGets);
        const afterDeniedWrite = f.requests.length;
        assert.equal(await f.workspace.refresh(), false);
        await f.event('mutation-review-confirm');
        assert.equal(f.workspace.state.catalog, null); assert.equal(f.workspace.state.uncertain, true);
        assert.equal(f.node('mutation-review-confirm').disabled, true);
        assert.equal(f.requests.length, afterDeniedWrite); assert.equal(f.posts().length, 1);
        f.replacementView.open(IDS.credential); assert(f.node('github-app-replace-panel').hidden); f.clean();
        assert.equal(await f.workspace.refresh({manual: true}), true);
        assert(f.workspace.state.catalog); assert.equal(f.node('load-error').hidden, true);
        assert.equal(f.requests.filter(row => row.method === 'GET').length, initialGets + 1);
        assert.equal(f.requests.length, afterDeniedWrite + 1); assert.equal(f.posts().length, 1);
        assert.equal(f.workspace.state.uncertain, true); assert.equal(f.workspace.ready('credentials'), false);
        f.replacementView.open(IDS.credential); assert(f.node('github-app-replace-panel').hidden);
        await f.event('github-app-replace-form', 'submit'); assert.equal(f.posts().length, 1);
        assert.equal(f.node('github-app-replace-private-key').value, ''); f.clean();
      } else {
        await f.workspace.refresh();
      }
      assert.equal(f.posts().length, 1); assert.equal(f.raw.credentials[0].credential_generation, mode === 'lost-after-commit' ? 2 : 1);
      assert.equal(f.node('mutation-review-confirm').disabled, false); await f.event('mutation-review-confirm');
      assert.equal(f.workspace.state.uncertain, false);
      f.replacementView.open(IDS.credential); assert(!f.node('github-app-replace-panel').hidden);
      assert.equal(f.node('github-app-replace-private-key').value, ''); assert.equal(f.posts().length, 1); f.clean();
    }
  }],
  ['replacement receipt requires exact identity generation policy and closed result metadata', async () => {
    for (const receiptChange of [v => v.credential.github_app.app_id = '999', v => v.credential.name = 'Different',
      v => v.credential.credential_generation++, v => delete v.credential.key_replaced_at, v => v.policy.sequence++,
      v => v.key_replacement.in_flight_requests = 'recalled', v => v.key_replacement.extra = true,
      v => v.key_replacement.cache_invalidation = 'private-error']) {
      const f = await fixture({replacement: REPLACEMENT, receiptChange}); f.replacementView.open(IDS.credential);
      f.node('github-app-replace-private-key').value = PEM; await f.event('github-app-replace-form', 'submit');
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.posts().length, 1); f.clean();
    }
    const f = await fixture({replacement: REPLACEMENT, receiptChange: value => value.key_replacement.cache_invalidation = 'local_unconfirmed'});
    f.replacementView.open(IDS.credential); f.node('github-app-replace-private-key').value = PEM;
    await f.event('github-app-replace-form', 'submit'); assert.equal(f.workspace.state.uncertain, false);
    assert.match(f.node('github-app-replace-status').textContent, /Local cache invalidation was not confirmed/); f.clean();
  }],
  ['replacement acknowledgement does not replace exact refreshed assignment and generation proof', async () => {
    for (const catalogChange of [v => v.credentials[0].credential_generation--, v => v.credentials[0].github_app.repository_id = '999',
      v => v.applications[0].token_generation++, v => v.access_rules[0].name = 'Different',
      v => v.credentials[0] = patCredential({name: NAME})]) {
      const f = await fixture({replacement: REPLACEMENT, rules: [githubRule()], catalogChange});
      f.replacementView.open(IDS.credential); f.node('github-app-replace-private-key').value = PEM;
      await f.event('github-app-replace-form', 'submit');
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.node('mutation-review-confirm').disabled, true);
      assert.equal(f.posts().length, 1); await f.workspace.refresh();
      assert.equal(f.posts().length, 1); f.clean();
    }
  }],
];
let group = 0;
async function main() {
  assert.equal(process.argv.length, 2, 'No target, credentials, browser or live arguments accepted');
  assert.equal(tests.length, 20, 'The complete nonempty regression roster is required');
  for (const [name, test] of tests) { group++; await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, network: false, browser: false, provider: false,
    scope: 'actual UI functions and core mutation; inert DOM and independent in-memory API, not provider acceptance'}));
}
main().catch(error => {
  const frames = [...String(error?.stack || '').matchAll(/test_operator_github_app_ui\.mjs:(\d+):(\d+)/g)].slice(0, 5).map(match => [Number(match[1]), Number(match[2])]);
  console.error(JSON.stringify({ok: false, group, frames})); process.exitCode = 1;
});
