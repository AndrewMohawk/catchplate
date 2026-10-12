#!/usr/bin/env node
// Inert DOM and synthetic fetch only. No browser, provider, consent or post.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {context, rawCatalog, IDS, clone} = require('./test_operator_npm_ui.cjs');
const {credential, rule, NOW} = require('./test_operator_catalog_browser.cjs');
const ORIGIN = 'https://operator.example.test';
const OP = '77777777-7777-4777-8777-777777777777';
const KEY = 'serverware.operator.x.account.operation.v1';
const SHA = 'sha256:' + 'a'.repeat(64);
const scopes = ['offline.access', 'tweet.read', 'tweet.write', 'users.read'];
const cap = () => ({schema: 'serverware.operatorXOAuth/v1', connection_type: 'x_user_oauth_v1', auth_type: 'x_oauth',
  permission_preset: 'x_text_post_v1', start_path: '/api/operator-demo/oauth/x/start',
  operation_path_prefix: '/api/operator-demo/oauth/x/operations/',
  disconnect_review_path_template: '/api/operator-demo/oauth/x/accounts/{credential_id}/disconnect-review',
  disconnect_path: '/api/operator-demo/oauth/x/disconnect', source_pair_required: true, automatic_refresh: true, daily_quota_available: false});
const postCap = () => ({schema: 'serverware.operatorXPost/v1', connection_type: 'x_user_oauth_v1',
  create_rule_path: '/api/operator-demo/access-rules/x-post', api_origin: 'https://api.x.com', destination_allowed: true,
  operation_bundles: ['x_text_post_v1'], sdk_auth_token: 'serverware-x-post-placeholder-v1',
  placeholder: 'Bearer serverware-x-post-placeholder-v1', response_mode: 'x_post_json_v1', source_pair_required: true, daily_quota_available: false});
const account = (changes = {}) => credential({auth_type: 'x_oauth', connection_type: 'x_user_oauth_v1', provider_id: 'x',
  provider_account: '@fixture_user', provider_subject: '123456789', oauth_client_id: 'fixture-client',
  permission_preset: 'x_text_post_v1', scopes: [...scopes], credential_generation: 1, ...changes});
const postRule = (changes = {}) => rule({operation_bundle: 'x_text_post_v1', methods: ['POST'], upstream_url: 'https://api.x.com/2/tweets',
  request_fields: [], response_fields: [], query_keys: [], allowed_headers: ['accept', 'accept-language', 'content-type', 'sec-fetch-mode', 'user-agent'],
  response_mode: 'x_post_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer serverware-x-post-placeholder-v1', ...changes});
const operation = (changes = {}) => ({schema: 'serverware.operatorXAccountOperation/v1', operation_id: OP, kind: 'consent',
  status: 'connected', credential_id: IDS.credential, reason: null, created_at: new Date(NOW).toISOString(), expires_at_epoch_ms: NOW + 600000, ...changes});
function catalog() {
  const value = rawCatalog({credentials: [account()], rules: [postRule()], capability: null, allowed: ['https://api.x.com']});
  value.capabilities.x_oauth = cap(); value.capabilities.x_post = postCap(); return value;
}
function fixture({saved = null, returned = null, response = operation(), onFetch = null, value = catalog()} = {}) {
  const f = context();
  for (const name of ['workspace_upstreams.js', 'workspace_x_accounts.js', 'workspace_x_post.js', 'workspace_x_configuration.js'])
    vm.runInContext(readFileSync(resolve(__dirname, '../serverware/operator_demo_web', name), 'utf8'), f.value, {timeout: 2000});
  const storage = new Map(saved === null ? [] : [[KEY, saved]]); const calls = []; const navigations = []; const replacements = [];
  Object.assign(f.value, {sessionStorage: {getItem: key => storage.get(key) ?? null, setItem: (key, val) => storage.set(key, val), removeItem: key => storage.delete(key)},
    AbortSignal: {timeout: () => undefined}, clearTimeout() {}, crypto: {randomUUID: () => OP},
    location: {origin: ORIGIN, protocol: 'https:', hash: '#overview', href: ORIGIN + '/' + (returned ? '?serverware_x_operation=' + returned : '') + '#overview',
      assign: url => navigations.push(url)}, history: {replaceState: (_a, _b, url) => replacements.push(url)},
    fetch: async (path, init) => {
      assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
      const call = {path, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null}; calls.push(call);
      const result = onFetch ? await onFetch(call) : response;
      return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => clone(result)};
    }});
  const workspace = f.run('createOperatorWorkspace()');
  workspace.state.catalog = f.run('projectCatalog(input)', value);
  workspace.refresh = async () => { workspace.emit(); return true; };
  f.value.workspace = workspace; f.value.apps = {}; f.value.connect = {selectXAccountCredential: id => navigations.push('selected:' + id)};
  return {...f, storage, calls, navigations, replacements, workspace, start: () => f.run('createXAccountsView(workspace, apps, connect)'),
    node: id => f.dom.nodes.get(id) || f.dom.getElementById('mutation-review').descendants().find(node => node.id === id),
    event: async id => f.dom.getElementById(id).events.click?.()};
}
const tests = [
  ['closed independent account and posting capabilities; no daily quota or fallback', () => {
    const f = fixture();
    assert.deepEqual(clone(f.run('projectXAccountCapability(input)', cap())), cap());
    assert.deepEqual(clone(f.run('projectXPostCapability(input)', postCap())), postCap());
    for (const value of [{...cap(), automatic_refresh: false}, {...cap(), extra: true}]) assert.equal(f.run('projectXAccountCapability(input)', value), null);
    for (const value of [{...postCap(), daily_quota_available: true}, {...postCap(), extra: true}]) assert.equal(f.run('projectXPostCapability(input)', value), null);
  }],
  ['public OAuth account projection refuses cross-marker, scopes, subject and lifecycle drift', () => {
    const f = fixture(); assert.equal(f.run('projectXAccount(input).provider_subject', account()), '123456789');
    for (const change of [{auth_type: 'bearer'}, {provider_subject: '01'}, {connection_type: 'x_app_bearer_v1'},
      {scopes: ['tweet.write']}, {credential_generation: null}, {status: 'revoked', credential_generation: 1}])
      assert.throws(() => f.run('projectXAccount(input)', account(change)));
    assert.equal(f.run('projectXAccount(input).credential_generation', account({status: 'revoked', credential_generation: null})), null);
  }],
  ['fixed posting DTO and pending capability withdrawal preserve saved rules without granting', () => {
    const f = fixture(); assert.equal(f.run('operatorRuleSupported(input.access_rules[0], input)', f.workspace.state.catalog), true);
    assert.deepEqual(clone(f.run('xPostRulePayload(input)', postRule())), {name: postRule().name, application_id: IDS.application,
      credential_id: IDS.credential, operation_bundle: 'x_text_post_v1'});
    for (const change of [{daily_quota: 5}, {request_body_mode: 'preserve_json_v1'}, {request_fields: ['text']},
      {placeholder: 'Bearer serverware-x-placeholder-v1'}, {upstream_url: 'https://api.x.com/2/users/me'}])
      assert.equal(f.run('xPostRuleValid(input.rule,input.account)', {rule: postRule(change), account: account()}), false);
    const raw = catalog(); raw.capabilities.x_post = null; const projected = f.run('projectCatalog(input)', raw);
    assert.equal(projected.access_rules.length, 1); assert.equal(f.run('operatorRuleSupported(input.access_rules[0],input)', projected), false);
  }],
  ['startup and returned callback retain only exact public UUID; no automatic I/O', async () => {
    const f = fixture({saved: OP, returned: OP}); f.start();
    assert.deepEqual(f.calls, []); assert.deepEqual(f.replacements, ['/#credentials']);
    assert.equal(f.storage.get(KEY), OP); assert.equal(f.workspace.state.consentHold, true);
    assert.equal(f.node('mutation-review').hidden, false); assert.equal(f.node('x-account-recovery-hint').hidden, false);
    assert.equal(f.node('x-account-start').disabled, true);
    await f.event('x-account-start'); assert.equal(f.calls.length, 0);
  }],
  ['connected GET recovery needs explicit acknowledgement; second reload does not re-block', async () => {
    const f = fixture({saved: OP}); f.start(); await f.event('x-account-check');
    assert.deepEqual(f.calls, [{path: '/api/operator-demo/oauth/x/operations/' + OP, method: 'GET', body: null}]);
    assert.equal(f.workspace.state.consentHold, false); assert.equal(f.workspace.state.uncertain, true);
    await f.event('x-account-acknowledge'); assert.equal(f.storage.size, 0); assert.equal(f.calls.length, 1);
    assert.equal(f.workspace.state.uncertain, true); await f.event('mutation-review-confirm');
    assert.equal(f.workspace.state.uncertain, false); await f.event('x-account-use');
    assert.deepEqual(f.navigations, ['selected:' + IDS.credential]);
    const reload = fixture(); reload.start(); assert.equal(reload.workspace.state.busy, false); assert.equal(reload.calls.length, 0);
  }],
  ['failed or uncertain exchange cannot be retired; another owner hold is never cleared', async () => {
    for (const status of ['failed', 'uncertain', 'exchanging']) {
      const f = fixture({saved: OP, response: operation({status, credential_id: null, reason: status === 'exchanging' ? null : 'exchange_failed'})});
      f.start(); await f.event('x-account-check'); await f.event('x-account-acknowledge');
      assert.equal(f.storage.get(KEY), OP); assert.equal(f.workspace.state.consentHold, true); assert.equal(f.calls.length, 1);
    }
    const f = fixture({saved: OP}); f.start(); f.workspace.setConsentHold(true, 'independent-google-owner');
    await f.event('x-account-check'); await f.event('x-account-acknowledge');
    assert.equal(f.storage.get(KEY), OP); assert.equal(f.workspace.state.busy, true);
  }],
  ['strict consent redirect binds exact profile, callback, PKCE, state and original expiry', () => {
    const f = fixture(); const configuration = {profile_binding_digest: SHA, public_profile: {client_id: 'fixture-client'}};
    const pairs = {response_type: 'code', client_id: 'fixture-client', redirect_uri: ORIGIN + '/api/oauth/callback/x',
      scope: scopes.join(' '), state: 's'.repeat(43), code_challenge: 'c'.repeat(43), code_challenge_method: 'S256'};
    const start = {schema: 'serverware.operatorXConsent/v1', operation_id: OP, status: 'consent_pending',
      authorization_url: 'https://x.com/i/oauth2/authorize?' + new URLSearchParams(pairs), state: pairs.state,
      expires_at_epoch_ms: NOW + 600000, profile_binding_digest: SHA};
    const parse = value => f.run('projectXConsentStart(input.value,input.id,input.configuration)', {value, id: OP, configuration});
    assert.equal(parse(start), start.authorization_url);
    for (const value of [{...start, authorization_url: start.authorization_url + '&state=other'}, {...start, profile_binding_digest: 'sha256:' + 'b'.repeat(64)},
      {...start, expires_at_epoch_ms: NOW}, {...start, authorization_url: start.authorization_url.replace('https://x.com/', 'https://wrong.invalid/')}]) assert.throws(() => parse(value));
  }],
  ['actual start handler saves UUID before its single POST and never retains authorization material', async () => {
    const configProfile = {schema: 'serverware.operatorXOAuthProfile/v1', profile: 'operator-x-oauth-v1', provider_id: 'x',
      client_id: 'fixture-client', redirect_uri: ORIGIN + '/api/oauth/callback/x', client_auth_method: 'client_secret_basic',
      permission_preset: 'x_text_post_v1', scopes: [...scopes], api_origins: ['https://api.x.com'], authorization_url: 'https://x.com/i/oauth2/authorize',
      token_url: 'https://api.x.com/2/oauth2/token', revocation_url: 'https://api.x.com/2/oauth2/revoke', identity_url: 'https://api.x.com/2/users/me'};
    const config = {schema: 'serverware.operatorXConfiguration/v1', state: 'configured', revision: 1,
      policy_hash: catalog().policy.policy_hash, redirect_uri: configProfile.redirect_uri, permission_preset: 'x_text_post_v1', scopes: [...scopes],
      configuration: {config_version: 1, profile_binding_digest: SHA, public_profile: configProfile, client_secret_configured: true},
      operation: null, review: null, blocked_reason: 'already_configured', consent_ready: false};
    const pairs = {response_type: 'code', client_id: configProfile.client_id, redirect_uri: configProfile.redirect_uri,
      scope: scopes.join(' '), state: 's'.repeat(43), code_challenge: 'c'.repeat(43), code_challenge_method: 'S256'};
    const url = configProfile.authorization_url + '?' + new URLSearchParams(pairs);
    const f = fixture({onFetch: call => {
      if (call.method === 'GET') { assert.equal(call.path, '/api/operator-demo/oauth/x/configuration/v1'); return config; }
      assert.equal(f.storage.get(KEY), OP); assert.equal(call.path, '/api/operator-demo/oauth/x/start');
      assert.deepEqual(call.body, {operation_id: OP, name: 'My X account', expected_revision: 1, expected_policy_hash: config.policy_hash});
      return {schema: 'serverware.operatorXConsent/v1', operation_id: OP, status: 'consent_pending', authorization_url: url,
        state: pairs.state, expires_at_epoch_ms: NOW + 600000, profile_binding_digest: SHA};
    }});
    f.start(); f.node('x-account-name').value = 'My X account'; await f.event('x-account-start');
    assert.deepEqual(f.navigations, [url]); assert.deepEqual([...f.storage], [[KEY, OP]]);
    await f.event('x-account-start'); assert.equal(f.calls.length, 2);
    assert(![...f.dom.nodes.values()].some(node => node.textContent.includes(pairs.state)));
    const lost = fixture({onFetch: call => { if (call.method === 'GET') return config; throw new Error('synthetic lost reply'); }});
    lost.start(); lost.node('x-account-name').value = 'My X account'; await lost.event('x-account-start');
    assert.equal(lost.storage.get(KEY), OP); assert.equal(lost.workspace.state.uncertain, true);
    await lost.event('x-account-start'); assert.equal(lost.calls.filter(call => call.method === 'POST').length, 1);
    assert.equal(lost.navigations.length, 0);
  }],
  ['disconnect scope is closed and bound to reviewed same-client account resources', () => {
    const f = fixture(); const value = {schema: 'serverware.operatorXDisconnectReview/v1', credential_id: IDS.credential,
      expected_credential_generation: 1, expected_revision: 1, expected_policy_hash: f.workspace.state.catalog.policy.policy_hash,
      review_digest: SHA, affected_credential_ids: [IDS.credential], affected_rule_ids: [IDS.rule]};
    const parse = review => f.run('projectXDisconnectReview(input.review,input.account,input.catalog)', {review, account: account(), catalog: f.workspace.state.catalog});
    assert.deepEqual(clone(parse(value)), value);
    for (const change of [{expected_revision: 2}, {affected_credential_ids: []}, {affected_rule_ids: [IDS.other]}, {extra: true}]) assert.throws(() => parse({...value, ...change}));
  }],
  ['actual disconnect handler uses reviewed digest and one retained UUID; lost reply is GET-only', async () => {
    const review = {schema: 'serverware.operatorXDisconnectReview/v1', credential_id: IDS.credential,
      expected_credential_generation: 1, expected_revision: 1, expected_policy_hash: catalog().policy.policy_hash,
      review_digest: SHA, affected_credential_ids: [IDS.credential], affected_rule_ids: [IDS.rule]};
    const f = fixture({onFetch: call => {
      if (call.method === 'GET') { assert.equal(call.path, '/api/operator-demo/oauth/x/accounts/' + IDS.credential + '/disconnect-review'); return review; }
      assert.equal(f.storage.get(KEY), OP); assert.deepEqual(call.body, {operation_id: OP, credential_id: IDS.credential,
        expected_credential_generation: 1, expected_revision: 1, expected_policy_hash: review.expected_policy_hash, review_digest: SHA});
      throw new Error('synthetic lost disconnect reply');
    }});
    const view = f.start(); await view.disconnect(IDS.credential); assert.equal(f.node('x-disconnect-submit').disabled, false);
    await f.event('x-disconnect-submit'); assert.equal(f.workspace.state.uncertain, true);
    assert.equal(f.storage.get(KEY), OP); await f.event('x-disconnect-submit');
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  }],
  ['gate unavailable permits protective disconnect only after actor-owned review, never new consent or posting', async () => {
    for (const status of ['active', 'quarantined']) {
      const value = catalog(); value.capabilities.x_oauth = null; value.capabilities.x_post = null;
      value.policy.activation = 'pending'; value.policy.loaded_policy_hash = SHA;
      if (status === 'quarantined') {
        value.credentials = [account({status, active_rule_count: 0, quarantined_at: new Date(NOW).toISOString(),
          quarantine_reason: 'operator_x_cleanup_fence', provider_revocation_status: 'not_proven'})];
        value.access_rules = [postRule({status: 'revoked'})];
      }
      const review = {schema: 'serverware.operatorXDisconnectReview/v1', credential_id: IDS.credential,
        expected_credential_generation: 1, expected_revision: 1, expected_policy_hash: value.policy.policy_hash,
        review_digest: SHA, affected_credential_ids: [IDS.credential], affected_rule_ids: status === 'active' ? [IDS.rule] : []};
      const f = fixture({value, onFetch: call => {
        if (call.method === 'GET') { assert.equal(call.path, '/api/operator-demo/oauth/x/accounts/' + IDS.credential + '/disconnect-review'); return review; }
        assert.equal(call.path, '/api/operator-demo/oauth/x/disconnect'); assert.equal(f.storage.get(KEY), OP);
        assert.equal(call.body.review_digest, SHA);
        return operation({kind: 'disconnect', status: 'disconnect_pending', expires_at_epoch_ms: null});
      }});
      const view = f.start();
      assert.equal(f.node('x-account-panel').hidden, false); assert.equal(f.node('connect-x-account').hidden, true);
      f.node('x-account-name').value = 'Must not start'; f.workspace.emit();
      assert.equal(f.node('x-account-start').disabled, true); await f.event('x-account-start'); assert.equal(f.calls.length, 0);
      assert.equal(f.run('operatorRuleSupported(input.access_rules[0],input)', f.workspace.state.catalog), false);
      assert.equal(f.node('x-disconnect-submit').disabled, true);
      await view.disconnect(IDS.credential); assert.equal(f.node('x-disconnect-submit').disabled, false);
      await f.event('x-disconnect-submit');
      assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
      assert.equal(f.storage.get(KEY), OP); assert.equal(f.workspace.state.consentHold, true);
      await f.event('x-disconnect-submit'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
    }
  }],
  ['gate unavailable does not bypass absent review, stale generation or another management hold', async () => {
    const value = catalog(); value.capabilities.x_oauth = null; value.capabilities.x_post = null;
    const refused = fixture({value, onFetch: () => { throw new Error('actor-owned review unavailable'); }});
    const view = refused.start(); await view.disconnect(IDS.credential);
    assert.equal(refused.node('x-disconnect-submit').disabled, true); await refused.event('x-disconnect-submit');
    assert.equal(refused.calls.length, 1); assert.equal(refused.calls[0].method, 'GET'); assert.equal(refused.storage.size, 0);
    const review = {schema: 'serverware.operatorXDisconnectReview/v1', credential_id: IDS.credential,
      expected_credential_generation: 1, expected_revision: 1, expected_policy_hash: value.policy.policy_hash,
      review_digest: SHA, affected_credential_ids: [IDS.credential], affected_rule_ids: [IDS.rule]};
    const stale = fixture({value, response: review}); const managed = stale.start(); await managed.disconnect(IDS.credential);
    stale.workspace.state.catalog.credentials[0].credential_generation = 2; stale.workspace.emit();
    assert.equal(stale.node('x-disconnect-submit').disabled, true); await stale.event('x-disconnect-submit'); assert.equal(stale.calls.length, 1);
    stale.workspace.setConsentHold(true, 'independent-google-owner'); await managed.disconnect(IDS.credential);
    assert.equal(stale.calls.length, 1); assert.equal(stale.workspace.state.busy, true);
  }],
  ['SDK recipe carries public config only, explicit local post-once and verified TLS', () => {
    const f = fixture(); const args = {proxyUrl: 'https://proxy.example.test:8443', applicationId: IDS.application,
      proxyAuthentication: 'basic_and_bearer_v1', caPath: './serverware-ca.pem', proxyCaPath: ''};
    const recipe = f.run('buildXPostClientRecipe(input)', args);
    assert.match(recipe, /SERVERWARE_X_POST_CONFIRM=post-once node client\.mjs/);
    assert.match(recipe, /SERVERWARE_X_POST_TEXT:\?/); assert.match(recipe, /Do not repeat automatically/);
    assert.doesNotMatch(recipe, /rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|access_token|refresh_token/);
    assert.throws(() => f.run('buildXPostClientRecipe(input)', {...args, proxyAuthentication: 'bearer'}));
  }],
  ['actual saved-account wizard grants only fixed posting and recovers pending-null policy without replay', async () => {
    const initial = catalog(); initial.access_rules = [];
    const f = fixture({value: initial, onFetch: call => {
      if (call.method === 'GET') { assert.equal(call.path, '/api/operator-demo/catalog'); return pending; }
      assert.equal(call.path, '/api/operator-demo/access-rules/x-post'); assert.equal(call.method, 'POST');
      assert.deepEqual(call.body, {name: 'Publish text · @fixture_user', application_id: IDS.application, credential_id: IDS.credential,
        operation_bundle: 'x_text_post_v1', expected_revision: 1, expected_policy_hash: initial.policy.policy_hash});
      return {revision: 2, policy: {policy_hash: SHA}, access_rule: postRule({name: call.body.name, enforcement: 'pending'})};
    }});
    const pending = catalog(); pending.revision = 2; pending.policy.policy_hash = SHA; pending.policy.activation = 'pending';
    pending.access_rules = [postRule({name: 'Publish text · @fixture_user', enforcement: 'pending'})];
    pending.capabilities.x_post = null; pending.capabilities.x_oauth = null;
    f.value.setTimeout = () => 0; // No polling executes in this inert controller fixture.
    f.run('createConnectView(workspace, {mount(){},tokenFor(){return null;}}, {mount(){},select(){}})');
    const event = async (id, kind = 'click') => { const node = f.node(id); await node.events[kind]({preventDefault(){}, currentTarget: node}); };
    await event('connect-use-saved'); f.node('connect-credential-choice').value = IDS.credential;
    await event('connect-credential-form', 'submit'); f.node('connect-application-choice').value = IDS.application;
    await event('connect-application-form', 'submit');
    assert.equal(f.node('connect-operation').value, 'x_text_post_v1');
    assert.equal(f.node('connect-x-post-group').hidden, false); assert.equal(f.node('connect-exact-content').hidden, true);
    await event('connect-access-form', 'submit'); assert.equal(f.node('connect-grant').disabled, false);
    await event('connect-grant'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1); assert.equal(f.workspace.state.uncertain, false);
    assert.match(f.node('connect-activation').textContent, /Waiting for the proxy/);
    pending.policy.activation = 'active'; pending.policy.loaded_policy_hash = SHA;
    pending.access_rules[0].enforcement = 'active'; pending.capabilities.x_post = postCap(); pending.capabilities.x_oauth = cap();
    f.workspace.state.catalog = f.run('projectCatalog(input)', pending); f.workspace.emit();
    assert.match(f.node('connect-activation').textContent, /Rule active in the proxy/); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  }],
  ['X refresh activity accepts recorded success only; unsupported failures stay unavailable', () => {
    const f = fixture();
    const value = {schema: 'serverware.operatorAccountActivity/v1', status: 'available', observed_at_epoch_ms: NOW,
      chain_verification: 'not_checked', window: {row_limit: 256, event_byte_limit: 16384, byte_limit: 2097152,
        rows_scanned: 1, bytes_read: 256, has_older_rows: false, byte_budget_exhausted: false, incomplete: false,
        oversized_events: 0, invalid_events: 0, unmatched_responses: 0},
      accounts: [{credential_id: IDS.credential, last_successful_response: null,
        last_refresh_success: {event_id: OP, recorded_at_epoch_ms: NOW - 1000, credential_version: 2},
        last_refresh_failure: null, last_refresh_outcome: 'success'}]};
    const project = activity => f.run('projectObservedAccountActivity(input,[credential],[],[])', activity);
    f.value.credential = account();
    assert.equal(project(value).accounts[0].last_refresh_outcome, 'success');
    const bad = clone(value); bad.accounts[0].last_refresh_failure = bad.accounts[0].last_refresh_success;
    bad.accounts[0].last_refresh_outcome = 'failure'; assert.equal(project(bad), null);
    bad.accounts[0].last_refresh_failure = null; assert.equal(project(bad), null);
  }],
];
(async () => {
  assert.equal(process.argv.length, 2);
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false,
    scope: 'actual public UI helpers and controller with inert DOM; no provider or backend acceptance'}));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
