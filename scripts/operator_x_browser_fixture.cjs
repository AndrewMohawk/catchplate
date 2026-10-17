// Synthetic intercepted X DTOs only. Not an API, custody, SDK or provider test.
const assert = require('node:assert/strict');
const {credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const ORIGIN = 'https://operator-catalog.example.test';
const API = 'https://api.x.com';
const CREATE = '/api/operator-demo/credentials/x-app-bearer';
const GRANT = '/api/operator-demo/access-rules/x-username';
const APP = '/api/operator-demo/applications';
const BUNDLE = 'x_username_read_v1';
const USERNAME = 'example_user';
const DUMMY = 'catchplate-x-placeholder-v1';
const PRIVATE = 'synthetic-X-provider-bearer-NEVER-RENDER';
const PRIVATE_ERROR = 'synthetic-private-storage-error-NEVER-RENDER';
const APP_TOKEN = 'synthetic_application_' + IDS.application.replaceAll('-', '') + '_generation_1';
const BASIC = 'basic_and_bearer_v1';
const clone = value => JSON.parse(JSON.stringify(value));
// Independent closed server descriptor: never call the production UI helpers.
const capability = (allowed = true) => ({schema: 'catchplate.operatorXAppRead/v1',
  connection_type: 'x_app_bearer_v1', create_credential_path: CREATE, create_rule_path: GRANT,
  api_origin: API, destination_allowed: allowed, operation_bundles: [BUNDLE],
  sdk_auth_token: DUMMY, placeholder: 'Bearer ' + DUMMY,
  response_mode: 'x_app_read_json_v1', source_pair_required: true});
const xCredential = (changes = {}) => credential({name: 'Saved X app token', version: 1,
  credential_generation: 1, connection_type: 'x_app_bearer_v1', provider_id: 'x', ...changes});
const xRule = (changes = {}) => rule({name: 'Read X username', version: 1,
  operation_bundle: BUNDLE, username: USERNAME, upstream_url: API + '/2/users/by/username/' + USERNAME,
  methods: ['GET'], request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent'],
  response_mode: 'x_app_read_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer ' + DUMMY, ...changes});
const options = changes => ({credentials: [xCredential()], applications: [application({proxy_authentication: BASIC})],
  rules: [], allowedUpstreams: [API], requestBodyModes: ['preserve_json_v1'],
  responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'], ...changes});

function catalog(state) {
  const result = publicCatalog(state);
  result.capabilities.application_proxy_authentication = {schema: 'catchplate.operatorProxyAuthentication/v1',
    modes: ['bearer', BASIC], path: '/api/operator-demo/applications/proxy-authentication'};
  // The backend advertises the paired X implementation only after fresh gate
  // health identifies the exact current policy. A saved, not-yet-loaded rule
  // remains in the catalog, but its capability is temporarily null.
  // Explicit missing/malformed descriptors remain intact once hashes match.
  if (state.xCapability !== undefined)
    result.capabilities.x = state.loaded === state.active ? clone(state.xCapability) : null;
  return state.xTransform ? state.xTransform(result) : result;
}
function cas(state, body) {
  assert.equal(body.expected_revision, state.revision, 'exact reviewed revision');
  assert.equal(body.expected_policy_hash, state.active, 'exact reviewed policy');
}
function admitCredential(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
  cas(state, body); assert.equal(body.name, 'My X token'); assert.equal(body.secret, PRIVATE);
  assert.deepEqual(catalog(state).capabilities.x, capability(state.xCapability.destination_allowed));
  assert.equal(state.credentials.length, 0);
}
function createCredential(state, body, config) {
  state.credentials.push(xCredential({name: body.name, ...(config.credentialChange || {})})); state.revision++;
  return {credential: catalog(state).credentials[0], revision: state.revision, policy: catalog(state).policy};
}
function createApplication(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'proxy_authentication', 'token_lifetime_seconds']);
  cas(state, body); assert.equal(body.name, 'X lookup client'); assert.equal(body.proxy_authentication, BASIC);
  assert.equal(body.token_lifetime_seconds, 3600); assert.equal(state.applications.length, 0);
  state.applications.push(application({name: body.name, version: 1, proxy_authentication: BASIC,
    token_expires_at_epoch_ms: NOW + body.token_lifetime_seconds * 1000})); state.revision++;
  return {application: catalog(state).applications[0], revision: state.revision, policy: catalog(state).policy, client_token: APP_TOKEN};
}
function admitRule(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
    'expected_revision', 'name', 'operation_bundle', 'username']);
  cas(state, body); assert.deepEqual(catalog(state).capabilities.x, capability()); assert(state.allowedUpstreams.includes(API));
  assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
  assert.equal(body.operation_bundle, BUNDLE); assert.equal(body.username, USERNAME);
  assert.equal(body.name, 'Look up X username · ' + USERNAME);
  assert(state.credentials.some(item => item.id === body.credential_id && item.status === 'active' &&
    item.connection_type === 'x_app_bearer_v1' && item.provider_id === 'x'));
  assert(state.applications.some(item => item.id === body.application_id && item.status === 'active'));
  assert.equal(state.rules.length, 0);
}
function createRule(state, body, config) {
  state.rules.push(xRule({name: body.name, ...(config.ruleChange || {})})); state.revision++;
  state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
  return {access_rule: catalog(state).access_rules[0], revision: state.revision, policy: catalog(state).policy};
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].filter(node => node.id !== 'client-token').map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  const text = JSON.stringify(surfaces);
  for (const value of [PRIVATE, PRIVATE_ERROR, APP_TOKEN]) assert(!text.includes(value), 'private material escaped its write-only/one-time field');
  assert.deepEqual(surfaces.local, []); assert.deepEqual(surfaces.session, []);
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.xCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
    const observed = {credentials: [], applications: [], grants: [], requests: [], catalogs: []};
    let signal; let release;
    const credentialArrived = new Promise(resolve => { signal = resolve; });
    const held = config.holdCredential ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json',
      headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(value)});
    page.on('download', () => state.errors.push('unexpected download'));
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(observed.requests.length < 48);
        observed.requests.push({path: url.pathname, method: request.method()});
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++;
          const result = catalog(state);
          observed.catalogs.push({revision: result.revision, policy: clone(result.policy),
            x: Object.hasOwn(result.capabilities, 'x') ? clone(result.capabilities.x) : undefined,
            ruleIds: result.access_rules.map(item => item.id)});
          await answer(route, result); return;
        }
        assert.equal(request.method(), 'POST');
        const limit = {[CREATE]: 16384, [APP]: 2048, [GRANT]: 4096}[url.pathname];
        assert(limit && bytes?.length && bytes.length <= limit);
        assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString()); let result;
        if (url.pathname === CREATE) {
          assert.equal(observed.credentials.length, 0, 'no automatic key replay'); admitCredential(state, body);
          observed.credentials.push({name: body.name, secretMatched: true, expected_revision: body.expected_revision});
          body.secret = ''; signal(); await held;
          if (config.credentialFault) {
            state.expectedFailures.add(CREATE); await answer(route, {detail: PRIVATE_ERROR}, 503); return;
          }
          result = createCredential(state, body, config);
        } else if (url.pathname === APP) {
          assert.equal(observed.applications.length, 0, 'no automatic application replay');
          observed.applications.push(clone(body)); result = createApplication(state, body);
        } else {
          assert.equal(url.pathname, GRANT); assert.equal(observed.grants.length, 0, 'no automatic grant replay');
          admitRule(state, body); observed.grants.push(clone(body));
          if (['409', '503'].includes(config.grantFault)) {
            state.expectedFailures.add(GRANT); await answer(route, {detail: PRIVATE_ERROR}, Number(config.grantFault)); return;
          }
          result = createRule(state, body, config);
          if (config.grantFault === 'lost-after-commit') {
            state.expectedFailures.add(GRANT); await route.abort('failed'); return;
          }
        }
        await answer(route, result, 201);
      } catch (_) { signal(); state.errors.push('X fixture closed DTO/CAS boundary failed'); await route.abort(); }
    };
    // The inherited deny-all handler still rejects every other HTTP target,
    // WebSocket and worker request. These handlers never continue/fetch traffic.
    for (const path of ['/api/operator-demo/catalog', CREATE, APP, GRANT]) await controls.context.route(ORIGIN + path, handler);
    try {
      await page.reload({waitUntil: 'networkidle'});
      assert.equal(new URL(page.url()).origin, ORIGIN);
      await exercise(page, state, observed, {credentialArrived, releaseCredential: () => release?.()});
      assert.deepEqual(state.posts, [], 'no generic grant, token rotation, OAuth, provider or unrelated mutation');
      assert(observed.credentials.length <= 1 && observed.applications.length <= 1 && observed.grants.length <= 1);
      await privateAbsent(page);
    } finally { release?.(); }
  });
}
module.exports = {fixture, capability, xCredential, xRule, clone, privateAbsent,
  ORIGIN, API, CREATE, GRANT, BUNDLE, USERNAME, DUMMY, PRIVATE, APP_TOKEN, IDS};
