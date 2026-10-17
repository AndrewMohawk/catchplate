// Independent synthetic Alchemy catalog oracle, not backend/SDK acceptance.
const assert = require('node:assert/strict');
const {credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const ORIGIN = 'https://operator-catalog.example.test';
const CREATE = '/api/operator-demo/credentials/alchemy-key';
const GRANT = '/api/operator-demo/access-rules/alchemy-chain-status';
const APP = '/api/operator-demo/applications';
const BUNDLE = 'alchemy_chain_status_read_v1';
const CHAINS = ['eth-mainnet', 'eth-sepolia'];
const RPC = ['eth_chainId', 'eth_blockNumber'];
const api = chain => 'https://' + chain + '.g.alchemy.com';
const DUMMY = 'catchplate-alchemy-placeholder-v1';
const PRIVATE = 'synthetic-Alchemy-key-NEVER-RENDER';
const PRIVATE_ERROR = 'synthetic-private-storage-error-NEVER-RENDER';
const APP_TOKEN = 'synthetic_application_' + IDS.application.replaceAll('-', '') + '_generation_1';
const BASIC = 'basic_and_bearer_v1';
const clone = value => JSON.parse(JSON.stringify(value));
// Closed wire descriptor is independent of all production UI helpers.
const capability = (allowed = CHAINS) => ({schema: 'catchplate.operatorAlchemyRpcRead/v1',
  connection_type: 'alchemy_key_v1', create_credential_path: CREATE, create_rule_path: GRANT,
  chains: CHAINS.map(chain => ({chain, api_origin: api(chain), destination_allowed: allowed.includes(chain)})),
  operation_bundles: [BUNDLE], rpc_methods: [...RPC], sdk_auth_token: DUMMY,
  placeholder: 'Bearer ' + DUMMY, response_mode: 'alchemy_rpc_read_json_v1', source_pair_required: true});
const alchemyCredential = (changes = {}) => credential({name: 'Saved Alchemy key', version: 1,
  credential_generation: 1, connection_type: 'alchemy_key_v1', provider_id: 'alchemy', ...changes});
const alchemyRule = (chain = CHAINS[0], changes = {}) => rule({name: 'Read chain status · ' + chain, version: 1,
  operation_bundle: BUNDLE, chain, upstream_url: api(chain) + '/v2', methods: ['POST'],
  request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: ['accept', 'accept-language', 'alchemy-ethers-sdk-method', 'alchemy-ethers-sdk-version', 'sec-fetch-mode', 'user-agent'],
  response_mode: 'alchemy_rpc_read_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer ' + DUMMY, ...changes});
const options = changes => ({credentials: [alchemyCredential()], applications: [application({proxy_authentication: BASIC})],
  rules: [], allowedUpstreams: CHAINS.map(api), requestBodyModes: ['preserve_json_v1'],
  responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'], ...changes});
function catalog(state) {
  const value = publicCatalog(state);
  value.capabilities.application_proxy_authentication = {schema: 'catchplate.operatorProxyAuthentication/v1',
    modes: ['bearer', BASIC], path: '/api/operator-demo/applications/proxy-authentication'};
  if (state.alchemyCapability !== undefined)
    value.capabilities.alchemy = state.loaded === state.active ? clone(state.alchemyCapability) : null;
  return state.alchemyTransform ? state.alchemyTransform(value) : value;
}
function cas(state, body) {
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
}
function admitCredential(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
  cas(state, body); assert.equal(body.name, 'My Alchemy key'); assert.equal(body.secret, PRIVATE);
  const allowed = state.alchemyCapability.chains.filter(item => item.destination_allowed).map(item => item.chain);
  assert.deepEqual(catalog(state).capabilities.alchemy, capability(allowed)); assert.equal(state.credentials.length, 0);
}
function createCredential(state, body, config) {
  state.credentials.push(alchemyCredential({name: body.name, ...(config.credentialChange || {})})); state.revision++;
  return {credential: catalog(state).credentials[0], revision: state.revision, policy: catalog(state).policy};
}
function createApplication(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'proxy_authentication', 'token_lifetime_seconds']);
  cas(state, body); assert.equal(body.name, 'Chain status client'); assert.equal(body.proxy_authentication, BASIC);
  assert.equal(body.token_lifetime_seconds, 3600); assert.equal(state.applications.length, 0);
  state.applications.push(application({name: body.name, version: 1, proxy_authentication: BASIC,
    token_expires_at_epoch_ms: NOW + 3600000})); state.revision++;
  return {application: catalog(state).applications[0], revision: state.revision, policy: catalog(state).policy, client_token: APP_TOKEN};
}
function admitRule(state, body, config) {
  assert.deepEqual(Object.keys(body).sort(), ['application_id', 'chain', 'credential_id', 'expected_policy_hash',
    'expected_revision', 'name', 'operation_bundle']);
  cas(state, body); assert.equal(body.chain, config.chain || CHAINS[0]); assert(CHAINS.includes(body.chain));
  const allowed = state.alchemyCapability.chains.filter(item => item.destination_allowed).map(item => item.chain);
  assert.deepEqual(catalog(state).capabilities.alchemy, capability(allowed));
  assert(allowed.includes(body.chain) && state.allowedUpstreams.includes(api(body.chain)));
  assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
  assert.equal(body.operation_bundle, BUNDLE); assert.equal(body.name, 'Read chain status · ' + body.chain);
  assert(state.credentials.some(item => item.id === body.credential_id && item.status === 'active' &&
    item.connection_type === 'alchemy_key_v1' && item.provider_id === 'alchemy'));
  assert(state.applications.some(item => item.id === body.application_id && item.status === 'active'));
  assert.equal(state.rules.length, 0);
}
function createRule(state, body, config) {
  state.rules.push(alchemyRule(body.chain, {name: body.name, ...(config.ruleChange || {})})); state.revision++;
  state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
  return {access_rule: catalog(state).access_rules[0], revision: state.revision, policy: catalog(state).policy};
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => ({url: location.href, html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].filter(node => node.id !== 'client-token').map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const value of [PRIVATE, PRIVATE_ERROR, APP_TOKEN])
    assert(!JSON.stringify(surfaces).includes(value), 'private material escaped its write-only/one-time field');
  assert.deepEqual(surfaces.local, []); assert.deepEqual(surfaces.session, []);
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.alchemyCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
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
        for (const value of [PRIVATE, APP_TOKEN]) assert(!request.url().includes(value));
        observed.requests.push({path: url.pathname, method: request.method()});
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++;
          const result = catalog(state); observed.catalogs.push({revision: result.revision, policy: clone(result.policy),
            alchemy: Object.hasOwn(result.capabilities, 'alchemy') ? clone(result.capabilities.alchemy) : undefined,
            ruleIds: result.access_rules.map(item => item.id)});
          await answer(route, result); return;
        }
        assert.equal(request.method(), 'POST');
        const limit = {[CREATE]: 16384, [APP]: 2048, [GRANT]: 4096}[url.pathname];
        assert(limit && bytes?.length && bytes.length <= limit); assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString()); let result;
        if (url.pathname === CREATE) {
          assert.equal(observed.credentials.length, 0, 'no automatic key replay'); admitCredential(state, body);
          observed.credentials.push({name: body.name, secretMatched: true, expected_revision: body.expected_revision});
          body.secret = ''; signal(); await held;
          if (config.credentialFault) { state.expectedFailures.add(CREATE); await answer(route, {detail: PRIVATE_ERROR}, 503); return; }
          result = createCredential(state, body, config);
        } else if (url.pathname === APP) {
          assert.equal(observed.applications.length, 0, 'no automatic application replay');
          observed.applications.push(clone(body)); result = createApplication(state, body);
        } else {
          assert.equal(url.pathname, GRANT); assert.equal(observed.grants.length, 0, 'no automatic grant replay');
          admitRule(state, body, config); observed.grants.push(clone(body));
          if (['409', '503'].includes(config.grantFault)) {
            state.expectedFailures.add(GRANT); await answer(route, {detail: PRIVATE_ERROR}, Number(config.grantFault)); return;
          }
          result = createRule(state, body, config);
          if (config.grantFault === 'lost-after-commit') { state.expectedFailures.add(GRANT); await route.abort('failed'); return; }
        }
        await answer(route, result, 201);
      } catch (_) { signal(); state.errors.push('Alchemy fixture closed DTO/CAS boundary failed'); await route.abort(); }
    };
    // Inherited deny-all HTTP/WebSocket routes and blocked service workers stay
    // in force. No route continues/fetches a request to any actual destination.
    for (const path of ['/api/operator-demo/catalog', CREATE, APP, GRANT]) await controls.context.route(ORIGIN + path, handler);
    try {
      await page.reload({waitUntil: 'networkidle'}); assert.equal(new URL(page.url()).origin, ORIGIN);
      await exercise(page, state, observed, {credentialArrived, releaseCredential: () => release?.()});
      assert.deepEqual(state.posts, [], 'no generic grant, provider call, token rotation or unrelated mutation');
      assert(observed.credentials.length <= 1 && observed.applications.length <= 1 && observed.grants.length <= 1);
      await privateAbsent(page);
    } finally { release?.(); }
  });
}
module.exports = {fixture, capability, alchemyCredential, alchemyRule, clone, privateAbsent,
  ORIGIN, CREATE, GRANT, BUNDLE, CHAINS, RPC, api, DUMMY, PRIVATE, APP_TOKEN, IDS};
