#!/usr/bin/env node
'use strict';
// Actual portal JS in an inert browser model. Fetch, DOM, timers, WindowProxy,
// OIDC status and public proof strings are synthetic; no browser, native TLS,
// signature verification, receipt persistence, disclosure or hardware proof.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const sourcePath = resolve(__dirname, '../catchplate/portal_native_jit_review.py');
const source = readFileSync(sourcePath, 'utf8');
const scripts = [...source.matchAll(/^NATIVE_JIT_REVIEW_SCRIPT = r"""\n([\s\S]*?)\n"""/gm)];
assert.equal(scripts.length, 1, 'one actual literal script, not a copied controller');
const actual = scripts[0][1];
const wireSource = readFileSync(resolve(__dirname, '../catchplate/authority_native_jit_review_open_contract.py'), 'utf8');
function wireKiB(name) {
  const matches = [...wireSource.matchAll(new RegExp('^' + name + ' = (\\d+) \\* 1024$', 'gm'))];
  assert.equal(matches.length, 1, 'one exact shared wire size literal');
  return Number(matches[0][1]) * 1024;
}
assert.match(wireSource, /^MAX_HTTP_REQUEST = 2 \* \(2 \* MAX_NATIVE_ORIGINAL \+ MAX_AUTHORITY_ORIGINAL\) \+ 1024$/m);
const MAX_REQUEST = 2 * (2 * wireKiB('MAX_NATIVE_ORIGINAL') + wireKiB('MAX_AUTHORITY_ORIGINAL')) + 1024;
const ID = '11111111-1111-4111-8111-111111111111';
const REVIEW = '33333333-3333-4333-8333-333333333333';
const PORTAL = 'https://portal.example.test', NATIVE = 'https://native.example.test';
const PATH = '/approvals/review/native', API = '/api/approvals/review/native/';
const MARKER = 'catchplate.nativeJitReviewUncertain.' + ID;
const NOW = Date.parse('2030-01-01T00:00:00Z');
const PRIVATE = 'private-review-cookie-recipient-key-canary';
const clone = value => JSON.parse(JSON.stringify(value));
const type = phase => 'catchplate.native-jit-review.' + phase;
function nativeOriginal(kind, value) {
  return JSON.stringify({statement: {schema: 'catchplate.nativeJitReviewOpening' + kind + '/v1', ...value},
    signature: 'synthetic-unverified-signature', nativeKeyEvidence: {synthetic: true}, assignmentOriginal: '{}'});
}
function authorityOriginal(kind, value) {
  return JSON.stringify({schema: 'catchplate.signedNativeJitReviewOpening' + kind + '/v1',
    payload: {schema: 'catchplate.nativeJitReviewOpening' + kind + '/v1', ...value},
    signatureBase64Url: 'synthetic-unverified-signature'});
}
function originals() {
  const scope = {reviewId: REVIEW, approvalRequestId: ID, reviewerId: 'oidc:fixture',
    browserNonceCommitment: 'sha256:' + 'a'.repeat(64), recipientPublicKey: 'synthetic-public-key'};
  const challenge = nativeOriginal('Challenge', {...scope, nativeOrigin: NATIVE, portalOrigin: PORTAL,
    expiresAtEpochNs: (NOW + 25000) * 1e6});
  const authorization = authorityOriginal('Authorization', {scope, expiresAtEpochNs: (NOW + 23000) * 1e6});
  const preparation = nativeOriginal('Preparation', {scope, reviewDigest: 'sha256:' + 'b'.repeat(64),
    expiresAtEpochNs: (NOW + 21000) * 1e6});
  const acknowledgment = authorityOriginal('CommitAcknowledgment', {scope, reviewDigest: 'sha256:' + 'b'.repeat(64),
    expiresAtEpochNs: (NOW + 19000) * 1e6});
  return {challenge, authorization, preparation, acknowledgment,
    grant: {authorizationOriginal: authorization, parentOriginal: '{"public":"parent"}',
      childOriginal: '{"public":"child"}', pairOriginal: '{"ciphertext":"synthetic"}',
      evidenceOriginal: '{"public":"unverified-evidence"}'}};
}
function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
function fixture(options = {}) {
  const values = originals(), events = [], requests = [], messages = [], listeners = new Map(), timers = new Map();
  const storage = options.storage || new Map();
  const control = {wall: NOW, mono: 1000, ...options};
  const button = {disabled: false, listeners: new Map(), addEventListener(name, fn) {this.listeners.set(name, fn);},
    removeEventListener(name, fn) {if (this.listeners.get(name) === fn) this.listeners.delete(name);}};
  const status = {textContent: ''};
  const location = new URL(PORTAL + PATH + (options.query || '') + (options.hash ?? '#approval=' + ID));
  const popup = {closed: false, postMessage(value, origin) {
    messages.push({value: clone(value), origin}); events.push('post:' + value.type);
  }, location: {replace(url) {events.push('navigate:' + url); assert.equal(url, NATIVE + '/reviews/jit');}}};
  const identity = {authenticated: true, userId: 'oidc:fixture', roles: ['approver'], authMethod: 'oidc-session',
    sessionState: 'active', webauthnRequired: false, oidcBrowserLoginConfigured: true, sessionActivationMode: 'protected'};
  const document = {getElementById(id) {
    assert.ok(['native-review-open', 'native-review-status'].includes(id));
    return id === 'native-review-open' ? button : status;
  }};
  Object.defineProperty(document, 'cookie', {get() {throw Error('portal attempted to read cookie');}});
  const window = {location, history: {replaceState(_state, _title, url) {
    events.push('fragment-cleared'); assert.equal(url, PATH); location.href = PORTAL + url;
  }}, open(url, target) {events.push('popup-open'); assert.equal(url, 'about:blank'); assert.equal(target, '_blank');
    return control.popupBlocked ? null : popup;
  }, addEventListener(name, fn) {assert.equal(name, 'message'); listeners.set(name, fn);},
  removeEventListener(name, fn) {if (listeners.get(name) === fn) listeners.delete(name);}};
  const context = {window, document, URL, TextEncoder, TextDecoder, AbortController, Uint8Array,
    Date: class extends Date {static now() {return control.wall;}}, performance: {now: () => control.mono},
    sessionStorage: {getItem(key) {if (control.storageReadFailure) throw Error('storage unavailable'); return storage.get(key) ?? null;},
      setItem(key, value) {events.push('marker'); if (control.storageWriteFailure) throw Error('storage unavailable'); storage.set(key, value);},
      removeItem(key) {storage.delete(key);}},
    localStorage: {getItem() {throw Error('unexpected private persistence');}, setItem() {throw Error('unexpected private persistence');}},
    setTimeout(fn, delay) {assert.equal(delay, 30000); const id = timers.size + 1; timers.set(id, fn); return id;},
    clearTimeout(id) {timers.delete(id);}, setInterval() {throw Error('automatic polling/retry forbidden');},
    fetch: async (url, init) => {
      requests.push({url, init}); events.push('fetch:' + url);
      assert.equal(init.credentials, 'same-origin'); assert.equal(init.mode, 'same-origin');
      assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
      assert.ok(init.signal instanceof AbortSignal);
      assert.ok(!init.headers?.Authorization && !init.headers?.Cookie);
      if (control.fetch) {
        const selected = await control.fetch(url, init, requests);
        if (selected !== undefined) return selected;
      }
      if (url === '/api/auth/status') return response(control.identity || identity);
      if (url === '/api/csrf') return response({ok: true, token: 'synthetic-csrf', cookie: 'catchplate_csrf', header: 'X-Catchplate-CSRF-Token'});
      assert.equal(init.method, 'POST'); assert.equal(init.headers['Content-Type'], 'application/json');
      assert.equal(init.headers['X-Catchplate-CSRF-Token'], 'synthetic-csrf');
      if (url === API + 'authorize') return response(values.grant);
      if (url === API + 'receipt') return response({acknowledgmentOriginal: values.acknowledgment});
      throw Error('unexpected route: ' + url);
    }};
  vm.createContext(context); vm.runInContext(actual, context, {timeout: 1000, filename: sourcePath});
  const controller = context.createNativeReviewController({nativeOrigin: options.nativeOrigin || NATIVE,
    maximumRequestBytes: Object.hasOwn(options, 'maximumRequestBytes') ? options.maximumRequestBytes : MAX_REQUEST});
  async function message(phase, extra = {}, override = {}) {
    const callback = listeners.get('message');
    if (callback) await callback({origin: NATIVE, source: popup, data: {type: type(phase), ...extra}, ...override});
  }
  async function start() {
    assert.equal(events[0], 'fragment-cleared');
    const handler = button.listeners.get('click'); assert.equal(typeof handler, 'function'); await handler();
  }
  async function authorize() {
    await start(); await message('ready'); await message('challenge', {challengeOriginal: values.challenge});
  }
  const posts = () => requests.filter(row => row.init.method === 'POST');
  const advance = milliseconds => {control.wall += milliseconds; control.mono += milliseconds;};
  return {values, events, requests, messages, storage, control, button, status, popup, location,
    controller, message, start, authorize, posts, advance, timers, identity};
}

const groups = [];
function group(name, test) {groups.push({name, test});}

group('initialization clears exact UUID fragment and performs no automatic opening', async () => {
  const f = fixture(); assert.deepEqual(f.events, ['fragment-cleared']);
  assert.equal(f.requests.length, 0); assert.equal(f.messages.length, 0); assert.equal(f.storage.size, 0);
  await f.start(); assert.deepEqual(f.events.slice(0, 3), ['fragment-cleared', 'popup-open', 'fetch:/api/auth/status']);
  assert.equal(f.events.at(-1), 'navigate:' + NATIVE + '/reviews/jit');
  assert.equal(f.posts().length, 0);
  await f.start(); assert.equal(f.events.filter(e => e === 'popup-open').length, 1);
});

group('invalid query/fragment and preexisting uncertainty never open or fetch', async () => {
  for (const options of [{query: '?native=1'}, {hash: '#approval=invalid'}, {hash: '#approval=' + ID + '&other=1'},
    {storage: new Map([[MARKER, ID]])}, {storage: new Map([['catchplate.approvalDecisionUncertain.' + ID, ID]])},
    {storageReadFailure: true}]) {
    const f = fixture(options); await f.start(); assert.equal(f.requests.length, 0);
    assert.ok(f.button.disabled); assert.ok(!f.events.includes('popup-open'));
  }
});

group('legacy uncertainty presence blocks direct review without clearing or retrying', async () => {
  for (const prefix of ['serverware.nativeJitReviewUncertain.', 'serverware.approvalDecisionUncertain.']) {
    for (const value of [ID, '', 'unrecognized historical marker']) {
      const original = [[prefix + ID, value]];
      const f = fixture({storage: new Map(original)});
      await f.start(); await f.start();
      assert.ok(f.button.disabled);
      assert.equal(f.requests.length, 0); assert.equal(f.messages.length, 0);
      assert.ok(!f.events.includes('popup-open'));
      assert.deepEqual([...f.storage], original);
    }
    const original = [[prefix + REVIEW, ID]];
    const f = fixture({storage: new Map(original)});
    await f.start();
    assert.ok(f.events.includes('popup-open'));
    assert.deepEqual([...f.storage], original);
  }
});

group('native target must be separate exact HTTPS origin with a valid source-bound request limit', () => {
  for (const nativeOrigin of [PORTAL, 'http://native.example.test', NATIVE + '/path', NATIVE + '?q=1',
    'https://user:pass@native.example.test', NATIVE + '#fragment']) assert.throws(() => fixture({nativeOrigin}));
  for (const maximumRequestBytes of [undefined, null, 0, -1, 1.5, Infinity, String(MAX_REQUEST)]) {
    assert.throws(() => fixture({maximumRequestBytes}));
  }
});

group('every relay accepts only the original WindowProxy and exact native origin', async () => {
  const f = fixture(); await f.start();
  for (const phase of ['ready', 'challenge', 'prepared', 'disclosed']) {
    await f.message(phase, {privateReview: PRIVATE}, {origin: 'https://hostile.example.test'});
    await f.message(phase, {privateReview: PRIVATE}, {source: {}});
  }
  assert.equal(f.messages.length, 0); assert.equal(f.posts().length, 0); assert.equal(f.storage.size, 0);
  await f.message('ready'); assert.equal(f.messages.length, 1);
  assert.deepEqual(f.messages[0], {origin: NATIVE, value: {type: type('start'), approvalRequestId: ID}});
  assert.equal(f.storage.get(MARKER), ID);
  assert.ok(f.events.indexOf('marker') < f.events.indexOf('post:' + type('start')));
});

group('actual authorize and receipt forward literal originals through exact public renamings', async () => {
  const f = fixture();
  // Large signed integers must stay in the original string, never be rebuilt.
  f.values.challenge = f.values.challenge.replace(/"expiresAtEpochNs":(\d+)/,
    (_match, value) => '"expiresAtEpochNs":' + String(BigInt(value) + 1n));
  await f.authorize();
  assert.deepEqual(JSON.parse(f.posts()[0].init.body), {challengeOriginal: f.values.challenge});
  assert.deepEqual(f.messages[1], {origin: NATIVE, value: {type: type('authorized'),
    authorizationOriginal: f.values.authorization, parentOriginal: f.values.grant.parentOriginal,
    childOriginal: f.values.grant.childOriginal, pairOriginal: f.values.grant.pairOriginal,
    proofOriginal: f.values.grant.evidenceOriginal}});
  await f.message('prepared', {preparationOriginal: f.values.preparation});
  assert.deepEqual(JSON.parse(f.posts()[1].init.body), {challengeOriginal: f.values.challenge,
    authorizationOriginal: f.values.authorization, preparationOriginal: f.values.preparation});
  assert.deepEqual(f.messages[2], {origin: NATIVE, value: {type: type('committed'), commitAckOriginal: f.values.acknowledgment}});
  assert.equal(f.storage.get(MARKER), ID);
  await f.message('disclosed', {reviewId: REVIEW});
  assert.equal(f.storage.has(MARKER), false); assert.equal(f.posts().length, 2); assert.equal(f.timers.size, 0);
  assert.match(f.status.textContent, /No approval or denial was submitted/);
  assert.ok(!JSON.stringify(f.messages).includes(PRIVATE));
  await f.start(); assert.equal(f.posts().length, 2);
});

group('authorization or receipt uncertainty holds UUID across reload and never resends', async () => {
  for (const failed of ['authorize', 'receipt']) {
    const f = fixture({fetch: async url => {if (url === API + failed) throw Error(PRIVATE);}});
    await f.authorize();
    if (failed === 'receipt') await f.message('prepared', {preparationOriginal: f.values.preparation});
    const count = f.posts().length;
    await f.start(); await f.message('challenge', {challengeOriginal: f.values.challenge});
    await f.message('prepared', {preparationOriginal: f.values.preparation});
    assert.equal(f.posts().length, count); assert.equal(f.storage.get(MARKER), ID);
    assert.deepEqual([...f.storage.entries()], [[MARKER, ID]]);
    assert.doesNotMatch(f.status.textContent, new RegExp(PRIVATE));
    const reload = fixture({storage: f.storage}); await reload.start(); assert.equal(reload.requests.length, 0);
  }
});

group('blocked popup and failed marker persistence cannot begin native challenge', async () => {
  const blocked = fixture({popupBlocked: true}); await blocked.start(); assert.equal(blocked.requests.length, 0);
  const f = fixture({storageWriteFailure: true}); await f.start(); await f.message('ready');
  assert.equal(f.messages.length, 0); assert.equal(f.posts().length, 0); assert.ok(f.button.disabled);
});

group('bearer/admin status or changing OIDC identity refuses before next POST', async () => {
  for (const delta of [{authMethod: 'admin-token'}, {authMethod: 'oidc-bearer'}, {authenticated: false},
    {sessionState: 'pending'}, {webauthnRequired: true}, {roles: ['auditor']}]) {
    const f = fixture(); f.control.identity = {...f.identity, ...delta}; await f.start();
    assert.equal(f.posts().length, 0); assert.ok(!f.events.some(e => e.startsWith('navigate:')));
  }
  const f = fixture(); await f.authorize(); f.control.identity = {...f.identity, userId: 'oidc:other'};
  await f.message('prepared', {preparationOriginal: f.values.preparation});
  assert.equal(f.posts().length, 1); assert.equal(f.storage.get(MARKER), ID);
});

group('hostile extra fields and out-of-order messages cannot relay private bytes', async () => {
  for (const value of [{type: type('ready'), privateReview: PRIVATE}, {type: type('disclosed'), reviewId: REVIEW},
    {type: type('challenge'), challengeOriginal: PRIVATE}]) {
    const f = fixture(); await f.start(); await f.message('ignored', {}, {data: value});
    assert.equal(f.posts().length, 0); assert.equal(f.messages.length, 0);
    assert.doesNotMatch(f.status.textContent, new RegExp(PRIVATE));
  }
});

group('wrong approval/native scope or mismatched authorization stops at the proper boundary', async () => {
  for (const field of ['approvalRequestId', 'portalOrigin', 'nativeOrigin']) {
    const f = fixture(); const value = JSON.parse(f.values.challenge); value.statement[field] = 'wrong';
    await f.start(); await f.message('ready'); await f.message('challenge', {challengeOriginal: JSON.stringify(value)});
    assert.equal(f.posts().length, 0); assert.equal(f.messages.length, 1);
  }
  for (const field of ['reviewId', 'approvalRequestId', 'reviewerId', 'browserNonceCommitment', 'recipientPublicKey']) {
    const f = fixture(); const value = JSON.parse(f.values.authorization); value.payload.scope[field] = 'wrong';
    f.values.grant.authorizationOriginal = JSON.stringify(value); await f.authorize();
    assert.equal(f.posts().length, 1); assert.equal(f.messages.length, 1);
  }
});

group('receipt and disclosure cannot clear uncertainty for a different review', async () => {
  const f = fixture(); await f.authorize();
  await f.message('prepared', {preparationOriginal: f.values.preparation});
  await f.message('disclosed', {reviewId: 'other'});
  assert.equal(f.storage.get(MARKER), ID); assert.equal(f.posts().length, 2);
  assert.doesNotMatch(f.status.textContent, /is open in the native window/);
  const g = fixture(); const value = JSON.parse(g.values.acknowledgment); value.payload.reviewDigest = 'wrong';
  g.values.acknowledgment = JSON.stringify(value); await g.authorize();
  await g.message('prepared', {preparationOriginal: g.values.preparation});
  assert.equal(g.messages.length, 2); assert.equal(g.storage.get(MARKER), ID);
});

group('one original deadline spans auth latency and cannot be renewed by challenge', async () => {
  const f = fixture(); f.control.fetch = async url => {if (url === '/api/auth/status') f.advance(29000);};
  await f.start(); await f.message('ready');
  const value = JSON.parse(f.values.challenge); value.statement.expiresAtEpochNs = (NOW + 90000) * 1e6;
  f.advance(2000); await f.message('challenge', {challengeOriginal: JSON.stringify(value)});
  assert.equal(f.posts().length, 0); assert.equal(f.messages.length, 1); assert.equal(f.storage.get(MARKER), ID);
});

group('slow response body is checked against retained deadline with no relay or retry', async () => {
  const f = fixture(); f.control.fetch = async url => {
    if (url !== API + 'authorize') return;
    let emitted = false;
    return {ok: true, headers: new Headers({'Content-Type': 'application/json'}), body: {getReader() {return {
      async read() {if (emitted) return {done: true}; emitted = true; f.advance(26000);
        return {done: false, value: new TextEncoder().encode(JSON.stringify(f.values.grant))};},
      async cancel() {}, releaseLock() {}};}}};
  };
  await f.authorize(); assert.equal(f.posts().length, 1); assert.equal(f.messages.length, 1);
  await f.start(); assert.equal(f.posts().length, 1); assert.equal(f.storage.get(MARKER), ID);
});

group('navigation, popup loss, expiry and disposal reject stale messages', async () => {
  for (const change of [f => {f.location.pathname = '/elsewhere';}, f => {f.popup.closed = true;},
    f => {f.advance(31000);}, f => {f.controller.dispose();}]) {
    const f = fixture(); await f.authorize(); change(f);
    await f.message('prepared', {preparationOriginal: f.values.preparation});
    assert.equal(f.posts().length, 1); assert.equal(f.storage.get(MARKER), ID);
  }
});

group('timer only closes the one attempt and all completed-stage replays fail closed', async () => {
  const f = fixture(); await f.authorize();
  assert.equal(f.timers.size, 1); [...f.timers.values()][0]();
  await f.start(); await f.message('prepared', {preparationOriginal: f.values.preparation});
  assert.equal(f.posts().length, 1); assert.equal(f.storage.get(MARKER), ID);
  const g = fixture(); await g.authorize(); await g.message('challenge', {challengeOriginal: g.values.challenge});
  await g.message('prepared', {preparationOriginal: g.values.preparation});
  assert.equal(g.posts().length, 1); assert.equal(g.storage.get(MARKER), ID);
});

(async () => {
  for (const {name, test} of groups) {await test(); process.stdout.write('PASS ' + name + '\n');}
  process.stdout.write(JSON.stringify({ok: true, groups: groups.length, synthetic: true,
    nativeAdmission: false, providerRequests: false}) + '\n');
})().catch(error => {process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1;});
