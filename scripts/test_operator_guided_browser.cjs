'use strict';
// Inert protocol/secret-handling tests only. Importing the real driver launches
// no browser, Docker process, socket, DNS, provider, or application request.
const assert = require('node:assert/strict');
const {Readable} = require('node:stream');
const groups = [];
const test = (name, run) => groups.push({name, run});
const {readyFrame, requestFrame, responseFrame, continueFrame, failureReceipt, downloadedBytes, validateChecker} =
  require('./check_operator_guided_browser.cjs');
const origin = 'https://serverware-guided.example.com', prefix = '/api/operator-demo';
const digest = 'sha256:' + 'a'.repeat(64), runId = 'operator-check-' + 'b'.repeat(32);
const ids = {credential: '11111111-1111-4111-8111-111111111111', application: '22222222-2222-4222-8222-222222222222',
  rule: '33333333-3333-4333-8333-333333333333'};
const steps = ['credential', 'application', 'permission', 'download', 'proxy_success', 'rule_revoked', 'proxy_denied', 'application_revoked', 'credential_revoked'];
const routes = ['credentials', 'applications', 'access-rules', 'access-rules/revoke', 'applications/revoke', 'credentials/revoke'].map(p => prefix + '/' + p);
const clone = value => JSON.parse(JSON.stringify(value));
const ready = () => ({kind: 'ready', schema: 'serverware.privateGuidedBrowser/v1', origin,
  proxyUrl: 'https://serverware-gmail-proxy.example.com', upstreamUrl: 'https://demo-upstream:8443/echo',
  names: {credential: runId + '-key', application: runId + '-app', rule: runId + '-rule'},
  providerSecret: 'synthetic-private-fixture-only', tokenTtlSeconds: 3600, placeholder: 'Bearer SERVERWARE_DUMMY',
  caPath: '/client-trust/inner-ca.pem', initialRevision: 1, initialPolicyHash: digest, timeoutSeconds: 180});
const request = (url, method = 'GET', body = null, headers = {}) => ({url: () => url, method: () => method,
  postDataBuffer: () => body, headers: () => headers});
const headers = {origin, 'content-type': 'application/json'};
const browser = () => ({postCount: 6, getCount: 12, pageErrors: 0, consoleErrors: 0, refusedRequests: 0,
  downloadCount: 1, downloadDeleted: true, tokenCleared: true, steps: [...steps]});
function result() {
  const eventCounts = Object.fromEntries(['credential', 'application', 'access_rule'].flatMap(kind =>
    ['created', 'revoked'].map(action => ['operator_catalog.' + kind + '.' + action, 1])));
  Object.assign(eventCounts, {'data_plane.credential.release_started': 1, 'data_plane.response.released': 1,
    'data_plane.connect.established': 1, 'data_plane.connect.denied': 1, 'data_plane.policy.reloaded': 2,
    'data_plane.credential_lease.issued': 2});
  return {schema: 'serverware.privateGuidedCheck/v1', ok: true, syntheticOnly: true, realProviderVerified: false,
    publicDnsVerified: false, externalSsoVerified: false, productionReady: false, hardwareVerified: false,
    runId, dataPlaneBinaryDigest: digest, resourceIds: {...ids}, initialRevision: 1, finalRevision: 7,
    initialPolicyHash: digest, policyHash: digest, providerArrivals: 1, proxyAttempts: 2,
    mutations: routes.map((route, i) => ({route, status: i < 3 ? 201 : 200, revision: i + 2,
      resourceId: ids[['credential', 'application', 'rule', 'rule', 'application', 'credential'][i]], policyHash: digest})),
    positive: {case: 'positive', status: 200, responseMode: 'unfiltered_json_or_empty_v2', responseBodySha256: digest,
      responseBodyBytes: 200, requestDigest: digest, operationDigest: digest},
    negative: {outcome: 'denied', connectStatus: 403, providerArrivals: 0},
    audit: {eventCounts, eventIds: Array.from({length: 14}, (_, i) => 'sha256:' + i.toString(16).padStart(64, '0')),
      attemptIds: [digest], chainVerified: true}, browser: browser()};
}
test('ready pins exact isolated origins, one run namespace, and original lifetime', () => {
  assert.deepEqual(readyFrame(ready()), ready());
  for (const change of [v => v.origin = 'https://serverware.example.com', v => v.proxyUrl += ':8443',
    v => v.timeoutSeconds = 181, v => v.tokenTtlSeconds = 7200, v => v.initialRevision = true,
    v => v.names.application += '-other', v => v.names.rule = 'other', v => v.providerSecret = 'x\nprivate',
    v => v.providerSecret = 'x'.repeat(257), v => v.extra = 'private']) {
    const value = ready(); change(value); assert.throws(() => readyFrame(value));
  }
});
test('requests preserve original bytes and forward only the closed nonsecret headers', () => {
  const body = Buffer.from('{ "fixture": "synthetic" }');
  for (const route of routes) {
    const frame = requestFrame(request(origin + route, 'POST', body, {...headers, accept: '*/*',
      referer: origin + '/', 'user-agent': 'browser'}), 1, route);
    assert.deepEqual(frame, {kind: 'request', id: 1, method: 'POST', path: route, headers: {...headers, accept: '*/*'}, body: body.toString('base64')});
  }
  assert.equal(requestFrame(request(origin + '/'), 2, null).body, '');
  assert.equal(requestFrame(request(origin + prefix + '/catalog'), 3, null).path, prefix + '/catalog');
});
test('unreviewed endpoints, retries, framing and private browser headers fail closed', () => {
  const body = Buffer.from('{}'), route = routes[0];
  assert.throws(() => requestFrame(request(origin + route, 'POST', body, headers), 1, null));
  for (const item of [request(origin + '/api/health'),
    request(origin + prefix + '/catalog?cursor=x'), request(origin + '/#hash'), request('https://external.example.com/'),
    request(origin + '/', 'GET', body), request(origin + '/', 'HEAD'), request(origin + routes[1], 'POST', body, headers),
    request(origin + route, 'POST', Buffer.alloc(8193), headers), request(origin + route, 'POST', body, {...headers, origin: 'https://other.example.com'}),
    request(origin + route, 'POST', body, {...headers, 'content-type': 'text/plain'})]) {
    assert.throws(() => requestFrame(item, 1, route));
  }
  for (const key of ['authorization', 'Authorization', 'proxy-authorization', 'cookie', 'x-serverware-admin-token', 'content-encoding', 'transfer-encoding'])
    assert.throws(() => requestFrame(request(origin + route, 'POST', body, {...headers, [key]: 'private'}), 1, route));
  for (const id of [true, 0, -1, 101, 1.5, '1']) assert.throws(() => requestFrame(request(origin + '/'), id, null));
});
test('response admits bounded original bytes and rejects redirect/cookie/encoding metadata', () => {
  const value = {kind: 'response', id: 2, status: 201, headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']], body: Buffer.from('{}').toString('base64')};
  assert.deepEqual(responseFrame(value, 2, 201), Buffer.from('{}'));
  for (const change of [v => v.id++, v => v.status = 200, v => v.body = 'e30', v => v.body = '', v => v.extra = 'private',
    v => v.headers.push(['content-type', 'application/json']), v => v.headers.push(['Set-Cookie', 'private']),
    v => v.headers.push(['Location', 'https://other.example.com']), v => v.headers.push(['Content-Encoding', 'gzip']),
    v => v.headers.push(['Transfer-Encoding', 'chunked']), v => v.headers.push(['X-Test', 'private\r\nvalue'])]) {
    const changed = clone(value); change(changed); assert.throws(() => responseFrame(changed, 2, 201));
  }
});
test('checkpoints bind checker continuation to the exact phase, frame, and created IDs', () => {
  const value = {kind: 'continue', id: 8, phase: 'revoke_rule', resourceIds: {...ids}};
  assert.equal(continueFrame(value, 8, 'revoke_rule', ids), value);
  for (const change of [v => v.id++, v => v.phase = 'revoke_rest', v => v.resourceIds.rule = ids.application,
    v => v.resourceIds.extra = ids.credential, v => v.extra = 'private']) {
    const changed = clone(value); change(changed); assert.throws(() => continueFrame(changed, 8, 'revoke_rule', ids));
  }
});
test('actual download stream bytes are copied and temporary download is deleted without saveAs', async () => {
  const chunks = [Buffer.from('{"private":'), Buffer.from('"synthetic"}')]; let deleted = 0;
  const download = {suggestedFilename: () => 'serverware-client.private.json',
    createReadStream: async () => Readable.from(chunks), delete: async () => { deleted++; }};
  const bytes = await downloadedBytes(download);
  assert.equal(bytes.toString(), '{"private":"synthetic"}'); assert.equal(deleted, 1);
  assert(chunks.every(chunk => chunk.every(byte => byte === 0))); bytes.fill(0);
});
test('download errors, oversize and wrong name still delete temporary private artifact', async () => {
  for (const failure of ['size', 'name', 'stream', 'empty']) {
    let deleted = 0;
    const value = {suggestedFilename: () => failure === 'name' ? 'private-other.json' : 'serverware-client.private.json',
      createReadStream: async () => { if (failure === 'stream') throw new Error('private');
        return Readable.from(failure === 'empty' ? [] : [Buffer.alloc(16385)]); }, delete: async () => { deleted++; }};
    await assert.rejects(downloadedBytes(value)); assert.equal(deleted, 1);
  }
});
test('closed failure receipt never retains source errors or secret-bearing arbitrary fields', () => {
  const value = failureReceipt('private-canary', {postCount: 2, getCount: 'private-canary', pageErrors: 0,
    consoleErrors: 0, refusedRequests: 0, downloadCount: 1, error: 'private-canary'});
  assert.equal(value.stage, 'inputs'); assert.equal(value.getCount, null); assert(!JSON.stringify(value).includes('private-canary'));
});
test('terminal admits only exact public evidence and preserves no real-provider claim', () => {
  const value = result(); assert.equal(validateChecker(value, browser(), ids), value);
  value.browser = Object.fromEntries(Object.entries(value.browser).reverse());
  assert.equal(validateChecker(value, browser(), ids), value);
  for (const change of [v => v.realProviderVerified = true, v => v.finalRevision = 8, v => v.providerArrivals = 2,
    v => v.mutations[0].route = routes[1], v => v.mutations[1].resourceId = ids.credential, v => v.browser.downloadDeleted = false,
    v => v.positive.private = 'private-canary', v => v.audit.private = 'private-canary', v => v.audit.eventCounts.other = 1,
    v => v.audit.eventIds[0] = 'private-canary', v => v.audit.attemptIds = [], v => v.audit.chainVerified = false]) {
    const changed = result(); change(changed); assert.throws(() => validateChecker(changed, browser(), ids));
  }
});

async function main() {
  assert.equal(groups.length, 9);
  for (const {name, run} of groups) {
    await run();
    process.stdout.write('PASS ' + name + '\n');
  }
  process.stdout.write(JSON.stringify({ok: true, groups: groups.length, browser: false, network: false,
    providerRequests: 0, scope: 'pure guided browser protocol and private download controls'}) + '\n');
}
if (require.main === module) main().catch(() => {
  process.stderr.write('Guided browser protocol controls failed.\n');
  process.exitCode = 1;
});
