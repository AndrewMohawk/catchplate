'use strict';
// Inert request projection controls: importing the driver launches nothing.
const assert = require('node:assert/strict');
const {requestFrame, failureReceipt, copiedRecipeFrame} = require('./check_operator_gmail_sdk_browser.cjs');
const origin = 'https://serverware-demo.example.com';
const raw = Buffer.from('{ "exact": "bytes" }');
const request = (url, method = 'GET', body = null, headers = {}) => ({
  url: () => url, method: () => method, postDataBuffer: () => body, headers: () => headers});
assert.deepEqual(requestFrame(request(origin + '/'), 1), {
  type: 'request', id: 1, method: 'GET', path: '/', headers: {}, body: ''});
const actual = requestFrame(request(origin + '/api/operator-demo/access-rules/gmail-read', 'POST', raw,
  {origin, 'content-type': 'application/json', 'user-agent': 'synthetic-browser'}), 2);
assert.deepEqual(Buffer.from(actual.body, 'base64'), raw);
assert.deepEqual(actual.headers, {origin, 'content-type': 'application/json'});
assert.equal(requestFrame(request(origin + '/api/operator-demo/oauth/google/intents'), 3).path,
  '/api/operator-demo/oauth/google/intents');
for (const value of [request('https://gmail.googleapis.com/'), request(origin + '/api/operator-demo/catalog?x=1'),
  request(origin + '/api/operator-demo/oauth/google/intents?x=1'),
  request(origin + '/api/operator-demo/oauth/google/intents', 'POST', raw),
  request(origin + '/api/operator-demo/oauth/google/start', 'POST', raw),
  request(origin + '/api/operator-demo/applications', 'POST', raw), request(origin + '/', 'POST', raw),
  request(origin + '/', 'GET', raw), request(origin + '/', 'GET', null, {authorization: 'canary'}),
  request(origin + '/', 'GET', null, {'x-serverware-admin-token': 'canary'}),
  request(origin + '/', 'GET', null, {cookie: 'canary'}), request(origin + '/', 'GET', null, {'proxy-authorization': 'canary'}),
  request(origin + '/api/operator-demo/access-rules/gmail-read', 'POST', Buffer.alloc(4097))]) {
  assert.throws(() => requestFrame(value, 1));
}
const counters = {postCount: 0, getCount: 2, pageErrors: 0, consoleErrors: 0, refusedRequests: 1};
assert.deepEqual(failureReceipt('await_observer', 'request_refused', counters), {
  schema: 'serverware.privateGmailBrowserFailure/v1', stage: 'await_observer', code: 'request_refused', ...counters});
const safe = failureReceipt('secret-canary', 'secret-canary', {...counters, postCount: 'secret-canary', raw: 'secret-canary'});
assert.equal(safe.stage, 'inputs'); assert.equal(safe.code, 'workflow'); assert.equal(safe.postCount, null);
assert(!JSON.stringify(safe).includes('secret-canary'));
const recipe = '# public synthetic recipe\nexport VALUE=\'exact bytes\'\n';
assert.deepEqual(copiedRecipeFrame(recipe, recipe, 7), {
  type: 'done', id: 7, copiedRecipe: Buffer.from(recipe).toString('base64')});
for (const [copied, displayed, id] of [[recipe, recipe + '\n', 7], ['', '', 7],
  ['x'.repeat(8193), 'x'.repeat(8193), 7], ['é'.repeat(4097), 'é'.repeat(4097), 7],
  ['\ud800', '\ud800', 7], ['x\0y', 'x\0y', 7], [recipe, recipe, 0], [recipe, recipe, 17],
  [recipe, recipe, true], [Buffer.from(recipe), recipe, 7]]) {
  assert.throws(() => copiedRecipeFrame(copied, displayed, id));
}
assert.equal(failureReceipt('copy_recipe', 'workflow', counters).stage, 'copy_recipe');
console.log('Gmail browser bridge inert request/diagnostic/copy-frame controls passed (30 cases; no browser or network)');
