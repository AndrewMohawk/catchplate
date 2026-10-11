'use strict';
// Inert request projection controls: importing the driver launches nothing.
const assert = require('node:assert/strict');
const {requestFrame} = require('./check_operator_gmail_sdk_browser.cjs');
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
for (const value of [request('https://gmail.googleapis.com/'), request(origin + '/api/operator-demo/catalog?x=1'),
  request(origin + '/api/operator-demo/applications', 'POST', raw), request(origin + '/', 'POST', raw),
  request(origin + '/', 'GET', raw), request(origin + '/', 'GET', null, {authorization: 'canary'}),
  request(origin + '/', 'GET', null, {'x-serverware-admin-token': 'canary'}),
  request(origin + '/', 'GET', null, {cookie: 'canary'}), request(origin + '/', 'GET', null, {'proxy-authorization': 'canary'}),
  request(origin + '/api/operator-demo/access-rules/gmail-read', 'POST', Buffer.alloc(4097))]) {
  assert.throws(() => requestFrame(value, 1));
}
console.log('Gmail browser bridge inert request controls passed (12 cases; no browser or network)');
