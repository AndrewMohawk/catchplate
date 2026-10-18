'use strict';
// Synthetic metadata and an inert DOM; no app, provider, browser or network.
const assert = require('node:assert/strict');
const {load, catalog, publication, IDS, NOW} = require('./test_operator_ecr_ui.cjs');
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const response = (body, status = 200) => ({status, ok: status === 200,
  headers: {get: () => 'application/json'}, text: async () => JSON.stringify(body)});
class Node {
  constructor() { this.children = []; this.dataset = {}; this.events = {}; this.value = ''; this.ownText = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(' '); }
  set innerHTML(_) { assert.fail('No HTML insertion'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.ownText = ''; this.children = children; }
  addEventListener(name, callback) { this.events[name] = callback; }
}
function fixture(handler) {
  const api = load(), nodes = new Map(), calls = [], authCallbacks = [];
  const node = id => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); };
  const workspace = {state: {catalog: api.projectCatalog(catalog()), browserRecoveryBlocked: false},
    loaded: () => true, subscribe: callback => callback(), onAuthenticationLost: callback => authCallbacks.push(callback),
    authenticationLost() { workspace.state.catalog = null; authCallbacks.forEach(callback => callback()); }};
  Object.assign(api, {document: {getElementById: node, createElement: () => new Node()}, AbortController,
    window: {addEventListener() {}}, sessionStorage: {getItem: () => null, setItem: () => assert.fail('No writes'), removeItem() {}},
    setTimeout(callback, delay) { assert.equal(delay, 30000); return 1; }, clearTimeout() {},
    fetch: async (path, init) => { assert.equal(init.method, 'GET'); assert.equal(init.credentials, 'same-origin');
      assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store'); calls.push(path); return handler(path); }});
  const view = api.createEcrPublicationsView(workspace);
  return {api, view, node, calls, workspace};
}
async function main() {
  const api = load(), summary = options => api.ecrPublicationsSummary({state: 'ready', rows: [], nextCursor: null, now: NOW, ...options});
  assert.equal(summary({state: 'not-checked'}).state, 'not-checked');
  assert.equal(summary({state: 'loading'}).state, 'loading');
  assert.match(summary({state: 'error'}).text, /not confirmed empty/);
  assert.match(summary({}).text, /No image publications were found at the last check/);
  const rows = ['awaiting_review', 'uncertain', 'approved', 'active', 'published'].map(status => publication({status}));
  const mixed = summary({rows, nextCursor: IDS[3]});
  assert.equal(mixed.state, 'incomplete');
  for (const text of ['1 awaiting review', '1 needs a status check', '1 waiting for the client', '1 staging or publishing', '1 completed or closed', 'only loaded images']) assert(mixed.text.includes(text));
  assert.match(summary({rows: [publication()], held: () => true}).text, /1 needs a status check/);
  assert.match(summary({rows: [publication({expires_at_epoch_ms: NOW})]}).text, /1 needs a status check/);
  assert.equal(summary({rows, failed: true}).state, 'error');
  assert.equal(summary({rows, busy: true}).state, 'loading');

  let release;
  const delayed = new Promise(resolve => { release = resolve; });
  const first = fixture(() => delayed);
  assert.equal(first.node('ecr-publications-summary').dataset.state, 'not-checked');
  first.view.show(true); await flush();
  assert.equal(first.node('ecr-publications-summary').dataset.state, 'loading');
  release(response({publications: []})); await flush();
  assert.equal(first.node('ecr-publications-summary').dataset.state, 'ready');
  assert.match(first.node('ecr-publications-summary').textContent, /No image publications/);

  let phase = 0;
  const paged = fixture(() => phase === 0 ? response({publications: [publication()], next_cursor: IDS[3]}) :
    phase === 1 ? response({}, 503) : response({publications: [publication({id: IDS[4], status: 'approved'})], next_cursor: null}));
  paged.view.show(true); await flush();
  assert.equal(paged.node('ecr-publications-summary').dataset.state, 'incomplete');
  assert.equal(paged.node('ecr-publications-list').children.length, 1);
  phase = 1; await paged.view.load(true);
  assert.equal(paged.node('ecr-publications-summary').dataset.state, 'error');
  assert.equal(paged.node('ecr-publications-list').children.length, 1);
  assert.match(paged.node('ecr-publications-summary').textContent, /counts are incomplete/);
  assert.equal(paged.node('ecr-publications-load-more').hidden, false);
  phase = 2; await paged.view.load(true);
  assert.equal(paged.node('ecr-publications-summary').dataset.state, 'ready');
  assert.match(paged.node('ecr-publications-summary').textContent, /^2 loaded image publications/);
  assert.match(paged.node('ecr-publications-summary').textContent, /1 waiting for the client/);
  assert.equal(paged.node('ecr-publications-list').children.length, 2);
  assert.equal(paged.node('ecr-publications-load-more').hidden, true);
  assert.equal(paged.calls.length, 3);
  paged.workspace.authenticationLost();
  assert.equal(paged.node('ecr-publications-summary').dataset.state, 'authentication');
  assert.equal(paged.node('ecr-publications-list').children.length, 0);
  console.log(JSON.stringify({ok: true, groups: 4, scope: 'queue summary states, exact counts, paged failure preserves rows, authentication clears metadata', network: false}));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
