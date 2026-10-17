// Pure stock endpoint construction only: no request(), paginate(), fetch or
// transport execution. Literal oracles match operator_github_fixture.py.
import assert from 'node:assert/strict';
import {readFileSync, realpathSync} from 'node:fs';
import {isAbsolute, join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

let stage = 'arguments';
let passed = 0;
let fetchCalls = 0;
const denyFetch = () => { fetchCalls++; throw new Error('Network is not part of this test'); };
globalThis.fetch = denyFetch;

try {
  assert.equal(process.argv.length, 4);
  assert.equal(process.argv[2], '--sdk-root');
  const root = process.argv[3];
  assert(isAbsolute(root) && resolve(root) === root && realpathSync(root) === root);
  stage = 'package_pins';
  for (const [name, version] of [['@octokit/rest', '22.0.1'], ['undici', '8.11.2']]) {
    const metadata = JSON.parse(readFileSync(join(root, 'node_modules', name, 'package.json'), 'utf8'));
    assert.equal(metadata.name, name); assert.equal(metadata.version, version);
  }
  const {Octokit} = await import(pathToFileURL(join(root, 'node_modules/@octokit/rest/dist-src/index.js')));
  // This is the same pure serializer used by the installed @octokit/request
  // fetch wrapper, without invoking that wrapper or any fetch implementation.
  const {JSONStringify} = await import(pathToFileURL(join(root, 'node_modules/json-with-bigint/json-with-bigint.js')));
  const sdk = new Octokit({auth: 'catchplate-github-placeholder-v1',
    log: {debug() {}, info() {}, warn() {}, error() {}}, request: {fetch: denyFetch}});
  const scope = {owner: 'catchplate-fixture', repo: 'operator-demo'};
  const origin = 'https://api.github.com';
  const base = '/repos/catchplate-fixture/operator-demo/issues';
  const query1 = 'per_page=1&state=open&labels=fixture%2Ctriaged&page=1';
  const query2 = 'per_page=1&state=open&labels=fixture%2Ctriaged&page=2';
  let initialPage;
  // Argument property order is intentionally the order in operator_github_job.mjs.
  const cases = [
    ['page1', () => (initialPage = sdk.issues.listForRepo.endpoint({...scope,
      per_page: 1, state: 'open', labels: 'fixture,triaged', page: 1})),
    'GET', base + '?' + query1, ''],
    // paginate.iterator sends the validated, normalized Link URL through the
    // original endpoint method. This does not test Link validation or rewriting.
    ['page2', () => sdk.issues.listForRepo.endpoint({method: initialPage.method,
      url: origin + base + '?' + query2, headers: initialPage.headers}),
    'GET', base + '?' + query2, ''],
    ['issue', () => sdk.issues.get.endpoint({...scope, issue_number: 11}),
    'GET', base + '/11', ''],
    ['comments', () => sdk.issues.listComments.endpoint({...scope, issue_number: 11, per_page: 1, page: 1}),
    'GET', base + '/11/comments?per_page=1&page=1', ''],
    ['comment', () => sdk.issues.getComment.endpoint({...scope, comment_id: 101}),
    'GET', base + '/comments/101', ''],
    ['create_issue', () => sdk.issues.create.endpoint({...scope,
      title: 'Synthetic fixture issue', body: 'Fixture body ☃', labels: ['fixture']}),
    'POST', base, '{"title":"Synthetic fixture issue","body":"Fixture body ☃","labels":["fixture"]}'],
    ['create_comment', () => sdk.issues.createComment.endpoint({...scope, issue_number: 11, body: 'Synthetic fixture comment'}),
    'POST', base + '/11/comments', '{"body":"Synthetic fixture comment"}'],
    ['not_found', () => sdk.issues.get.endpoint({...scope, issue_number: 404}),
    'GET', base + '/404', ''],
    ['rate_limit', () => sdk.issues.get.endpoint({...scope, issue_number: 429}),
    'GET', base + '/429', ''],
    ['cross_repo_link', () => sdk.issues.listForRepo.endpoint({...scope, per_page: 1, labels: 'fixture-cross-repo', page: 1}),
    'GET', base + '?per_page=1&labels=fixture-cross-repo&page=1', ''],
    ['cross_origin_link', () => sdk.issues.listForRepo.endpoint({...scope, per_page: 1, labels: 'fixture-cross-origin', page: 1}),
    'GET', base + '?per_page=1&labels=fixture-cross-origin&page=1', ''],
  ];
  for (const [name, build, method, target, body] of cases) {
    stage = name;
    const result = build();
    assert.equal(result.method, method);
    assert.equal(result.url, origin + target, 'exact raw path/query, including order and escapes');
    const serialized = result.body === undefined ? '' : typeof result.body === 'string' ? result.body : JSONStringify(result.body);
    assert.deepEqual(Buffer.from(serialized, 'utf8'), Buffer.from(body, 'utf8'), 'literal fixture body bytes');
    assert.equal(fetchCalls, 0);
    passed++;
  }
  console.log(JSON.stringify({ok: true, passed, jobSpecs: 9, hostileInitialRoutes: 2, fetchCalls,
    scope: 'stock endpoint and JSON serialization only; no SDK requests, pagination execution, proxy or provider'}));
} catch {
  console.log(JSON.stringify({ok: false, passed, expected: 11, stage, fetchCalls}));
  process.exitCode = 1;
}
