// Stock @octokit/rest, not the full octokit retry/throttling distribution.
// Only documented fetch/ProxyAgent transport configuration and passive response
// observation are added. No request header, body, query or Link rewriting.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Octokit } from '/sdk/node_modules/@octokit/rest/dist-src/index.js';
import undici from '/sdk/node_modules/undici/index.js';

const { ProxyAgent, fetch } = undici;
const require = (value) => { if (!value) throw new Error('fixture assertion'); };
const sha = (value) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const inputBytes = readFileSync(0);
require(inputBytes.length <= 4096);
const input = JSON.parse(inputBytes);
require(process.version === 'v25.5.0'
  && /^[0-9a-f-]{36}$/.test(input.applicationId)
  && /^[A-Za-z0-9_-]{43}$/.test(input.token)
  && /^operator-check-[0-9a-f]{32}$/.test(input.runId)
  && ['wrong_app', 'wrong_repo', 'wrong_dummy', 'numeric', 'job', 'cross_repo_link', 'cross_origin_link'].includes(input.phase));
const deadline = setTimeout(() => process.exit(70), 65000);
const proxy = new ProxyAgent({
  uri: 'https://proxy.operator-basic.example.test:8443',
  token: 'Basic ' + Buffer.from(input.applicationId + ':' + input.token).toString('base64'),
  proxyTls: { ca: readFileSync('/client-trust/outer-ca.pem') },
  requestTls: { ca: readFileSync('/client-trust/inner-ca.pem') },
  connections: 1,
});
const observations = [];
const sdk = new Octokit({
  auth: input.phase === 'wrong_dummy' ? 'serverware-wrong-placeholder-v1' : 'serverware-github-placeholder-v1',
  userAgent: 'serverware-test-run/' + input.runId,
  log: { debug() {}, info() {}, warn() {}, error() {} },
  request: { fetch: async (url, options) => {
    require(typeof url === 'string' && url.length <= 4096 && url.startsWith('https://api.github.com/'));
    const requestBody = options.body === undefined ? Buffer.alloc(0) : Buffer.from(options.body);
    require(requestBody.length <= 65536 && observations.length < 12);
    const response = await fetch(url, { ...options, dispatcher: proxy });
    const copy = response.clone();
    const reader = copy.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.length;
      require(size <= 1048576);
      chunks.push(Buffer.from(item.value));
    }
    const body = Buffer.concat(chunks);
    const headers = Object.fromEntries(response.headers.entries());
    require(JSON.stringify(headers).length <= 16384);
    // Authorization is deliberately not exported. The independent fixture
    // validates every parsed upstream header, including actual injection.
    const clientHeaders = Object.fromEntries(Object.entries(options.headers)
      .filter(([name]) => ['accept', 'user-agent', 'content-type', 'x-github-api-version'].includes(name.toLowerCase()))
      .map(([name, value]) => [name.toLowerCase(), value]));
    observations.push({ method: options.method, target: url.slice('https://api.github.com'.length), clientHeaders,
      requestBodySha256: sha(requestBody), requestBodyBase64: requestBody.toString('base64'),
      status: response.status, headers, responseBodyBase64: body.toString('base64') });
    return response;
  } },
});
const scope = { owner: 'serverware-fixture', repo: 'operator-demo' };
const fullIssue = (number) => ({ id: 1700 + number, number, title: `Fixture issue ${number}`,
  body: 'Complete synthetic body ☃', labels: [{ name: 'fixture' }], user: { login: 'fixture-user' },
  extra: { preserved: [true, null, 7] } });
const same = (a, b) => require(JSON.stringify(a) === JSON.stringify(b));

let result;
try {
  if (input.phase === 'job') {
    const values = await sdk.paginate(sdk.issues.listForRepo, { ...scope,
      per_page: 1, state: 'open', labels: 'fixture,triaged', page: 1 });
    same(values, [fullIssue(11), fullIssue(12)]);
    same((await sdk.issues.get({ ...scope, issue_number: values[0].number })).data, fullIssue(11));
    same((await sdk.issues.listComments({ ...scope, issue_number: 11, per_page: 1, page: 1 })).data,
      [{ id: 101, body: 'Fixture comment', user: { login: 'fixture-user' }, extra: [1, 2] }]);
    same((await sdk.issues.getComment({ ...scope, comment_id: 101 })).data,
      { id: 101, body: 'Fixture comment', user: { login: 'fixture-user' }, extra: [1, 2] });
    const created = await sdk.issues.create({ ...scope,
      title: 'Synthetic fixture issue', body: 'Fixture body ☃', labels: ['fixture'] });
    require(created.status === 201); same(created.data, fullIssue(13));
    const comment = await sdk.issues.createComment({ ...scope, issue_number: 11, body: 'Synthetic fixture comment' });
    require(comment.status === 201);
    same(comment.data, { id: 103, body: 'Synthetic fixture comment', extra: { preserved: true } });
    for (const status of [404, 429]) {
      let error;
      try { await sdk.issues.get({ ...scope, issue_number: status }); } catch (caught) { error = caught; }
      require(error?.status === status && error.response?.status === status);
      same(error.response.data, status === 404
        ? { message: 'Fixture issue absent', documentation_url: 'https://docs.github.com/rest/issues', status: '404', extra: [1, 2] }
        : { message: 'Fixture rate limit', documentation_url: 'https://docs.github.com/rest', status: '429', extra: { retry: false } });
      require(error.response.headers['x-ratelimit-limit'] === '5000');
      if (status === 429) require(error.response.headers['retry-after'] === '2'
        && error.response.headers['x-ratelimit-remaining'] === '0');
    }
    require(observations.length === 9);
    result = { ok: true, phase: input.phase, observations, sdkDataVerified: true };
  } else {
    let error;
    try {
      if (input.phase === 'numeric') await sdk.request('GET /repositories/1729/issues');
      else if (input.phase.endsWith('_link')) await sdk.paginate(sdk.issues.listForRepo,
        { ...scope, per_page: 1, labels: input.phase === 'cross_repo_link' ? 'fixture-cross-repo' : 'fixture-cross-origin', page: 1 });
      else await sdk.issues.get({ ...scope,
        ...(input.phase === 'wrong_repo' ? { repo: 'other-repo' } : {}), issue_number: 11 });
    } catch (caught) { error = caught; }
    require(error && (input.phase === 'wrong_app' ? observations.length === 0 : observations.length === 1));
    result = { ok: true, phase: input.phase, refused: true,
      status: Number.isInteger(error.status) ? error.status : null, observations };
  }
} catch {
  // RequestError can contain raw request credentials: never stringify it.
  result = { ok: false, phase: input.phase, error: 'stock SDK fixture operation failed' };
} finally {
  await proxy.destroy();
  clearTimeout(deadline);
}
process.stdout.write(JSON.stringify({ schema: 'serverware.privateGithubSdk/v1',
  package: '@octokit/rest', version: '22.0.1', undiciVersion: '8.11.2',
  retryPlugin: false, throttlePlugin: false, requestRewrite: false, ...result }) + '\n');
process.exitCode = result.ok ? 0 : 1;
