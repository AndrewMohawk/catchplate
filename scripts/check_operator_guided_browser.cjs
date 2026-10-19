#!/usr/bin/env node
'use strict';
// Genuine UI bytes are relayed to the isolated checker over private stdio.
// No fake catalog/backend replies, host HTTP, external SSO, or provider access.
// The caller owns the original 185s cgroup and private TMPDIR cleanup.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const ORIGIN = 'https://catchplate-guided.example.com';
const PREFIX = '/api/operator-demo';
const CATALOG = PREFIX + '/catalog';
const SCHEMA = 'catchplate.privateGuidedBrowser/v1';
const PLAYWRIGHT = '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright';
const CHROME = '/home/catchplate/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell';
const CHROME_SHA = '27e55cc30e487493b89b663085d6deeb0707be201a568657c922fac9076c317c';
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
// Fixed public byte oracle, joined to operator_ordinary_client_fixture.py by
// the inert regression suite; a well-formed arbitrary digest is not evidence.
const ORACLE_BODY_BYTES = 126;
const ORACLE_BODY_SHA256 = 'sha256:0e8924971815df1897718e8de313ed2652a80ee5113059bfea46a4db3be3d542';
const ROUTES = ['credentials', 'applications', 'access-rules', 'access-rules/revoke', 'applications/revoke', 'credentials/revoke'].map(p => PREFIX + '/' + p);
const STEPS = ['credential', 'application', 'permission', 'download', 'proxy_success', 'rule_revoked',
  'proxy_denied', 'application_revoked', 'credential_revoked'];
const STAGES = ['inputs', 'launch', 'ready', 'open', 'credential', 'credential_reply_lost', 'credential_reload',
  'credential_review', 'credential_reuse', 'application', 'permission', 'download',
  'proxy_success', 'rule_revoked', 'proxy_denied', 'application_revoked', 'credential_revoked', 'result', 'close'];
const CHECKER_STAGES = ['preflight', 'create', 'revoke_rule', 'revoke_rest', 'audit'];
const CHECKER_ERRORS = ['CheckFailure', 'AssertionError', 'ValueError', 'TypeError', 'KeyError', 'RuntimeError',
  'AttributeError', 'OSError', 'FileNotFoundError', 'PermissionError', 'TimeoutError', 'ConnectionError',
  'ConnectionRefusedError', 'ConnectionResetError', 'BrokenPipeError', 'JSONDecodeError', 'UnicodeDecodeError',
  'SSLError', 'SSLCertVerificationError', 'RemoteDisconnected', 'IncompleteRead', 'HTTPException'];
const CHECKER_MODULES = ['scripts.check_operator_guided', 'scripts.operator_guided_browser',
  'scripts.operator_guided_hosted_profile',
  'scripts.check_operator_catalog', 'scripts.check_operator_demo', 'scripts.check_operator_live_smoke',
  'scripts.check_operator_ordinary_client', 'scripts.operator_catalog_feature_checks', 'scripts.run_ordinary_regression'];
function need(value) { if (!value) throw new Error('Guided browser check refused'); }
function applicationRevocationDialog(name, id) {
  return `Revoke client "${name}" (${id}) and its 0 active permissions? This also cancels workload renewal and previous-token overlap. Shared provider credentials and other clients remain. Enforcement begins after the proxy loads the new policy; already-dispatched requests cannot be recalled.`;
}
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === 'object' ?
  Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])])) : value;
const same = (a, b) => JSON.stringify(ordered(a)) === JSON.stringify(ordered(b));
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const RECOVERY_COUNTS = ['lostReplyCount', 'abortedRequests', 'networkConsoleErrors', 'reloadCount', 'acknowledgements'];
const RECOVERY_FLAGS = ['markerBeforeDispatch', 'holdBeforeReload', 'holdAfterReload', 'freshCatalogReviewed',
  'reusedSavedCredential', 'privateStorageClean'];
function recoveryEvidence(complete = false) {
  return {...Object.fromEntries(RECOVERY_COUNTS.map(key => [key, complete ? 1 : 0])),
    ...Object.fromEntries(RECOVERY_FLAGS.map(key => [key, complete]))};
}
function validateRecovery(value) {
  need(exact(value, [...RECOVERY_COUNTS, ...RECOVERY_FLAGS]) && same(value, recoveryEvidence(true)));
  return value;
}
function credentialReplyFault() {
  // The sole expected network failure is our already-committed credential
  // request. Request identity, exact Chromium error and exact console location
  // must all agree; another failure, duplicate event or later error is fatal.
  let selected = null, closed = false, aborted = 0, logged = 0;
  const matchesRequest = request => !closed && selected !== null && request === selected &&
    request.failure()?.errorText === 'net::ERR_FAILED';
  const matchesConsole = message => !closed && selected !== null && message.type() === 'error' &&
    message.location()?.url === ORIGIN + ROUTES[0] &&
    message.text() === 'Failed to load resource: net::ERR_FAILED';
  return {
    arm(request) {
      need(!closed && selected === null && request.method() === 'POST' && request.url() === ORIGIN + ROUTES[0]);
      selected = request;
    },
    matchesRequest, matchesConsole,
    requestFailed(request) { if (!matchesRequest(request) || aborted !== 0) return false; aborted++; return true; },
    consoleError(message) { if (!matchesConsole(message) || logged !== 0) return false; logged++; return true; },
    finish() { need(!closed && selected !== null && aborted === 1 && logged === 1); closed = true; selected = null; }
  };
}
function decode(value, maximum) {
  need(typeof value === 'string' && value.length <= Math.ceil(maximum / 3) * 4);
  const raw = Buffer.from(value, 'base64'); need(raw.length <= maximum && raw.toString('base64') === value); return raw;
}
function readyFrame(value) {
  need(exact(value, ['kind', 'schema', 'origin', 'proxyUrl', 'upstreamUrl', 'names', 'providerSecret',
    'tokenTtlSeconds', 'placeholder', 'caPath', 'initialRevision', 'initialPolicyHash', 'timeoutSeconds']));
  need(value.kind === 'ready' && value.schema === SCHEMA && value.origin === ORIGIN &&
    value.proxyUrl === 'https://catchplate-gmail-proxy.example.com' && value.upstreamUrl === 'https://demo-upstream:8443/ordinary-client' &&
    value.tokenTtlSeconds === 3600 && value.placeholder === 'Bearer CATCHPLATE_DUMMY' &&
    value.caPath === '/client-trust/inner-ca.pem' && value.initialRevision === 1 && DIGEST.test(value.initialPolicyHash) && value.timeoutSeconds === 180);
  need(exact(value.names, ['credential', 'application', 'rule']));
  const match = /^operator-check-([0-9a-f]{32})-key$/.exec(value.names.credential);
  need(match && value.names.application === 'operator-check-' + match[1] + '-app' && value.names.rule === 'operator-check-' + match[1] + '-rule');
  need(typeof value.providerSecret === 'string' && /^[!-~]{16,256}$/.test(value.providerSecret)); return value;
}
function requestFrame(request, id, expectedPost) {
  need(integer(id, 1, 100)); const url = new URL(request.url());
  need(url.origin === ORIGIN && !url.username && !url.password && !url.search && !url.hash);
  const method = request.method(), raw = request.postDataBuffer() || Buffer.alloc(0), all = request.headers();
  need(!Object.keys(all).some(key => /^(authorization|proxy-authorization|cookie|x-catchplate-|transfer-encoding|content-encoding)/i.test(key)));
  const headers = Object.fromEntries(Object.entries(all).filter(([key]) => ['accept', 'content-type', 'origin'].includes(key)));
  need(Object.values(headers).every(value => typeof value === 'string' && /^[\x20-\x7e]{0,512}$/.test(value)));
  need(method === 'GET' && ['/', CATALOG].includes(url.pathname) && !raw.length && !headers.origin && !headers['content-type'] ||
    method === 'POST' && ROUTES.includes(expectedPost) && url.pathname === expectedPost && raw.length > 0 && raw.length <= 8192 &&
    headers.origin === ORIGIN && headers['content-type'] === 'application/json');
  return {kind: 'request', id, method, path: url.pathname, headers, body: raw.toString('base64')};
}
function responseFrame(value, id, status) {
  need(exact(value, ['kind', 'id', 'status', 'headers', 'body']) && value.kind === 'response' && value.id === id && value.status === status);
  need(Array.isArray(value.headers) && value.headers.length <= 64);
  const names = new Set();
  for (const pair of value.headers) {
    need(Array.isArray(pair) && pair.length === 2 && typeof pair[0] === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(pair[0]) &&
      typeof pair[1] === 'string' && /^[\x20-\x7e]{0,8192}$/.test(pair[1]));
    const name = pair[0].toLowerCase(); need(!names.has(name) && !['set-cookie', 'location', 'content-encoding', 'transfer-encoding'].includes(name)); names.add(name);
  }
  need(JSON.stringify(value.headers).length <= 16384);
  const raw = decode(value.body, 2 * 1024 ** 2); need(raw.length > 0); return raw;
}
function continueFrame(value, id, phase, ids) {
  need(exact(value, ['kind', 'id', 'phase', 'resourceIds']) && value.kind === 'continue' && value.id === id && value.phase === phase &&
    exact(value.resourceIds, ['credential', 'application', 'rule']) &&
    Object.entries(ids).every(([key, item]) => UUID.test(item) && value.resourceIds[key] === item)); return value;
}
const failureSiteValid = value => value === null || exact(value, ['module', 'line']) &&
  CHECKER_MODULES.includes(value.module) && integer(value.line, 1, 100000);
function checkerFailureFrame(frame) {
  need(exact(frame, ['kind', 'result']) && frame.kind === 'result');
  const value = frame.result;
  need(exact(value, ['schema', 'ok', 'error', 'stage', 'exceptionType', 'failureSite']) &&
    value.schema === 'catchplate.privateGuidedCheck/v1' && value.ok === false && value.error === 'guided_check_failed' &&
    CHECKER_STAGES.includes(value.stage) && CHECKER_ERRORS.includes(value.exceptionType) && failureSiteValid(value.failureSite));
  return {stage: value.stage, exceptionType: value.exceptionType,
    failureSite: value.failureSite === null ? null : {module: value.failureSite.module, line: value.failureSite.line}};
}
function stderrCollector() {
  const hash = crypto.createHash('sha256'); let capturedBytes = 0, truncated = false;
  return {
    append(data) {
      need(Buffer.isBuffer(data)); const size = Math.min(data.length, 65536 - capturedBytes);
      hash.update(data.subarray(0, size)); capturedBytes += size; truncated ||= size !== data.length;
      return !truncated;
    },
    snapshot() { return {capturedBytes, sha256: 'sha256:' + hash.copy().digest('hex'), truncated}; }
  };
}
function failureReceipt(stage, observations, checkerFailure = null, stderr = null) {
  const checker = exact(checkerFailure, ['stage', 'exceptionType', 'failureSite']) && CHECKER_STAGES.includes(checkerFailure.stage) &&
    CHECKER_ERRORS.includes(checkerFailure.exceptionType) && failureSiteValid(checkerFailure.failureSite) ?
    {stage: checkerFailure.stage, exceptionType: checkerFailure.exceptionType,
      failureSite: checkerFailure.failureSite === null ? null : {module: checkerFailure.failureSite.module, line: checkerFailure.failureSite.line}} : null;
  const diagnostic = exact(stderr, ['capturedBytes', 'sha256', 'truncated']) && integer(stderr.capturedBytes, 0, 65536) &&
    typeof stderr.sha256 === 'string' && DIGEST.test(stderr.sha256) && typeof stderr.truncated === 'boolean' ?
    {capturedBytes: stderr.capturedBytes, sha256: stderr.sha256, truncated: stderr.truncated} : null;
  return {schema: 'catchplate.privateGuidedBrowserFailure/v1', ok: false,
    stage: STAGES.includes(stage) ? stage : 'inputs', error: 'guided_browser_refused',
    checkerFailure: checker, checkerStderr: diagnostic,
    ...Object.fromEntries(['postCount', 'getCount', 'documentCount', 'pageErrors', 'consoleErrors', 'refusedRequests', 'downloadCount'].map(key =>
      [key, integer(observations[key], 0, 100) ? observations[key] : null])),
    credentialRecovery: {...Object.fromEntries(RECOVERY_COUNTS.map(key =>
      [key, integer(observations.credentialRecovery?.[key], 0, 100) ? observations.credentialRecovery[key] : null])),
      ...Object.fromEntries(RECOVERY_FLAGS.map(key =>
        [key, typeof observations.credentialRecovery?.[key] === 'boolean' ? observations.credentialRecovery[key] : null]))}};
}
function publicFailureReceipt(raw) {
  need(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 4096);
  const value = JSON.parse(raw.toString('utf8'));
  // The source writer emits exactly this canonical serialization. Requiring it
  // also refuses duplicate keys, invalid UTF-8 and nonfinite JSON spellings.
  need(Buffer.from(JSON.stringify(value) + '\n').equals(raw));
  need(exact(value, ['schema', 'ok', 'stage', 'error', 'checkerFailure', 'checkerStderr',
    'postCount', 'getCount', 'documentCount', 'pageErrors', 'consoleErrors', 'refusedRequests', 'downloadCount', 'credentialRecovery']));
  const checked = failureReceipt(value.stage, value, value.checkerFailure, value.checkerStderr);
  need(same(value, checked));
  // Export neither private bytes nor their fingerprint. These counters describe
  // observations/attempts, not successful mutations or acceptance.
  return {...checked, schema: 'catchplate.guidedBrowserFailure/v1', checkerStderr: checked.checkerStderr === null ? null : {
    capturedBytes: checked.checkerStderr.capturedBytes, truncated: checked.checkerStderr.truncated}};
}
async function downloadedBytes(download) {
  let stream; const chunks = []; let size = 0;
  try {
    need(download.suggestedFilename() === 'catchplate-client.private.json');
    stream = await download.createReadStream(); need(stream);
    for await (const chunk of stream) { need(Buffer.isBuffer(chunk) && (size += chunk.length) <= 16384); chunks.push(chunk); }
    need(size > 0); return Buffer.concat(chunks);
  } finally { stream?.destroy(); for (const chunk of chunks) chunk.fill(0); await download.delete(); }
}
function validateChecker(value, browser, ids) {
  validateRecovery(browser.credentialRecovery);
  need(browser.documentCount === 2);
  need(exact(value, ['schema', 'ok', 'syntheticOnly', 'realProviderVerified', 'publicDnsVerified', 'externalSsoVerified',
    'productionReady', 'hardwareVerified', 'runId', 'dataPlaneBinaryDigest', 'resourceIds', 'initialRevision', 'finalRevision',
    'initialPolicyHash', 'policyHash', 'providerArrivals', 'proxyAttempts', 'mutations', 'positive', 'negative', 'audit', 'browser']));
  need(value.schema === 'catchplate.privateGuidedCheck/v1' && value.ok === true && value.syntheticOnly === true &&
    ['realProviderVerified', 'publicDnsVerified', 'externalSsoVerified', 'productionReady', 'hardwareVerified'].every(key => value[key] === false) &&
    /^operator-check-[0-9a-f]{32}$/.test(value.runId) && ['dataPlaneBinaryDigest', 'initialPolicyHash', 'policyHash'].every(key => DIGEST.test(value[key])) &&
    value.initialRevision === 1 && value.finalRevision === 7 && value.providerArrivals === 1 && value.proxyAttempts === 2 &&
    exact(value.resourceIds, ['credential', 'application', 'rule']) && Object.entries(ids).every(([key, id]) => value.resourceIds[key] === id) && same(value.browser, browser));
  need(Array.isArray(value.mutations) && value.mutations.length === 6);
  for (const [i, row] of value.mutations.entries()) need(exact(row, ['route', 'status', 'revision', 'resourceId', 'policyHash']) &&
    row.route === ROUTES[i] && row.status === (i < 3 ? 201 : 200) && row.revision === i + 2 &&
    row.resourceId === ids[['credential', 'application', 'rule', 'rule', 'application', 'credential'][i]] && DIGEST.test(row.policyHash));
  need(exact(value.negative, ['outcome', 'connectStatus', 'providerArrivals']) && value.negative.outcome === 'denied' &&
    value.negative.connectStatus === 403 && value.negative.providerArrivals === 0);
  const positive = value.positive, audit = value.audit;
  need(exact(positive, ['case', 'status', 'responseMode', 'responseBodySha256', 'responseBodyBytes', 'requestDigest', 'operationDigest']) &&
    positive.case === 'positive' && positive.status === 200 && positive.responseMode === 'unfiltered_json_or_empty_v2' &&
    positive.responseBodyBytes === ORACLE_BODY_BYTES && positive.responseBodySha256 === ORACLE_BODY_SHA256 &&
    ['requestDigest', 'operationDigest'].every(key => DIGEST.test(positive[key])));
  const events = Object.fromEntries(['credential', 'application', 'access_rule'].flatMap(kind =>
    ['created', 'revoked'].map(action => ['operator_catalog.' + kind + '.' + action, 1])));
  Object.assign(events, {'data_plane.credential.release_started': 1, 'data_plane.response.released': 1,
    'data_plane.connect.established': 1, 'data_plane.connect.denied': 1, 'data_plane.policy.reloaded': 2});
  need(exact(audit, ['eventCounts', 'eventIds', 'attemptIds', 'chainVerified']) && audit.chainVerified === true &&
    exact(audit.eventCounts, [...Object.keys(events), 'data_plane.credential_lease.issued']) &&
    Object.entries(events).every(([key, count]) => audit.eventCounts[key] === count) &&
    integer(audit.eventCounts['data_plane.credential_lease.issued'], 1, 32));
  need(Array.isArray(audit.eventIds) && audit.eventIds.length === Object.values(audit.eventCounts).reduce((a, b) => a + b, 0) &&
    audit.eventIds.every(id => typeof id === 'string' && (UUID.test(id) || DIGEST.test(id))) && new Set(audit.eventIds).size === audit.eventIds.length &&
    Array.isArray(audit.attemptIds) && audit.attemptIds.length === 1 && DIGEST.test(audit.attemptIds[0])); return value;
}

async function main() {
  const [checker, evidence] = process.argv.slice(2);
  need(process.argv.length === 4 && /^[0-9a-f]{64}$/.test(checker) && path.isAbsolute(evidence) &&
    fs.realpathSync(evidence) === evidence && fs.statSync(evidence).isDirectory());
  need(crypto.createHash('sha256').update(fs.readFileSync(CHROME)).digest('hex') === CHROME_SHA && require(PLAYWRIGHT + '/package.json').version === '1.58.2');
  const temporary = process.env.TMPDIR; need(temporary && path.isAbsolute(temporary) && fs.realpathSync(temporary) === temporary);
  const owned = fs.statSync(temporary); need(owned.isDirectory() && owned.uid === process.geteuid() && (owned.mode & 0o777) === 0o700);
  const out = {postCount: 0, getCount: 0, documentCount: 0, pageErrors: 0, consoleErrors: 0, refusedRequests: 0,
    downloadCount: 0, downloadDeleted: false, tokenCleared: false, steps: [], credentialRecovery: recoveryEvidence()};
  const fault = credentialReplyFault();
  const ids = {}; let browser, child, pending, failed, stage = 'inputs', expectedPost = null, expectedDialog = null;
  let sequence = 0, total = 0, stderrBytes = 0, input = Buffer.alloc(0), chain = Promise.resolve(), lastCatalog, readyValue, checkerFailure = null;
  const stderr = stderrCollector();
  let readyResolve, readyReject, downloadExpected = false;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; }); ready.catch(() => {});
  const fail = () => { if (!failed) { failed = new Error('Guided browser check refused'); readyReject(failed); pending?.reject(failed); pending = null; } };
  const timer = setTimeout(fail, 180000);
  const signal = () => { fail(); browser?.close().catch(() => {}); };
  process.once('SIGTERM', signal); process.once('SIGINT', signal);
  function send(frame) {
    need(!failed && child && !pending && frame.id === ++sequence && sequence <= 100);
    const bytes = JSON.stringify(frame) + '\n'; need(Buffer.byteLength(bytes) <= 65536);
    return new Promise((resolve, reject) => {
      pending = {id: frame.id, kind: frame.kind, phase: frame.phase, resolve, reject};
      child.stdin.write(bytes, error => { if (error) fail(); });
    });
  }
  try {
    stage = 'launch';
    browser = await require(PLAYWRIGHT).chromium.launch({executablePath: CHROME, headless: true, timeout: 10000,
      env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', TMPDIR: temporary},
      args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update', '--disable-domain-reliability',
        '--disable-sync', '--no-first-run', '--host-resolver-rules=MAP * ~NOTFOUND']});
    const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block', acceptDownloads: true});
    await context.routeWebSocket('**/*', socket => { out.refusedRequests++; socket.close(); fail(); });
    await context.route('**/*', route => {
      chain = chain.then(async () => {
        try {
          const frame = requestFrame(route.request(), sequence + 1, expectedPost);
          if (frame.method === 'POST') { need(++out.postCount <= 6); expectedPost = null; }
          else { need(++out.getCount <= 80); if (frame.path === '/') need(++out.documentCount <= 2); }
          if (frame.path === ROUTES[0] && frame.method === 'POST') {
            need(out.postCount === 1 && await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 1 &&
              sessionStorage.getItem('catchplate.operator.mutation.review.v1') === 'required'));
            out.credentialRecovery.markerBeforeDispatch = true;
          }
          const response = await send(frame);
          const body = responseFrame(response, frame.id, frame.method === 'POST' ? out.postCount <= 3 ? 201 : 200 : 200);
          if (frame.path === CATALOG) lastCatalog = JSON.parse(body);
          else if (frame.method === 'POST' && out.postCount <= 3) {
            const key = ['credential', 'application', 'rule'][out.postCount - 1];
            const saved = JSON.parse(body)[key === 'rule' ? 'access_rule' : key];
            need(UUID.test(saved?.id) && saved.name === readyValue.names[key] && !Object.values(ids).includes(saved.id)); ids[key] = saved.id;
          }
          if (frame.path === ROUTES[0] && frame.method === 'POST') {
            // The checker emits only after the real 201 survives an independent
            // fresh catalog read. Lose browser delivery, never backend commit.
            need(out.credentialRecovery.lostReplyCount === 0 && out.postCount === 1);
            fault.arm(route.request()); out.credentialRecovery.lostReplyCount++;
            await route.abort('failed'); return;
          }
          await route.fulfill({status: response.status, headers: Object.fromEntries(response.headers), body});
        } catch (_) { out.refusedRequests++; fail(); await route.abort().catch(() => {}); }
      }); return chain;
    });
    const page = await context.newPage(); page.setDefaultTimeout(10000);
    page.on('pageerror', () => { out.pageErrors++; fail(); });
    page.on('console', message => { if (message.type() === 'error') {
      if (fault.consoleError(message)) out.credentialRecovery.networkConsoleErrors++;
      else { out.consoleErrors++; fail(); }
    } });
    page.on('requestfailed', request => {
      if (fault.requestFailed(request)) out.credentialRecovery.abortedRequests++;
      else { out.refusedRequests++; fail(); }
    });
    page.on('popup', popup => { out.refusedRequests++; popup.close().catch(() => {}); fail(); });
    page.on('download', download => { if (!downloadExpected || ++out.downloadCount !== 1) { download.cancel().catch(() => {}); fail(); } downloadExpected = false; });
    page.on('dialog', async dialog => {
      if (dialog.type() !== 'confirm' || !expectedDialog || dialog.message() !== expectedDialog) { await dialog.dismiss(); fail(); return; }
      expectedDialog = null; await dialog.accept();
    });
    stage = 'ready';
    child = spawn('/usr/bin/docker', ['start', '--attach', '--interactive', checker], {stdio: ['pipe', 'pipe', 'pipe'],
      env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GOMAXPROCS: '2', DOCKER_HOST: 'unix:///var/run/docker.sock'}});
    const exited = new Promise(resolve => child.once('exit', (code, sig) => resolve({code, signal: sig})));
    child.on('error', fail); child.stdin.on('error', fail);
    child.stderr.on('data', data => { stderrBytes += data.length; if (!stderr.append(data)) fail(); });
    child.stdout.on('data', data => {
      try {
        total += data.length; need(total <= 8 * 1024 ** 2); input = Buffer.concat([input, data]); need(input.length <= 3 * 1024 ** 2);
        while (input.includes(10)) {
          const end = input.indexOf(10), frame = JSON.parse(input.subarray(0, end)); input = input.subarray(end + 1);
          if (frame.kind === 'result' && frame.result?.ok === false) {
            need(!checkerFailure); checkerFailure = checkerFailureFrame(frame); fail(); return;
          } else if (frame.kind === 'ready') { need(!readyValue && !pending); readyValue = readyFrame(frame); readyResolve(readyValue); }
          else {
            need(pending && (frame.kind === 'result' ? pending.kind === 'checkpoint' && pending.phase === 'completed' : frame.id === pending.id));
            const next = pending; pending = null; next.resolve(frame);
          }
        }
      } catch (_) { fail(); }
    });
    child.stdout.on('end', () => { if (pending || input.length) fail(); });
    // Close follows stdio drain; do not lose an early terminal failure to exit ordering.
    child.once('close', () => { if (!readyValue || pending) fail(); });
    const setup = await ready;
    const step = async name => { await page.locator('#connect-' + name + '-step').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled); need(!failed); };
    const loaded = () => lastCatalog?.policy?.activation === 'active' && lastCatalog.policy.loaded_policy_hash === lastCatalog.policy.policy_hash;
    async function refresh(button) {
      const response = page.waitForResponse(res => res.url() === ORIGIN + CATALOG);
      await page.locator(button).click(); await (await response).finished(); await page.waitForLoadState('networkidle'); need(!failed);
    }
    async function awaitLoaded(button) {
      for (let count = 0; count < 20 && !loaded(); count++) { await new Promise(resolve => setTimeout(resolve, 500)); await refresh(button); }
      need(loaded());
    }
    const privateClean = async () => need(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0 &&
      document.querySelector('#connect-credential-secret').value === ''));
    stage = 'open'; await page.goto(ORIGIN + '/#connect', {waitUntil: 'networkidle'}); await step('credential');
    need(page.url() === ORIGIN + '/#connect' && /Catchplate/.test(await page.title()) && lastCatalog.revision === setup.initialRevision &&
      lastCatalog.policy.policy_hash === setup.initialPolicyHash && loaded());
    stage = 'credential'; await page.locator('#connect-use-key').click();
    await page.locator('#connect-credential-name').fill(setup.names.credential); await page.locator('#connect-credential-auth-type').selectOption('bearer');
    await page.locator('#connect-credential-secret').fill(setup.providerSecret); setup.providerSecret = '';
    const expectedFailure = Promise.all([
      page.waitForEvent('requestfailed', {predicate: request => fault.matchesRequest(request)}),
      page.waitForEvent('console', {predicate: message => fault.matchesConsole(message)})]);
    expectedFailure.catch(() => {});
    expectedPost = ROUTES[0]; await page.locator('#connect-credential-next').click();
    stage = 'credential_reply_lost'; await expectedFailure; fault.finish();
    await page.locator('#mutation-review').waitFor({state: 'visible'});
    await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
    const recoveryPage = async () => {
      const value = await page.evaluate(() => ({
        warning: !document.querySelector('#mutation-review').hidden,
        marker: localStorage.length === 0 && sessionStorage.length === 1 &&
          sessionStorage.getItem('catchplate.operator.mutation.review.v1') === 'required',
        privateInputsEmpty: [...document.querySelectorAll('input[type="password"], #connect-github-private-key')].every(input => input.value === ''),
        writesDisabled: ['connect-use-key', 'connect-use-saved', 'connect-credential-next', 'credential-add', 'application-create']
          .every(id => document.getElementById(id).matches(':disabled'))}));
      need(same(value, {warning: true, marker: true, privateInputsEmpty: true, writesDisabled: true}) && out.postCount === 1 && !failed);
    };
    await recoveryPage(); out.credentialRecovery.holdBeforeReload = true;
    stage = 'credential_reload'; await page.reload({waitUntil: 'networkidle'}); out.credentialRecovery.reloadCount++;
    await step('credential'); await recoveryPage(); out.credentialRecovery.holdAfterReload = true;
    stage = 'credential_review'; await page.locator('nav a[href="#credentials"]').click();
    await page.locator('#credentials').waitFor({state: 'visible'}); await refresh('#credentials-refresh');
    need(out.documentCount === 2 && lastCatalog.revision === setup.initialRevision + 1 && loaded() &&
      lastCatalog.credentials.length === 1 && lastCatalog.credentials[0].id === ids.credential &&
      lastCatalog.credentials[0].name === setup.names.credential && lastCatalog.credentials[0].version === 1 &&
      lastCatalog.credentials[0].status === 'active' && lastCatalog.applications.length === 0 && lastCatalog.access_rules.length === 0);
    const savedCard = page.locator('#credentials [data-resource-id="' + ids.credential + '"]');
    const savedGroup = savedCard.locator('xpath=ancestor::details[1]');
    if (await savedGroup.count() && !await savedGroup.evaluate(node => node.open)) await savedGroup.locator(':scope > summary').click();
    await savedCard.waitFor({state: 'visible'});
    need((await savedCard.innerText()).includes(setup.names.credential) && await savedCard.locator('[data-action="use-credential"]').isDisabled());
    await recoveryPage(); out.credentialRecovery.freshCatalogReviewed = true;
    need(await page.locator('#mutation-review-confirm').isEnabled());
    await page.locator('#mutation-review-confirm').click(); out.credentialRecovery.acknowledgements++;
    await page.locator('#mutation-review').waitFor({state: 'hidden'}); await privateClean();
    need(out.postCount === 1 && await savedCard.locator('[data-action="use-credential"]').isEnabled());
    out.credentialRecovery.privateStorageClean = true;
    stage = 'credential_reuse'; await savedCard.locator('[data-action="use-credential"]').click();
    await step('application'); await privateClean();
    need(out.postCount === 1 && lastCatalog.revision === setup.initialRevision + 1);
    out.credentialRecovery.reusedSavedCredential = true; validateRecovery(out.credentialRecovery); out.steps.push('credential');
    stage = 'application'; await page.locator('#connect-application-choice').selectOption('new');
    await page.locator('#connect-application-name').fill(setup.names.application); await page.locator('#connect-token-ttl').selectOption('3600');
    expectedPost = ROUTES[1]; await page.locator('#connect-application-next').click(); await step('access'); out.steps.push(stage);
    need(lastCatalog.applications.find(app => app.id === ids.application)?.proxy_authentication === 'basic_and_bearer_v1');
    stage = 'permission'; await page.locator('#connect-rule-choice').selectOption('new'); need(await page.locator('#connect-operation').inputValue() === 'exact');
    await page.locator('#connect-origin').selectOption('https://demo-upstream:8443'); await page.locator('#connect-path').fill('/ordinary-client');
    await page.locator('input[name="connect-method"][value="GET"]').uncheck(); await page.locator('input[name="connect-method"][value="POST"]').check();
    await page.locator('#connect-credential-input').selectOption('replace_exact'); await page.locator('#connect-placeholder').fill(setup.placeholder);
    await page.locator('#connect-restrictions > summary').click(); await page.locator('#connect-rule-name').fill(setup.names.rule);
    await page.locator('#connect-request-body-mode').selectOption('preserve_json_v1'); await page.locator('#connect-response-mode').selectOption('unfiltered_json_or_empty_v2');
    await page.locator('#connect-request-extras > summary').click(); await page.locator('#connect-query-keys').fill('case\nexpectedAuthorizationSha256\nexpectedBodySha256');
    await page.locator('#connect-allowed-headers').fill('accept\naccept-encoding\nuser-agent'); await page.locator('#connect-review').click(); await step('review');
    need((await page.locator('#connect-review-details').innerText()).includes(setup.upstreamUrl));
    expectedPost = ROUTES[2]; await page.locator('#connect-grant').click(); await step('setup'); await awaitLoaded('#connect-status-refresh'); out.steps.push(stage);
    stage = 'download'; await page.locator('#ca-path').fill(setup.caPath); await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
    downloadExpected = true; const download = page.waitForEvent('download'); await page.locator('#download-config').click();
    const bytes = await downloadedBytes(await download); out.downloadDeleted = true; out.steps.push(stage);
    expectedDialog = 'Clear the one-time token from this page? It cannot be retrieved again.';
    await page.locator('#dismiss-token').click(); need(expectedDialog === null && await page.locator('#client-token').inputValue() === '');
    out.tokenCleared = true; await privateClean(); await chain;
    stage = 'proxy_success'; const firstId = sequence + 1; let continuation;
    try { continuation = await send({kind: 'checkpoint', id: firstId, phase: 'configured', configuration: bytes.toString('base64')}); }
    finally { bytes.fill(0); }
    continueFrame(continuation, firstId, 'revoke_rule', ids); out.steps.push(stage);
    async function revoke(key, section, route, text, button) {
      stage = key + '_revoked'; await page.locator('nav a[href="#' + section + '"]').click();
      await page.locator('#' + section).waitFor({state: 'visible'}); expectedDialog = text; expectedPost = route;
      const card = page.locator('#' + section + ' [data-resource-id="' + ids[key] + '"]');
      const group = card.locator('xpath=ancestor::details[1]'); if (await group.count() && !await group.evaluate(node => node.open)) await group.locator(':scope > summary').click();
      await card.locator('[data-action="revoke-' + key + '"]').click();
      await card.locator('[data-action="revoke-' + key + '"]').waitFor({state: 'detached'});
      need(expectedDialog === null); await awaitLoaded(button); await privateClean(); out.steps.push(stage);
    }
    await revoke('rule', 'access-rules', ROUTES[3], `Revoke rule "${setup.names.rule}" (${ids.rule})? The application and saved credential remain. New requests are denied after the proxy loads the updated policy; already-dispatched requests cannot be recalled.`, '#rules-refresh');
    stage = 'proxy_denied'; await chain; const secondId = sequence + 1;
    continueFrame(await send({kind: 'checkpoint', id: secondId, phase: 'rule_revoked'}), secondId, 'revoke_rest', ids); out.steps.push(stage);
    await revoke('application', 'applications', ROUTES[4], applicationRevocationDialog(setup.names.application, ids.application), '#applications-refresh');
    await revoke('credential', 'credentials', ROUTES[5], `Revoke locally stored credential "${setup.names.credential}" (${ids.credential})? This does not revoke the key at its provider.`, '#credentials-refresh');
    stage = 'result'; need(same(out.steps, STEPS) && out.postCount === 6 && out.downloadCount === 1 && !failed); await chain;
    const terminal = await send({kind: 'checkpoint', id: sequence + 1, phase: 'completed', browser: out});
    need(exact(terminal, ['kind', 'result']) && terminal.kind === 'result'); const result = validateChecker(terminal.result, out, ids);
    const exit = await exited; need(!failed && exit.code === 0 && exit.signal === null && stderrBytes === 0 && input.length === 0);
    stage = 'close'; await browser.close(); browser = null;
    return {schema: 'catchplate.privateGuidedBrowserJoined/v1', ok: true, browserClosed: true, browser: out, checker: result};
  } catch (_) {
    fs.writeFileSync(path.join(evidence, 'guided-browser-failure.json'), JSON.stringify(failureReceipt(stage, out, checkerFailure, stderr.snapshot())) + '\n', {flag: 'wx', mode: 0o600});
    throw new Error('Guided browser check failed');
  } finally {
    clearTimeout(timer); process.removeListener('SIGTERM', signal); process.removeListener('SIGINT', signal);
    if (browser) await browser.close().catch(() => {});
    if (child && child.exitCode === null && child.signalCode === null) { child.stdin.destroy(); child.kill('SIGTERM'); }
    // Runner owns exact checker container cleanup and original cgroup teardown.
  }
}
module.exports = {readyFrame, requestFrame, responseFrame, continueFrame, checkerFailureFrame, stderrCollector,
  failureReceipt, publicFailureReceipt, applicationRevocationDialog, downloadedBytes, validateChecker,
  credentialReplyFault, recoveryEvidence, validateRecovery};
if (require.main === module) main().then(value => process.stdout.write(JSON.stringify(value) + '\n')).catch(() => {
  process.stderr.write('Guided browser check failed; no private request, response or download details emitted\n'); process.exitCode = 1;
});
