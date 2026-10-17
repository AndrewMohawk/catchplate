#!/usr/bin/env node
'use strict';
// Explicit one-shot real UI creation/revocation through the internal app bridge.
// No external SSO, proxy request, provider operation, restart, or history deletion.
// Usage: node THIS FULL_APP_ID SOURCE_COMMIT FRESH_PRIVATE_OUTPUT_DIRECTORY
// --self-test is pure: no browser/process execution, filesystem, or live imports.
const {createHash, randomBytes} = require('node:crypto');
const APP = 'e55a00276cfea38d01ebea858177de182773a228c336a117aad41fdd3c84088a';
const COMMIT = 'a30c645ef06711a4acf605c3f01f4b129d10b0f6';
const PUBLIC = 'https://catchplate-demo.example.com', PREFIX = '/api/operator-demo/';
const COLLECTIONS = ['credentials', 'applications', 'access_rules'];
const KINDS = ['credential', 'application', 'rule'], ROUTES = ['credentials', 'applications', 'access-rules'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const DUMMY = 'Bearer CATCHPLATE_BROWSER_SYNTHETIC_DUMMY';
const SCRIPTS = ['workspace_core.js', 'workspace_github.js', 'workspace_npm.js', 'workspace_npm_publish.js', 'workspace_x.js',
  'workspace_alchemy.js', 'workspace_aws.js', 'workspace_google.js', 'workspace_google_reauthorization.js', 'workspace_resources.js',
  'workspace_applications.js', 'workspace_gmail_sdk.js', 'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_notifications.js',
  'workspace_upstreams.js', 'workspace_google_configuration.js', 'app.js'];
class Refusal extends Error {}
function need(value, code) { if (!value) throw new Refusal(code); }
const sha = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ?
  Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const serial = value => JSON.stringify(stable(value));
const resourceName = (run, index) => 'catchplate-browser-' + run + '-' + KINDS[index];
const loaded = catalog => catalog?.policy?.activation === 'active' && catalog.policy.loaded_policy_hash === catalog.policy.policy_hash;
function parameters(args) {
  need(args.length === 3 && args[0] === APP && args[1] === COMMIT && typeof args[2] === 'string' &&
    args[2].startsWith('/') && !args[2].includes('\0'), 'reviewed_parameters_required');
  return {app: args[0], commit: args[1], output: args[2]};
}
function ruleValues(run, owned) {
  return {name: resourceName(run, 2), application_id: owned.applications, credential_id: owned.credentials,
    upstream_url: 'https://demo-upstream:8443/echo', methods: ['POST'], request_fields: [], response_fields: [],
    request_body_mode: 'preserve_json_v1', response_mode: 'unfiltered_json_or_empty_v2', credential_input: 'replace_exact',
    placeholder: DUMMY, query_keys: [], allowed_headers: ['accept', 'user-agent']};
}
function scriptRoster(portal) {
  need(typeof portal === 'string' && Buffer.byteLength(portal) <= 65536 && (portal.match(/^SCRIPT_FILES\s*=/gm) || []).length === 1,
    'renderer_roster_refused');
  const match = /^SCRIPT_FILES = \(([^)]*)\)/m.exec(portal);
  need(match && /^\s*"[a-z_]+\.js"(?:\s*,\s*"[a-z_]+\.js")*\s*,?\s*$/.test(match[1]), 'renderer_roster_refused');
  const names = JSON.parse('[' + match[1].replace(/,\s*$/, '') + ']');
  need(serial(names) === serial(SCRIPTS), 'renderer_roster_refused'); return names;
}
function requestAdmission(url, method, headers, body, expectedRoute) {
  need(typeof url === 'string' && (url === PUBLIC + '/' || url.startsWith(PUBLIC + PREFIX)), 'browser_origin_refused');
  need(!['authorization', 'proxy-authorization', 'x-catchplate-admin-token', 'cookie', 'transfer-encoding'].some(key => headers[key]),
    'browser_private_header_refused');
  const path = url.slice(PUBLIC.length);
  if (method === 'GET') need(['/', PREFIX + 'catalog'].includes(path) && !body?.length, 'browser_get_refused');
  else need(method === 'POST' && path === expectedRoute && Buffer.isBuffer(body) && body.length > 0 && body.length <= 8192 &&
    headers['content-type'] === 'application/json', 'browser_post_refused');
  return path;
}
function preserved(before, after, owned) {
  for (const collection of COLLECTIONS) {
    const original = new Map(before[collection].map(row => [row.id, row]));
    const current = new Map(after[collection].map(row => [row.id, row]));
    const extra = owned[collection] ? [owned[collection]] : [];
    need(current.size === after[collection].length && current.size === original.size + extra.length &&
      [...current.keys()].every(id => original.has(id) || extra.includes(id)) &&
      [...original].every(([id, row]) => serial(row) === serial(current.get(id))), 'prior_resource_rows_changed');
  }
}
function commandEnvironment(binary) {
  // Bound only the host Docker CLI's Go scheduler, not Chromium or the app.
  return {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', ...(binary === '/usr/bin/docker' ? {GOMAXPROCS: '2'} : {})};
}
function latestCatalogResponse(requestEpoch, latestEpoch) {
  return Number.isSafeInteger(requestEpoch) && requestEpoch > 0 && requestEpoch === latestEpoch;
}
function stderrSignature(binary, stderr) {
  // Inspect only a fixed prefix, and return an enum, never a matching substring.
  // A signature identifies emitted text, not which host/cgroup limit caused it.
  if (binary !== '/usr/bin/docker') return 'not_docker';
  if (typeof stderr !== 'string' || stderr.length === 0) return 'none';
  const prefix = stderr.slice(0, 8192);
  if (/^runtime: failed to create new OS thread \(have [0-9]{1,10} already; errno=11\)\r?$/m.test(prefix) &&
      /^fatal error: newosproc\r?$/m.test(prefix)) return 'go_os_thread_resource';
  if (/^OCI runtime exec failed:/m.test(prefix))
    return /resource temporarily unavailable/.test(prefix) ? 'oci_exec_resource' : 'oci_exec_failed';
  if (/^Error response from daemon: [Cc]ontainer [0-9a-f]{12,64} is not running\r?$/m.test(prefix)) return 'container_not_running';
  if (/^Error response from daemon: No such container:/m.test(prefix)) return 'container_missing';
  if (/^Cannot connect to the Docker daemon at /m.test(prefix)) return 'docker_daemon_unreachable';
  return 'unclassified';
}
function subprocessFailure(binary, error, stdout, stderr) {
  // Closed diagnostic categories only. argv, stderr, raw response bytes and
  // exception messages may contain the one-time token and are never retained.
  return {executable: binary === '/usr/bin/docker' ? 'docker' : 'other',
    code: Number.isInteger(error.code) ? error.code :
      ['EAGAIN', 'ENOMEM', 'ENOENT', 'EACCES'].includes(error.code) ? error.code : 'other',
    signal: ['SIGKILL', 'SIGTERM', 'SIGABRT', 'SIGSEGV'].includes(error.signal) ? error.signal : null,
    killed: error.killed === true,
    bridge_refused: typeof stdout === 'string' && stdout.trim() === '{"ok":false,"reason":"runtime_creation_bridge_refused"}',
    stderr_signature: stderrSignature(binary, stderr),
    stderr_prefix_only: typeof stderr === 'string' && stderr.length > 8192};
}
function selfTest() {
  const assert = require('node:assert/strict');
  assert.equal(parameters([APP, COMMIT, '/private/fresh']).app, APP);
  assert.throws(() => parameters(['0'.repeat(64), COMMIT, '/private/fresh']));
  assert.deepEqual(scriptRoster('SCRIPT_FILES = (' + SCRIPTS.map(name => JSON.stringify(name)).join(',') + ',)'), SCRIPTS);
  assert.throws(() => scriptRoster('SCRIPT_FILES = ("../outside.js",)'));
  assert.equal(requestAdmission(PUBLIC + '/', 'GET', {}, null, null), '/');
  for (const [url, method, headers, body] of [[PUBLIC + '/outside', 'GET', {}, null], [PUBLIC + '/', 'GET', {cookie: 'x'}, null],
    [PUBLIC + PREFIX + 'credentials', 'POST', {'content-type': 'application/json'}, Buffer.from('{}')]])
    assert.throws(() => requestAdmission(url, method, headers, body, null));
  const rows = Object.fromEntries(COLLECTIONS.map(key => [key, [{id: 'old', status: 'active'}]]));
  preserved(rows, rows, {});
  assert.throws(() => preserved(rows, {...rows, credentials: [{id: 'old', status: 'revoked'}]}, {}));
  assert.equal(ruleValues('a'.repeat(32), {applications: 'a', credentials: 'c'}).response_mode, 'unfiltered_json_or_empty_v2');
  assert.deepEqual(subprocessFailure('/usr/bin/docker', {code: 2, message: 'PRIVATE', signal: 'PRIVATE'},
    '{"ok":false,"reason":"runtime_creation_bridge_refused"}'),
  {executable: 'docker', code: 2, signal: null, killed: false, bridge_refused: true, stderr_signature: 'none', stderr_prefix_only: false});
  assert(!serial(subprocessFailure('PRIVATE', {code: 'PRIVATE', message: 'PRIVATE'}, 'PRIVATE')).includes('PRIVATE'));
  const thread = 'runtime: failed to create new OS thread (have 16 already; errno=11)\n' +
    'runtime: may need to increase max user processes (ulimit -u)\nfatal error: newosproc\nPRIVATE';
  for (const [stderr, expected] of [[thread, 'go_os_thread_resource'], [thread.replace('errno=11', 'errno=22'), 'unclassified'],
    ['fatal error: newosproc\nPRIVATE', 'unclassified'], ['OCI runtime exec failed: PRIVATE: resource temporarily unavailable', 'oci_exec_resource'],
    ['OCI runtime exec failed: PRIVATE', 'oci_exec_failed'], ['Error response from daemon: Container ' + APP + ' is not running\nPRIVATE', 'container_not_running'],
    ['Error response from daemon: No such container: PRIVATE', 'container_missing'], ['Cannot connect to the Docker daemon at PRIVATE', 'docker_daemon_unreachable'],
    ['PRIVATE', 'unclassified'], ['x'.repeat(8192) + '\n' + thread, 'unclassified'], ['', 'none']]) {
    const diagnostic = subprocessFailure('/usr/bin/docker', {code: 2}, '', stderr);
    assert.equal(diagnostic.stderr_signature, expected);
    assert.equal(diagnostic.stderr_prefix_only, stderr.length > 8192);
    assert(!serial(diagnostic).includes('PRIVATE'));
  }
  assert.deepEqual(commandEnvironment('/usr/bin/docker'), {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GOMAXPROCS: '2'});
  for (const binary of ['/usr/bin/python3', '/tmp/docker', 'docker'])
    assert.deepEqual(commandEnvironment(binary), {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'});
  const altered = commandEnvironment('/usr/bin/docker'); altered.GOMAXPROCS = '99';
  assert.equal(commandEnvironment('/usr/bin/docker').GOMAXPROCS, '2');
  let latest = 0, observation = 'baseline';
  const older = ++latest, newer = ++latest;
  const accept = (epoch, value) => { if (latestCatalogResponse(epoch, latest)) observation = value; };
  accept(older, 'stale_before_latest'); assert.equal(observation, 'baseline');
  accept(newer, 'latest'); accept(older, 'stale_after_latest'); assert.equal(observation, 'latest');
  for (const invalid of [0, -1, true, null, '2', 1.5, 3]) assert.equal(latestCatalogResponse(invalid, latest), false);
  return {ok: true, groups: 8, scope: 'pure admission, source, preservation, diagnostics, Docker-only environment, and catalog response ordering'};
}

async function run(args) {
  const selected = parameters(args);
  const fs = require('node:fs'), path = require('node:path'), {execFile} = require('node:child_process');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const {app, commit, output} = selected, root = path.resolve(__dirname, '..');
  const source = path.join(path.dirname(root), 'catchplate-operator-artifacts/source-' + commit);
  need(path.resolve(output) === output && fs.realpathSync(path.dirname(output)) === path.dirname(output), 'private_output_path_refused');
  const parent = fs.statSync(path.dirname(output));
  need(parent.isDirectory() && parent.uid === process.geteuid() && (parent.mode & 0o777) === 0o700, 'private_output_parent_refused');
  process.umask(0o077); fs.mkdirSync(output, {mode: 0o700});
  const runId = randomBytes(16).toString('hex'), owned = Object.fromEntries(COLLECTIONS.map(key => [key, null]));
  const secret = 'catchplate-browser-synthetic-key-' + runId;
  const bridgeCode = fs.readFileSync(path.join(__dirname, 'operator_runtime_creation_bridge.py'), 'utf8');
  const receipt = {schema: 'catchplate.operatorRuntimeCreationBrowser/v1', ok: false, runId, appContainerId: app, sourceCommit: commit,
    boundary: 'Actual internal app UI creation and normal local revocation only. No external SSO, proxy or provider request; no history deletion.',
    driverSha256: sha(fs.readFileSync(__filename)), bridgeSha256: sha(bridgeCode), consumedAssets: [], mutations: [],
    resourceIds: owned, tokenWrittenToEvidence: false, browserTransactionVerified: false, resourcesRevoked: false,
    refusedRequests: 0, pageErrors: 0, consoleErrors: 0, subprocessFailures: []};
  const children = new Set(), claims = new Set(), acknowledged = new Set();
  let browser, page, stopped = false, phase = 'identity', expectedRoute = null, routeFailure = null;
  let expectedHtml, original, lastCatalog, heldToken = null, dialogExpected = null, gets = 0, browserCatalogEpoch = 0;
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  function journal(file, value) {
    const fd = fs.openSync(path.join(output, file), 'wx', 0o600);
    try { fs.writeFileSync(fd, serial(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const directory = fs.openSync(output, 'r'); try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }
  journal('run-claim.json', {runId, app, commit, driverSha256: receipt.driverSha256, bridgeSha256: receipt.bridgeSha256,
    plannedNames: KINDS.map((_, index) => resourceName(runId, index))});
  const timer = setTimeout(() => {
    stopped = true; receipt.deadlineReached = true;
    for (const child of children) child.kill('SIGKILL');
    browser?.close().catch(() => {});
  }, 175000);
  async function command(binary, argv, input = '') {
    need(!stopped, 'run_stopped');
    return new Promise((resolve, reject) => {
      const child = execFile(binary, argv, {timeout: 12000, killSignal: 'SIGKILL', maxBuffer: 3 * 1024 * 1024,
        encoding: 'utf8', env: commandEnvironment(binary)}, (error, stdout, stderr) => {
        children.delete(child);
        if (error) {
          if (receipt.subprocessFailures.length < 16) receipt.subprocessFailures.push({phase, ...subprocessFailure(binary, error, stdout, stderr)});
          reject(new Refusal('bounded_transport_refused'));
        } else resolve(stdout);
      });
      children.add(child); child.stdin.on('error', () => {}); child.stdin.end(input);
    });
  }
  async function identity() {
    const format = '{"id":{{json .Id}},"running":{{json .State.Running}},"health":{{json .State.Health.Status}},' +
      '"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"mounts":[' +
      '{{range .Mounts}}{{if eq .Destination "/app"}}{"source":{{json .Source}},"rw":{{json .RW}},"type":{{json .Type}}}{{end}}{{end}}]}';
    const actual = JSON.parse(await command('/usr/bin/docker', ['inspect', '--format', format, app]));
    need(actual.id === app && actual.running === true && actual.health === 'healthy' && actual.project === 'catchplate-operator-demo' &&
      actual.service === 'catchplate' && serial(actual.mounts) === serial([{source, rw: false, type: 'bind'}]), 'runtime_identity_changed');
  }
  function documentBytes() {
    need(fs.realpathSync(source) === source && (fs.statSync(source).mode & 0o777) === 0o555, 'source_root_refused');
    const observations = [];
    function read(relative) {
      const file = path.join(source, relative), info = fs.lstatSync(file);
      need(fs.realpathSync(file) === file && info.isFile() && info.nlink === 1 && (info.mode & 0o777) === 0o444 &&
        info.size > 0 && info.size <= 2 * 1024 * 1024, 'consumed_asset_refused');
      const bytes = fs.readFileSync(file); observations.push({path: relative, sha256: sha(bytes)}); return bytes.toString('utf8');
    }
    const names = scriptRoster(read('catchplate/operator_demo_portal.py'));
    const asset = name => read('catchplate/operator_demo_web/' + name);
    let html = asset('index.html'); const scripts = names.map(asset).join('\n'), css = asset('style.css');
    need(!/<\/script/i.test(scripts) && !/<\/style/i.test(css), 'raw_asset_terminator');
    for (const [marker, value] of [['__OPERATOR_DEMO_STYLE__', css], ['__OPERATOR_DEMO_SCRIPT__', "(() => {\n'use strict';\n" + scripts + '\n})();\n']]) {
      need(html.split(marker).length === 2, 'renderer_marker_refused'); html = html.replace(marker, () => value);
    }
    if (receipt.consumedAssets.length) need(serial(observations) === serial(receipt.consumedAssets), 'consumed_assets_changed');
    else receipt.consumedAssets = observations;
    return Buffer.from(html);
  }
  function catalog(value) {
    need(value?.schema === 'catchplate.operatorCatalog/v1' && value.mode === 'operator-development' && value.productionReady === false &&
      value.hardwareVerified === false && Number.isSafeInteger(value.revision) && /^sha256:[a-f0-9]{64}$/.test(value.policy?.policy_hash || '') &&
      value.allowed_upstreams?.includes('https://demo-upstream:8443') && COLLECTIONS.every(key => Array.isArray(value[key])), 'catalog_refused');
    for (const key of COLLECTIONS) need(new Set(value[key].map(row => row.id)).size === value[key].length, 'duplicate_catalog_id');
    return value;
  }
  async function transport(method, requestPath, body = null) {
    const payload = {method, path: requestPath, body_base64: body ? body.toString('base64') : '',
      headers: method === 'POST' ? {'content-type': 'application/json'} : {}, run_id: runId, owned: {...owned}};
    const result = JSON.parse(await command('/usr/bin/docker', ['exec', '-i', app, 'python3', '-I', '-B', '-c', bridgeCode], serial(payload)));
    need(result.ok === true && [200, 201].includes(result.status) && Array.isArray(result.headers), 'bridge_refused');
    const bytes = Buffer.from(result.body_base64, 'base64');
    need(bytes.length > 0 && bytes.length <= 2 * 1024 * 1024, 'response_size_refused');
    if (requestPath === '/') need(bytes.equals(expectedHtml), 'actual_renderer_differs');
    return {status: result.status, headers: Object.fromEntries(result.headers), body: bytes};
  }
  async function readCatalog() {
    need(++gets <= 80, 'read_budget_exhausted'); return catalog(JSON.parse((await transport('GET', PREFIX + 'catalog')).body));
  }
  function ownedRow(snapshot, index) {
    return snapshot[COLLECTIONS[index]].find(row => row.id === owned[COLLECTIONS[index]]);
  }
  function checkOwned(snapshot) {
    for (let index = 0; index < 3; index++) {
      const matches = snapshot[COLLECTIONS[index]].filter(row => row.name === resourceName(runId, index));
      need(matches.length === (owned[COLLECTIONS[index]] ? 1 : 0), 'owned_name_ambiguous');
      if (matches.length) {
        const row = matches[0]; need(row.id === owned[COLLECTIONS[index]], 'owned_id_changed');
        if (index === 0) need(row.auth_type === 'bearer' && row.header_name === 'Authorization', 'owned_credential_changed');
        if (index === 1) need(row.principal_id === 'agent:operator-demo:' + row.id && row.token_generation === 1, 'owned_application_changed');
        if (index === 2) need(Object.entries(ruleValues(runId, owned)).every(([key, value]) => serial(row[key]) === serial(value)), 'owned_rule_changed');
      }
    }
  }
  async function waitFor(condition, code, ms = 12000) {
    const end = Date.now() + ms;
    while (!condition() && Date.now() < end && !stopped) { if (routeFailure) throw new Refusal(routeFailure); await pause(50); }
    need(!stopped && condition(), code);
  }
  async function navigate(section) {
    need(['credentials', 'applications', 'access-rules'].includes(section), 'navigation_refused');
    await page.locator('nav a[href="#' + section + '"]').click();
    await page.locator('#' + section).waitFor({state: 'visible'});
  }
  async function perform(index, revoke, click) {
    const route = PREFIX + ROUTES[index] + (revoke ? '/revoke' : '');
    need(!claims.has(route), 'mutation_replay_refused'); expectedRoute = route; routeFailure = null;
    try { await click(); await waitFor(() => acknowledged.has(route), 'mutation_not_acknowledged'); await page.waitForLoadState('networkidle'); }
    finally { expectedRoute = null; }
  }
  async function clearToken() {
    if (await page.locator('#one-time-access').isVisible()) {
      dialogExpected = 'Clear the one-time token from this page? It cannot be retrieved again.';
      await page.locator('#dismiss-token').click();
      need(dialogExpected === null, 'token_clear_confirmation_missing');
    }
    heldToken = null;
    await page.waitForFunction(() => document.querySelector('#client-token').value === '' && document.querySelector('#one-time-access').hidden);
    need(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0 &&
      [...document.querySelectorAll('input[type="password"]')].every(input => input.value === '')), 'browser_secret_not_cleared');
  }
  async function cleanup() {
    if (stopped || !page || !original) return;
    phase = 'cleanup'; routeFailure = null; expectedRoute = null;
    // A lost create response may be reconciled once, never submitted again.
    let snapshot = await readCatalog();
    const unresolved = [];
    for (let index = 0; index < 3; index++) {
      if (owned[COLLECTIONS[index]] || !claims.has(PREFIX + ROUTES[index])) continue;
      const matches = snapshot[COLLECTIONS[index]].filter(row => row.name === resourceName(runId, index));
      need(matches.length <= 1, 'uncertain_creation_ambiguous');
      if (matches.length) {
        need(UUID.test(matches[0].id) && !original[COLLECTIONS[index]].some(row => row.id === matches[0].id), 'uncertain_creation_not_owned');
        owned[COLLECTIONS[index]] = matches[0].id;
        journal('reconciled-' + KINDS[index] + '.json', {id: matches[0].id, name: matches[0].name});
      } else unresolved.push(KINDS[index]);
    }
    checkOwned(snapshot);
    // Reload clears any uncertainty UI without replaying a write. Every revoke
    // still comes from the real exact-ID card with current UI CAS metadata.
    await page.reload({waitUntil: 'networkidle'});
    await clearToken();
    for (const index of [2, 1, 0]) {
      if (!owned[COLLECTIONS[index]]) continue;
      snapshot = await readCatalog(); checkOwned(snapshot);
      const row = ownedRow(snapshot, index), route = PREFIX + ROUTES[index] + '/revoke';
      if (row.status === 'revoked') continue;
      need(row.status === 'active' && !claims.has(route), 'uncertain_revocation_not_replayed');
      await navigate(ROUTES[index]);
      const refresh = index === 2 ? 'rules-refresh' : ROUTES[index] + '-refresh';
      await page.locator('#' + refresh).click(); await page.waitForLoadState('networkidle');
      if (index === 0) {
        const card = page.locator('#credentials-list [data-resource-id="' + row.id + '"]');
        const group = card.locator('xpath=ancestor::details[@data-expired-app-access][1]');
        need(await group.count() <= 1, 'credential_group_ambiguous');
        if (await group.count() === 1 && !await group.evaluate(node => node.open))
          await group.locator(':scope > summary').click();
        await card.waitFor({state: 'visible'});
      }
      dialogExpected = index === 2 ? `Revoke rule "${row.name}" (${row.id})? The application and saved credential remain. New requests are denied after the proxy loads the updated policy; already-dispatched requests cannot be recalled.` :
        index === 1 ? `Revoke application "${row.name}" (${row.id}) and its 0 active access rules? Shared provider credentials and other applications remain. Enforcement begins after the proxy loads the new policy; already-dispatched requests cannot be recalled.` :
        `Revoke locally stored credential "${row.name}" (${row.id})? This does not revoke the key at its provider.`;
      const list = index === 2 ? 'access-rules-list' : ROUTES[index] + '-list';
      await perform(index, true, () => page.locator('#' + list + ' [data-resource-id="' + row.id + '"] [data-action="revoke-' + KINDS[index] + '"]').click());
      need(dialogExpected === null, 'revoke_confirmation_missing');
    }
    const end = Date.now() + 20000;
    do { snapshot = await readCatalog(); if (loaded(snapshot)) break; await pause(500); } while (Date.now() < end && !stopped);
    need(loaded(snapshot), 'cleanup_policy_not_loaded'); checkOwned(snapshot); preserved(original, snapshot, owned);
    need(COLLECTIONS.every((key, index) => !owned[key] || ownedRow(snapshot, index).status === 'revoked'), 'owned_resource_not_revoked');
    if (owned.access_rules) need(ownedRow(snapshot, 2).enforcement === 'revoked', 'revocation_not_enforced');
    receipt.resourcesRevoked = unresolved.length === 0; receipt.finalRevision = snapshot.revision; receipt.finalPolicy = snapshot.policy;
    journal(unresolved.length ? 'cleanup-uncertain.json' : 'cleanup-confirmed.json', {resourceIds: owned, revision: snapshot.revision,
      policy: snapshot.policy, unresolvedCreations: unresolved, priorResourceRowsPreserved: true,
      retainedRowsAdded: COLLECTIONS.filter(key => owned[key]).length});
    need(unresolved.length === 0, 'claimed_creation_outcome_unresolved');
  }
  try {
    await identity(); expectedHtml = documentBytes(); original = await readCatalog();
    need(loaded(original), 'baseline_policy_not_loaded'); receipt.initialRevision = original.revision; receipt.initialPolicy = original.policy;
    receipt.initialCounts = Object.fromEntries(COLLECTIONS.map(key => [key, original[key].length]));
    journal('baseline-resource-commitments.json', {schema: 'catchplate.operatorBrowserBaselineRows/v1', runId, sourceCommit: commit,
      revision: original.revision, policy: original.policy,
      canonicalization: 'SHA256 of UTF-8 compact JSON with recursively sorted object keys; array order retained',
      rows: Object.fromEntries(COLLECTIONS.map(key => [key, original[key].map(row => ({id: row.id, sha256: sha(serial(row))}))]))});
    for (const key of COLLECTIONS) {
      const limit = original.limits?.[key];
      need(limit && limit.active < limit.active_max && limit.retained < limit.retained_max &&
        !original[key].some(row => KINDS.some((_, index) => row.name === resourceName(runId, index))), 'capacity_or_name_refused');
    }
    for (const [key, value] of [['credential_types', 'bearer'], ['request_body_modes', 'preserve_json_v1'],
      ['response_modes', 'unfiltered_json_or_empty_v2'], ['credential_input_modes', 'replace_exact']])
      need(original.capabilities?.[key]?.includes(value), 'required_capability_missing');
    browser = await chromium.launch({headless: true, timeout: 15000, args: ['--disable-background-networking', '--disable-component-update',
      '--disable-sync', '--host-resolver-rules=MAP * ~NOTFOUND']});
    const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block', acceptDownloads: false});
    context.setDefaultTimeout(10000); context.setDefaultNavigationTimeout(15000);
    await context.routeWebSocket('**/*', socket => { receipt.refusedRequests++; socket.close(); });
    await context.route('**/*', async route => {
      const request = route.request();
      const catalogEpoch = request.method() === 'GET' && request.url() === PUBLIC + PREFIX + 'catalog' ? ++browserCatalogEpoch : null;
      try {
        const body = request.postDataBuffer(), requestPath = requestAdmission(request.url(), request.method(), await request.allHeaders(), body, expectedRoute);
        need(requestPath === '/' ? request.isNavigationRequest() : request.resourceType() === 'fetch', 'request_kind_refused');
        if (request.method() === 'GET') {
          need(++gets <= 80, 'read_budget_exhausted'); const response = await transport('GET', requestPath);
          if (requestPath !== '/') {
            const observed = catalog(JSON.parse(response.body));
            if (latestCatalogResponse(catalogEpoch, browserCatalogEpoch)) lastCatalog = observed;
          }
          await route.fulfill(response); return;
        }
        need(!claims.has(requestPath) && claims.size < 6, 'mutation_replay_refused');
        const input = JSON.parse(body), revoke = requestPath.endsWith('/revoke');
        const index = ROUTES.findIndex(value => requestPath === PREFIX + value + (revoke ? '/revoke' : ''));
        need(index >= 0 && input.expected_revision === lastCatalog?.revision && input.expected_policy_hash === lastCatalog?.policy.policy_hash,
          'browser_cas_differs');
        const ordinal = claims.size + 1;
        journal(String(ordinal) + '-mutation-claim.json', {path: requestPath, method: 'POST', name: resourceName(runId, index),
          ownedIds: {...owned}, expectedRevision: input.expected_revision, expectedPolicyHash: input.expected_policy_hash});
        claims.add(requestPath); receipt.mutations.push({path: requestPath, via: 'actual_ui', state: 'submitted_response_uncertain'});
        const response = await transport('POST', requestPath, body), result = JSON.parse(response.body);
        const row = result[index === 2 ? 'access_rule' : KINDS[index]];
        need(row && UUID.test(row.id) && row.name === resourceName(runId, index) && result.revision === input.expected_revision + 1 &&
          row.status === (revoke ? 'revoked' : 'active'), 'mutation_receipt_differs');
        if (revoke) need(row.id === owned[COLLECTIONS[index]], 'revoke_receipt_id_differs');
        else {
          need(!owned[COLLECTIONS[index]] && !original[COLLECTIONS[index]].some(old => old.id === row.id), 'created_id_not_new');
          owned[COLLECTIONS[index]] = row.id;
          if (index === 1) {
            need(TOKEN.test(result.client_token || '') && row.token_generation === 1 &&
              row.token_expires_at_epoch_ms > Date.now() + 3500000 && row.token_expires_at_epoch_ms <= Date.now() + 3600000, 'one_time_token_differs');
            heldToken = result.client_token;
          }
        }
        receipt.mutations.at(-1).state = 'acknowledged';
        journal(String(ordinal) + '-mutation-ack.json', {id: row.id, path: requestPath, status: row.status, revision: result.revision, policy: result.policy});
        acknowledged.add(requestPath); await route.fulfill(response);
      } catch (error) {
        receipt.refusedRequests++; routeFailure = error instanceof Refusal ? error.message : 'browser_transport_refused';
        await route.abort().catch(() => {});
      }
    });
    page = await context.newPage();
    page.on('pageerror', () => receipt.pageErrors++); page.on('console', message => { if (message.type() === 'error') receipt.consoleErrors++; });
    page.on('dialog', async dialog => {
      if (dialog.type() === 'confirm' && dialog.message() === dialogExpected) { dialogExpected = null; await dialog.accept(); }
      else { receipt.refusedRequests++; await dialog.dismiss(); }
    });
    page.on('download', download => { receipt.refusedRequests++; download.cancel().catch(() => {}); });
    page.on('popup', popup => { receipt.refusedRequests++; popup.close().catch(() => {}); });
    page.on('worker', () => receipt.refusedRequests++);
    await page.goto(PUBLIC + '/', {waitUntil: 'networkidle'});
    need(lastCatalog?.revision === original.revision && loaded(lastCatalog), 'browser_baseline_drifted');
    phase = 'create_credential'; await navigate('credentials');
    await page.locator('#credentials [data-credential-provider="manual"]').click();
    await page.locator('#connect-credential-name').fill(resourceName(runId, 0)); await page.locator('#connect-credential-secret').fill(secret);
    await perform(0, false, () => page.locator('#connect-credential-next').click());
    need(await page.locator('#connect-credential-secret').inputValue() === '', 'submitted_secret_not_cleared');
    need(await page.locator('#connect-credential-saved').isVisible() &&
      await page.locator('#connect-application-step').isHidden(), 'save_only_credential_boundary_differs');
    phase = 'create_application'; await navigate('applications');
    await page.locator('#application-name').fill(resourceName(runId, 1)); await page.locator('#application-token-ttl').selectOption('3600');
    await perform(1, false, () => page.locator('#application-create').click());
    need(await page.locator('#client-token').getAttribute('type') === 'password' &&
      await page.locator('#client-token').inputValue() === heldToken && await page.locator('#one-time-access').isVisible(), 'one_time_token_ui_differs');
    need(!serial(lastCatalog).includes(heldToken) && await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), 'token_persisted_publicly');
    phase = 'create_rule'; await navigate('access-rules');
    await page.locator('#rule-application-id').selectOption(owned.applications); await page.locator('#rule-credential-id').selectOption(owned.credentials);
    await page.locator('#rule-credential-input').selectOption('replace_exact'); await page.locator('#rule-placeholder').fill(DUMMY);
    await page.locator('#rule-upstream-origin').selectOption('https://demo-upstream:8443'); await page.locator('#rule-path').fill('/echo');
    for (const value of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) await page.locator('input[name="rule-method"][value="' + value + '"]').setChecked(value === 'POST');
    if (!await page.locator('#rule-restrictions').evaluate(node => node.open)) await page.locator('#rule-restrictions > summary').click();
    await page.locator('#rule-name').fill(resourceName(runId, 2));
    await page.locator('#rule-request-body-mode').selectOption('preserve_json_v1');
    await page.locator('#rule-response-mode').selectOption('unfiltered_json_or_empty_v2');
    await perform(2, false, () => page.locator('#rule-save').click());
    await waitFor(() => loaded(lastCatalog) && lastCatalog.revision === original.revision + 3, 'created_rule_not_loaded', 30000);
    checkOwned(lastCatalog); preserved(original, lastCatalog, owned);
    need(ownedRow(lastCatalog, 2).enforcement === 'active', 'created_rule_not_active');
    await page.locator('#access-rules-list [data-resource-id="' + owned.access_rules + '"] .badge').filter({hasText: /^Active$/}).waitFor();
    phase = 'token_dismissal'; await navigate('applications'); await clearToken();
    await page.reload({waitUntil: 'networkidle'}); await clearToken();
    need(await page.locator('#client-token').isDisabled() && await page.locator('#download-config').isDisabled(), 'token_retrieved_after_reload');
    receipt.browserTransactionVerified = true; receipt.oneTimeTokenClearedAndNotRetrieved = true;
  } catch (error) { receipt.failure = error instanceof Refusal ? error.message : 'browser_step_failed'; receipt.failurePhase = phase; }
  finally {
    try { await cleanup(); } catch (error) { receipt.cleanupFailure = error instanceof Refusal ? error.message : 'cleanup_step_failed'; }
    heldToken = null;
    try { if (!stopped) { await identity(); need(documentBytes().equals(expectedHtml), 'served_source_changed'); } }
    catch (_) { receipt.identityRecheckFailed = true; }
    clearTimeout(timer); stopped = true;
    for (const child of children) child.kill('SIGKILL');
    try { await browser?.close(); } catch (_) { receipt.browserCloseFailed = true; }
    receipt.ok = !receipt.failure && !receipt.cleanupFailure && !receipt.identityRecheckFailed && !receipt.browserCloseFailed &&
      receipt.browserTransactionVerified && receipt.resourcesRevoked && receipt.mutations.length === 6 &&
      receipt.mutations.every(row => row.state === 'acknowledged') && receipt.refusedRequests === 0 && receipt.pageErrors === 0 && receipt.consoleErrors === 0;
    if (receipt.ok && (receipt.finalRevision !== receipt.initialRevision + 6 ||
        receipt.finalPolicy.sequence !== receipt.initialPolicy.sequence + 2)) {
      receipt.ok = false; receipt.failure = 'six_mutation_revision_or_policy_sequence_differs';
    }
    journal('result.json', receipt);
  }
  return receipt;
}

module.exports = {parameters, ruleValues, scriptRoster, requestAdmission, preserved, commandEnvironment, latestCatalogResponse,
  stderrSignature, subprocessFailure, selfTest};
if (require.main === module) {
  if (process.argv.length === 3 && process.argv[2] === '--self-test') console.log(JSON.stringify(selfTest()));
  else run(process.argv.slice(2)).then(result => { console.log(JSON.stringify(result)); process.exitCode = result.ok ? 0 : 1; })
    .catch(() => { console.log('{"ok":false,"reason":"runtime_creation_browser_refused"}'); process.exitCode = 1; });
}
