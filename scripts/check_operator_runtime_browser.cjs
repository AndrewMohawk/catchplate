#!/usr/bin/env node
'use strict';
// Actual app responses through an internal GET-only bridge. No external SSO,
// provider, proxy, CA, notification delivery, restart or mutation acceptance.
// Usage: node scripts/check_operator_runtime_browser.cjs FULL_APP_ID SOURCE_COMMIT FRESH_OUTPUT_DIRECTORY
//   [--managed-google-unconfigured] [--expected-upstreams JSON_ARRAY] [--expected-catalog-revision INTEGER]
const {readFileSync, realpathSync, mkdirSync, writeFileSync} = require('node:fs');
const {join, dirname, resolve, isAbsolute} = require('node:path');
const {createHash} = require('node:crypto');
const {execFile} = require('node:child_process');
const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
const ROOT = resolve(__dirname, '..'), PUBLIC = 'https://serverware-demo.example.com';
const CATALOG = '/api/operator-demo/catalog', NOTIFICATIONS = '/api/operator-demo/notifications', UPSTREAMS = '/api/operator-demo/proxy/upstreams';
const PATHS = ['/', CATALOG, NOTIFICATIONS, UPSTREAMS], FIXTURE = 'https://demo-upstream:8443';
const GOOGLE = '/api/operator-demo/oauth/google/configuration/v2', GMAIL = 'https://gmail.googleapis.com';
const REVIEWED_UPSTREAMS = [[FIXTURE], [FIXTURE, GMAIL],
  [FIXTURE, 'https://api.github.com', 'https://registry.npmjs.org', GMAIL]];
const GOOGLE_SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const SLOTS = ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'];
const SCRIPTS = ['workspace_core.js', 'workspace_github.js', 'workspace_npm.js', 'workspace_npm_publish.js', 'workspace_x.js', 'workspace_alchemy.js', 'workspace_aws.js', 'workspace_google.js', 'workspace_google_reauthorization.js',
  'workspace_resources.js', 'workspace_applications.js', 'workspace_gmail_sdk.js', 'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_notifications.js', 'workspace_upstreams.js', 'workspace_google_configuration.js', 'app.js'];
const PRE_GMAIL_SCRIPTS = SCRIPTS.filter(name => name !== 'workspace_gmail_sdk.js');
const SCRIPT_ROSTERS = [PRE_GMAIL_SCRIPTS.filter(name => !['workspace_x.js', 'workspace_alchemy.js', 'workspace_aws.js'].includes(name)),
  PRE_GMAIL_SCRIPTS.filter(name => !['workspace_alchemy.js', 'workspace_aws.js'].includes(name)),
  PRE_GMAIL_SCRIPTS.filter(name => name !== 'workspace_aws.js'), PRE_GMAIL_SCRIPTS, SCRIPTS];
const sha = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ?
  Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const serial = value => JSON.stringify(stable(value));
class Refusal extends Error {}
function need(value, reason) { if (!value) throw new Refusal(reason); }
let appId, commit, output, source, manifest, expectedHtml, bridgeCode, browser, context, phase = 'parameters', claimed = false, stopped = false, timer;
let managedGoogle = false;
let expectedUpstreams = [FIXTURE], expectedRevision = null;
const paths = () => managedGoogle ? [...PATHS, GOOGLE] : PATHS;
const children = new Set(), before = {}, seen = {};
const receipt = {schema: 'serverware.operatorRuntimeReadonlyBrowser/v1', ok: false, gets: [], screenshots: [], refused_requests: 0,
  page_errors: 0, console_errors: 0, boundary: 'Actual internal app HTML/APIs only. No external SSO, provider, proxy, CA, delivery or mutation acceptance.'};
function parseRuntimeOptions(args) {
  need(Array.isArray(args) && args.length >= 3 && args.length <= 8 && args.every(value => typeof value === 'string'),
    'usage_full_app_id_commit_fresh_output');
  const selected = {appId: args[0], commit: args[1], output: args[2], managedGoogle: false,
    expectedUpstreams: [FIXTURE], expectedRevision: null, explicitUpstreams: false};
  const used = new Set();
  for (let index = 3; index < args.length; index++) {
    const flag = args[index];
    need(['--managed-google-unconfigured', '--expected-upstreams', '--expected-catalog-revision'].includes(flag) && !used.has(flag),
      'runtime_option_refused');
    used.add(flag);
    if (flag === '--managed-google-unconfigured') selected.managedGoogle = true;
    else {
      const value = args[++index];
      need(typeof value === 'string' && value.length <= 1024, 'runtime_option_value_refused');
      if (flag === '--expected-upstreams') {
        let origins;
        try { origins = JSON.parse(value); } catch (_) { throw new Refusal('expected_upstreams_refused'); }
        need(REVIEWED_UPSTREAMS.some(reviewed => serial(origins) === serial(reviewed)), 'expected_upstreams_refused');
        selected.expectedUpstreams = origins; selected.explicitUpstreams = true;
      } else {
        need(/^[1-9][0-9]*$/.test(value) && Number.isSafeInteger(Number(value)), 'expected_revision_refused');
        selected.expectedRevision = Number(value);
      }
    }
  }
  return selected;
}
const expectedGoogleRevision = () => expectedRevision === null ? 13 : expectedRevision;
const expectedGoogleOrigins = () => expectedUpstreams.includes(GMAIL) ? [...expectedUpstreams] : [...expectedUpstreams, GMAIL];
const expectedGoogleAddedOrigin = () => expectedUpstreams.includes(GMAIL) ?
  'None — https://gmail.googleapis.com is already an allowed destination.' : GMAIL;
function applicationBadge(application, catalog, now = Date.now()) {
  const expiry = application.token_expires_at_epoch_ms;
  const loaded = catalog.policy?.activation === 'active' && catalog.policy.loaded_policy_hash === catalog.policy.policy_hash;
  need(['active', 'revoked'].includes(application.status) && Number.isSafeInteger(expiry) && expiry > 0 &&
    Number.isSafeInteger(application.token_generation) && application.token_generation > 0 &&
    Number.isSafeInteger(application.active_rule_count) && application.active_rule_count >= 0, 'reviewed_application_state_mismatch');
  const revoked = application.status === 'revoked', expired = now >= expiry;
  const token = revoked ? 'revoked' : expired ? 'expired' : 'valid';
  const access = revoked ? loaded ? 'revoked' : 'pending' : !application.active_rule_count ? 'unassigned' :
    loaded && !expired ? 'active' : 'pending';
  need(application.token_status === token && application.access_status === access, 'reviewed_application_state_mismatch');
  return revoked ? loaded ? 'Revoked · enforced' : 'Revoked · enforcement pending' : expired ? 'Token expired' :
    access === 'unassigned' ? 'No access rules' : loaded && access === 'active' ? 'Active' : 'Access pending';
}
function subprocessFailure(binary, error, stdout) {
  // Public diagnostic categories only: never retain argv, stderr, raw response
  // bytes or exception messages, which may contain secrets.
  return {
    executable: binary === '/usr/bin/docker' ? 'docker' : 'other',
    code: Number.isInteger(error.code) ? error.code :
      ['EAGAIN', 'ENOMEM', 'ENOENT', 'EACCES'].includes(error.code) ? error.code : 'other',
    signal: ['SIGKILL', 'SIGTERM', 'SIGABRT', 'SIGSEGV'].includes(error.signal) ? error.signal : null,
    killed: error.killed === true,
    bridge_refused: typeof stdout === 'string' && stdout.trim() === '{"ok":false,"reason":"runtime_readonly_bridge_refused"}'
  };
}
function command(binary, args, input = '', timeout = 25000) {
  need(!stopped, 'run_stopped');
  return new Promise((resolve, reject) => {
    const child = execFile(binary, args, {timeout, killSignal: 'SIGKILL', maxBuffer: 3 * 1024 * 1024,
      encoding: 'utf8', env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'}}, (error, stdout) => {
      children.delete(child);
      if (error) {
        receipt.subprocess_failure = subprocessFailure(binary, error, stdout);
        reject(new Refusal('bounded_subprocess_refused'));
      } else resolve(stdout);
    });
    children.add(child); child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
async function bridge(payload) {
  const value = JSON.parse(await command('/usr/bin/docker', ['exec', '-i', appId, 'python3', '-I', '-B', '-', JSON.stringify(payload)], bridgeCode));
  need(value.ok === true, 'bridge_refused'); return value;
}
async function identity() {
  // Deliberately never inspect environment variables, logs or private mounts.
  const format = '{"id":{{json .Id}},"running":{{json .State.Running}},"health":{{json .State.Health.Status}},' +
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"mounts":[' +
    '{{range .Mounts}}{{if eq .Destination "/app"}}{"source":{{json .Source}},"rw":{{json .RW}},"type":{{json .Type}}}{{end}}{{end}}]}';
  const actual = JSON.parse(await command('/usr/bin/docker', ['inspect', '--format', format, appId]));
  need(actual.id === appId && actual.running === true && actual.health === 'healthy' && actual.project === 'serverware-operator-demo' &&
    actual.service === 'serverware' && serial(actual.mounts) === serial([{source, rw: false, type: 'bind'}]), 'runtime_identity_mismatch');
  const verified = JSON.parse(await command('/usr/bin/python3', ['-I', '-B', join(__dirname, 'verify_operator_source_snapshot.py'), '--commit', commit], '', 40000));
  need(verified.ok === true && verified.commit === commit && verified.source === source && verified.git_blob_equality === true &&
    verified.world_readable_and_nonwritable === true && /^[0-9a-f]{64}$/.test(verified.manifest_sha256), 'host_source_mismatch');
  if (manifest) need(serial(verified) === serial(manifest), 'host_source_changed'); else manifest = verified;
  const inside = await bridge({op: 'source', manifest_sha256: manifest.manifest_sha256, files: manifest.files});
  need(inside.manifest_sha256 === manifest.manifest_sha256 && inside.files === manifest.files, 'container_source_mismatch');
}
function sourceScriptFiles() {
  // Read only the fixed literal from the already Git-verified source. Never
  // execute its renderer or permit arbitrary filenames/imports from the tuple.
  const portal = readFileSync(join(source, 'serverware/operator_demo_portal.py'), 'utf8');
  need(Buffer.byteLength(portal, 'utf8') <= 65536 && (portal.match(/^SCRIPT_FILES\s*=/gm) || []).length === 1,
    'renderer_roster_refused');
  const match = /^SCRIPT_FILES = \(([^)]*)\)/m.exec(portal);
  need(match && /^\s*"[a-z_]+\.js"(?:\s*,\s*"[a-z_]+\.js")*\s*,?\s*$/.test(match[1]), 'renderer_roster_refused');
  const names = JSON.parse('[' + match[1].replace(/,\s*$/, '') + ']');
  need(SCRIPT_ROSTERS.some(roster => serial(names) === serial(roster)), 'renderer_roster_refused');
  return names;
}
function documentBytes() {
  const names = sourceScriptFiles();
  const asset = name => readFileSync(join(source, 'serverware/operator_demo_web', name), 'utf8');
  let html = asset('index.html'); const scripts = names.map(asset).join('\n'), css = asset('style.css');
  need(!/<\/script/i.test(scripts) && !/<\/style/i.test(css), 'renderer_raw_text_terminator');
  for (const [marker, value] of [['__OPERATOR_DEMO_STYLE__', css], ['__OPERATOR_DEMO_SCRIPT__', "(() => {\n'use strict';\n" + scripts + '\n})();\n']]) {
    need(html.split(marker).length === 2, 'renderer_marker'); html = html.replace(marker, () => value);
  }
  return Buffer.from(html);
}
function snapshot(path, value) {
  const result = structuredClone(value);
  // These two sampling clocks are the only ignored public fields.
  if (path === CATALOG) delete result.observed_activity?.observed_at_epoch_ms;
  if (path === NOTIFICATIONS) delete result.worker?.last_cycle_at_epoch_ms;
  return result;
}
function validate(path, value) {
  if (path === CATALOG) {
    need(value.schema === 'serverware.operatorCatalog/v1' && value.mode === 'operator-development' && value.productionReady === false &&
      value.hardwareVerified === false && serial(value.allowed_upstreams) === serial(expectedUpstreams), 'catalog_profile_or_destination_changed');
    for (const key of ['credentials', 'applications', 'access_rules']) need(Array.isArray(value[key]) && value[key].length > 0, 'retained_resources_missing');
    if (expectedRevision === null) need(value.applications.every(app => app.status === 'active' && app.token_status === 'expired' &&
      Number.isSafeInteger(app.token_expires_at_epoch_ms) && app.token_expires_at_epoch_ms > 0 && app.token_expires_at_epoch_ms <= Date.now()), 'retained_app_not_expired');
    else {
      need(value.revision === expectedRevision, 'reviewed_catalog_revision_mismatch');
      for (const application of value.applications) applicationBadge(application, value);
    }
    if (managedGoogle) need(value.revision === expectedGoogleRevision() && value.capabilities?.oauth === false && value.capabilities.google_oauth === null,
      'managed_unconfigured_catalog_mismatch');
  } else if (path === NOTIFICATIONS) {
    need(value.schema === 'serverware.operatorNotifications/v1' && value.available === true && Array.isArray(value.slots) &&
      serial(value.slots.map(slot => slot.slot).sort()) === serial([...SLOTS].sort()), 'notification_slots_missing');
    for (const slot of value.slots) need(slot.enabled === false && slot.secret_present === false && slot.revision === 0 &&
      slot.label === '' && serial(slot.event_types) === '[]' && slot.last_delivery === null, 'notification_slot_not_unconfigured');
    need(value.capabilities?.native_hardware?.configured === false && value.capabilities.native_hardware.source_available === false &&
      value.capabilities.action_required?.source_available === false && value.capabilities.audit_log?.source_available === true &&
      value.worker?.state === 'running' && value.worker.last_code === 'ready', 'notification_source_state_changed');
  } else if (path === GOOGLE) {
    need(managedGoogle && exactKeys(value, ['schema', 'state', 'revision', 'policy_hash', 'effective_settings', 'effective_settings_digest',
      'public_url', 'redirect_uri', 'permission_preset', 'scopes', 'blocked_reason', 'review', 'operation', 'readiness']) &&
      value.schema === 'serverware.operatorGoogleConfiguration/v2' && value.state === 'unconfigured' && value.revision === expectedGoogleRevision() &&
      value.revision === before[CATALOG].revision && value.policy_hash === before[CATALOG].policy.policy_hash &&
      exactKeys(value.effective_settings, ['allowed_upstreams', 'fixture_cidrs']) &&
      serial(value.effective_settings) === serial(before[UPSTREAMS].old_settings) &&
      value.effective_settings_digest === 'sha256:' + sha(serial(value.effective_settings)) &&
      value.public_url === PUBLIC && value.redirect_uri === PUBLIC + '/api/oauth/callback/google' &&
      value.permission_preset === 'gmail_readonly' && serial(value.scopes) === serial(GOOGLE_SCOPES) &&
      value.blocked_reason === null && value.operation === null, 'managed_google_discovery_mismatch');
    need(exactKeys(value.readiness, ['pair_ready', 'consent_ready', 'loaded_policy_hash']) &&
      value.readiness.pair_ready === true && value.readiness.consent_ready === false &&
      value.readiness.loaded_policy_hash === value.policy_hash, 'managed_google_readiness_mismatch');
    const review = value.review;
    need(exactKeys(review, ['schema', 'expected_revision', 'expected_policy_hash', 'expected_settings_digest', 'old_settings',
      'target_settings', 'public_url', 'redirect_uri', 'provider_id', 'permission_preset', 'scopes', 'eligible']) &&
      review.schema === 'serverware.operatorGoogleManagedSetupReview/v2' && review.expected_revision === value.revision &&
      review.expected_policy_hash === value.policy_hash && review.expected_settings_digest === value.effective_settings_digest &&
      serial(review.old_settings) === serial(value.effective_settings) &&
      serial(review.target_settings) === serial({allowed_upstreams: expectedGoogleOrigins(), fixture_cidrs: value.effective_settings.fixture_cidrs}) &&
      review.public_url === PUBLIC && review.redirect_uri === value.redirect_uri && review.provider_id === 'google' &&
      review.permission_preset === 'gmail_readonly' && serial(review.scopes) === serial(GOOGLE_SCOPES) && review.eligible === true,
      'managed_google_review_mismatch');
  } else need(value.schema === 'serverware.operatorUpstreamSetupReview/v1' &&
    exactKeys(value.old_settings, ['allowed_upstreams', 'fixture_cidrs']) &&
    serial(value.old_settings.allowed_upstreams) === serial(expectedUpstreams) &&
    value.expected_settings_digest === 'sha256:' + sha(serial(value.old_settings)) &&
    value.cold_restart_required === true && value.eligible === true && value.pending_operation_id === null && value.blocked_reason === null &&
    value.expected_revision === before[CATALOG].revision && value.expected_policy_hash === before[CATALOG].policy.policy_hash, 'upstream_review_mismatch');
  const observed = snapshot(path, value);
  if (Object.hasOwn(before, path)) need(serial(observed) === serial(before[path]), 'public_resource_changed_during_read');
  else before[path] = observed;
}
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && serial(Object.keys(value).sort()) === serial([...keys].sort());
}
async function get(path) {
  need(paths().includes(path) && receipt.gets.length < (managedGoogle ? 17 : 16), 'get_route_or_bound');
  receipt.gets.push({path, method: 'GET'}); const response = await bridge({op: 'get', path,
    ...(managedGoogle ? {managed_google_unconfigured: true} : {})});
  const body = Buffer.from(response.body_base64, 'base64');
  need(response.status === 200 && body.length > 0 && body.length <= 2 * 1024 * 1024 && Array.isArray(response.headers), 'response_invalid');
  if (path === '/') need(body.equals(expectedHtml), 'actual_renderer_mismatch'); else validate(path, JSON.parse(body));
  return {status: response.status, headers: Object.fromEntries(response.headers), body};
}
async function noSecrets(page) {
  need(await page.evaluate(() => [...document.querySelectorAll('input[type="password"]')].every(field => field.value === '') &&
    document.getElementById('client-token').value === '' && localStorage.length === 0 && sessionStorage.length === 0), 'browser_secret_or_storage_present');
  need(await page.locator('#one-time-access').isHidden() && await page.locator('#client-token').isDisabled(), 'one_time_access_unexpected');
}
async function capture(page, selector, name) {
  await noSecrets(page); need(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'horizontal_overflow');
  await page.locator(selector).screenshot({path: join(output, name), animations: 'disabled', timeout: 10000});
  receipt.screenshots.push({file: name, sha256: sha(readFileSync(join(output, name)))});
}
async function navigateSection(page, name) {
  need(['proxy', 'applications', 'notifications'].includes(name), 'navigation_section_refused');
  const link = page.locator('nav a[href="#' + name + '"]');
  await link.click();
  await page.locator('section.page#' + name).waitFor({state: 'visible'});
  need(await link.getAttribute('aria-current') === 'page' && await page.locator('section.page:visible').count() === 1,
    'navigation_state_mismatch');
}
async function verifyProxyDefault(page) {
  const checks = {
    panel_visible: await page.locator('#proxy-upstreams').isVisible(),
    effective_fixture: await page.locator('#upstreams-effective').innerText() === expectedUpstreams.join('\n'),
    form_hidden: await page.locator('#upstreams-form').isHidden(),
    no_review_get: !seen[UPSTREAMS],
    restart_notice_present: (await page.locator('#proxy-upstreams').innerText()).includes('Apps still need permission. Changes require a controlled restart.'),
  };
  const valid = Object.values(checks).every(value => value === true);
  if (!valid) receipt.proxy_default_checks = checks; // Fixed booleans only, never DOM text.
  need(valid, 'proxy_default_mismatch');
}
async function run() {
  const selected = parseRuntimeOptions(process.argv.slice(2));
  ({appId, commit, output, managedGoogle, expectedUpstreams, expectedRevision} = selected);
  need(/^[0-9a-f]{64}$/.test(appId) && /^[0-9a-f]{40}$/.test(commit) && isAbsolute(output) && resolve(output) === output &&
    realpathSync(dirname(output)) === dirname(output), 'exact_parameters_required');
  source = join(dirname(ROOT), 'serverware-operator-artifacts/source-' + commit);
  need(realpathSync(source) === source, 'source_directory_not_exact');
  bridgeCode = readFileSync(join(__dirname, 'operator_runtime_readonly_bridge.py'), 'utf8');
  mkdirSync(output, {mode: 0o700}); claimed = true; // A used directory can never be replayed.
  receipt.app_container_id = appId; receipt.source_commit = commit; receipt.started_at = new Date().toISOString();
  if (managedGoogle) receipt.mode = 'managed-google-unconfigured';
  if (selected.explicitUpstreams || expectedRevision !== null) receipt.expected_upstreams = [...expectedUpstreams];
  if (expectedRevision !== null) receipt.expected_catalog_revision = expectedRevision;
  receipt.checker_sha256 = sha(readFileSync(__filename)); receipt.bridge_sha256 = sha(bridgeCode);
  writeFileSync(join(output, 'run-claim.json'), serial({appId, commit, started_at: receipt.started_at,
    ...(receipt.expected_upstreams ? {expected_upstreams: receipt.expected_upstreams} : {}),
    ...(expectedRevision !== null ? {expected_catalog_revision: expectedRevision} : {})}) + '\n', {flag: 'wx', mode: 0o600});
  phase = 'identity_before'; await identity(); expectedHtml = documentBytes();
  phase = 'public_before'; for (const path of paths()) await get(path);
  phase = 'render';
  const launched = await chromium.launch({headless: true, timeout: 15000, args: ['--disable-background-networking', '--disable-component-update',
    '--disable-sync', '--host-resolver-rules=MAP * ~NOTFOUND']});
  if (stopped) { await launched.close(); throw new Refusal('run_stopped'); } browser = launched;
  const opened = await browser.newContext({viewport: {width: 1280, height: 960}, locale: 'en-US', timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false});
  if (stopped) { await opened.close(); throw new Refusal('run_stopped'); } context = opened;
  context.setDefaultTimeout(5000); context.setDefaultNavigationTimeout(15000);
  await context.routeWebSocket('**/*', socket => { receipt.refused_requests++; socket.close(); });
  await context.route('**/*', async route => {
    const request = route.request();
    try {
      const path = request.url().slice(PUBLIC.length), headers = await request.allHeaders();
      need(request.url() === PUBLIC + path && paths().includes(path) && request.method() === 'GET' && !request.postDataBuffer() &&
        !headers.authorization && !headers['proxy-authorization'] && !headers['x-serverware-admin-token'] && !headers.cookie &&
        !headers['transfer-encoding'] && (!headers['content-length'] || headers['content-length'] === '0'), 'browser_request_refused');
      seen[path] = (seen[path] || 0) + 1;
      need(path === '/' ? phase === 'render' && seen[path] === 1 && request.isNavigationRequest() && request.resourceType() === 'document' :
        request.resourceType() === 'fetch' && (path === CATALOG ? seen[path] <= (managedGoogle ? 3 : 2) &&
          ['render', 'review', ...(managedGoogle ? ['google_review'] : [])].includes(phase) :
          path === UPSTREAMS ? phase === 'review' && seen[path] === 1 : path === GOOGLE ?
            managedGoogle && phase === 'google_review' && seen[path] === 1 : phase === 'notifications' && seen[path] === 1), 'browser_request_phase_refused');
      await route.fulfill(await get(path)); // Actual body and headers; no fixture or security-header substitution.
    } catch (error) {
      receipt.refused_requests++; receipt.refusal_reason = error instanceof Refusal ? error.message : 'browser_response_refused';
      await route.abort().catch(() => {});
    }
  });
  const page = await context.newPage();
  page.on('pageerror', () => receipt.page_errors++); page.on('console', message => { if (message.type() === 'error') receipt.console_errors++; });
  page.on('download', download => { receipt.refused_requests++; download.cancel().catch(() => {}); });
  page.on('dialog', dialog => { receipt.refused_requests++; dialog.dismiss().catch(() => {}); });
  page.on('popup', popup => { receipt.refused_requests++; popup.close().catch(() => {}); });
  page.on('worker', () => receipt.refused_requests++); context.on('serviceworker', () => receipt.refused_requests++);
  await page.goto(PUBLIC + '/', {waitUntil: 'networkidle'});
  await page.waitForFunction(() => !document.getElementById('credential-fields').disabled && document.getElementById('load-error').hidden);
  need(await page.title() === 'Overview - Serverware operator workspace' && seen[CATALOG] === 1, 'landing_failed');
  phase = 'proxy'; await navigateSection(page, 'proxy');
  await verifyProxyDefault(page);
  phase = 'review'; await page.locator('#upstreams-review').click();
  await page.waitForFunction(() => !document.getElementById('upstreams-review').disabled && !document.getElementById('upstreams-form').hidden);
  await page.waitForLoadState('networkidle');
  need(seen[UPSTREAMS] === 1 && seen[CATALOG] === 2 && await page.locator('#upstreams-proposed').inputValue() === expectedUpstreams.join('\n') &&
    await page.locator('#upstreams-effective').innerText() === expectedUpstreams.join('\n') && await page.locator('#upstreams-prepare').isDisabled() &&
    await page.locator('#upstreams-operation').isHidden() && (await page.locator('#upstreams-form').innerText()).includes('cold restart before it takes effect'), 'review_not_readonly');
  for (const width of [1280, 390]) { await page.setViewportSize({width, height: width === 1280 ? 960 : 844}); await capture(page, '#proxy', 'proxy-review-' + width + '.png'); }
  if (managedGoogle) {
    phase = 'google_review'; await page.setViewportSize({width: 1280, height: 960});
    need(!seen[GOOGLE] && await page.locator('#google-configuration-panel').isVisible() &&
      await page.locator('#google-configuration-form').isHidden(), 'managed_google_opening_not_inert');
    const response = page.waitForResponse(value => value.url() === PUBLIC + GOOGLE && value.request().method() === 'GET');
    await page.locator('#google-configuration-review').click(); await (await response).finished();
    await page.waitForFunction(() => !document.getElementById('google-configuration-review').disabled &&
      !document.getElementById('google-configuration-form').hidden);
    need(seen[GOOGLE] === 1 && seen[CATALOG] === 3 &&
      await page.locator('#google-configuration-callback').innerText() === PUBLIC + '/api/oauth/callback/google' &&
      (await page.locator('#google-configuration-discovery-state').innerText()).startsWith('Not configured.') &&
      await page.locator('#google-configuration-client-id').inputValue() === '' &&
      await page.locator('#google-configuration-client-secret').inputValue() === '' &&
      await page.locator('#google-configuration-prepare').isDisabled() &&
      await page.locator('#google-configuration-operation').isHidden() &&
      await page.locator('#google-configuration-check').isDisabled() && await page.locator('#google-configuration-cancel').isDisabled() &&
      await page.locator('#google-configuration-connect-link').isHidden(), 'managed_google_form_not_unconfigured');
    await page.locator('#google-configuration-scopes').locator('..').locator(':scope > summary').click();
    need(await page.locator('#google-configuration-scopes').isVisible() &&
      await page.locator('#google-configuration-scopes').innerText() === GOOGLE_SCOPES.join('\n') &&
      await page.locator('#google-configuration-added-upstream').innerText() === expectedGoogleAddedOrigin() &&
      (await page.locator('#google-configuration-review-state').innerText()).includes('Prepare does not restart services or contact Google.'),
      'managed_google_scope_review_mismatch');
    for (const width of [1280, 390]) { await page.setViewportSize({width, height: width === 1280 ? 960 : 844});
      await capture(page, '#google-configuration-panel', 'google-configuration-unconfigured-' + width + '.png'); }
    receipt.managed_google = {state: 'unconfigured', revision: expectedGoogleRevision(), pair_ready: true, consent_ready: false, operation: null, prepare_sent: false};
  }
  phase = 'applications'; await page.setViewportSize({width: 1280, height: 960}); await navigateSection(page, 'applications');
  need(await page.locator('#applications-list [data-resource-id]').count() === before[CATALOG].applications.length, 'retained_application_rows_changed');
  for (const app of before[CATALOG].applications) need(await page.locator('#applications-list [data-resource-id="' + app.id + '"] .badge').innerText() ===
    (expectedRevision === null ? 'Token expired' : applicationBadge(app, before[CATALOG])), 'application_badge_mismatch');
  await capture(page, '#applications-list', expectedRevision === null ? 'expired-applications.png' : 'reviewed-applications.png');
  phase = 'notifications'; await navigateSection(page, 'notifications');
  await page.waitForFunction(() => !document.getElementById('notifications-refresh').disabled && document.querySelectorAll('form[data-notification-slot]').length === 4);
  need(seen[NOTIFICATIONS] === 1 && await page.locator('[data-notification-channel="action_required"]').count() === 1 &&
    await page.locator('[data-notification-channel="audit_log"]').count() === 1 &&
    (await page.locator('[data-native-source]').innerText()).includes('not configured') && await page.locator('[data-native-review]').isHidden() &&
    await page.locator('[data-native-review]').getAttribute('href') === null, 'notification_separation_or_native_state');
  for (const slot of SLOTS) {
    const form = page.locator('form[data-notification-slot="' + slot + '"]');
    need(await form.locator('[data-slot-status]').innerText() === 'Not configured.' && !await form.locator('[name="enabled"]').isChecked() &&
      await form.locator('[name="url"]').inputValue() === '' && await form.locator('[data-notification-test]').isDisabled(), 'notification_controls_not_disabled');
  }
  for (const width of [1280, 390]) { await page.setViewportSize({width, height: width === 1280 ? 960 : 844}); await capture(page, '#notifications', 'notifications-' + width + '.png'); }
  await noSecrets(page); need(context.pages().length === 1, 'unexpected_page');
  await context.close(); context = null; await browser.close(); need(!browser.isConnected(), 'browser_close_unconfirmed'); browser = null;
  phase = 'public_after'; for (const path of paths()) await get(path);
  phase = 'identity_after'; await identity();
  need(receipt.gets.length === (managedGoogle ? 17 : 13) && receipt.refused_requests === 0 && receipt.page_errors === 0 && receipt.console_errors === 0 && children.size === 0, 'final_boundary_check_failed');
  receipt.source = manifest; receipt.html_sha256 = sha(expectedHtml);
  receipt.unchanged_public_sha256 = Object.fromEntries(Object.entries(before).map(([path, value]) => [path, sha(serial(value))]));
  receipt.ignored_sampling_clocks = ['catalog.observed_activity.observed_at_epoch_ms', 'notifications.worker.last_cycle_at_epoch_ms'];
  receipt.checks = ['exact_running_readonly_source_before_after', 'actual_html_and_public_resources_unchanged',
    selected.explicitUpstreams ? 'proxy_exact_reviewed_destinations_and_explicit_GET_review' : 'proxy_effective_fixture_and_explicit_GET_review',
    'restart_required_no_preparation', expectedRevision === null ? 'retained_expired_applications' : 'exact_reviewed_application_states_and_badges',
    'separate_action_and_audit_four_disabled_slots', 'desktop_mobile_no_overflow', 'browser_closed'];
  if (managedGoogle) receipt.checks.push(expectedRevision === null ? 'managed_unconfigured_exact_GET_review_revision13_pair_ready_no_consent' :
    'managed_unconfigured_exact_reviewed_revision_pair_ready_no_consent', 'empty_writeonly_provider_form_no_prepare');
  receipt.ok = true; phase = 'complete';
}
(async () => {
  try { await Promise.race([run(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Refusal('overall_120s_deadline')), 120000); })]); }
  catch (error) { receipt.reason = error instanceof Refusal ? error.message : 'unexpected_failure_redacted'; }
  finally {
    stopped = true; clearTimeout(timer); for (const child of children) child.kill('SIGKILL');
    for (const handle of [context, browser]) {
      try { if (handle) await handle.close(); } catch (_) { receipt.ok = false; receipt.cleanup_failure = true; }
    }
    receipt.phase = phase; receipt.finished_at = new Date().toISOString();
    if (claimed) writeFileSync(join(output, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    process.stdout.write(JSON.stringify(receipt) + '\n'); process.exitCode = receipt.ok ? 0 : 1;
  }
})();
