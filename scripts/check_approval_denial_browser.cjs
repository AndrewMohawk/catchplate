// Rendered Approve/Deny UI only (historical filename retained): every HTTP
// request and navigator.credentials.get is synthetic.
// No browser launcher, app import, backend, real authority, provider or hardware.
// Prefer Playwright MCP when its runtime permits loading this module. The MCP
// runtime tested here has neither require nor dynamic import; in that runtime,
// use the installed local Playwright fallback in a bounded owned process:
//   const {chromium} = require('/installed/playwright');
//   const {check} = require('/reviewed/repo/scripts/check_approval_denial_browser.cjs');
//   const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
//   try { await check(browser, {
//     fixturePath: '/tmp/fresh-owned/fixture.json', fixtureSha256: '<export receipt>',
//     appSha256: '<reviewed app.py SHA-256>', evidenceDir: '/tmp/fresh-owned/actual'
//   }); } finally { await browser.close(); }
// The helper opens and closes only new isolated contexts, never the MCP page or
// shared browser. Output directory must not exist. Stops on the first failure.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ORIGIN = 'https://approval-denial.example.test';
const ID = '11111111-1111-4111-8111-111111111111';
const RECEIPT = '22222222-2222-4222-8222-222222222222';
const CHALLENGE = '33333333-3333-4333-8333-333333333333';
const MARKER = `catchplate.approvalDecisionUncertain.${ID}`;
const PRIVATE_REVIEW = 'SYNTHETIC_PRIVATE_REVIEW_DISPLAY';
const REASON = 'Synthetic reviewer chose to deny this request';
const CSRF = 'synthetic-csrf-not-an-authorization';
const CREDENTIAL = Buffer.from('synthetic-credential').toString('base64url');
const BYTES = {
  challenge: Buffer.alloc(32, 3).toString('base64url'),
  clientDataJSON: Buffer.from('synthetic-client-data').toString('base64url'),
  authenticatorData: Buffer.from('synthetic-authenticator-data').toString('base64url'),
  signature: Buffer.from('synthetic-signature-not-a-valid-signature').toString('base64url'),
};
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const digest = char => 'sha256:' + char.repeat(64);
const response = value => ({status: 200, contentType: 'application/json', body: JSON.stringify(value)});
const CASES = [
  {name: 'desktop-panel-denial', kind: 'deny'},
  {name: 'mobile-queue-denial', kind: 'deny', mobile: true, queue: true},
  {name: 'unknown-reload-recovery', kind: 'deny', unknown: true},
  {name: 'desktop-panel-approval', kind: 'approve'},
  {name: 'mobile-queue-approval-vote', kind: 'approve', mobile: true, queue: true, votePending: true},
  {name: 'unknown-approval-reload-recovery', kind: 'approve', unknown: true},
];

function fixtures(spec) {
  const now = Date.now();
  const at = offset => new Date(now + offset).toISOString();
  // Independent literals matching db.approval_public_summary and the stored
  // catchplate.jitApproverPolicy/v1 DTO, not a production-function-derived oracle.
  const policy = {schema: 'catchplate.jitApproverPolicy/v1', requiredRoles: ['approver'], roleMatch: 'any',
    allowedApproverIds: spec.votePending ? ['oidc:synthetic-reviewer', 'oidc:synthetic-second'] : ['oidc:synthetic-reviewer'],
    allowAnyApproverId: false, requireWebAuthn: true, threshold: spec.votePending ? 2 : 1,
    credentialPolicy: {allowedCredentialRecordIds: ['synthetic-record'], allowedAuthenticatorClasses: ['hardware'],
      allowedAaguids: [], requireAttestationTrusted: true, requiredTrustBundleDigest: null,
      minimumTrustBundleSequence: null, rpId: new URL(ORIGIN).hostname, origins: [ORIGIN],
      requireUserPresence: true, requireUserVerification: true, counterPolicy: 'strict-or-zero', maxAssertionAgeSeconds: 120}};
  const item = {id: ID, status: 'pending', route_id: 'synthetic-route', principal_id: 'user:fixture',
    credential_id: 'synthetic-credential', credential_version: 1, policy_hash: digest('a'),
    request_digest: digest('b'), operation_digest: digest('c'), method: 'POST', url: digest('d'),
    requested_at: at(-10000), expires_at: at(120000), grant_ttl_seconds: 30, grant_max_uses: 1,
    approved_until: null, decision_note: null, approver_policy_digest: digest('f'),
    verified_assertion_receipt_digest: null, approved_by: null, approver_policy: policy};
  const review = {id: ID, status: item.status, route_id: item.route_id, principal_id: item.principal_id,
    credential_ref: item.credential_id, credential_version: item.credential_version,
    policy_hash: item.policy_hash, method: item.method, requested_at: item.requested_at,
    expires_at: item.expires_at, url: 'https://synthetic.example.test/redacted',
    source_identity: {syntheticOnly: true}, normalized_operation_fields: {name: 'synthetic.write'},
    redacted_payload_summary: {display: PRIVATE_REVIEW}, risk_flags: ['policy_hash_current'],
    previous_similar_approvals: [], review_digest: digest('e'),
    retry_semantics: {request_digest: item.request_digest, operation_digest: item.operation_digest,
      grant_ttl_seconds: 30, grant_max_uses: 1},
    review_receipt: {id: RECEIPT, expires_at: at(90000)}};
  const options = {publicKey: {challenge: BYTES.challenge, rpId: new URL(ORIGIN).hostname,
    allowCredentials: [{type: 'public-key', id: CREDENTIAL}], timeout: 120000, userVerification: 'required'},
  catchplate: {operation: spec.kind === 'approve' ? 'jit.decide' : 'jit.deny', authorityChallengeId: CHALLENGE}};
  return {item, review, options, approvedUntil: at(30000)};
}

async function storage(page) {
  return page.evaluate(() => ({session: Object.entries(sessionStorage), local: Object.entries(localStorage)}));
}

async function textIs(page, selector, text) {
  await page.waitForFunction(({selector, text}) =>
    document.querySelector(selector)?.textContent.includes(text), {selector, text});
}

async function runCase(browser, html, spec, evidenceDir) {
  let context = null, page = null;
  const source = fixtures(spec);
  const terminal = spec.kind === 'approve' ? 'approved' : 'denied';
  const label = spec.kind === 'approve' ? 'Approve' : 'Deny';
  const ledger = [], events = [], errors = [], unexpected = [];
  const record = {name: spec.name, decision: spec.kind, syntheticOnly: true, passed: false, contextClosed: false,
    unknownOutcomeScenario: spec.unknown === true, thresholdVoteScenario: spec.votePending === true,
    requests: ledger, events, errors, unexpected, screenshots: [], phase: 'fixture-setup', timings: []};
  const started = Date.now();
  const phase = name => { record.phase = name; record.timings.push({phase: name, elapsedMs: Date.now() - started}); };
  let status = 'pending', terminalOnNextMetadata = false, timedOut = false, failure = null;
  const timeout = setTimeout(() => { timedOut = true; context?.close().catch(() => {}); }, 18000);
  const count = (method, endpoint) => ledger.filter(item => item.method === method && item.path === endpoint).length;
  const endpoint = `/api/approvals/${ID}`;
  const optionsPath = endpoint + (spec.kind === 'approve' ? '/webauthn/options' : '/deny/webauthn/options');
  const finalPath = endpoint + '/' + spec.kind;
  const metadata = () => ({...source.item, status, approved_until: status === 'approved' ? source.approvedUntil : null});
  try {
  context = await browser.newContext({viewport: spec.mobile ? {width: 390, height: 844}
    : {width: 1280, height: 900}, serviceWorkers: 'block', reducedMotion: 'reduce'});
  page = await context.newPage();
  page.setDefaultTimeout(4000);
  page.setDefaultNavigationTimeout(5000);
  page.on('pageerror', () => errors.push('pageerror'));
  page.on('console', message => { if (message.type() === 'error') errors.push('console.error'); });
  page.on('dialog', dialog => { unexpected.push('dialog'); dialog.dismiss().catch(() => {}); });
  context.on('page', popup => { if (popup !== page) { unexpected.push('popup'); popup.close().catch(() => {}); } });
  await context.exposeBinding('__syntheticDecisionAssertion', async (_, actual) => {
    assert.equal(count('POST', optionsPath), 1, 'assertion must follow exactly one matching options POST');
    assert.equal(count('POST', finalPath), 0, 'assertion must precede final POST');
    assert.deepEqual(actual.fields, ['publicKey']);
    assert.deepEqual(actual.publicKeyFields, ['allowCredentials', 'challenge', 'rpId', 'timeout', 'userVerification']);
    assert.equal(actual.challenge, BYTES.challenge);
    assert.equal(actual.rpId, new URL(ORIGIN).hostname);
    assert.equal(actual.userVerification, 'required');
    assert.deepEqual(actual.allowCredentials, [{type: 'public-key', id: CREDENTIAL}]);
    assert(Number.isInteger(actual.timeout) && actual.timeout > 0 && actual.timeout <= 90000);
    events.push('mock-assertion');
    return {id: CREDENTIAL, ...BYTES};
  });
  await context.addInitScript(() => {
    const encode = value => btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')
      + '='.repeat((4 - value.length % 4) % 4)), item => item.charCodeAt(0)).buffer;
    if (typeof PublicKeyCredential !== 'function' || !navigator.credentials) {
      throw new Error('Synthetic fixture requires a secure WebAuthn-capable browser context');
    }
    Object.defineProperty(navigator.credentials, 'get', {configurable: true, value: async options => {
      const key = options.publicKey;
      const value = await window.__syntheticDecisionAssertion({fields: Object.keys(options).sort(),
        publicKeyFields: Object.keys(key).sort(), challenge: encode(key.challenge), rpId: key.rpId,
        userVerification: key.userVerification, timeout: key.timeout,
        allowCredentials: key.allowCredentials.map(item => ({type: item.type, id: encode(item.id)}))});
      return {id: value.id, rawId: decode(value.id), type: 'public-key', response: {
        clientDataJSON: decode(value.clientDataJSON), authenticatorData: decode(value.authenticatorData),
        signature: decode(value.signature), userHandle: null}};
    }});
  });
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    ledger.push({method, path: url.pathname, query: url.search});
    try {
      assert(ledger.length <= 160, 'request budget exceeded');
      assert.equal(url.origin, ORIGIN, 'external origin attempted');
      assert.equal(request.headers().authorization, undefined, 'unexpected real authorization header');
      assert.equal(request.headers()['x-catchplate-admin-token'], undefined, 'unexpected operator token');
      assert.equal(request.headers().cookie, undefined, 'unexpected cookie');
      if (method === 'GET' && (url.pathname === '/' || url.pathname === `/approvals/${ID}`)) {
        assert.equal(url.search, '');
        return await route.fulfill({status: 200, contentType: 'text/html', body: html});
      }
      if (method === 'GET' && url.pathname === '/favicon.ico') return await route.fulfill({status: 204, body: ''});
      if (url.pathname === '/attestation') {
        assert.equal(method, 'GET');
        assert.deepEqual([...url.searchParams.keys()], ['nonce']);
        assert(/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('nonce')));
        return await route.fulfill(response({error: 'Synthetic UI check; no attestation'}));
      }
      const limited = ['/api/control-plane/approvals', '/api/setup/sessions'].includes(url.pathname);
      const decisionQuery = spec.kind === 'approve' && method === 'POST' && url.pathname === finalPath;
      assert.equal(url.search, limited ? '?limit=100' : decisionQuery ? '?ttl_seconds=30' : '');
      if (method === 'GET') {
        let value;
        switch (url.pathname) {
          case '/api/auth/status': value = {authenticated: true, userId: 'oidc:synthetic-reviewer',
            roles: ['approver'], authMethod: 'oidc-session', sessionState: 'active',
            webauthnRequired: false, oidcBrowserLoginConfigured: true, sessionActivationMode: 'protected'}; break;
          case '/api/bootstrap': value = {credentials: [], routes: [], approvals: [metadata()], logs: [],
            pendingOAuthCredentials: [], oauthIssuanceUncertainties: [], oauthProviders: [],
            policyPrincipals: [], webauthnCredentials: [], ca_ready: false,
            currentUserId: 'oidc:synthetic-reviewer'}; break;
          case '/api/control-plane/approvals': value = []; break;
          case '/api/policy': value = {ready: false, bundle: null}; break;
          case '/api/policy/canary/status': value = null; break;
          case '/api/setup/sessions': value = {sessions: []}; break;
          case '/api/csrf': value = {token: CSRF}; break;
          case '/api/approvals':
            if (terminalOnNextMetadata) {
              assert.equal(spec.unknown, true);
              assert.equal(count('GET', '/api/approvals'), 3);
              status = terminal;
              terminalOnNextMetadata = false;
            }
            events.push('metadata'); value = [metadata()]; break;
          case endpoint + '/review': events.push('private-review'); value = source.review; break;
          default: throw new Error('unmocked GET');
        }
        return await route.fulfill(response(value));
      }
      assert.equal(method, 'POST', 'only synthetic decision POSTs are allowed');
      assert.equal(request.headers()['x-catchplate-csrf-token'], CSRF);
      assert.equal(request.headers()['content-type'], 'application/json');
      const body = request.postDataJSON();
      if (url.pathname === optionsPath) {
        assert.equal(count('POST', optionsPath), 1);
        assert.deepEqual(body, spec.kind === 'approve' ? {reviewReceiptId: RECEIPT, ttlSeconds: 30}
          : {reason: REASON, reviewReceiptId: RECEIPT});
        assert.deepEqual(events, ['private-review']);
        events.push('options');
        return await route.fulfill(response(source.options));
      }
      assert.equal(url.pathname, finalPath, 'unexpected mutation');
      assert.equal(count('POST', finalPath), 1);
      assert.deepEqual(events, ['private-review', 'options', 'mock-assertion']);
      assert.deepEqual(body, {...(spec.kind === 'deny' ? {reason: REASON} : {}),
        reviewReceiptId: RECEIPT, authorityChallengeId: CHALLENGE,
        assertion: {id: CREDENTIAL, rawId: CREDENTIAL, type: 'public-key', response: {
          clientDataJSON: BYTES.clientDataJSON, authenticatorData: BYTES.authenticatorData, signature: BYTES.signature}}});
      assert.deepEqual(await storage(page), {session: [[MARKER, ID]], local: []}, 'pre-POST hold must contain only the UUID');
      events.push(spec.kind);
      if (spec.unknown) {
        // This deliberately incomplete response cannot prove approval/vote/denial.
        return await route.fulfill(response({id: ID, status: 'pending'}));
      }
      if (!spec.votePending) status = terminal;
      const result = spec.kind === 'approve' ? {...metadata(), data_plane_grant_publish: {
        enabled: !spec.votePending, ok: !spec.votePending, error: null}} : {id: ID, status};
      return await route.fulfill(response(result));
    } catch (_) {
      unexpected.push(`${method} ${url.pathname}`);
      await route.abort('blockedbyclient');
    }
  });
  const screenshot = async label => {
    const name = `${spec.name}-${label}.png`;
    await page.screenshot({path: path.join(evidenceDir, name), fullPage: false});
    record.screenshots.push({file: name, sha256: sha(fs.readFileSync(path.join(evidenceDir, name)))});
  };
    phase('document-load');
    await page.goto(ORIGIN + '/', {waitUntil: 'networkidle'});
    assert.equal(await page.title(), 'Catchplate');
    const queue = page.locator('#approvals');
    await queue.getByRole('button', {name: 'Review', exact: true}).waitFor({state: 'visible'});
    assert(await queue.getByRole('button', {name: 'Deny', exact: true}).isDisabled());
    assert(await queue.getByRole('button', {name: 'Approve', exact: true}).isDisabled());
    assert.equal(count('GET', endpoint + '/review'), 0);
    phase('review-click');
    await queue.getByRole('button', {name: 'Review', exact: true}).click();
    const note = page.locator(`#approval-review-deny-note-${ID}`);
    const panelAction = page.locator(`#approval-review-${spec.kind}-${ID}`);
    await note.waitFor({state: 'visible'});
    assert.equal(page.url(), ORIGIN + `/approvals/${ID}`);
    assert(await panelAction.isEnabled());
    assert((await page.locator('#approval-review').innerText()).includes(PRIVATE_REVIEW));
    if (spec.kind === 'deny') await note.fill('  ' + REASON + '  ');
    assert.equal(await queue.locator('input').count(), 0, 'queue must share the visible review note');
    await page.locator('#approval-review-actions').scrollIntoViewIfNeeded();
    await screenshot('decision');
    phase(spec.kind + '-click');
    const action = spec.queue ? queue.getByRole('button', {name: label, exact: true}) : panelAction;
    await action.click();
    const expectedMessage = spec.unknown ? (spec.kind === 'approve' ? 'Approval' : 'Denial') + ' outcome is unknown'
      : spec.votePending ? 'Approval vote recorded; waiting for additional approvers. No grant is ready yet.'
        : spec.kind === 'approve' ? 'Approval recorded and proxy grant delivery acknowledged.' : `Approval ${ID} was denied.`;
    await textIs(page, '#operator-status', expectedMessage);
    record.decisionStatus = await page.locator('#operator-status').innerText();
    assert.equal(await page.locator('#operator-status').getAttribute('class'),
      'operator-status ' + (spec.unknown ? 'error' : spec.votePending ? 'pending' : 'success'));
    assert.equal(count('POST', optionsPath), 1);
    assert.equal(count('POST', finalPath), 1);
    assert.equal(count('GET', endpoint + '/review'), 1);
    assert.equal(events.filter(item => item === 'mock-assertion').length, 1);
    assert(events.includes('metadata'));
    assert.equal(await page.locator('#approval-review-actions').isHidden(), true);
    assert(!(await page.locator('body').innerText()).includes(PRIVATE_REVIEW));
    if (spec.unknown || spec.votePending) {
      assert(await queue.getByRole('button', {name: 'Deny', exact: true}).isDisabled());
      assert(await queue.getByRole('button', {name: 'Approve', exact: true}).isDisabled());
    } else {
      assert.equal(await queue.getByRole('button', {name: 'Deny', exact: true}).count(), 0);
      assert.equal(await queue.getByRole('button', {name: 'Approve', exact: true}).count(), 0);
    }
    if (spec.votePending) {
      assert.equal(status, 'pending');
      assert.equal(metadata().approved_until, null);
    }
    if (spec.unknown) {
      phase('unknown-reload');
      assert.deepEqual(await storage(page), {session: [[MARKER, ID]], local: []});
      await page.reload({waitUntil: 'networkidle'});
      await queue.getByRole('button', {name: 'Review', exact: true}).waitFor({state: 'visible'});
      assert.equal(page.url(), ORIGIN + `/approvals/${ID}`);
      assert.equal(count('GET', endpoint + '/review'), 1, 'reload must not mint another review receipt');
      assert(!(await page.locator('body').innerText()).includes(PRIVATE_REVIEW));
      assert(await queue.getByRole('button', {name: 'Deny', exact: true}).isDisabled());
      assert(await queue.getByRole('button', {name: 'Approve', exact: true}).isDisabled());
      assert.deepEqual(await storage(page), {session: [[MARKER, ID]], local: []});
      const prior = count('GET', '/api/approvals');
      await queue.getByRole('button', {name: 'Review', exact: true}).click();
      await textIs(page, '#operator-status', 'Current approval status: pending. No decision or private review was retried.');
      assert.equal(count('GET', '/api/approvals'), prior + 1);
      assert.equal(count('GET', endpoint + '/review'), 1);
      assert.deepEqual(await storage(page), {session: [[MARKER, ID]], local: []});
      await queue.scrollIntoViewIfNeeded();
      await screenshot('reload-held');
      terminalOnNextMetadata = true;
      await queue.getByRole('button', {name: 'Review', exact: true}).click();
      await textIs(page, '#operator-status', `Current approval status: ${terminal}. No decision or private review was retried.`);
      assert.equal(await queue.getByRole('button', {name: 'Deny', exact: true}).count(), 0);
      assert.equal(await queue.getByRole('button', {name: 'Approve', exact: true}).count(), 0);
      await screenshot('terminal-recovered');
    } else {
      await queue.scrollIntoViewIfNeeded();
      await screenshot(spec.votePending ? 'vote-pending' : terminal);
    }
    assert.deepEqual(await storage(page), {session: [], local: []});
    assert.equal(count('GET', '/api/approvals'), spec.unknown ? 3 : 1);
    assert.equal(count('GET', `/approvals/${ID}`), spec.unknown ? 1 : 0);
    assert.equal(count('POST', optionsPath), 1);
    assert.equal(count('POST', finalPath), 1);
    assert.equal(count('POST', endpoint + (spec.kind === 'approve' ? '/deny' : '/approve')), 0);
    assert.equal(count('POST', endpoint + (spec.kind === 'approve' ? '/deny/webauthn/options' : '/webauthn/options')), 0);
    assert.equal(count('GET', endpoint + '/review'), 1);
    assert.equal(events.filter(item => item === 'mock-assertion').length, 1);
    assert.deepEqual(unexpected, []);
    assert.deepEqual(errors, []);
    assert.equal(timedOut, false);
    record.passed = true;
    phase('complete');
    record.counts = {optionsPosts: 1, syntheticAssertions: 1, decisionPosts: 1,
      approvalPosts: count('POST', endpoint + '/approve'), denialPosts: count('POST', endpoint + '/deny'), privateReviewGets: 1,
      metadataRecoveryGets: count('GET', '/api/approvals')};
    return record;
  } catch (error) {
    failure = error;
    record.failure = 'rendered-check-failed';
    record.failureMessage = String(error?.message || 'unknown failure').slice(0, 4096);
    try {
      record.failureLayout = await page.evaluate(() => {
        const button = [...document.querySelectorAll('#approvals button')].find(item => item.textContent === 'Review');
        if (!button) return {reviewFound: false};
        const dimensions = element => {
          const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
          return {tag: element.tagName, id: element.id, class: element.className,
            x: rect.x, y: rect.y, width: rect.width, height: rect.height,
            scrollWidth: element.scrollWidth, clientWidth: element.clientWidth,
            scrollLeft: element.scrollLeft, overflowX: style.overflowX, position: style.position};
        };
        const rect = button.getBoundingClientRect();
        const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
        const ancestors = [];
        for (let element = button; element && ancestors.length < 8; element = element.parentElement) ancestors.push(dimensions(element));
        return {reviewFound: true, operatorStatus: document.getElementById('operator-status')?.textContent,
          viewport: {width: innerWidth, height: innerHeight}, scrollX, scrollY,
          hit: hit ? dimensions(hit) : null, ancestors};
      });
    } catch (_) { record.failureLayout = {unavailable: true}; }
    try {
      const file = `${spec.name}-failure.png`;
      await page.screenshot({path: path.join(evidenceDir, file), fullPage: false, timeout: 2000});
      record.screenshots.push({file, sha256: sha(fs.readFileSync(path.join(evidenceDir, file)))});
    } catch (_) { record.failureScreenshotUnavailable = true; }
    throw error;
  } finally {
    clearTimeout(timeout);
    let cleanupFailure = null;
    try { if (context) await context.close(); } catch (error) { cleanupFailure = error; }
    record.contextClosed = context === null || !browser.contexts().includes(context);
    if (cleanupFailure || !record.contextClosed) {
      record.passed = false;
      record.cleanupFailure = 'owned-context-close-failed';
    }
    fs.writeFileSync(path.join(evidenceDir, `${spec.name}.json`), JSON.stringify(record, null, 2) + '\n',
      {flag: 'wx', mode: 0o600});
    if (!failure && record.cleanupFailure) throw new Error('Owned browser context did not close');
  }
}

async function check(browser, configuration) {
  const {fixturePath, fixtureSha256, appSha256, evidenceDir} = configuration;
  assert(browser && browser.isConnected(), 'requires a connected caller-owned browser');
  assert(/^[0-9a-f]{64}$/.test(fixtureSha256) && /^[0-9a-f]{64}$/.test(appSha256));
  assert(path.isAbsolute(fixturePath) && path.isAbsolute(evidenceDir));
  assert(evidenceDir.startsWith('/tmp/') && !fs.existsSync(evidenceDir), 'use a fresh owned /tmp output directory');
  const info = fs.lstatSync(fixturePath);
  assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 16 * 1024 * 1024);
  const raw = fs.readFileSync(fixturePath);
  assert.equal(sha(raw), fixtureSha256, 'exported fixture changed');
  const fixture = JSON.parse(raw);
  assert.equal(fixture.schema, 'catchplate.approvalDenialBrowserFixture/v1');
  assert.equal(fixture.syntheticOnly, true);
  assert.equal(fixture.sourceSha256['catchplate/app.py'], appSha256);
  assert.equal(sha(fixture.html), fixture.htmlSha256);
  fs.mkdirSync(evidenceDir, {mode: 0o700});
  const before = browser.contexts();
  const result = {schema: 'catchplate.approvalDenialBrowserResult/v1', syntheticOnly: true,
    actualBackendVerified: false, nativeAuthorityVerified: false, hardwareVerified: false,
    decisionsCovered: ['approve', 'deny'],
    passed: false, fixtureSha256, htmlSha256: fixture.htmlSha256, sourceSha256: fixture.sourceSha256,
    groups: [], contextsPreserved: false};
  try {
    assert.equal(CASES.length, 6);
    assert.equal(new Set(CASES.map(spec => spec.name)).size, 6);
    assert.equal(CASES.filter(spec => spec.kind === 'approve').length, 3);
    assert.equal(CASES.filter(spec => spec.kind === 'deny').length, 3);
    for (const spec of CASES) {
      assert.equal(spec.unknown === true, ['unknown-reload-recovery', 'unknown-approval-reload-recovery'].includes(spec.name));
      assert.equal(spec.votePending === true, spec.name === 'mobile-queue-approval-vote');
      try {
        result.groups.push(await runCase(browser, fixture.html, spec, evidenceDir));
      } catch (error) {
        const receipt = path.join(evidenceDir, `${spec.name}.json`);
        result.groups.push(fs.existsSync(receipt) ? JSON.parse(fs.readFileSync(receipt, 'utf8'))
          : {name: spec.name, passed: false, failure: 'case-setup-failed-before-receipt'});
        throw error;
      }
    }
    assert.equal(sha(fs.readFileSync(fixturePath)), fixtureSha256);
    assert.deepEqual(browser.contexts(), before, 'all original MCP contexts must be preserved');
    result.contextsPreserved = true;
    result.passed = true;
  } finally {
    result.contextsPreserved = browser.contexts().length === before.length
      && before.every(context => browser.contexts().includes(context));
    fs.writeFileSync(path.join(evidenceDir, 'result.json'), JSON.stringify(result, null, 2) + '\n',
      {flag: 'wx', mode: 0o600});
  }
  return {passed: result.passed, syntheticOnly: true, groups: result.groups.map(group => ({
    name: group.name, passed: group.passed, counts: group.counts, contextClosed: group.contextClosed})),
  contextsPreserved: result.contextsPreserved, evidenceDir,
  resultSha256: sha(fs.readFileSync(path.join(evidenceDir, 'result.json')))};
}

module.exports = {check};
