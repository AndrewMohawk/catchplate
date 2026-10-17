'use strict';
// One bounded rendered flow; every request is intercepted. No live AWS or app.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {mkdtempSync, readFileSync} = require('node:fs');
const {join} = require('node:path');
const {ROOT, NOW, IDS, SCOPE, hash, copy, catalog, application, rule, publication} = require('./test_operator_ecr_ui.cjs');
const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
const ORIGIN = 'https://ecr-ui.example.test', PREFIX = '/api/operator-demo/ecr-publications';
const PUBLISHED = '66666666-6666-4666-8666-666666666666', UNCERTAIN = '77777777-7777-4777-8777-777777777777';
async function main() {
  assert.equal(process.argv.length, 2, 'intercepted smoke accepts no target');
  const directory = mkdtempSync('/tmp/catchplate-ecr-ui-'), raw = catalog(), requests = [], errors = [];
  const html = execFileSync('python3', ['-B', '-c', 'from catchplate.operator_demo_portal import render; print(render())'],
    {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 2 * 1024 * 1024});
  raw.applications = []; raw.access_rules = []; raw.credentials[0].active_rule_count = 0;
  const records = new Map(); const token = 'synthetic-ecr-client-token-not-real';
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, acceptDownloads: true, serviceWorkers: 'block'});
  await context.addInitScript(now => {const Original = Date; window.Date = class extends Original {static now() {return now;}};}, NOW);
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    const reply = (value, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(value)});
    try {
      assert.equal(url.origin, ORIGIN); assert(requests.length < 50); requests.push({path, query: url.search, method: request.method()});
      if (request.method() === 'GET' && path === '/') return route.fulfill({status: 200, contentType: 'text/html', body: html});
      if (request.method() === 'GET' && path === '/favicon.ico') return route.fulfill({status: 204, body: ''});
      if (request.method() === 'GET' && path === '/api/operator-demo/catalog') {
        raw.credentials[0].active_rule_count = raw.access_rules.length;
        for (const item of raw.applications) {item.active_rule_count = raw.access_rules.length; item.access_status = raw.access_rules.length ? 'active' : 'unassigned';}
        for (const key of ['credentials', 'applications', 'access_rules']) raw.limits[key] = {active: raw[key].length, retained: raw[key].length, active_max: 32, retained_max: 1024};
        return reply(raw);
      }
      if (request.method() === 'GET' && path === '/api/operator-demo/oauth/x/configuration/v1') return reply({}, 404);
      if (request.method() === 'GET' && path === '/api/approvals/capabilities') return reply({schema: 'catchplate.approvalCapabilities/v1', can_list: true,
        can_open_native_review: false, can_decide: false, reason: 'protected_review_unavailable'});
      if (request.method() === 'GET' && path === '/api/approvals') return reply([]);
      if (path === PREFIX && request.method() === 'GET') {
        if (!url.search) return reply({publications: [records.get(IDS[3])], next_cursor: IDS[3]});
        assert.equal(url.search, '?before=' + IDS[3]);
        return reply({publications: [records.get(IDS[4]), records.get(PUBLISHED), records.get(UNCERTAIN)], next_cursor: null});
      }
      if (path.startsWith(PREFIX + '/')) {
        const [id, action] = path.slice(PREFIX.length + 1).split('/'); assert(records.has(id)); const item = records.get(id);
        if (!action) {assert.equal(request.method(), 'GET'); return reply(item);}
        assert.equal(request.method(), 'POST'); const body = request.postDataJSON();
        if (action === 'review') {
          assert.deepEqual(body, {}); return reply({publication: item, assurance: 'host-trusted', review_receipt_id: id,
            review_digest: hash(14), review_expires_at_epoch_ms: NOW + 60000});
        }
        if (action === 'retire') {
          assert.equal(id, PUBLISHED); assert.deepEqual(body, {}); assert.equal(item.status, 'published'); item.revision++;
          if (item.artifact_retirement_status === 'available') {item.artifact_retirement_status = 'pending'; return reply({});}
          assert.equal(item.artifact_retirement_status, 'pending'); item.artifact_retirement_status = 'retired';
          item.artifacts_retired = true; item.artifacts_retired_at_epoch_ms = NOW + 1; return reply(item);
        }
        assert.equal(action, 'decision'); assert.deepEqual(body, {decision: 'approve', review_receipt_id: id, review_digest: hash(14), note: null});
        item.status = 'approved'; item.revision++; item.reviewer_id = 'operator:synthetic';
        return reply(id === IDS[4] ? {} : item); // Lost receipt after synthetic approval; never retry it.
      }
      assert.equal(request.method(), 'POST'); const body = request.postDataJSON();
      assert.equal(body.expected_revision, raw.revision); assert.equal(body.expected_policy_hash, raw.policy.policy_hash);
      let key, item, extra = {};
      if (path === '/api/operator-demo/applications') {
        assert.equal(body.proxy_authentication, 'basic_and_bearer_v1');
        item = {...application(), name: body.name, active_rule_count: 0, access_status: 'unassigned'}; raw.applications.push(item);
        key = 'application'; extra.client_token = token;
      } else {
        assert.equal(path, '/api/operator-demo/access-rules/aws-ecr-publication');
        for (const [name, value] of Object.entries(SCOPE)) assert.equal(body[name], value);
        assert.equal(body.approval_mode, 'host_review_v1'); assert.equal(body.credential_id, IDS[0]); assert.equal(body.application_id, IDS[1]);
        assert.equal(body.operation_bundle, 'aws_ecr_publish_v1'); assert(!Object.hasOwn(body, 'secret'));
        item = {...rule(), name: body.name}; raw.access_rules.push(item); key = 'access_rule';
        raw.policy = {policy_hash: hash(2), loaded_policy_hash: hash(2), sequence: 2, activation: 'active'};
        for (const id of [IDS[3], IDS[4]]) records.set(id, publication({id, policy_hash: hash(2)}));
        records.set(PUBLISHED, publication({id: PUBLISHED, status: 'published', policy_hash: hash(2)}));
        records.set(UNCERTAIN, publication({id: UNCERTAIN, status: 'uncertain', policy_hash: hash(2)}));
      }
      raw.revision++; return reply({[key]: item, revision: raw.revision, policy: raw.policy, ...extra});
    } catch (error) {errors.push(error.message); await route.abort();}
  });
  const page = await context.newPage(); page.setDefaultTimeout(5000);
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', event => {if (event.type() === 'error' && !event.text().includes('404')) errors.push(event.text());});
  try {
    await page.goto(ORIGIN, {waitUntil: 'networkidle'});
    await page.locator('nav a[href="#credentials"]').click();
    await page.locator('[data-action="use-credential"]').click();
    await page.locator('#connect-application-name').fill('Release CI'); await page.locator('#connect-application-next').click();
    await page.locator('#connect-access-step').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-operation').inputValue(), 'aws_ecr_publish_v1');
    for (const [key, value] of Object.entries(SCOPE)) await page.locator('#connect-ecr-' + key).fill(value);
    assert(!await page.locator('#connect-approval-group').isVisible());
    await page.locator('#connect-review').click(); await page.locator('#connect-review-step').waitFor({state: 'visible'});
    assert((await page.locator('#connect-review-details').innerText()).includes('Required for the entire exact staged image'));
    await page.locator('#connect-grant').click(); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
    const downloadEvent = page.waitForEvent('download'); await page.locator('#download-config').click();
    const download = await downloadEvent, config = JSON.parse(readFileSync(await download.path(), 'utf8'));
    assert.equal(config.schema, 'catchplate.awsEcrPublicationClient/v1'); assert.equal(config.proxy_password, token);
    assert.equal(config.control_api_url, 'https://proxy.example.test/v1/ecr/publications'); assert.equal(config.expected_policy_hash, hash(2));
    assert(!Object.hasOwn(config, 'publication_id')); assert(!JSON.stringify(config).includes('secret_access_key'));
    await page.locator('nav a[href="#pending-actions"]').click();
    await page.locator('[data-ecr-select="' + IDS[3] + '"]').click();
    assert.equal(await page.locator('[data-ecr-select="' + IDS[4] + '"]').count(), 0);
    assert.equal(requests.filter(item => item.path === PREFIX && item.query).length, 0, 'older pages are never fetched automatically');
    await page.getByRole('button', {name: 'Review this image', exact: true}).click();
    await page.getByRole('button', {name: 'Approve this image', exact: true}).waitFor();
    const selected = page.locator('#ecr-publications-selected');
    for (const text of ['Release CI', 'Release AWS credentials', SCOPE.repository_name, SCOPE.image_tag, hash(10), '2 unique blob(s)', '1,044 bytes'])
      assert((await selected.innerText()).includes(text));
    assert(!(await selected.innerText()).includes('identical HTTP retry'));
    assert.equal(await page.title(), 'Pending actions - Catchplate operator workspace');
    await page.screenshot({path: join(directory, 'ecr-review-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({path: join(directory, 'ecr-review-mobile.png'), fullPage: true});
    await page.getByRole('button', {name: 'Approve this image', exact: true}).click();
    await selected.getByText(/Approval did not publish it/).waitFor();
    await page.locator('#ecr-publications-load-more').click();
    await page.locator('[data-ecr-select="' + IDS[4] + '"]').waitFor();
    assert.equal(requests.filter(item => item.path === PREFIX && item.query).length, 1);
    assert(!await page.locator('#ecr-publications-load-more').isVisible());
    await page.locator('[data-ecr-select="' + IDS[4] + '"]').click();
    await page.getByRole('button', {name: 'Review this image', exact: true}).click();
    await page.getByRole('button', {name: 'Approve this image', exact: true}).click();
    await page.getByRole('button', {name: 'Check decision status (read only)', exact: true}).click();
    await selected.getByText(/Approval did not publish it/).waitFor();
    await page.locator('[data-ecr-select="' + UNCERTAIN + '"]').click();
    await selected.getByText(/Do not automatically retry or resume/).waitFor();
    assert.equal(await page.getByRole('button', {name: 'Retire staged files', exact: true}).count(), 0);
    await page.locator('[data-ecr-select="' + PUBLISHED + '"]').click();
    await page.getByRole('button', {name: 'Retire staged files', exact: true}).click();
    assert.equal(requests.filter(item => item.path.endsWith('/retire')).length, 0, 'opening confirmation does not retire anything');
    await page.getByRole('button', {name: 'Confirm retire staged files', exact: true}).waitFor();
    await page.setViewportSize({width: 1280, height: 960});
    await page.screenshot({path: join(directory, 'ecr-retirement-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({path: join(directory, 'ecr-retirement-mobile.png'), fullPage: true});
    await page.getByRole('button', {name: 'Confirm retire staged files', exact: true}).click();
    await page.getByRole('button', {name: 'Check retirement status (read only)', exact: true}).waitFor();
    assert.equal(await page.getByRole('button', {name: 'Retry retiring staged files', exact: true}).count(), 0);
    await page.getByRole('button', {name: 'Check retirement status (read only)', exact: true}).click();
    await page.getByRole('button', {name: 'Retry retiring staged files', exact: true}).click();
    assert.equal(requests.filter(item => item.path.endsWith('/retire')).length, 1, 'read recovery and confirmation never automatically resubmit');
    await page.getByRole('button', {name: 'Confirm retire staged files', exact: true}).click();
    await selected.getByText(/Local staged files have been retired/).waitFor();
    assert((await selected.innerText()).includes('AWS image and the publication’s audit history are unchanged'));
    assert.equal(await page.getByRole('button', {name: 'Retire staged files', exact: true}).count(), 0);
    await page.locator('nav a[href="#proxy"]').click();
    assert.equal(await page.locator('#ecr-client-publication').inputValue(), '');
    assert(!(await page.locator('#ecr-client-publication-command').textContent()).includes('--execute-write'));
    await page.locator('#ecr-client-publication').selectOption(IDS[3]);
    await page.waitForFunction(() => document.getElementById('ecr-client-publication-command').textContent.includes('--execute-write'));
    assert((await page.locator('#ecr-client-publication-command').innerText()).includes('--publication ' + IDS[3]));
    assert.equal(requests.filter(item => item.path.endsWith('/decision')).length, 2);
    assert.equal(requests.filter(item => item.path.endsWith('/retire')).length, 2);
    assert.equal(requests.filter(item => item.method === 'POST').length, 8);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ok: true, scope: 'intercepted ECR setup, compound review, explicit paging, local retirement recovery and publication selection',
      requests, errors, providerRequests: 0, liveRequests: 0, screenshots: directory}));
  } catch (error) {
    await page.screenshot({path: join(directory, 'failure.png'), fullPage: true});
    throw new Error(error.message + '\n' + JSON.stringify({errors, directory, load: await page.locator('#load-error-text').textContent(),
      setup: await page.locator('#connect-status').textContent(), publication: await page.locator('#ecr-publications-status').textContent()}));
  } finally {await context.close(); await browser.close();}
}
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
