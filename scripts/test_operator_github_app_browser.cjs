#!/usr/bin/env node
// Actual rendered assets with intercepted synthetic API responses only. This
// does not verify a GitHub signature, token mint, lease, backend or SDK request.
// Every unknown network request remains refused by the inherited local fixture.
const assert = require('node:assert/strict');
const {withoutMutationReview, acknowledgeMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash, generateKeyPairSync} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest, pair, step, review, grant} = require('./test_operator_ordinary_modes_browser.cjs');
const {capability: patCapability, githubRule} = require('./test_operator_github_browser.cjs');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const API = 'https://api.github.com';
const CATALOG = '/api/operator-demo/catalog';
const CREATE = '/api/operator-demo/credentials/github-app';
const PAT_CREATE = '/api/operator-demo/credentials/github-token';
const GRANT = '/api/operator-demo/access-rules/github';
const REPLACE = '/api/operator-demo/credentials/github-app/replace-key';
const REPLACEMENT = {schema: 'serverware.operatorGithubAppKeyReplacement/v1', path: REPLACE};
const READ = 'github_issues_read_v1';
const WRITE = 'github_issues_write_v1';
const REPOSITORY = {owner: 'Example-Owner', name: 'Example.Repo'};
const PAT = 'synthetic_github_PAT_NEVER_RETAIN';
const PRIVATE_ERROR = 'synthetic-GitHub-private-provider-error-NEVER-RENDER';
const AUTH = {schema: 'serverware.operatorProxyAuthentication/v1', modes: ['bearer', 'basic_and_bearer_v1'],
  path: '/api/operator-demo/applications/proxy-authentication'};
const PLAYWRIGHT = '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright';
const clone = value => JSON.parse(JSON.stringify(value));
const appCapability = () => ({...patCapability(), schema: 'serverware.operatorGithubApp/v1',
  connection_type: 'github_app_v1', create_credential_path: CREATE});
const binding = (permission = 'read') => ({app_id: '123456', installation_id: '234567', account_id: '345678',
  repository_id: '456789', repository: clone(REPOSITORY), issues_permission: permission, token_refresh: 'automatic'});
const appCredential = (permission = 'read') => credential({name: 'My GitHub App', version: 1, credential_generation: 1,
  connection_type: 'github_app_v1', provider_id: 'github', github_app: binding(permission)});
let pem; let pemCanary; let activeGroup = 0; let activeStep = 'not-started'; let activeVariant = 'not-started';

function catalog(state, config) {
  const value = clone(publicCatalog(state));
  value.capabilities.application_proxy_authentication = clone(AUTH);
  value.capabilities.github = config.pat === false ? null : patCapability();
  value.capabilities.github_app = Object.hasOwn(config, 'appCapability') ? config.appCapability : appCapability();
  value.capabilities.github_app_key_replacement = Object.hasOwn(config, 'replacementCapability') ? config.replacementCapability :
    config.replacement ? clone(REPLACEMENT) : null;
  if (config.catalogDrift && value.credentials.length) value.credentials[0].github_app.account_id = '345679';
  return value;
}
async function noMaterial(page, draft = false) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => ({id: item.id, value: item.value})),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const secret of [PAT, pemCanary, PRIVATE_ERROR]) {
    assert(!surfaces.html.includes(secret), 'private material must not become HTML');
    assert(!JSON.stringify([surfaces.local, surfaces.session]).includes(secret), 'private material must not enter storage');
    for (const item of surfaces.fields) if (!(draft && ['connect-github-private-key', 'github-app-replace-private-key'].includes(item.id)))
      assert(!item.value.includes(secret), 'private material must clear from non-draft controls');
  }
  assert.deepEqual(surfaces.local, []); assert.deepEqual(withoutMutationReview(surfaces.session), []);
}
async function refresh(page) {
  const received = page.waitForResponse(response => response.url() === ORIGIN + CATALOG && response.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await received).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function fixture(browser, config, exercise) {
  activeVariant = config.fault || (config.catalogDrift ? 'catalog-binding-drift' : config.receiptDrift ? 'receipt-binding-drift' : 'ordinary');
  return ordinaryFixture(browser, {credentials: config.credentials || [],
    applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules: config.rules || [],
    allowedUpstreams: config.allowedUpstreams || [API], requestBodyModes: ['preserve_json_v1'],
    responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'],
    autoLoad: config.autoLoad !== false}, async (page, state, controls) => {
    const observed = {creates: [], grants: [], replacements: [], reads: 0};
    const appsBefore = clone(state.applications);
    let arrived; let release;
    const arrival = new Promise(resolve => { arrived = resolve; });
    const gate = config.defer ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json',
      headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(value)});
    page.on('console', message => {
      if ([PAT, pemCanary, PRIVATE_ERROR].some(secret => message.text().includes(secret)))
        state.errors.push('private browser console material refused');
    });
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, '');
        if (url.pathname === CATALOG) {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); assert(++observed.reads <= 24);
          state.catalogCalls++; return await answer(route, catalog(state, config));
        }
        assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= (url.pathname === REPLACE ? 32768 : 16384));
        assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString());
        assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
        if (url.pathname === REPLACE) {
          assert.deepEqual(catalog(state, config).capabilities.github_app_key_replacement, REPLACEMENT);
          assert.equal(observed.replacements.length, 0, 'a replacement is never automatically repeated');
          assert.deepEqual(Object.keys(body).sort(), ['expected_credential_generation', 'expected_policy_hash', 'expected_revision', 'id', 'private_key_pem']);
          const target = state.credentials.find(item => item.id === body.id);
          assert(target?.status === 'active' && target.connection_type === 'github_app_v1');
          assert.equal(body.expected_credential_generation, target.credential_generation);
          assert.equal(body.private_key_pem === pem, true); delete body.private_key_pem;
          observed.replacements.push({...clone(body), pemMatched: true}); arrived(); await gate;
          if (['409', '422', '503'].includes(config.fault)) {
            state.expectedFailures.add(REPLACE); return await answer(route, {detail: PRIVATE_ERROR}, Number(config.fault));
          }
          const previous = target.credential_generation; target.credential_generation++; target.version++;
          target.key_replaced_at = new Date(NOW).toISOString(); state.revision++;
          if (config.fault === 'lost-after-commit') { state.expectedFailures.add(REPLACE); return await route.abort('failed'); }
          const current = catalog(state, config), result = {credential: current.credentials.find(item => item.id === target.id),
            revision: state.revision, policy: current.policy, key_replacement: {
              previous_credential_generation: previous, credential_generation: target.credential_generation,
              cache_invalidation: config.cacheUnconfirmed ? 'local_unconfirmed' : 'local_completed', in_flight_requests: 'not_recalled'}};
          config.replacementReceiptChange?.(result); config.replacementCatalogChange?.(state);
          return await answer(route, result);
        }
        if (url.pathname === CREATE || url.pathname === PAT_CREATE) {
          assert.equal(observed.creates.length, 0, 'a credential POST is never automatically repeated');
          const isApp = url.pathname === CREATE;
          assert.deepEqual(Object.keys(body).sort(), isApp ? ['app_id', 'expected_policy_hash', 'expected_revision',
            'installation_id', 'issues_permission', 'name', 'private_key_pem', 'repository'] :
            ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
          assert.equal(body.name, isApp ? 'My GitHub App' : 'My GitHub PAT');
          assert.equal(isApp ? body.private_key_pem === pem : body.secret === PAT, true, 'synthetic private input must match');
          if (isApp) {
            assert.deepEqual(catalog(state, config).capabilities.github_app, appCapability());
            assert.equal(body.app_id, '123456'); assert.equal(body.installation_id, '234567');
            assert.deepEqual(body.repository, REPOSITORY); assert.equal(body.issues_permission, config.permission || 'read');
          }
          observed.creates.push({path: url.pathname, name: body.name, privateInputMatched: true,
            ...(isApp ? {app_id: body.app_id, installation_id: body.installation_id, repository: clone(body.repository),
              issues_permission: body.issues_permission} : {})});
          delete body.private_key_pem; delete body.secret; arrived(); await gate;
          if (['409', '422', '503'].includes(config.fault)) {
            state.expectedFailures.add(url.pathname); return await answer(route, {detail: PRIVATE_ERROR}, Number(config.fault));
          }
          assert.equal(state.credentials.length, 0);
          state.credentials.push(isApp ? appCredential(config.permission) : credential({name: body.name, version: 1,
            credential_generation: 1, connection_type: 'github_token_v1', provider_id: 'github'}));
          state.revision++;
          if (config.fault === 'lost-after-commit') { state.expectedFailures.add(url.pathname); return await route.abort('failed'); }
          const value = catalog(state, {...config, catalogDrift: false});
          const result = {credential: value.credentials[0], revision: state.revision, policy: value.policy};
          if (config.receiptDrift) result.credential.github_app.repository.name = 'Different.Repo';
          return await answer(route, result, 201);
        }
        assert.equal(url.pathname, GRANT); assert.equal(observed.grants.length, 0);
        assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
          'expected_revision', 'name', 'operation_bundle', 'repository']);
        assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
        assert.deepEqual(body.repository, REPOSITORY);
        assert([READ, WRITE].includes(body.operation_bundle));
        const saved = state.credentials.find(item => item.id === body.credential_id && item.status === 'active');
        assert(saved && saved.connection_type === 'github_app_v1');
        assert(body.operation_bundle !== WRITE || saved.github_app.issues_permission === 'write');
        assert.equal(body.name, (body.operation_bundle === READ ? 'Read issues and comments' : 'Read and create issues/comments') +
          ' · ' + REPOSITORY.owner + '/' + REPOSITORY.name);
        assert.equal(state.rules.length, 0); observed.grants.push(clone(body));
        state.rules.push(githubRule(body.operation_bundle, {name: body.name})); state.revision++;
        state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
        const value = catalog(state, config);
        return await answer(route, {access_rule: value.access_rules[0], revision: state.revision, policy: value.policy}, 201);
      } catch (_) { state.errors.push('GitHub App fixture closed DTO/CAS boundary failed'); await route.abort(); }
    };
    for (const path of [CATALOG, CREATE, PAT_CREATE, GRANT, REPLACE]) await controls.context.route(ORIGIN + path, handler);
    try {
      await page.reload({waitUntil: 'networkidle'});
      await exercise(page, state, observed, {arrival, release: () => release?.()});
      assert.deepEqual(state.posts, [], 'no generic mutations, rotation, consent or unrelated grant');
      assert.deepEqual(state.applications, appsBefore, 'existing app identity and token are not changed');
      assert(observed.creates.length <= 1 && observed.grants.length <= 1 && observed.replacements.length <= 1); await noMaterial(page);
    } finally { release?.(); }
  });
}
async function appForm(page, permission = 'read') {
  activeStep = 'app-form'; await ready(page); await view(page, 'connect');
  await page.locator('#connect-use-github').click(); await page.locator('#connect-github-type').selectOption('github_app_v1');
  assert(await page.locator('#connect-provider-secret-group').isHidden());
  assert(await page.locator('#connect-credential-secret').isDisabled());
  await page.locator('#connect-credential-name').fill('My GitHub App');
  await page.locator('#connect-github-app-id').fill('123456');
  await page.locator('#connect-github-installation-id').fill('234567');
  await page.locator('#connect-github-app-owner').fill(REPOSITORY.owner);
  await page.locator('#connect-github-app-repo').fill(REPOSITORY.name);
  await page.locator('#connect-github-app-permission').selectOption(permission);
  await page.locator('#connect-github-private-key').fill(pem);
  assert.equal(await page.locator('#connect-credential-next').innerText(), 'Save and verify GitHub App');
  await noMaterial(page, true);
}
async function useExistingApplication(page) {
  await step(page, 'application');
  assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
  await page.locator('#connect-application-choice').selectOption(IDS.application);
  await page.locator('#connect-application-next').click(); await step(page, 'access');
}
async function fixedRepository(page) {
  for (const [id, value] of [['connect-github-owner', REPOSITORY.owner], ['connect-github-repo', REPOSITORY.name]]) {
    assert.equal(await page.locator('#' + id).inputValue(), value);
    assert.equal(await page.locator('#' + id).evaluate(node => node.readOnly), true);
  }
}
async function copyRecipe(page) {
  activeStep = 'copy-sdk'; await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  await page.locator('#github-proxy-ca-path').fill('./outer-proxy.pem');
  const text = await page.locator('#client-command').innerText();
  for (const literal of ['@octokit/rest@22.0.1', 'undici@8.11.2', 'process.env.SERVERWARE_PROXY_TOKEN',
    'auth: "serverware-github-placeholder-v1"', "token: 'Basic ' + Buffer.from",
    'proxyTls: { ca: readFileSync("./outer-proxy.pem"), rejectUnauthorized: true }',
    'requestTls: { ca: readFileSync("./serverware-ca.pem"), rejectUnauthorized: true }', REPOSITORY.owner, REPOSITORY.name])
    assert(text.includes(literal), 'copied SDK recipe preserves the named public setting');
  assert(!/rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED/.test(text));
  assert(![pemCanary, PAT, PRIVATE_ERROR].some(value => text.includes(value)));
  await page.locator('#copy-command').click();
  await page.waitForFunction(() => document.querySelector('#client-copy-status').textContent ===
    'Copied the GitHub client recipe. Set the application token and any creation content locally. No request was executed by this page.');
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
  assert.match(await page.locator('#client-guidance').innerText(), /No GitHub request was tested here/);
  assert(await page.locator('#download-config').isDisabled(), 'no held application token is invented');
}
const replacementAction = page => page.locator('#credentials-list [data-resource-id="' + IDS.credential + '"] [data-action="replace-github-app-key"]');
async function openReplacement(page) {
  activeStep = 'replacement-review'; await ready(page); await view(page, 'credentials');
  await replacementAction(page).click(); await page.locator('#github-app-replace-panel').waitFor({state: 'visible'});
  assert.equal(await page.locator('#github-app-replace-private-key').inputValue(), '');
  assert.equal(await page.locator('#github-app-replace-private-key').getAttribute('autocomplete'), 'new-password');
  assert.equal(await page.locator('#github-app-replace-panel input').count(), 0, 'no editable App identity or scope fields');
}
async function replacementRefresh(page) {
  const response = page.waitForResponse(value => value.url() === ORIGIN + CATALOG && value.request().method() === 'GET');
  await page.locator('#credentials-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function replacementSettled(page) {
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled &&
    document.querySelector('#github-app-replace-status').textContent !== 'Saving...');
  assert(await page.locator('#github-app-replace-panel').isHidden()); await noMaterial(page);
}

const tests = [
  ['separate capability controls preserve PAT and reject missing or altered App profiles', async browser => {
    for (const value of [null, {...appCapability(), create_credential_path: '/other'}]) await fixture(browser,
      {appCapability: value}, async (page, state, observed) => {
        await ready(page); await view(page, 'connect'); await page.locator('#connect-use-github').click();
        assert.equal(await page.locator('#connect-github-type').inputValue(), 'github_token_v1');
        assert(await page.locator('#connect-github-type option[value="github_app_v1"]').isDisabled());
        assert(!await page.locator('#connect-github-type option[value="github_token_v1"]').isDisabled());
        assert.equal(observed.creates.length, 0);
      });
    await fixture(browser, {pat: false}, async page => {
      await ready(page); await view(page, 'connect'); await page.locator('#connect-use-github').click();
      assert.equal(await page.locator('#connect-github-type').inputValue(), 'github_app_v1');
      assert(await page.locator('#connect-github-type option[value="github_token_v1"]').isDisabled());
    });
  }],
  ['PAT remains the default and uses its unchanged private field and separate save endpoint', browser => fixture(browser, {}, async (page, state, observed) => {
    await ready(page); await view(page, 'connect'); await page.locator('#connect-use-github').click();
    assert.equal(await page.locator('#connect-github-type').inputValue(), 'github_token_v1');
    assert(await page.locator('#connect-github-app-fields').isHidden());
    await page.locator('#connect-credential-name').fill('My GitHub PAT'); await page.locator('#connect-credential-secret').fill(PAT);
    assert(await page.locator('#connect-credential-form').evaluate(form => form.checkValidity()), 'synthetic PAT satisfies the real form profile');
    await page.locator('#connect-credential-next').click(); await step(page, 'application');
    assert.equal(observed.creates[0].path, PAT_CREATE); assert.equal(observed.grants.length, 0);
    assert.equal(state.credentials[0].connection_type, 'github_token_v1'); await noMaterial(page);
  })],
  ['App save selects its exact repository once, bounds permissions and copies the rendered SDK setup', async (browser, directory) => {
    for (const permission of ['read', 'write']) await fixture(browser, {permission, autoLoad: false}, async (page, state, observed) => {
      await appForm(page, permission); await page.locator('#connect-credential-next').click(); await useExistingApplication(page);
      await fixedRepository(page); await noMaterial(page);
      const choices = await page.locator('#connect-operation option').evaluateAll(nodes => nodes.filter(node => !node.disabled).map(node => node.value));
      assert.deepEqual(choices, permission === 'read' ? [READ] : [READ, WRITE]);
      await page.locator('#connect-operation').selectOption(permission === 'read' ? READ : WRITE);
      await review(page); assert.equal(observed.grants.length, 0); await grant(page);
      assert(await page.locator('#connect-setup-slot').isHidden(), 'unloaded policy cannot produce ready setup');
      state.loaded = state.active; await refresh(page); await copyRecipe(page);
      assert.equal(observed.creates.length, 1); assert.equal(observed.grants.length, 1);
      assert.deepEqual(state.credentials[0].github_app, binding(permission));
      if (permission === 'read') {
        assert(await page.locator('#github-client-operation option[value="create"]').isDisabled());
        await page.screenshot({path: join(directory, 'app-sdk-desktop.png'), fullPage: true,
          mask: [page.locator('#client-token'), page.locator('#connect-github-private-key')]});
      } else {
        await page.locator('#github-client-operation').selectOption('create'); await copyRecipe(page);
        assert((await page.locator('#client-command').innerText()).includes('octokit.rest.issues.create('));
      }
    });
  }],
  ['PEM clears before the asynchronous save resolves and a pending request is never repeated', browser => fixture(browser,
    {defer: true}, async (page, state, observed, controls) => {
      await appForm(page); activeStep = 'pending-private-clear'; await page.locator('#connect-credential-next').click();
      await controls.arrival; assert.equal(observed.creates.length, 1); assert.equal(state.credentials.length, 0);
      await noMaterial(page); assert(await page.locator('#connect-credential-next').isDisabled());
      await page.clock.runFor(1000); assert.equal(observed.creates.length, 1);
      controls.release(); await step(page, 'application'); assert.equal(state.credentials.length, 1);
    })],
  ['refused or lost App save clears PEM and remains uncertain without any automatic repeat', async browser => {
    for (const fault of ['422', '409', '503', 'lost-after-commit']) await fixture(browser, {fault}, async (page, state, observed) => {
      await appForm(page); activeStep = 'save-refusal'; await page.locator('#connect-credential-next').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      await noMaterial(page); assert(await page.locator('#connect-credential-next').isDisabled());
      assert(await page.locator('#connect-application-step').isHidden());
      await refresh(page); await page.clock.runFor(1000);
      assert.equal(observed.creates.length, 1); assert.equal(observed.grants.length, 0);
      assert.equal(state.credentials.length, fault === 'lost-after-commit' ? 1 : 0);
      await page.reload({waitUntil: 'networkidle'});
      assert(await page.locator('#credential-fields').evaluate(node => node.disabled), 'reload preserves the saved-state review hold');
      await acknowledgeMutationReview(page); await ready(page); await noMaterial(page);
      assert.equal(observed.creates.length, 1, 'reload does not resubmit private material');
    });
  }],
  ['App draft is usable at 390px and clears private material on method, navigation and page lifecycle changes', async (browser, directory) => {
    await fixture(browser, {}, async (page, state, observed) => {
      await page.setViewportSize({width: 390, height: 844}); await appForm(page);
      assert(await page.locator('#connect-github-type').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.locator('#connect-github-type').selectOption('github_token_v1'); await noMaterial(page);
      await page.locator('#connect-github-type').selectOption('github_app_v1');
      assert(await page.locator('#connect-github-app-fields').isVisible()); await noMaterial(page);
      await page.screenshot({path: join(directory, 'app-form-mobile-cleared.png'), fullPage: true,
        mask: [page.locator('#connect-github-private-key'), page.locator('#connect-credential-secret'), page.locator('#client-token')]});
      await page.locator('#connect-github-private-key').fill(pem); await view(page, 'overview'); await noMaterial(page);
      await view(page, 'connect'); await page.locator('#connect-github-private-key').fill(pem);
      await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}))); await noMaterial(page);
      assert.equal(observed.creates.length, 0); assert.equal(observed.grants.length, 0);
    });
  }],
  ['receipt or catalog binding drift prevents advancement and a reviewed saved binding cannot silently change', async browser => {
    for (const config of [{receiptDrift: true}, {catalogDrift: true}]) await fixture(browser, config, async (page, state, observed) => {
      await appForm(page); await page.locator('#connect-credential-next').click();
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(observed.creates.length, 1); assert(await page.locator('#connect-application-step').isHidden());
      assert(await page.locator('#connect-credential-next').isDisabled()); await refresh(page); await noMaterial(page);
      assert.equal(observed.creates.length, 1); assert.equal(observed.grants.length, 0);
    });
    await fixture(browser, {credentials: [appCredential()]}, async (page, state, observed) => {
      await pair(page); await fixedRepository(page); await review(page);
      state.credentials[0].github_app.account_id = '345679'; await refresh(page);
      assert(await page.locator('#connect-grant').isDisabled());
      assert.equal(observed.creates.length, 0); assert.equal(observed.grants.length, 0);
    });
  }],
  ['replacement is separately advertised and never enables generic PAT replacement for an App', async browser => {
    for (const capability of [null, {...REPLACEMENT, extra: true}, {...REPLACEMENT, path: '/api/operator-demo/credentials/replace-key'}])
      await fixture(browser, {credentials: [appCredential()], replacementCapability: capability}, async (page, state, observed) => {
        await ready(page); await view(page, 'credentials');
        assert.equal(await replacementAction(page).count(), 0);
        assert.equal(await page.locator('#credentials-list [data-action="replace-key"]').count(), 0);
        assert.equal(observed.replacements.length, 0);
      });
    for (const denied of [{appCapability: null}, {appCapability: {...appCapability(), destination_allowed: false}}, {allowedUpstreams: []}])
      await fixture(browser, {credentials: [appCredential()], replacement: true, ...denied}, async (page, state, observed) => {
        await ready(page); await view(page, 'credentials'); assert.equal(await replacementAction(page).count(), 0);
        assert.equal(observed.replacements.length, 0);
      });
    await fixture(browser, {credentials: [appCredential()], replacement: true}, async page => {
      await ready(page); await view(page, 'credentials'); assert(await replacementAction(page).isEnabled());
      await page.locator('#credentials-list [data-credential-details] > summary').click();
      const details = page.locator('#credentials-list [data-key-replacement-details]');
      assert((await details.innerText()).includes('Stored key generation'));
      assert.equal(await page.locator('#credentials-list [data-action="replace-key"]').count(), 0);
    });
  }],
  ['replacement preserves assignments and policy at desktop and mobile and clears PEM before acknowledgement', async (browser, directory) => {
    for (const mobile of [false, true]) await fixture(browser, {credentials: [appCredential()], rules: [githubRule(READ)],
      replacement: true, defer: true, cacheUnconfirmed: mobile}, async (page, state, observed, controls) => {
      if (mobile) await page.setViewportSize({width: 390, height: 844});
      const original = clone({rules: state.rules, active: state.active, sequence: state.sequence, binding: state.credentials[0].github_app});
      await openReplacement(page);
      assert.match(await page.locator('#github-app-replace-count').innerText(), /^1 affected app · 1 active access rule/);
      assert.equal(await page.locator('#github-app-replace-apps [data-application-id="' + IDS.application + '"]').count(), 1);
      const text = await page.locator('#github-app-replace-panel').innerText();
      assert(text.includes(REPOSITORY.owner + '/' + REPOSITORY.name));
      assert(text.includes('Delete the old private key separately in GitHub'));
      assert(text.includes('not recalled')); assert(text.includes('expiry are unchanged'));
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(directory, 'app-key-replacement-' + (mobile ? 'mobile' : 'desktop') + '.png'), fullPage: true,
        mask: [page.locator('#github-app-replace-private-key'), page.locator('#client-token')]});
      await page.locator('#github-app-replace-private-key').fill(pem); await noMaterial(page, true);
      await page.locator('#github-app-replace-submit').click(); await controls.arrival;
      assert.equal(observed.replacements.length, 1); assert.equal(state.credentials[0].credential_generation, 1);
      assert(await page.locator('#github-app-replace-panel').isHidden()); await noMaterial(page);
      await page.clock.runFor(1000); assert.equal(observed.replacements.length, 1);
      controls.release(); await page.waitForFunction(() => document.querySelector('#github-app-replace-status').textContent.includes('replacement saved in Serverware'));
      assert.equal(state.credentials[0].credential_generation, 2);
      assert.deepEqual({rules: state.rules, active: state.active, sequence: state.sequence, binding: state.credentials[0].github_app}, original);
      assert(await page.locator('#mutation-review').isHidden());
      if (mobile) assert((await page.locator('#github-app-replace-status').innerText()).includes('Local cache invalidation was not confirmed'));
      assert.equal(observed.creates.length, 0); assert.equal(observed.grants.length, 0); await noMaterial(page);
    });
  }],
  ['replacement PEM is write-only across cancellation navigation and page lifecycle without provider work', browser => fixture(browser,
    {credentials: [appCredential()], replacement: true}, async (page, state, observed) => {
      await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
      await page.locator('#github-app-replace-cancel').click(); await noMaterial(page);
      await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
      await view(page, 'overview'); await noMaterial(page);
      await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
      await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}))); await noMaterial(page);
      assert.equal(observed.replacements.length, 0); assert.equal(observed.creates.length, 0); assert.equal(observed.grants.length, 0);
    })],
  ['replacement draft refuses newly observed key generation capability and repository binding changes', async browser => {
    for (const drift of ['generation', 'capability', 'binding']) {
      const config = {credentials: [appCredential()], replacement: true};
      await fixture(browser, config, async (page, state, observed) => {
        await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
        if (drift === 'generation') state.credentials[0].credential_generation++;
        else if (drift === 'capability') config.replacementCapability = null;
        else state.credentials[0].github_app.account_id = '345679';
        await replacementRefresh(page); await page.locator('#github-app-replace-panel').waitFor({state: 'hidden'});
        await noMaterial(page); assert.equal(observed.replacements.length, 0);
      });
    }
  }],
  ['failed and lost replacement requires fresh manual review and never automatically resubmits PEM', async browser => {
    for (const fault of ['409', '422', '503', 'lost-after-commit']) await fixture(browser,
      {credentials: [appCredential()], replacement: true, fault}, async (page, state, observed) => {
        await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
        await page.locator('#github-app-replace-submit').click(); await page.locator('#mutation-review').waitFor({state: 'visible'});
        await replacementSettled(page); assert(await replacementAction(page).isDisabled());
        await replacementRefresh(page); await page.clock.runFor(1000); assert.equal(observed.replacements.length, 1);
        assert.equal(state.credentials[0].credential_generation, fault === 'lost-after-commit' ? 2 : 1);
        await page.locator('#mutation-review-confirm').click(); await replacementAction(page).click();
        assert.equal(await page.locator('#github-app-replace-private-key').inputValue(), '');
        assert.equal(observed.replacements.length, 1); await page.locator('#github-app-replace-cancel').click();
        await page.reload({waitUntil: 'networkidle'}); await ready(page); await noMaterial(page);
        assert.equal(observed.replacements.length, 1);
      });
  }],
  ['replacement receipt and refreshed catalog must match the original binding and acknowledged generation', async browser => {
    for (const alteration of [
      {replacementReceiptChange: value => value.credential.github_app.repository_id = '999'},
      {replacementReceiptChange: value => value.key_replacement.in_flight_requests = 'recalled'},
      {replacementReceiptChange: value => value.key_replacement.extra = true},
      {replacementCatalogChange: state => state.credentials[0].credential_generation--},
      {replacementCatalogChange: state => state.rules[0].name = 'Changed permission'}])
      await fixture(browser, {credentials: [appCredential()], rules: [githubRule(READ)], replacement: true, ...alteration},
        async (page, state, observed) => {
          await openReplacement(page); await page.locator('#github-app-replace-private-key').fill(pem);
          await page.locator('#github-app-replace-submit').click(); await page.locator('#mutation-review').waitFor({state: 'visible'});
          await replacementSettled(page); assert(await replacementAction(page).isDisabled());
          if (alteration.replacementCatalogChange) assert(await page.locator('#mutation-review-confirm').isDisabled());
          await replacementRefresh(page); assert.equal(observed.replacements.length, 1);
          assert.equal(observed.creates.length, 0); assert.equal(observed.grants.length, 0); await noMaterial(page);
        });
  }],
];

async function hashes() {
  const assets = await readdir(join(ROOT, 'serverware/operator_demo_web'));
  const names = ['scripts/test_operator_github_app_browser.cjs', 'scripts/test_operator_github_browser.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...assets.filter(name => /\.(?:js|css|html)$/.test(name)).sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
function selectedGroups(args) {
  if (!args.length) return tests.map((_, index) => index + 1);
  assert.equal(args.length, 2); assert.equal(args[0], '--groups');
  assert(typeof args[1] === 'string' && args[1].length <= 64 && /^[1-9][0-9]*(?:,[1-9][0-9]*)*$/.test(args[1]));
  const values = args[1].split(',').map(Number); assert.equal(new Set(values).size, values.length);
  assert(values.every(value => value <= tests.length)); return values;
}
async function runSuite(browser, groups = selectedGroups([])) {
  // Synthetic, locally generated input only. Never accepts a PEM path or key.
  pem = generateKeyPairSync('rsa', {modulusLength: 2048, privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
    publicKeyEncoding: {type: 'spki', format: 'pem'}}).privateKey;
  pemCanary = pem.split('\n')[1];
  const selected = tests.map(([name, test], index) => ({group: index + 1, name, test})).filter(item => groups.includes(item.group));
  const before = await hashes(); const directory = await mkdtemp('/tmp/serverware-github-app-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory,
    groups: selected.map(({group, name}) => ({group, name})), scope: 'actual rendered assets; intercepted synthetic API only'}));
  const contexts = new Set(); let finished = false; let timeout; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('Suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => {
      for (const {group, name, test} of selected) {
        activeGroup = group; activeStep = 'fixture-start'; activeVariant = 'not-started';
        await test(bounded, directory); passed++; console.log('PASS ' + name);
      }
    })(), new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Suite expired')), 180000); })]);
    const result = {ok: true, renderedGroups: selected.length, totalGroups: tests.length, selectedGroups: groups, passed,
      artifactDirectory: directory, backendAcceptance: false, signatureVerified: false, installationTokenMinted: false,
      leaseVerified: false, sdkExecuted: false, generatedCommandsExecuted: false, providerRequests: 0, proxyRequests: 0,
      deploymentChanged: false};
    console.log(JSON.stringify(result)); return result;
  } catch (error) {
    const frames = String(error?.stack || '').split('\n').map(line =>
      line.match(/(?:test_operator_github_app_browser|test_operator_github_browser|test_operator_ordinary_modes_browser|test_operator_catalog_browser)\.cjs:\d+:\d+(?=\)?$)/)?.[0]).filter(Boolean).slice(0, 4);
    console.log(JSON.stringify({phase: 'fixed-failure-checkpoint', group: activeGroup, step: activeStep,
      variant: activeVariant, passed, frames, rawErrorSuppressed: true}));
    throw new Error('GitHub App rendered regression refused; fixed checkpoint retained');
  } finally {
    finished = true; clearTimeout(timeout);
    try { await Promise.all([...contexts].map(context => context.close())); }
    finally { const after = await hashes(); assert.deepEqual(after, before, 'source changed during suite');
      console.log(JSON.stringify({phase: 'source-after', hashes: after, sameSource: true, passed})); }
  }
}
async function main() {
  assert.equal(process.version, 'v25.5.0');
  const groups = selectedGroups(process.argv.slice(2));
  assert.equal(require(PLAYWRIGHT + '/package.json').version, '1.58.2');
  const {chromium} = require(PLAYWRIGHT);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { assert.equal(browser.version(), '145.0.7632.6'); await runSuite(browser, groups); }
  finally { await browser.close(); }
}
if (require.main === module) main().catch(() => { console.error('GitHub App rendered regression failed; raw error suppressed'); process.exitCode = 1; });
module.exports = {runSuite, selectedGroups};
