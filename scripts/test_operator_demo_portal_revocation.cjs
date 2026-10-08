// Intercepted UI contracts only. These fixtures do not prove backend mutation,
// gate enforcement, provider revocation, or cancellation of in-flight traffic.
const assert = require('node:assert/strict');

module.exports = function revocationTests({fixture, connection, response, ready, fill, statusText,
  noClientActions, noTokenActions, revokeFixture, hash, oldHash, revokedHash, fixtureNow,
  fakeClientToken, fakeProviderSecret}) {
  const targetId = 'fixture-connection';
  const targetCard = page => page.locator(`[data-connection-id="${targetId}"]`);
  const receiptCard = page => page.locator(`[data-revoked-connection-id="${targetId}"]`);
  const other = () => connection({id: 'other-connection', name: 'Other API', credential_id: 'other-credential', principal_id: 'other-client'});
  async function confirmRevoke(page, id = targetId, accept = true) {
    await page.locator('nav a[href="#credentials"]').click();
    const dialogEvent = page.waitForEvent('dialog');
    const clicked = page.locator(`[data-connection-id="${id}"] .revoke-connection`).click();
    const dialog = await dialogEvent;
    assert.equal(dialog.type(), 'confirm');
    const prompt = dialog.message();
    assert(prompt.includes(id), 'confirmation must name the exact connection ID');
    assert(prompt.includes(id === targetId ? 'My API' : 'Other API'), 'confirmation must name the connection');
    assert(!prompt.includes(fakeClientToken)); assert(!prompt.includes(fakeProviderSecret));
    if (accept) await dialog.accept(); else await dialog.dismiss();
    await clicked;
  }
  async function noSecretsStored(page) {
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    const body = await page.locator('body').innerText();
    assert(!body.includes(fakeProviderSecret)); assert(!body.includes(fakeClientToken));
  }
  async function refreshed(page, state) {
    const before = state.statusCalls;
    const received = page.waitForResponse(result => new URL(result.url()).pathname === '/api/operator-demo/status');
    await page.locator('#refresh-status').click();
    await received;
    await page.waitForFunction(() => document.querySelector('#load-error').hidden);
    assert(state.statusCalls > before, 'explicit refresh must fetch status');
  }
  return [
    ['revoke cancellation names the target and sends no mutation or token clearing', browser => fixture(browser, {}, async (page, state) => {
      await fill(page); await page.locator('#add-connection').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'});
      await confirmRevoke(page, targetId, false);
      assert.equal(state.revokes.length, 0); assert.equal(state.posts.length, 1);
      assert.equal(await page.locator('#client-token').inputValue(), fakeClientToken);
      assert.equal(await targetCard(page).count(), 1); await noSecretsStored(page);
    })],
    ['explicit revoke uses exact ID/current hash, clears its token and waits for enforcement', browser => fixture(browser, {
      connections: [other()],
    }, async (page, state) => {
      await fill(page); await page.locator('#add-connection').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'});
      await confirmRevoke(page);
      await statusText(page, '#revocations-list', 'Pending enforcement');
      assert.deepEqual(state.revokes, [{connection_id: targetId, expected_policy_hash: hash}]);
      assert.equal(await targetCard(page).count(), 0); await noTokenActions(page); await noSecretsStored(page);
      assert.equal(await page.locator('[data-connection-id="other-connection"]').count(), 1);
      assert.equal(state.connections[0].credential_id, 'other-credential');
      assert.equal(state.connections[0].principal_id, 'other-client');
      state.loaded = revokedHash; await refreshed(page, state);
      await statusText(page, '#revocations-list', 'Enforced');
      assert.equal(state.revokes.length, 1);
      await page.locator('nav a[href="#proxy"]').click();
      await page.locator('#client-connection').selectOption('other-connection');
      assert(await page.locator('#copy-command').isEnabled());
      assert(await page.locator('#download-config').isDisabled());
      assert.equal(await page.locator('#client-connection option[value="fixture-connection"]').count(), 0);
    })],
    ['enforcement follows the current policy, never an older revocation hash after later changes', browser => fixture(browser, {
      connections: [connection(), other()],
    }, async (page, state) => {
      await ready(page); await confirmRevoke(page);
      await statusText(page, '#revocations-list', 'Pending enforcement');
      state.loaded = revokedHash; state.active = oldHash;
      await refreshed(page, state);
      await statusText(page, '#revocations-list', 'Pending enforcement');
      assert.equal(await receiptCard(page).locator('.badge.active').count(), 0);
      state.loaded = oldHash; await refreshed(page, state);
      await statusText(page, '#revocations-list', 'Enforced');
      assert.equal(state.revokes.length, 1);
    })],
    ['expired connections still offer explicit revocation without renewing token expiry', browser => fixture(browser, {
      connections: [connection({token_expires_at_epoch_ms: fixtureNow, client_status: 'expired'})],
    }, async (page, state) => {
      await ready(page); await statusText(page, '#connections-list', 'Token expired');
      assert(await targetCard(page).locator('.revoke-connection').isEnabled());
      await confirmRevoke(page); await statusText(page, '#revocations-list', 'Pending enforcement');
      assert.deepEqual(state.revokes, [{connection_id: targetId, expected_policy_hash: hash}]);
      assert.equal(state.posts.length, 0); await noTokenActions(page);
      await page.locator('nav a[href="#proxy"]').click(); await noClientActions(page);
    })],
    ...[409, 404].map(code => ['revoke HTTP ' + code + ' stays uncertain, redacts errors and never retries automatically', browser => fixture(browser, {
      connections: [connection()], override: (url, request, state) => {
        if (url.pathname !== '/api/operator-demo/connections/revoke') return null;
        if (code === 409) state.active = oldHash;
        return response({detail: fakeProviderSecret + fakeClientToken}, code);
      },
    }, async (page, state) => {
      await ready(page); await confirmRevoke(page);
      await page.waitForFunction(() => document.querySelector('#revocation-status').textContent.length > 0);
      await refreshed(page, state); await page.clock.runFor(12000);
      assert.equal(state.revokes.length, 1); assert.equal(state.posts.length, 0);
      assert.equal(await receiptCard(page).count(), 0); await noSecretsStored(page);
      assert(!/\bEnforced\b/.test(await page.locator('#revocation-status').innerText()));
    })]),
    ['lost revoke response reconciles the tombstone through status without repeating POST', browser => fixture(browser, {
      override: (url, request, state) => {
        if (url.pathname !== '/api/operator-demo/connections/revoke') return null;
        revokeFixture(state, state.connections.find(item => item.id === request.postDataJSON().connection_id));
        return {abort: 'failed'};
      },
    }, async (page, state) => {
      await fill(page); await page.locator('#add-connection').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'});
      await confirmRevoke(page);
      await refreshed(page, state); await statusText(page, '#revocations-list', 'Pending enforcement');
      await noTokenActions(page); assert.equal(await targetCard(page).count(), 0);
      await page.clock.runFor(12000);
      assert.deepEqual(state.revokes, [{connection_id: targetId, expected_policy_hash: hash}]);
      assert.equal(state.posts.length, 1); await noSecretsStored(page);
      state.loaded = revokedHash; await refreshed(page, state);
      await statusText(page, '#revocations-list', 'Enforced');
      assert.equal(state.revokes.length, 1);
    })],
    ['status-observed revocation from another tab clears the matching held token', browser => fixture(browser, {}, async (page, state) => {
      await fill(page); await page.locator('#add-connection').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'});
      revokeFixture(state, state.connections[0]); state.loaded = revokedHash;
      await refreshed(page, state); await statusText(page, '#revocations-list', 'Enforced');
      await noTokenActions(page); await noSecretsStored(page);
      assert.equal(state.revokes.length, 0);
      await page.locator('nav a[href="#proxy"]').click(); await noClientActions(page);
      await page.reload(); await ready(page); await noTokenActions(page);
      assert.equal(state.revokes.length, 0);
    })],
    ['revoking a different connection leaves the held token for the unaffected client', browser => fixture(browser, {
      connections: [other()],
    }, async (page, state) => {
      await fill(page); await page.locator('#add-connection').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'});
      await confirmRevoke(page, 'other-connection');
      await statusText(page, '#revocations-list', 'Pending enforcement');
      assert.equal(await page.locator('#client-token').inputValue(), fakeClientToken);
      assert.equal(await targetCard(page).count(), 1);
      assert.deepEqual(state.revokes, [{connection_id: 'other-connection', expected_policy_hash: hash}]);
      state.loaded = revokedHash; await refreshed(page, state);
      await page.locator('nav a[href="#proxy"]').click();
      await page.locator('#client-connection').selectOption(targetId);
      assert(await page.locator('#download-config').isEnabled()); await noSecretsStored(page);
    })],
    ['page load, polling, audit navigation and reload never initiate revocation', browser => fixture(browser, {
      connections: [connection()], loaded: oldHash,
    }, async (page, state) => {
      await ready(page); await page.clock.runFor(12000);
      for (const view of ['credentials', 'proxy', 'audit', 'overview']) await page.locator(`nav a[href="#${view}"]`).click();
      await page.reload(); await ready(page); await page.clock.runFor(12000);
      assert.equal(state.revokes.length, 0); assert.equal(state.posts.length, 0); await noSecretsStored(page);
    })],
    ...['active', 'retained'].map(kind => ['connection ' + kind + ' capacity blocks create but not explicit revoke', browser => fixture(browser, {
      connections: [connection()], connectionLimits: {active_count: kind === 'active' ? 32 : 1, active_max: 32,
        retained_count: kind === 'retained' ? 1024 : 32, retained_max: 1024},
    }, async (page, state) => {
      await statusText(page, '#connection-capacity', kind === 'active' ? 'Active connection capacity' : 'Lifetime connection capacity');
      assert(await page.locator('#connection-fields').evaluate(element => element.disabled));
      assert(await page.locator('#add-connection').isDisabled());
      assert(await targetCard(page).locator('.revoke-connection').isEnabled());
      await confirmRevoke(page); await statusText(page, '#revocations-list', 'Pending enforcement');
      assert.equal(state.revokes.length, 1); assert.equal(state.posts.length, 0);
    })]),
  ];
};
