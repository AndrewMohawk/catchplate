function createApplicationsView(workspace) {
  let held = null; let expiryTimer; let channel;
  const rotationLifetimes = new Map();
  const lifetimes = [[3600, '1 hour'], [86400, '1 day'], [604800, '7 days'], [2592000, '30 days'], [7776000, '90 days']];
  const validLifetime = value => Number.isInteger(value) && value >= 3600 && value <= 7776000;
  function clear(reason = '') {
    held = null; clearTimeout(expiryTimer); element('client-token').value = ''; element('client-token').type = 'password';
    element('one-time-access').hidden = true; element('reveal-token').textContent = 'Reveal'; element('reveal-token').setAttribute('aria-pressed', 'false');
    for (const id of ['client-token', 'reveal-token', 'copy-token', 'dismiss-token']) element(id).disabled = true;
    element('download-config').disabled = true;
    if (reason) element('token-expiry-status').textContent = reason;
  }
  function reconcile() {
    if (!held) return;
    const application = workspace.state.catalog?.applications.find(item => item.id === held.id);
    if (!application || application.status !== 'active' || application.token_status !== 'valid' ||
        application.token_generation !== held.generation || application.token_expires_at_epoch_ms !== held.expires || Date.now() >= held.expires)
      clear('The held token was cleared because its current generation, expiry or application state could not be confirmed. No token has been renewed or retrieved.');
  }
  function tokenFor(id) { reconcile(); return held?.id === id ? held.token : ''; }
  function scheduleExpiry() {
    clearTimeout(expiryTimer);
    if (held) expiryTimer = setTimeout(() => { reconcile(); scheduleExpiry(); workspace.emit(); }, Math.max(1, Math.min(held.expires - Date.now(), 2147483647)));
  }
  function hold(result) {
    const application = result.application;
    if (!application || typeof application.id !== 'string' || typeof result.client_token !== 'string' || result.client_token.length < 32 ||
        !Number.isSafeInteger(application.token_generation) || application.token_generation < 1 ||
        !Number.isSafeInteger(application.token_expires_at_epoch_ms) || application.token_expires_at_epoch_ms <= Date.now())
      throw operatorError('The response did not contain a complete one-time application token. Review saved application state; do not repeat automatically.');
    clear(); held = {id: application.id, generation: application.token_generation, expires: application.token_expires_at_epoch_ms, token: result.client_token};
    result.client_token = ''; element('client-token').value = held.token;
    element('token-application-label').textContent = application.name + ' · expires ' + new Date(held.expires).toLocaleString();
    element('one-time-access').hidden = false; element('token-expiry-status').textContent = '';
    for (const id of ['client-token', 'reveal-token', 'copy-token', 'dismiss-token']) element(id).disabled = false;
    element('token-status').textContent = 'Save this token now. Clipboard contents and downloaded files are outside Serverware; keep them private.';
    scheduleExpiry();
  }
  function invalidate(id) {
    if (held?.id === id) clear('The token was cleared before its replacement or revocation. Review saved state if the response is lost.');
    try { channel?.postMessage({kind: 'application-token-invalidated', application_id: id}); }
    catch (_) { channel = null; } // A closed/unavailable notifier never blocks explicit token changes.
  }
  function connectChannel() {
    if (channel || typeof BroadcastChannel === 'undefined') return;
    try { channel = new BroadcastChannel('serverware-operator-catalog-v1'); } catch (_) { return; }
    channel.addEventListener('message', event => {
      if (event.data?.kind !== 'application-token-invalidated' || typeof event.data.application_id !== 'string') return;
      if (held?.id === event.data.application_id) clear('Another tab changed this application token. It was cleared from this page.');
      workspace.refresh();
    });
  }
  connectChannel();
  const form = element('application-form');
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!workspace.ready('applications') || !form.reportValidity()) return;
    const lifetime = Number(element('application-token-ttl').value); if (!validLifetime(lifetime)) return;
    if (held && !window.confirm('Creating another application clears the held one-time token from this page. Have you saved it?')) return;
    clear(); await workspace.mutate('applications', {name: element('application-name').value.trim(), token_lifetime_seconds: lifetime}, 'application-form-status', hold);
  });
  async function copyHeld() {
    reconcile(); if (!held) return;
    try { await navigator.clipboard.writeText(held.token); element('token-status').textContent = 'Copied. Keep the clipboard private.'; }
    catch (_) { element('token-status').textContent = 'Clipboard access was denied. Select and copy the displayed token manually.'; }
  }
  element('copy-token').addEventListener('click', copyHeld);
  element('reveal-token').addEventListener('click', () => {
    reconcile(); if (!held) return;
    const visible = element('client-token').type === 'password'; element('client-token').type = visible ? 'text' : 'password';
    element('reveal-token').textContent = visible ? 'Hide' : 'Reveal'; element('reveal-token').setAttribute('aria-pressed', String(visible));
  });
  element('dismiss-token').addEventListener('click', () => {
    if (held && window.confirm('Clear the one-time token from this page? It cannot be retrieved again.')) { clear(); workspace.emit(); }
  });
  function render() {
    reconcile(); const catalog = workspace.state.catalog;
    element('application-fields').disabled = !workspace.ready('applications');
    if (!catalog) return;
    renderCards('applications-list', catalog.applications.map(application => {
      const revoked = application.status === 'revoked';
      const badge = revoked ? workspace.loaded() && application.access_status === 'revoked' ? 'Revoked · enforced' : 'Revoked · enforcement pending' :
        application.token_status === 'expired' || Date.now() >= application.token_expires_at_epoch_ms ? 'Token expired' :
          application.access_status === 'unassigned' ? 'No access rules' : workspace.loaded() && application.access_status === 'active' ? 'Active' : 'Access pending';
      const card = resourceCard(application, badge, [['Token expires', new Date(application.token_expires_at_epoch_ms).toLocaleString()],
        ['Token generation', String(application.token_generation)], ['Active rules', String(application.active_rule_count)], ['Application ID', application.id]]);
      if (!revoked) {
        const select = textNode('select'); select.className = 'application-rotate-ttl'; select.setAttribute('aria-label', 'Replacement token lifetime for ' + application.name);
        for (const [seconds, label] of lifetimes) { const option = textNode('option', label); option.value = String(seconds); select.append(option); }
        select.value = rotationLifetimes.get(application.id) || '2592000'; select.disabled = workspace.state.busy || workspace.state.uncertain;
        select.addEventListener('change', () => rotationLifetimes.set(application.id, select.value));
        const rotate = textNode('button', 'Rotate client token', 'secondary'); rotate.dataset.action = 'rotate-application';
        const revoke = textNode('button', 'Revoke application', 'secondary'); revoke.dataset.action = 'revoke-application';
        rotate.disabled = revoke.disabled = workspace.state.busy || workspace.state.uncertain;
        rotate.addEventListener('click', async () => {
          const lifetime = Number(select.value); if (!validLifetime(lifetime)) return;
          if (held && held.id !== application.id && !window.confirm('Rotating this application clears the other held one-time token from this page. Have you saved it?')) return;
          if (!window.confirm(`Replace the client token for "${application.name}" (${application.id}) with a token valid for ${select.selectedOptions[0].textContent}? The previous token stops working after the proxy loads the new policy. Save the replacement immediately. This does not refresh a provider OAuth credential.`)) return;
          invalidate(application.id); await workspace.mutate('applications/rotate-token', {id: application.id, token_lifetime_seconds: lifetime}, 'application-action-status', hold);
        });
        revoke.addEventListener('click', async () => {
          if (!window.confirm(`Revoke application "${application.name}" (${application.id}) and its ${application.active_rule_count} active access rules? Shared provider credentials and other applications remain. Enforcement begins after the proxy loads the new policy; already-dispatched requests cannot be recalled.`)) return;
          invalidate(application.id); await workspace.mutate('applications/revoke', {id: application.id}, 'application-action-status');
        });
        card.append(textNode('p', 'Replacement token lifetime', 'small'), select); const actions = textNode('div', undefined, 'actions'); actions.append(rotate, revoke); card.append(actions);
      }
      return card;
    }), 'No applications. Create a client identity and save its one-time token, then add an access rule.');
  }
  window.addEventListener('pagehide', () => { clear(); channel?.close(); channel = null; });
  window.addEventListener('pageshow', event => { if (event.persisted) { connectChannel(); workspace.refresh(); } });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { reconcile(); workspace.refresh(); } });
  window.addEventListener('focus', () => { reconcile(); workspace.refresh(); });
  workspace.subscribe(render); return {tokenFor, clear, render};
}
