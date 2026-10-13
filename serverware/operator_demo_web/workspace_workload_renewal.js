// Public enrollment configuration only. Private keys and proxy tokens stay in the workload.
function workloadRenewalAudience(value, proxyUrl) {
  try {
    const url = new URL(value);
    return typeof value === 'string' && value.length <= 512 && url.protocol === 'https:' &&
      !url.username && !url.password && !url.search && !url.hash &&
      (value === url.origin + '/v1/workload/renew' || !url.port && value === url.origin + ':443/v1/workload/renew') &&
      (proxyUrl === undefined || value === proxyUrl.replace(/\/+$/, '') + '/v1/workload/renew');
  } catch (_) { return false; }
}
function projectWorkloadRenewalCapability(value, proxyUrl) {
  if (!value || !workloadRenewalAudience(value.audience, proxyUrl)) return null;
  const expected = {schema: 'serverware.workloadTokenRenewal/v1',
    enroll_path: '/api/operator-demo/applications/renewal/enroll',
    cancel_path: '/api/operator-demo/applications/renewal/cancel', path: '/v1/workload/renew',
    audience: value.audience, overlap_seconds: 300,
    token_lifetime_seconds: {min: 3600, max: 86400, default: 3600},
    enrollment_lifetime_seconds: {min: 86400, max: 7776000, default: 2592000}, single_writer: true};
  return operatorExact(value, expected) ? expected : null;
}
function projectClientRenewal(value, proxyUrl) {
  if (value == null) return null;
  const names = ['version', 'enrollment_id', 'expires_at_epoch_ms', 'public_key_fingerprint',
    'token_lifetime_seconds', 'overlap_seconds', 'audience', 'status'];
  if (typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== names.sort().join(',') || value.version !== 1 ||
      typeof value.enrollment_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.enrollment_id) ||
      !Number.isSafeInteger(value.expires_at_epoch_ms) || value.expires_at_epoch_ms <= 0 ||
      typeof value.public_key_fingerprint !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.public_key_fingerprint) ||
      !Number.isInteger(value.token_lifetime_seconds) || value.token_lifetime_seconds < 3600 || value.token_lifetime_seconds > 86400 ||
      value.overlap_seconds !== 300 || !workloadRenewalAudience(value.audience, proxyUrl) ||
      !['active', 'expired'].includes(value.status))
    throw operatorError('Saved client renewal metadata is unsupported. Refresh and review before making changes.');
  return Object.fromEntries(names.map(name => [name, value[name]]));
}
function workloadRenewalEnrollment(id, publicKey, days, hours) {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) ||
      typeof publicKey !== 'string' || !/^[0-9a-f]{64}$/.test(publicKey) ||
      !Number.isInteger(days) || days < 1 || days > 90 || !Number.isInteger(hours) || hours < 1 || hours > 24)
    throw operatorError('Enter an Ed25519 public key as 64 lowercase hexadecimal characters, 1–90 days and 1–24 hours. Never paste a private key.');
  return {id, public_key: publicKey, enrollment_lifetime_seconds: days * 86400, token_lifetime_seconds: hours * 3600};
}
function workloadRenewalSetup(application, proxyUrl) {
  const renewal = projectClientRenewal(application?.client_renewal, proxyUrl);
  if (!renewal || renewal.status !== 'active' || renewal.expires_at_epoch_ms <= Date.now() ||
      typeof application.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(application.id) ||
      application.status !== 'active' || !Number.isSafeInteger(application.token_generation) || application.token_generation < 1 ||
      !Number.isSafeInteger(application.token_expires_at_epoch_ms) || application.token_expires_at_epoch_ms <= 0 ||
      application.token_expires_at_epoch_ms > renewal.expires_at_epoch_ms) return null;
  return {schema: 'serverware.managedClientSetup/v1', application_id: application.id,
    enrollment_id: renewal.enrollment_id, audience: renewal.audience, public_key_fingerprint: renewal.public_key_fingerprint,
    token_generation: application.token_generation, token_expires_at_epoch_ms: application.token_expires_at_epoch_ms,
    enrollment_expires_at_epoch_ms: renewal.expires_at_epoch_ms, token_lifetime_seconds: renewal.token_lifetime_seconds,
    overlap_seconds: renewal.overlap_seconds};
}
function createWorkloadRenewalView(workspace, invalidate) {
  const form = element('application-renewal-form');
  const select = element('application-renewal-client');
  const key = element('application-renewal-key');
  const consent = element('application-renewal-consent');
  let selected = ''; let optionsKey = ''; let hashing = false; let expiryTimer;
  const application = () => workspace.state.catalog?.applications.find(item => item.id === select.value);
  const capability = () => projectWorkloadRenewalCapability(workspace.state.catalog?.capabilities.workload_renewal, workspace.state.catalog?.proxy_url);
  const cancelReady = () => Boolean(workspace.state.catalog && application()?.status === 'active' &&
    !workspace.state.busy && !workspace.state.uncertain && !hashing);
  const ready = () => Boolean(cancelReady() && capability() && workspace.loaded());
  const clearInput = () => { key.value = ''; consent.checked = false; };
  const status = message => { element('application-renewal-status').textContent = message; };
  function snapshot(cancellation = false) {
    if (!(cancellation ? cancelReady() : ready())) return null;
    const catalog = workspace.state.catalog;
    return JSON.stringify({application: application(), capability: capability(), revision: catalog.revision, policy: catalog.policy});
  }
  function render() {
    clearTimeout(expiryTimer);
    const catalog = workspace.state.catalog;
    const choices = catalog?.applications.filter(item => item.status === 'active') || [];
    const nextOptions = JSON.stringify(choices.map(item => [item.id, item.name]));
    if (optionsKey !== nextOptions) {
      const previous = select.value; select.replaceChildren();
      select.append(new Option('Select an existing client', ''));
      for (const item of choices) select.append(new Option(item.name + ' · ' + item.id, item.id));
      select.value = choices.some(item => item.id === previous) ? previous : ''; optionsKey = nextOptions;
    }
    if (selected !== select.value || !catalog) { clearInput(); selected = select.value; }
    const item = application(); const renewal = item?.client_renewal;
    if (renewal?.expires_at_epoch_ms > Date.now())
      expiryTimer = setTimeout(render, Math.max(1, Math.min(renewal.expires_at_epoch_ms - Date.now(), 2147483647)));
    const supported = Boolean(capability());
    element('application-renewal-availability').textContent = supported ?
      'Available for this loaded proxy policy. Enrollment is optional; existing clients use manual token rotation unless you enroll them.' :
      'Managed renewal is not currently advertised by the loaded proxy policy. No new enrollment can be sent; existing enrollment can still be cancelled. Refresh after paired proxy support and policy activation.';
    select.disabled = !catalog || workspace.state.busy || workspace.state.uncertain || hashing;
    element('application-renewal-fields').disabled = !ready();
    element('application-renewal-enroll').disabled = !ready();
    element('application-renewal-cancel').disabled = !cancelReady() || !renewal;
    element('application-renewal-enroll').textContent = renewal ? 'Replace renewal enrollment' : 'Enroll workload public key';
    element('application-renewal-summary').textContent = !item ? 'Select a client to review its renewal authority.' : !renewal ?
      (Number.isSafeInteger(item.client_renewal_cancelled_at_epoch_ms) ?
        'Renewal cancelled ' + new Date(item.client_renewal_cancelled_at_epoch_ms).toLocaleString() + '. Manual token rotation required; no workload key is enrolled.' :
        'Manual token rotation required. No workload key is enrolled.') :
      (renewal.status === 'expired' || renewal.expires_at_epoch_ms <= Date.now() ? 'Enrollment expired' : 'Enrollment active') +
      ' · authority ends ' + new Date(renewal.expires_at_epoch_ms).toLocaleString() +
      ' · token lifetime ' + renewal.token_lifetime_seconds / 3600 + ' hours · up to 5 minutes of previous-token overlap. Key fingerprint: ' + renewal.public_key_fingerprint;
    const setup = item && workloadRenewalSetup(item, catalog.proxy_url);
    const usable = Boolean(setup && ready());
    element('application-renewal-setup').textContent = usable ? JSON.stringify(setup, null, 2) :
      'Public setup is available after an active enrollment and its matching proxy policy are confirmed. This page never creates a workload private key.';
    element('application-renewal-download').disabled = !usable;
  }
  function receipt(result, before, body, fingerprint) {
    const item = result.application;
    const renewal = projectClientRenewal(item?.client_renewal, workspace.state.catalog?.proxy_url);
    const assigned = before.application.active_rule_count > 0;
    if (!item || Object.hasOwn(result, 'client_token') || result.revision !== before.revision + 1 ||
        !/^sha256:[0-9a-f]{64}$/.test(result.policy?.policy_hash || '') || !['active', 'pending'].includes(result.policy.activation) ||
        result.policy.sequence !== before.policy.sequence + (assigned ? 1 : 0) ||
        (assigned ? result.policy.policy_hash === before.policy.policy_hash : result.policy.policy_hash !== before.policy.policy_hash) ||
        ['id', 'name', 'principal_id', 'status', 'token_generation', 'proxy_authentication', 'active_rule_count'].some(name => item[name] !== before.application[name]) ||
        !Number.isSafeInteger(item.token_expires_at_epoch_ms) || item.token_expires_at_epoch_ms <= 0 ||
        (body ? !renewal || renewal.status !== 'active' || renewal.enrollment_id === before.application.client_renewal?.enrollment_id ||
          renewal.public_key_fingerprint !== fingerprint || renewal.token_lifetime_seconds !== body.token_lifetime_seconds ||
          renewal.expires_at_epoch_ms <= Date.now() || renewal.expires_at_epoch_ms > Date.now() + body.enrollment_lifetime_seconds * 1000 + 5000 ||
          item.token_expires_at_epoch_ms !== Math.min(before.application.token_expires_at_epoch_ms, renewal.expires_at_epoch_ms) :
          renewal !== null || item.token_expires_at_epoch_ms !== before.application.token_expires_at_epoch_ms))
      throw operatorError('The renewal change receipt could not be confirmed. Review saved state; do not repeat the request automatically.');
    return {id: item.id, generation: item.token_generation, expiry: item.token_expires_at_epoch_ms, renewal,
      revision: result.revision, policyHash: result.policy.policy_hash, sequence: result.policy.sequence};
  }
  async function save(kind, body, fingerprint, reviewed) {
    const before = JSON.parse(reviewed); let received = null;
    clearInput();
    if (body) invalidate(before.application.id);
    const accepted = await workspace.mutate('applications/renewal/' + kind, body || {id: before.application.id}, 'application-renewal-status', result => {
      received = receipt(result, before, body, fingerprint);
    });
    if (!accepted) return;
    const catalog = workspace.state.catalog;
    const item = catalog?.applications.find(value => value.id === received.id);
    const confirmed = item && catalog.revision === received.revision && catalog.policy.policy_hash === received.policyHash &&
      catalog.policy.sequence === received.sequence && item.token_generation === received.generation && item.token_expires_at_epoch_ms === received.expiry &&
      operatorExact(item.client_renewal ?? null, received.renewal);
    if (!confirmed) {
      const message = 'Renewal change acknowledged, but refreshed saved state could not be confirmed. Review it before another change; do not assume rollback.';
      workspace.requireReview(message); status(message); return;
    }
    status(kind === 'enroll' ? 'Enrollment saved. Configure one workload renewal helper with its locally held private key and the public setup below. ' +
      (workspace.loaded() ? 'The saved policy is loaded; no workload renewal or SDK connection was tested.' : 'Wait for the exact saved policy to load.') :
      'Renewal enrollment cancelled. The current token and its expiry are unchanged; previous-token overlap is cancelled. Enforcement requires the saved policy to load.');
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!ready() || !form.reportValidity() || !consent.checked) return;
    const reviewed = snapshot(); let body;
    try { body = workloadRenewalEnrollment(select.value, key.value, Number(element('application-renewal-days').value), Number(element('application-renewal-hours').value)); }
    catch (error) { status(operatorMessage(error)); return; }
    const item = application();
    if (!window.confirm('Enroll this public workload key for "' + item.name + '" (' + item.id + ') for ' + body.enrollment_lifetime_seconds / 86400 +
        ' days, with tokens lasting at most ' + body.token_lifetime_seconds / 3600 + ' hours? This replaces any previous enrollment and cancels its overlap. ' +
        'The current token is not renewed; its expiry may be shortened. Save any displayed one-time token first: it will be cleared from this page. ' +
        'Keep the private key in one workload only. Permissions and provider credentials do not change.')) return;
    if (snapshot() !== reviewed) { clearInput(); status('Saved state changed. Review again; no enrollment was sent.'); return; }
    let fingerprint;
    hashing = true; render();
    try {
      const bytes = Uint8Array.from(body.public_key.match(/../g), value => parseInt(value, 16));
      fingerprint = 'sha256:' + Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('');
    } catch (_) { status('This browser cannot verify the public-key fingerprint. No enrollment was sent.'); return; }
    finally { hashing = false; render(); }
    if (snapshot() !== reviewed) { clearInput(); status('Saved state changed. Review again; no enrollment was sent.'); return; }
    try { await save('enroll', body, fingerprint, reviewed); }
    finally { body.public_key = ''; }
  });
  element('application-renewal-cancel').addEventListener('click', async () => {
    const reviewed = snapshot(true); const item = application();
    if (!reviewed || !item.client_renewal || !window.confirm('Cancel workload renewal for "' + item.name + '" (' + item.id +
        ')? Its current token remains valid until its existing expiry. Previous-token overlap is removed after the new policy loads. No replacement token is created.')) return;
    if (snapshot(true) !== reviewed) { clearInput(); status('Saved state changed. Review again; no cancellation was sent.'); return; }
    await save('cancel', null, null, reviewed);
  });
  element('application-renewal-download').addEventListener('click', () => {
    if (!ready()) return;
    const setup = workloadRenewalSetup(application(), workspace.state.catalog.proxy_url); if (!setup) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(setup, null, 2) + '\n'], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'serverware-managed-client.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status('Downloaded public setup only. Configure the helper with its matching local private key; no key or token was created or downloaded.');
  });
  select.addEventListener('change', () => { clearInput(); status(''); render(); });
  window.addEventListener('pagehide', () => { clearInput(); clearTimeout(expiryTimer); });
  window.addEventListener('hashchange', () => { if (location.hash !== '#applications') clearInput(); });
  workspace.subscribe(render); render();
  return {render, select(id) { select.value = id; clearInput(); render(); element('application-renewal').scrollIntoView(); key.focus(); }};
}
