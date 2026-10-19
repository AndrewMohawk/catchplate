// Same-origin old and new tabs must both discard invalidated one-time tokens.
// These advisory messages contain only a public client ID, never the token.
// Received messages are not forwarded: there is no bridge/rebroadcast loop.
function createApplicationTokenInvalidations(onInvalidate) {
  const channels = new Map();
  const names = ['catchplate-operator-catalog-v1', 'serverware-operator-catalog-v1'];
  const validId = id => typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id);
  function connect() {
    if (typeof BroadcastChannel === 'undefined') return;
    for (const name of names) {
      if (channels.has(name)) continue;
      try {
        const channel = new BroadcastChannel(name);
        channel.addEventListener('message', event => {
          if (event.data?.kind === 'application-token-invalidated' && validId(event.data.application_id)) onInvalidate(event.data.application_id);
        });
        channels.set(name, channel);
      } catch (_) { /* An unavailable notifier never grants access or triggers a retry. */ }
    }
  }
  function send(id) {
    if (!validId(id)) return;
    for (const [name, channel] of channels) {
      try { channel.postMessage({kind: 'application-token-invalidated', application_id: id}); }
      catch (_) { try { channel.close(); } catch (_) {} channels.delete(name); }
    }
  }
  function close() {
    for (const channel of channels.values()) try { channel.close(); } catch (_) {}
    channels.clear();
  }
  return {connect, send, close};
}
function createApplicationsView(workspace, actions = {}) {
  const inventory = createResourceInventory('applications-list', 'clients', {jump: true});
  const tokenHome = document.createComment('shared application token panel');
  element('one-time-access').before(tokenHome);
  let held = null; let expiryTimer;
  const invalidations = createApplicationTokenInvalidations(id => {
    if (held?.id === id) clear('Another tab changed this application token. It was cleared from this page.');
    workspace.refresh();
  });
  const rotationLifetimes = new Map();
  const lifetimes = [[3600, '1 hour'], [86400, '1 day'], [604800, '7 days'], [2592000, '30 days'], [7776000, '90 days']];
  const validLifetime = value => Number.isInteger(value) && value >= 3600 && value <= 7776000;
  function clear(reason = '') {
    held = null; clearTimeout(expiryTimer); element('client-token').value = ''; element('client-token').type = 'password';
    element('one-time-access').hidden = true; element('reveal-token').textContent = 'Reveal'; element('reveal-token').setAttribute('aria-pressed', 'false');
    for (const id of ['client-token', 'reveal-token', 'copy-token', 'dismiss-token']) element(id).disabled = true;
    element('download-config').disabled = true;
    element('token-add-permission').setAttribute('aria-disabled', 'true');
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
  function continuation() {
    reconcile();
    const application = workspace.state.catalog?.applications.find(item => item.id === held?.id);
    return {application, configure: Boolean(application?.active_rule_count)};
  }
  function focusResult(statusId, applicationId) {
    if (location.hash !== '#applications') return;
    reconcile();
    const target = element(held && held.id === applicationId ? 'one-time-access' : statusId);
    target.setAttribute('tabindex', '-1'); target.focus(); target.scrollIntoView({block: 'start'});
  }
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
    element('token-status').textContent = 'Save this token now. Clipboard contents and downloaded files are outside Catchplate; keep them private.';
    scheduleExpiry();
  }
  function invalidate(id) {
    if (held?.id === id) clear('The token was cleared before its replacement or revocation. Review saved state if the response is lost.');
    invalidations.send(id);
  }
  invalidations.connect();
  async function create(name, lifetime, statusId) {
    if (!workspace.ready('applications') || !validLifetime(lifetime)) return null;
    if (held && !window.confirm('Creating another application clears the held one-time token from this page. Have you saved it?')) return null;
    clear(); let receipt = null;
    const login = newApplicationProxyAuthentication(workspace.state.catalog);
    await workspace.mutate('applications', {name, token_lifetime_seconds: lifetime, ...login}, statusId, result => {
      if (!Number.isSafeInteger(result.revision)) throw operatorError('The saved application revision was unavailable. Review saved state before continuing.');
      if (applicationProxyAuthentication(result.application) !== (login.proxy_authentication || 'bearer'))
        throw operatorError('The saved proxy login mode did not match the reviewed application creation. Review saved state; do not repeat automatically.');
      hold(result);
      receipt = {id: result.application.id, revision: result.revision};
    });
    return receipt;
  }
  const form = element('application-form');
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!workspace.ready('applications') || !form.reportValidity()) return;
    const lifetime = Number(element('application-token-ttl').value); if (!validLifetime(lifetime)) return;
    const receipt = await create(element('application-name').value.trim(), lifetime, 'application-form-status');
    if (receipt) {
      if (!workspace.state.uncertain && tokenFor(receipt.id))
        element('application-form-status').textContent = 'Client created. Save its one-time access and add a permission before use.';
      focusResult('application-form-status', receipt.id);
    }
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
  element('token-add-permission').addEventListener('click', event => {
    event.preventDefault();
    const next = continuation();
    const action = next.configure ? actions.configure : actions.addPermission;
    if (!held || !next.application || workspace.state.busy || workspace.state.uncertain || !action?.(held.id))
      element('token-status').textContent = 'Client setup could not be opened. Keep any current setup draft, resolve pending changes and refresh saved state before continuing. No permission was granted.';
  });
  function loginIdentity(application) {
    return JSON.stringify(Object.fromEntries(['id', 'name', 'status', 'created_at', 'revoked_at', 'principal_id',
      'token_expires_at_epoch_ms', 'token_generation', 'active_rule_count'].map(name => [name, application[name]])));
  }
  function loginReview(id) {
    const catalog = workspace.state.catalog;
    const application = catalog?.applications.find(item => item.id === id && item.status === 'active');
    if (!application || !projectApplicationProxyAuthenticationCapability(catalog.capabilities.application_proxy_authentication) ||
        !applicationProxyAuthentication(application) || workspace.state.busy || workspace.state.uncertain) return null;
    const omit = (item, names) => Object.fromEntries(Object.entries(item).filter(([name]) => !names.includes(name)));
    const rules = catalog.access_rules.filter(item => item.application_id === id && item.status === 'active');
    return {id, mode: applicationProxyAuthentication(application), revision: catalog.revision,
      policyHash: catalog.policy.policy_hash, sequence: catalog.policy.sequence,
      application: loginIdentity(application),
      applications: JSON.stringify(catalog.applications.map(item => omit(item, item.id === id ?
        ['proxy_authentication', 'token_status', 'access_status'] : ['token_status', 'access_status']))),
      rules: JSON.stringify(catalog.access_rules.map(item => omit(item, ['enforcement']))),
      ruleIds: rules.map(item => item.id).sort(),
      ruleNames: operatorConnectResourceChoices(rules).map(item => item.name),
      name: operatorConnectResourceChoices(catalog.applications.filter(item => item.status === 'active')).find(item => item.id === id).name};
  }
  async function changeProxyAuthentication(id, target) {
    const reviewed = loginReview(id);
    if (!reviewed || !['bearer', 'basic_and_bearer_v1'].includes(target) || target === reviewed.mode) return;
    const title = target === 'basic_and_bearer_v1' ? 'Enable standard client login' : 'Use bearer only';
    const consequence = target === 'basic_and_bearer_v1' ?
      'Use this public application ID as the proxy username and its existing application token as the password. Bearer authentication remains available.' :
      'Username/password proxy login will stop being accepted after the new policy is loaded. Configure clients to send the existing token as a Bearer proxy header.';
    if (!window.confirm(title + ' for "' + reviewed.name + '" (' + id + ')?\nAffected active access rules (' +
        reviewed.ruleIds.length + '): ' + (reviewed.ruleNames.join(', ') || 'None') +
        '\nThe current application token, its expiry and all access rules stay unchanged. No provider credential is used as the proxy password.\n' +
        consequence + '\nAssigned rules must wait for the exact saved policy to load. This is not a client connection test.')) return;
    if (JSON.stringify(loginReview(id)) !== JSON.stringify(reviewed)) {
      element('application-action-status').textContent = 'Saved state changed. Review the application and affected rules again; no change was sent.'; return;
    }
    let receipt = null;
    const accepted = await workspace.mutate('applications/proxy-authentication', {id, proxy_authentication: target}, 'application-action-status', result => {
      const application = result.application;
      const affected = result.affected_rule_ids;
      const assigned = reviewed.ruleIds.length > 0;
      if (!application || Object.hasOwn(result, 'client_token') || applicationProxyAuthentication(application) !== target ||
          loginIdentity(application) !== reviewed.application ||
          result.revision !== reviewed.revision + 1 || !/^sha256:[a-f0-9]{64}$/.test(result.policy?.policy_hash || '') ||
          !['active', 'pending'].includes(result.policy.activation) ||
          (assigned ? result.policy.sequence !== reviewed.sequence + 1 || result.policy.policy_hash === reviewed.policyHash ||
            !Array.isArray(affected) || JSON.stringify([...affected].sort()) !== JSON.stringify(reviewed.ruleIds) :
            result.policy.sequence !== reviewed.sequence || result.policy.policy_hash !== reviewed.policyHash ||
            affected !== undefined && (!Array.isArray(affected) || affected.length)))
        throw operatorError('The proxy login change receipt could not be confirmed. Review saved state; no token was renewed and no automatic retry will be sent.');
      receipt = {policyHash: result.policy.policy_hash, sequence: result.policy.sequence};
    });
    if (!accepted) return;
    const current = loginReview(id);
    const confirmed = receipt && current && current.revision === reviewed.revision + 1 && current.mode === target &&
      current.policyHash === receipt.policyHash && current.sequence === receipt.sequence &&
      current.application === reviewed.application && current.applications === reviewed.applications && current.rules === reviewed.rules;
    const notice = confirmed ? 'Proxy login change saved. The application token and expiry are unchanged. ' +
      (reviewed.ruleIds.length ? workspace.loaded() ? 'The saved policy is loaded; no client request was tested.' :
        'Waiting for the exact saved policy to load before using this change.' : 'No access rules are assigned; add a rule before use.') :
      'Proxy login change acknowledged, but the refreshed saved state could not be confirmed. Refresh and review it before another change; do not assume rollback.';
    if (!confirmed) workspace.requireReview(notice);
    element('application-action-status').textContent = notice;
  }
  function render() {
    reconcile(); const catalog = workspace.state.catalog;
    const next = continuation();
    element('token-add-permission').textContent = next.configure ? 'Download client configuration →' : 'Set up access for this client →';
    element('token-add-permission').setAttribute('href', next.configure ? '#proxy' : '#connect');
    element('token-next-step-description').textContent = next.configure ?
      'Your saved permissions stay in place. Download a new private configuration for this client, then update its workload. You do not need to add permissions again.' :
      'This client has no permissions yet. Set up access using a saved credential, then download its private configuration.';
    element('token-add-permission').setAttribute('aria-disabled', String(!held || workspace.state.busy ||
      workspace.state.uncertain || typeof (next.configure ? actions.configure : actions.addPermission) !== 'function'));
    element('application-fields').disabled = !workspace.ready('applications');
    element('application-proxy-default').textContent = newApplicationProxyAuthentication(catalog).proxy_authentication ?
      'New apps use standard proxy login: public application ID as username, application token as password. Bearer also remains supported. Never use the provider key.' :
      'New apps use Bearer proxy authentication. Standard username/password login is not advertised by this deployment.';
    if (!catalog) { inventory.render(null); return; }
    const diagnostic = operatorDiagnosticResources(catalog);
    inventory.render(catalog.applications.map(application => {
      const revoked = application.status === 'revoked';
      const badge = revoked ? workspace.loaded() && application.access_status === 'revoked' ? 'Revoked · enforced' : 'Revoked · enforcement pending' :
        application.token_status === 'expired' || Date.now() >= application.token_expires_at_epoch_ms ? 'Token expired' :
          application.access_status === 'unassigned' ? 'No access rules' : workspace.loaded() && application.access_status === 'active' ? 'Active' : 'Access pending';
      const login = applicationProxyAuthentication(application);
      const card = resourceCard(application, badge, [['Token expires', new Date(application.token_expires_at_epoch_ms).toLocaleString()],
        ['Proxy login', login === 'basic_and_bearer_v1' ? 'Standard username/password and Bearer' : login === 'bearer' ? 'Bearer only' : 'Unsupported'],
        ['Token generation', String(application.token_generation)], ['Active rules', String(application.active_rule_count)], ['Client ID', application.id]]);
      const loginStatus = textNode('p', revoked ? 'Proxy login unavailable: application revoked.' :
        !applicationProxyAuthenticationSupported(catalog, application) ? 'Saved proxy login is unsupported by this workspace. Refresh before use.' :
        !application.active_rule_count ? 'Login choice saved; no access rules are assigned.' :
        workspace.loaded() && application.access_status === 'active' ? 'Saved login policy loaded. Token validity is separate; no client connection was tested.' :
          'Login enforcement pending: wait for the exact saved policy to load.', 'small muted');
      loginStatus.dataset.applicationProxyStatus = ''; card.append(loginStatus);
      if (!revoked) {
        const next = textNode('p', badge === 'Token expired' ?
          'Next: replace this client’s token below and update its private configuration. Your saved provider credentials and permissions stay in place.' :
          !application.active_rule_count ? 'Next: add a permission. A client token alone grants no provider access.' :
          !workspace.loaded() ? 'Next: wait for the saved permission policy to load, then open Configure client.' :
          'Next: open Configure client for its permissions and connection instructions.', 'small muted');
        next.dataset.applicationNextStep = ''; card.querySelector('.metadata').before(next);
        const setup = textNode('div', undefined, 'actions');
        const configure = textNode('button', 'Configure client', 'secondary'); configure.dataset.action = 'configure-client';
        const permission = textNode('button', 'Add permission', 'secondary'); permission.dataset.action = 'add-permission';
        configure.disabled = workspace.state.busy || workspace.state.uncertain || typeof actions.configure !== 'function';
        permission.disabled = workspace.state.busy || workspace.state.uncertain || typeof actions.addPermission !== 'function';
        configure.addEventListener('click', () => {
          if (workspace.state.busy || workspace.state.uncertain || !actions.configure?.(application.id))
            element('application-action-status').textContent = 'This exact client is unavailable for setup. Refresh saved state; no request was sent.';
        });
        permission.addEventListener('click', () => {
          if (workspace.state.busy || workspace.state.uncertain || !actions.addPermission?.(application.id))
            element('application-action-status').textContent = 'Client setup could not be opened. Keep any current setup draft or finish its pending operation before starting another.';
        });
        setup.append(configure, permission); card.append(setup);
        const select = textNode('select'); select.className = 'application-rotate-ttl'; select.setAttribute('aria-label', 'Replacement token lifetime for ' + application.name);
        for (const [seconds, label] of lifetimes) { const option = textNode('option', label); option.value = String(seconds); select.append(option); }
        select.value = rotationLifetimes.get(application.id) || '2592000'; select.disabled = workspace.state.busy || workspace.state.uncertain;
        select.addEventListener('change', () => rotationLifetimes.set(application.id, select.value));
        const rotate = textNode('button', 'Rotate client token', 'secondary'); rotate.dataset.action = 'rotate-application';
        const revoke = textNode('button', 'Revoke client', 'secondary'); revoke.dataset.action = 'revoke-application';
        rotate.disabled = revoke.disabled = workspace.state.busy || workspace.state.uncertain;
        rotate.addEventListener('click', async () => {
          const lifetime = Number(select.value); if (!validLifetime(lifetime)) return;
          if (held && held.id !== application.id && !window.confirm('Rotating this application clears the other held one-time token from this page. Have you saved it?')) return;
          if (!window.confirm(`Replace the client token for "${application.name}" (${application.id}) with a token valid for ${select.selectedOptions[0].textContent}? This cancels any workload renewal enrollment and previous-token overlap. The previous token stops working after the proxy loads the new policy. Save the replacement immediately. This does not refresh a provider OAuth credential.`)) return;
          invalidate(application.id);
          const accepted = await workspace.mutate('applications/rotate-token', {id: application.id, token_lifetime_seconds: lifetime}, 'application-action-status', hold);
          if (accepted && !workspace.state.uncertain && tokenFor(application.id))
            element('application-action-status').textContent = 'Replacement token saved. Save the new client configuration. ' +
              (workspace.loaded() ? 'The saved policy is loaded; no client request was tested.' : 'Waiting for the exact saved policy to load before use.');
          focusResult('application-action-status', application.id);
        });
        revoke.addEventListener('click', async () => {
          if (!window.confirm(`Revoke client "${application.name}" (${application.id}) and its ${application.active_rule_count} active permissions? This also cancels workload renewal and previous-token overlap. Shared provider credentials and other clients remain. Enforcement begins after the proxy loads the new policy; already-dispatched requests cannot be recalled.`)) return;
          invalidate(application.id);
          const accepted = await workspace.mutate('applications/revoke', {id: application.id}, 'application-action-status');
          if (accepted && !workspace.state.uncertain)
            element('application-action-status').textContent = 'Client revoked. ' +
              (workspace.loaded() ? 'The revocation policy is loaded.' : 'Waiting for the exact saved policy to load before revocation is enforced.') +
              ' Shared provider credentials and other clients remain. Already-dispatched requests cannot be recalled.';
          focusResult('application-action-status');
        });
        card.append(textNode('p', 'Replacement token lifetime', 'small'), select); const tokenActions = textNode('div', undefined, 'actions'); tokenActions.append(rotate, revoke);
        if (login && projectApplicationProxyAuthenticationCapability(catalog.capabilities.application_proxy_authentication)) {
          const target = login === 'bearer' ? 'basic_and_bearer_v1' : 'bearer';
          const change = textNode('button', target === 'bearer' ? 'Use bearer only' : 'Enable standard client login', 'secondary');
          change.dataset.action = 'change-proxy-authentication'; change.dataset.proxyAuthentication = target;
          change.disabled = workspace.state.busy || workspace.state.uncertain;
          change.addEventListener('click', () => changeProxyAuthentication(application.id, target)); tokenActions.append(change);
        }
        card.append(tokenActions);
        const enrollment = application.client_renewal;
        card.append(textNode('p', !enrollment ? Number.isSafeInteger(application.client_renewal_cancelled_at_epoch_ms) ?
          'Workload renewal: cancelled · ' + new Date(application.client_renewal_cancelled_at_epoch_ms).toLocaleString() : 'Tokens: manual rotation' :
          'Workload renewal: ' + (enrollment.status === 'expired' || Date.now() >= enrollment.expires_at_epoch_ms ? 'expired' : 'enrolled') +
          ' · authority ends ' + new Date(enrollment.expires_at_epoch_ms).toLocaleString(), 'small muted'));
        if (projectWorkloadRenewalCapability(catalog.capabilities.workload_renewal, catalog.proxy_url)) {
          const manage = textNode('button', 'Manage workload renewal', 'secondary'); manage.dataset.action = 'manage-workload-renewal';
          manage.disabled = workspace.state.busy || workspace.state.uncertain;
          manage.addEventListener('click', () => { element('application-renewal').open = true; renewalView.select(application.id); }); card.append(manage);
        }
      }
      return {card, keywords: catalog.access_rules.filter(rule => rule.application_id === application.id).flatMap(rule => [
        rule.id, rule.name, rule.credential_id, catalog.credentials.find(item => item.id === rule.credential_id)?.name || '']),
        group: revoked ? 'revoked' : diagnostic.applications.has(application.id) ? 'diagnostic' : 'current'};
    }), 'No current clients in the main list. Create a client and save its one-time token, or expand a retained group below to manage existing clients.');
  }
  window.addEventListener('pagehide', () => { clear(); invalidations.close(); });
  window.addEventListener('pageshow', event => { if (event.persisted) { invalidations.connect(); workspace.refresh(); } });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { reconcile(); workspace.refresh(); } });
  window.addEventListener('focus', () => { reconcile(); workspace.refresh(); });
  function mount(container) {
    if (container) container.append(element('one-time-access'), element('token-expiry-status'));
    else tokenHome.after(element('one-time-access'), element('token-expiry-status'));
    for (const link of element('one-time-access').querySelectorAll('a')) link.hidden = Boolean(container);
  }
  const renewalView = createWorkloadRenewalView(workspace, invalidate);
  workspace.subscribe(render); return {tokenFor, clear, render, create, mount, hasHeldToken() { reconcile(); return Boolean(held); }};
}
