// Google consent is a server-owned operation. Only public intent/account
// metadata lives in this controller; authorization URLs are transient locals.
const operatorGoogleScopes = Object.freeze(['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid']);
const operatorGoogleUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const operatorGooglePending = Object.freeze(['prepared', 'awaiting_consent', 'exchanging']);
function googleInvalid() { const error = new Error('Invalid Google consent metadata'); error.uiMessage = 'Google connection could not be verified. Refresh its saved status; do not repeat consent automatically.'; return error; }
function googleScopes(value) { return Array.isArray(value) && value.length === operatorGoogleScopes.length && value.every((item, index) => item === operatorGoogleScopes[index]); }
function googleText(value, maximum) { return typeof value === 'string' && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value); }
function projectGoogleCapability(capabilities, origin) {
  const value = capabilities?.google_oauth;
  if (capabilities?.oauth !== true) {
    if (value != null || capabilities?.oauth !== undefined && capabilities.oauth !== false) throw googleInvalid();
    return null;
  }
  const fixed = {schema: 'serverware.operatorGoogleCapability/v1', profile: 'operator-google-v1', provider_id: 'google',
    permission_preset: 'gmail_readonly', authorization_origin: 'https://accounts.google.com', authorization_path: '/o/oauth2/v2/auth',
    start_path: '/api/operator-demo/oauth/google/start', intents_path: '/api/operator-demo/oauth/google/intents'};
  if (!value || Object.keys(value).length !== Object.keys(fixed).length + 3 ||
      Object.entries(fixed).some(([key, expected]) => value[key] !== expected) || !googleScopes(value.scopes) ||
      !Array.isArray(value.api_origins) || value.api_origins.length !== 1 || value.api_origins[0] !== 'https://gmail.googleapis.com' ||
      !Array.isArray(capabilities.credential_types) || !capabilities.credential_types.includes('google_oauth')) throw googleInvalid();
  const base = new URL(origin); const callback = new URL(value.redirect_uri);
  if (base.protocol !== 'https:' || base.origin !== origin || callback.href !== origin + '/api/oauth/callback/google') throw googleInvalid();
  return {...fixed, scopes: [...operatorGoogleScopes], api_origins: [...value.api_origins], redirect_uri: callback.href};
}
function projectGoogleIntent(value) {
  const statuses = [...operatorGooglePending, 'connected', 'failed', 'expired'];
  const reasons = ['expired', 'consent_denied', 'exchange_failed', 'persistence_failed', 'identity_conflict'];
  if (!value || !operatorGoogleUuid.test(value.id) || !googleText(value.name, 128) || value.name !== value.name.trim() ||
      value.provider_id !== 'google' || value.permission_preset !== 'gmail_readonly' || !googleScopes(value.scopes) ||
      !googleText(value.created_at, 64) || !Number.isFinite(Date.parse(value.created_at)) ||
      !Number.isSafeInteger(value.expires_at_epoch) || value.expires_at_epoch < 1 || !statuses.includes(value.status) ||
      (value.status === 'connected' ? !operatorGoogleUuid.test(value.credential_id) : Object.hasOwn(value, 'credential_id')) ||
      (value.status === 'failed' ? !reasons.includes(value.reason) : value.status === 'expired' ? value.reason !== 'expired' : Object.hasOwn(value, 'reason')))
    throw googleInvalid();
  return {id: value.id, name: value.name, provider_id: 'google', permission_preset: 'gmail_readonly', scopes: [...operatorGoogleScopes],
    created_at: value.created_at, expires_at_epoch: value.expires_at_epoch, status: value.status,
    ...(value.status === 'connected' ? {credential_id: value.credential_id} : {}), ...(value.reason ? {reason: value.reason} : {})};
}
function projectGoogleIntents(value) {
  if (value?.apiVersion !== 'serverware.operatorGoogleConsent/v1' || value.productionReady !== false ||
      value.protectedActivationSupported !== false || value.limits?.active !== 32 || value.limits?.retained !== 1024 ||
      !Array.isArray(value.intents) || value.intents.length > 1024) throw googleInvalid();
  const intents = value.intents.map(projectGoogleIntent);
  if (new Set(intents.map(item => item.id)).size !== intents.length) throw googleInvalid();
  return intents;
}
function validateGoogleStart(value, capability, name, now = Date.now()) {
  const intent = projectGoogleIntent(value?.operatorGoogleIntent);
  if (!capability || value.provider !== 'google' || value.redirectUri !== capability.redirect_uri || !googleScopes(value.scopes) ||
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(value.state) ||
      !Number.isSafeInteger(value.expiresAtEpoch) || value.expiresAtEpoch * 1000 <= now || intent.expires_at_epoch > value.expiresAtEpoch ||
      intent.expires_at_epoch * 1000 <= now || intent.name !== name || intent.status !== 'awaiting_consent' ||
      typeof value.authorizationUrl !== 'string' || value.authorizationUrl.length > 8192) throw googleInvalid();
  const url = new URL(value.authorizationUrl); const query = url.searchParams;
  const fixed = {response_type: 'code', redirect_uri: capability.redirect_uri, scope: operatorGoogleScopes.join(' '), state: value.state,
    code_challenge_method: 'S256', access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true'};
  const keys = [...Object.keys(fixed), 'client_id', 'code_challenge'];
  if (url.origin !== capability.authorization_origin || url.pathname !== capability.authorization_path || url.username || url.password || url.hash ||
      [...query.keys()].length !== keys.length || [...query.keys()].some(key => !keys.includes(key)) ||
      Object.entries(fixed).some(([key, expected]) => query.get(key) !== expected) ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,199}\.apps\.googleusercontent\.com$/.test(query.get('client_id') || '') ||
      !/^[A-Za-z0-9_-]{43}$/.test(query.get('code_challenge') || '')) throw googleInvalid();
  return {intent, authorizationUrl: url.href};
}
function googleConnectedAccount(intent, catalog) {
  if (intent?.status !== 'connected') return null;
  return catalog?.credentials.find(item => item.id === intent.credential_id && item.status === 'active' &&
    item.auth_type === 'google_oauth' && item.permission_preset === intent.permission_preset && googleScopes(item.scopes)) || null;
}
function googleReturnHint(href) {
  const url = new URL(href); const values = url.searchParams.getAll('operator_google_intent');
  const exact = [...url.searchParams.keys()].length === 1;
  if (values.length) url.search = ''; // Never carry unexpected callback material onward.
  return {present: values.length > 0, id: exact && values.length === 1 && operatorGoogleUuid.test(values[0]) ? values[0] : null,
    clean: url.pathname + url.search + url.hash};
}

function createGoogleView(workspace, applications, connect) {
  const hint = googleReturnHint(location.href);
  // Remove the untrusted navigation hint before any API request or user action.
  if (hint.present) history.replaceState(null, '', hint.clean);
  let currentId = hint.id; let attempted = hint.present; let opened = hint.present;
  let intents = []; let checked = false; let checking = false; let knownCapability = ''; let generation = 0;
  let notice = hint.present && !hint.id ? 'The return reference is invalid. Inspect saved Google connections; no consent was started.' : '';
  const capability = () => workspace.state.catalog?.capabilities.google_oauth || null;
  const current = () => intents.find(item => item.id === currentId);
  const held = () => applications.hasHeldToken();
  const statusLabels = {prepared: 'Preparing consent', awaiting_consent: 'Waiting for Google consent', exchanging: 'Connection outcome still being confirmed',
    connected: 'Account saved', failed: 'Connection not completed', expired: 'Consent expired'};
  const reasons = {consent_denied: 'Google consent was declined.', expired: 'The consent window expired.',
    exchange_failed: 'The consent exchange did not complete.', persistence_failed: 'The account could not be safely saved.',
    identity_conflict: 'This account conflicts with an existing saved account. Do not repeat consent.'};
  function render() {
    const enabled = Boolean(capability());
    const available = enabled && !workspace.state.busy && !workspace.state.uncertain && !checking;
    for (const id of ['connect-google', 'credential-google-connect']) {
      element(id).textContent = enabled ? 'Connect Google' : 'Google connection unavailable';
      element(id).disabled = !available;
    }
    for (const id of ['connect-google-status', 'credential-oauth-status']) element(id).textContent = enabled ?
      'Connect with Google for Read Gmail. Provider tokens stay in Serverware; apps receive a separate, scoped identity.' :
      'Google connection is unavailable in this deployment. An administrator must enable the supported Google profile. Do not paste Google access or refresh tokens.';
    element('google-consent-panel').hidden = !opened;
    element('google-start-fields').disabled = !available || !checked || attempted || held();
    element('google-token-warning').hidden = !held();
    element('google-consent-refresh').disabled = !enabled || checking || workspace.writeInFlight();
    element('google-consent-leave').disabled = workspace.writeInFlight() || checking;
    const intent = current(); const account = checked ? googleConnectedAccount(intent, workspace.state.catalog) : null;
    element('google-consent-status').textContent = notice || (checking ? 'Checking saved consent and account state...' : intent ?
      statusLabels[intent.status] + '. ' + (reasons[intent.reason] || '') : currentId ?
      'This return reference was not found in your saved Google connections. No account was selected.' : attempted ?
      'Consent may have started, but no exact receipt was confirmed. Inspect saved connections. No repeat request was sent.' :
      'Read Gmail only. You choose the Google account on Google’s consent page. Saving an account grants no application access.');
    element('google-consent-account').hidden = !account;
    element('google-consent-account').textContent = account ? account.provider_account + ' · Read Gmail. Account saved; refresh health and a Gmail request have not been checked here.' : '';
    element('google-consent-use').hidden = !account;
    element('google-consent-use').disabled = !account || workspace.state.busy || workspace.state.uncertain || checking;
    element('google-consent-pending').hidden = !attempted || !workspace.state.consentHold;
    if (intent?.status === 'connected' && checked && !account) element('google-consent-status').textContent =
      'Consent has a saved receipt, but the exact Google account is missing or unavailable. No application can be configured from this receipt.';
    const cards = intents.map(item => {
      const row = textNode('li'); row.append(textNode('span', item.name + ' · ' + statusLabels[item.status] + ' '));
      const button = textNode('button', 'Inspect', 'secondary'); button.type = 'button'; button.dataset.googleIntent = item.id;
      button.disabled = checking || workspace.writeInFlight();
      button.addEventListener('click', () => { currentId = item.id; attempted = true; opened = true; notice = ''; workspace.setConsentHold(true); observe(); });
      row.append(button); return row;
    });
    element('google-consent-intents').replaceChildren(...cards);
    element('google-consent-history').hidden = !intents.length;
  }
  async function observe() {
    if (checking || !capability()) return false;
    checking = true; checked = false; const version = ++generation; const before = JSON.stringify(capability()); render();
    try {
      const values = projectGoogleIntents(await workspace.api(capability().intents_path));
      const refreshed = await workspace.refresh({manual: true});
      if (version !== generation || !refreshed || JSON.stringify(capability()) !== before) throw googleInvalid();
      intents = values; checked = true; notice = '';
      const item = current();
      // Only this explicitly selected attempt holds writes. Retained unrelated
      // exchanges may be uncertain indefinitely and do not freeze the workspace.
      workspace.setConsentHold(attempted && (!item || operatorGooglePending.includes(item.status)));
      return true;
    } catch (_) { notice = 'Saved Google connection status is unavailable. No retry or account selection was performed.'; return false; }
    finally { checking = false; render(); }
  }
  function open() {
    if (!capability() || workspace.state.busy || workspace.state.uncertain) return;
    opened = true; notice = ''; render(); element('google-consent-panel').scrollIntoView({block: 'nearest'});
    observe();
  }
  for (const id of ['connect-google', 'credential-google-connect']) element(id).addEventListener('click', open);
  element('google-start-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!capability() || !checked || checking || attempted || held() || workspace.state.busy || workspace.state.uncertain || !element('google-start-form').reportValidity()) return;
    const name = element('google-account-name').value.trim();
    const pendingWarning = intents.some(item => operatorGooglePending.includes(item.status)) ?
      ' Another saved consent attempt is still pending; starting a new one can invalidate it. Inspect saved attempts first if unsure.' : '';
    if (!googleText(name, 128) || !window.confirm('Continue to Google in this tab? Unsaved form drafts will be lost. Provider tokens stay on the server. No app access is granted by consent.' + pendingWarning)) return;
    const reviewedCapability = JSON.stringify(capability()); let receipt = null;
    attempted = true; notice = '';
    const saved = await workspace.mutate('oauth/google/start', {name, permission_preset: 'gmail_readonly'}, 'google-consent-status', result => {
      receipt = validateGoogleStart(result, capability(), name); currentId = receipt.intent.id;
      workspace.setConsentHold(true);
    });
    workspace.setConsentHold(true);
    if (!saved) { receipt = null; notice = 'Consent may have started, but its response was not confirmed. Inspect saved connections; no repeat request was sent.'; await observe(); render(); return; }
    if (!await observe() || reviewedCapability !== JSON.stringify(capability()) || current()?.status !== 'awaiting_consent' ||
        JSON.stringify(current()) !== JSON.stringify(receipt.intent) || held() || workspace.state.uncertain || current().expires_at_epoch * 1000 <= Date.now()) {
      receipt = null; notice = 'The exact consent attempt could not be reconciled. No navigation or retry occurred. Inspect saved status.'; render(); return;
    }
    // A single validated destination; never rendered, stored or reopened later.
    const destination = receipt.authorizationUrl; receipt = null; location.assign(destination);
  });
  element('google-consent-refresh').addEventListener('click', observe);
  element('google-consent-leave').addEventListener('click', () => {
    if (checking || workspace.writeInFlight() || !window.confirm('Leave Google connection setup? This does not cancel consent or revoke anything at Google. Other workspace changes can invalidate a pending flow. An uncertain write still needs the existing saved-state review. No request will be retried.')) return;
    ++generation; currentId = null; attempted = false; opened = false; notice = ''; workspace.setConsentHold(false); render();
  });
  element('google-consent-use').addEventListener('click', () => {
    const account = checked && googleConnectedAccount(current(), workspace.state.catalog);
    if (!account || checking || workspace.state.busy || workspace.state.uncertain) return;
    if (connect.selectGoogleCredential(account.id)) { opened = false; location.hash = 'connect'; render(); }
  });
  workspace.subscribe(() => {
    const key = JSON.stringify(capability());
    if (key !== knownCapability) {
      knownCapability = key; checked = false;
      if (capability()) queueMicrotask(observe);
      else if (attempted) workspace.setConsentHold(true);
    }
    render();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) { checked = false; if (attempted) workspace.setConsentHold(true); observe(); } });
  if (attempted) workspace.setConsentHold(true);
  render();
}

if (typeof module !== 'undefined' && module.exports) module.exports = {projectGoogleCapability, projectGoogleIntent, projectGoogleIntents,
  validateGoogleStart, googleConnectedAccount, googleReturnHint};
