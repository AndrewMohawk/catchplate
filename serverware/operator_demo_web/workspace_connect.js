// Guided composition of the same independent resources and mutation gate.
// Only public IDs/drafts live here; the applications controller owns all tokens.
function createConnectView(workspace, applications, proxy) {
  const steps = ['credential', 'application', 'access', 'review', 'setup'];
  const labels = ['Provider credential', 'Application', 'Allowed use', 'Review access', 'Client setup'];
  let step = 0; let selectedCredential = ''; let selectedApplication = ''; let selectedRule = '';
  let review = null; let checkpoint = null; let open = false;
  let connectionMethod = null; let savedChoice = ''; let beforeGoogle = null;
  const catalog = () => workspace.state.catalog;
  const writable = () => Boolean(catalog() && !workspace.state.busy && !workspace.state.uncertain);
  const credential = () => catalog()?.credentials.find(item => item.id === selectedCredential && item.status === 'active');
  const application = () => catalog()?.applications.find(item => item.id === selectedApplication && item.status === 'active');
  const validApp = item => item?.token_status === 'valid' && Number.isSafeInteger(item.token_expires_at_epoch_ms) && item.token_expires_at_epoch_ms > Date.now();
  const matchingRules = () => catalog()?.access_rules.filter(item => item.status === 'active' && item.application_id === selectedApplication && item.credential_id === selectedCredential) || [];
  const message = text => { element('connect-status').textContent = text; };
  renderOperatorCompatibility('connect-compatibility-content');
  const accountSummary = textNode('article', undefined, 'notice'); accountSummary.id = 'connect-google-account-summary';
  accountSummary.hidden = true; element('connect-progress').after(accountSummary);
  function renderGoogleAccount() {
    const id = step === 0 ? element('connect-credential-choice').value : selectedCredential;
    const item = catalog()?.credentials.find(item => item.id === id);
    accountSummary.hidden = connectionMethod === 'google' || step === 0 && connectionMethod !== 'saved' || item?.auth_type !== 'google_oauth';
    accountSummary.replaceChildren();
    if (accountSummary.hidden) return;
    const details = textNode('dl', undefined, 'metadata');
    details.append(...operatorGoogleAccountRows(item, catalog()).flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
    accountSummary.append(textNode('h2', item.status === 'quarantined' ? 'Google account quarantined — unavailable' : 'Saved Google account'),
      details, textNode('p', operatorGoogleAccountNotice(item), 'small muted'));
  }

  // A vanished choice remains visibly unavailable: never silently pick another
  // resource, permission or capability after refresh.
  function choices(id, items, initial) {
    const control = element(id); const previous = control.value;
    const value = previous || initial;
    const options = items.map(item => { const option = textNode('option', item.name); option.value = item.id; return option; });
    if (value && !items.some(item => item.id === value)) {
      const missing = textNode('option', 'Previous choice unavailable — choose again'); missing.value = value; missing.disabled = true; options.push(missing);
    }
    if (!options.length) { const empty = textNode('option', 'No supported choice available'); empty.value = ''; options.push(empty); }
    control.replaceChildren(...options); control.value = value || options[0].value;
  }
  function fields(id, active) {
    element(id).hidden = !active;
    for (const control of element(id).querySelectorAll('input,select,textarea')) control.disabled = !active;
  }
  function goto(next) { step = next; render(); if (open) element('connect-progress').scrollIntoView({block: 'nearest'}); }
  function activePair() { return credential() && validApp(application()); }
  function supported(rule) { return operatorRuleSupported(rule, catalog()); }
  function confirmCheckpoint() {
    if (!checkpoint || !catalog() || workspace.state.busy || workspace.state.uncertain || catalog().revision < checkpoint.revision) return;
    const item = catalog()[checkpoint.collection].find(item => item.id === checkpoint.id && item.status === 'active');
    if (!item) { message('The exact saved resource cannot be confirmed. Review saved state; no repeat request was sent.'); return; }
    if (checkpoint.collection === 'credentials') {
      selectedCredential = item.id; selectedApplication = ''; selectedRule = ''; review = null;
      connectionMethod = 'saved'; savedChoice = item.id;
      element('connect-credential-choice').value = ''; renderInputs();
      element('connect-credential-choice').value = item.id; step = 1;
    }
    if (checkpoint.collection === 'applications') {
      if (!validApp(item)) { message('The saved application token is not currently valid. Use Applications for explicit rotation.'); return; }
      selectedApplication = item.id; selectedRule = ''; review = null; element('connect-application-choice').value = item.id; step = 2;
      renderInputs(); // The new app is now an exact confirmed pair; initialize its permission choice before showing access.
    }
    if (checkpoint.collection === 'access_rules') {
      if (item.application_id !== selectedApplication || item.credential_id !== selectedCredential) { message('Saved rule references did not match this setup. Review saved state.'); return; }
      if (isGmailRule(review?.rule) && (!isGmailRule(item) || item.query_mode !== review.rule.query_mode ||
          item.credential_input !== review.rule.credential_input || item.placeholder !== review.rule.placeholder)) {
        message('The saved permission does not match the reviewed Read Gmail configuration. Review saved state; no repeat request was sent.'); return;
      }
      selectedRule = item.id; step = 4;
    }
    checkpoint = null; message('Saved resource confirmed in the refreshed catalog.');
  }
  function receipt(result, collection, key) {
    if (!result[key] || typeof result[key].id !== 'string' || !Number.isSafeInteger(result.revision))
      throw operatorError('The saved resource receipt was incomplete. Review saved state; do not repeat automatically.');
    checkpoint = {collection, id: result[key].id, revision: result.revision};
  }
  function renderInputs() {
    const value = catalog(); if (!value) return;
    if (connectionMethod === 'key') choices('connect-credential-choice', [{id: 'new', name: 'New provider key'}], 'new');
    if (connectionMethod === 'saved') choices('connect-credential-choice', [{id: '', name: 'Choose a saved connection'},
      ...value.credentials.filter(item => item.status === 'active').map(item => ({id: item.id,
        name: item.name + (item.auth_type === 'google_oauth' ? ' · Google account ' + item.provider_account : '') + ' · ' + item.id}))], savedChoice);
    choices('connect-application-choice', [...value.applications.filter(item => item.status === 'active').map(item => ({id: item.id, name: item.name + ' · ' + item.id})), {id: 'new', name: 'Create a new application'}], 'new');
    choices('connect-rule-choice', [{id: 'new', name: 'Grant a new permission'}, ...matchingRules().map(item => ({id: item.id, name: item.name + ' · ' + item.id}))], 'new');
    choices('connect-origin', value.allowed_upstreams.map(origin => ({id: origin, name: origin})), value.allowed_upstreams[0]);
    choices('connect-credential-input', availableCredentialInputModes(value).map(id => ({id, name: operatorCredentialInputModes[id]})), 'insert');
    const responseChoices = responseFormChoices(value, element('connect-response-mode').value);
    choices('connect-response-mode', responseChoices, responseChoices[0]?.id);
    if (activePair()) {
      const bundle = gmailAvailable(value, credential());
      choices('connect-operation', [...(bundle ? [{id: operatorGmail.bundle, name: 'Read Gmail'}] : []),
        {id: 'exact', name: 'Advanced: one exact endpoint'}], bundle ? operatorGmail.bundle : 'exact');
    }
  }
  function renderForms() {
    const newCredential = connectionMethod === 'key';
    const newApp = element('connect-application-choice').value === 'new';
    const newRule = element('connect-rule-choice').value === 'new';
    const gmail = newRule && element('connect-operation').value === operatorGmail.bundle;
    fields('connect-saved-choice', connectionMethod === 'saved'); fields('connect-credential-new', newCredential);
    fields('connect-application-new', newApp); fields('connect-rule-new', newRule);
    const custom = newCredential && element('connect-credential-auth-type').value === 'header';
    fields('connect-credential-header-group', custom); element('connect-credential-header-name').required = custom;
    const replacing = newRule && element('connect-credential-input').value === 'replace_exact';
    fields('connect-placeholder-group', replacing); element('connect-placeholder').required = replacing;
    try { element('connect-header-target').textContent = credentialHeaderTarget(credential()); }
    catch (_) { element('connect-header-target').textContent = 'Unsupported credential header'; }
    element('connect-placeholder').placeholder = element('connect-header-target').textContent === 'Authorization' ? 'Bearer SERVERWARE_DUMMY' : 'SERVERWARE_DUMMY';
    element('connect-input-help').textContent = !availableCredentialInputModes(catalog()).includes(element('connect-credential-input').value) ?
      'Choose an advertised credential-input mode. Unavailable choices cannot grant access.' : replacing ? 'Replacement applies only to this exact rule, not every use of the saved credential.' :
      'Automatic insertion: your client sends no provider credential header; Serverware supplies it after authorization.';
    const projected = newRule && element('connect-response-mode').value === 'projected_json';
    fields('connect-response-fields-group', projected); element('connect-response-fields').required = projected;
    renderOperatorRequestBodyForm('connect', catalog(), credential(), 'connect-body-warning', newRule);
    element('connect-response-limits').textContent = operatorResponseLimits(element('connect-response-mode').value);
    const content = review && step >= 3 ? review.rule : {response_mode: element('connect-response-mode').value};
    if (!(review && step >= 3) && element('connect-request-body-mode').value === 'preserve_json_v1') content.request_body_mode = 'preserve_json_v1';
    renderOperatorCompatibility('connect-compatibility-content', gmail && !(review && step >= 3) ? gmailRuleFields() : content);
    renderBasicCompatibility('connect', catalog(), credential());
    // Apply these last: nested legacy field renderers must not re-enable hidden
    // required controls. Switching permissions never clears the exact-rule draft.
    element('connect-operation-group').hidden = !newRule || credential()?.auth_type !== 'google_oauth' && !gmail;
    fields('connect-exact-destination', newRule && !gmail);
    element('connect-exact-content').hidden = !newRule || gmail;
    if (!newRule || gmail) for (const input of element('connect-exact-content').querySelectorAll('input,select,textarea')) input.disabled = true;
    element('connect-gmail-summary').hidden = !gmail;
    element('connect-gmail-summary').textContent = gmail && !gmailAvailable(catalog(), credential()) ?
      'Read Gmail is no longer advertised for this account. Refresh or explicitly choose another permission; no rule is changed automatically.' :
      'Read Gmail: list messages, follow pagination and read individual messages in this account. No age restriction or optional content filtering. No sending, changes, attachments, history or Calendar. GET only, no request body; bounded JSON responses only.';
    element('connect-credential-next').textContent = newCredential ? 'Save credential & continue' : 'Use saved credential';
    element('connect-credential-next').disabled = !newCredential && !catalog()?.credentials.some(item =>
      item.id === element('connect-credential-choice').value && item.status === 'active');
    element('connect-application-next').textContent = newApp ? 'Create app and show token' : 'Use this application';
    const selected = catalog()?.applications.find(item => item.id === element('connect-application-choice').value);
    element('connect-application-note').textContent = newApp ? '' : selected ?
      'Expires ' + new Date(selected.token_expires_at_epoch_ms).toLocaleString() + '. Use the token already configured in your app. If lost or expired, rotate explicitly in Applications; this flow does not retrieve or renew it.' : 'Select an available application.';
    element('connect-credential-fields').disabled = !['key', 'saved'].includes(connectionMethod) || !writable() || Boolean(checkpoint) || newCredential && !workspace.ready('credentials');
    element('connect-application-fields').disabled = !writable() || Boolean(checkpoint) || !credential() || newApp && !workspace.ready('applications');
    element('connect-access-fields').disabled = !writable() || Boolean(checkpoint) || !activePair() || newRule &&
      (!workspace.ready('access_rules') || !availableCredentialInputModes(catalog()).length ||
        (!gmail && !availableResponseModes(catalog()).length) || !catalog()?.allowed_upstreams.length);
    element('connect-review').disabled = newRule && gmail && !gmailAvailable(catalog(), credential());
  }
  function reviewCurrent() {
    return review && activePair() && catalog()?.revision === review.revision && catalog()?.policy.policy_hash === review.policyHash && supported(review.rule);
  }
  function renderReview() {
    if (!review) return;
    const rows = [...operatorRuleCredentialRows(review.rule, credential()), ...operatorRuleRestrictions(review.rule)];
    element('connect-review-details').replaceChildren(...rows.flatMap(([name, value]) => [textNode('dt', name), textNode('dd', value)]));
    element('connect-review-context').textContent = reviewCurrent() ?
      `${application().name} (${selectedApplication}) may use ${credential().name} (${selectedCredential}) only as follows.` :
      'Saved state changed or a selected resource is unavailable. Go Back, verify your choices and Review access again. No grant was sent.';
    element('connect-grant').textContent = review.existing ? 'Use this saved rule' : 'Grant access';
    element('connect-grant').disabled = !writable() || Boolean(checkpoint) || !reviewCurrent();
  }
  function renderSetup() {
    const rule = matchingRules().find(item => item.id === selectedRule);
    const provider = catalog()?.credentials.find(item => item.id === selectedCredential);
    element('connect-provider-status').textContent = (!provider ? 'Provider status is unavailable; refresh saved state.' :
      provider.auth_type === 'google_oauth' ? provider.status === 'quarantined' ?
        'Google account: quarantined and unavailable for use. Provider revocation is not proven. This setup does not start consent or cleanup.' :
        'Google account: saved metadata only. This setup has not tested consent, token refresh or a Google request. ' +
          (catalog()?.capabilities.google_oauth ? 'Use Connect Google for a separate, explicit consent flow.' : 'Google account connection remains disabled here.') :
        'Provider key: stored, not tested here.') +
      ' Application token: separate expiry. Rule: usable only after the proxy confirms the saved policy.';
    const active = writable() && activePair() && workspace.loaded() && rule?.enforcement === 'active' && application()?.access_status === 'active' && supported(rule);
    element('connect-activation').textContent = active ? 'Rule active in the proxy. Configure your client below; no upstream request has been tested here.' :
      !catalog() ? 'Status unavailable. Refresh saved state before using this setup.' : !activePair() || !rule ?
        'A selected credential, app token or rule is no longer available. Return to your choices or explicitly rotate an expired token in Applications.' :
        'Waiting for the proxy to confirm this exact saved rule and policy. No request has been tested. Refresh saved state if automatic observation has stopped.';
    element('connect-setup-slot').hidden = !active;
    if (open && step === 4) { proxy.mount(element('connect-setup-slot')); if (active) proxy.select(selectedApplication, selectedRule); }
  }
  function render() {
    renderInputs(); confirmCheckpoint(); renderForms(); renderReview(); renderGoogleAccount();
    const googleOpen = connectionMethod === 'google';
    element('connect-method-choice').hidden = connectionMethod !== null;
    element('connect-credential-form').hidden = !['key', 'saved'].includes(connectionMethod);
    element('connect-credential-heading').textContent = connectionMethod === 'key' ? 'Use an API key' : 'Use a saved connection';
    element('connect-google-slot').hidden = !googleOpen;
    element('connect-method-change').hidden = connectionMethod === null || googleOpen;
    element('connect-method-change').disabled = !writable() || Boolean(checkpoint);
    element('connect-use-key').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials');
    element('connect-use-saved').disabled = !writable() || Boolean(checkpoint) || !catalog()?.credentials.some(item => item.status === 'active');
    for (const id of ['connect-actions', 'connect-leave-help', 'connect-compatibility']) element(id).hidden = googleOpen;
    steps.forEach((name, index) => { element('connect-' + name + '-step').hidden = index !== step; });
    element('connect-progress').textContent = (step + 1) + ' of 5 · ' + labels[step];
    element('connect-back').hidden = step === 0 || step === 4;
    element('connect-back').disabled = workspace.state.busy || Boolean(checkpoint);
    element('connect-cancel').disabled = workspace.state.busy;
    element('connect-status-refresh').disabled = workspace.state.busy;
    element('connect-start-over').hidden = step !== 4;
    element('connect-start-over').disabled = workspace.state.busy || Boolean(checkpoint);
    const missingToken = selectedApplication && !applications.tokenFor(selectedApplication);
    element('connect-token-note').hidden = !missingToken;
    element('connect-token-note').textContent = 'This page does not hold this application’s one-time token. Use the token you already saved. If it was lost or cleared, explicitly rotate it in Applications; no token is retrieved or renewed by this flow.';
    if (!catalog()) element('connect-credential-secret').value = '';
    if (checkpoint) message('Save received, but the exact resource is not yet confirmed in refreshed state. Refresh; do not submit again.');
    renderSetup();
  }

  element('connect-credential-form').addEventListener('submit', async event => {
    event.preventDefault(); if (step !== 0 || !['key', 'saved'].includes(connectionMethod) || !writable() || checkpoint || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-credential-choice').value;
    if (connectionMethod === 'saved') {
      if (!catalog().credentials.some(item => item.id === choice && item.status === 'active')) return;
      savedChoice = choice; selectedCredential = choice; selectedApplication = ''; selectedRule = ''; review = null; goto(1); return;
    }
    if (!workspace.ready('credentials')) return;
    const body = {name: element('connect-credential-name').value.trim(), auth_type: element('connect-credential-auth-type').value,
      header_name: element('connect-credential-auth-type').value === 'bearer' ? 'Authorization' : element('connect-credential-header-name').value.trim(), secret: element('connect-credential-secret').value};
    element('connect-credential-secret').value = '';
    await workspace.mutate('credentials', body, 'connect-status', result => receipt(result, 'credentials', 'credential')); render();
  });
  element('connect-application-form').addEventListener('submit', async event => {
    event.preventDefault(); if (step !== 1 || !writable() || checkpoint || !credential() || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-application-choice').value;
    if (choice !== 'new') {
      const item = catalog().applications.find(item => item.id === choice && item.status === 'active');
      if (!validApp(item)) { message('This application token is expired or unavailable. Rotate explicitly in Applications, then refresh.'); return; }
      selectedApplication = choice; selectedRule = ''; review = null; goto(2); return;
    }
    const saved = await applications.create(element('connect-application-name').value.trim(), Number(element('connect-token-ttl').value), 'connect-status');
    if (saved) checkpoint = {collection: 'applications', ...saved};
    render();
  });
  function draftRule() {
    if (element('connect-operation').value === operatorGmail.bundle) {
      const rule = {...gmailRuleFields(), name: 'Read Gmail', application_id: selectedApplication, credential_id: selectedCredential,
        credential_input: element('connect-credential-input').value};
      if (rule.credential_input === 'replace_exact') rule.placeholder = element('connect-placeholder').value;
      if (!supported(rule)) throw operatorError('Read Gmail is unavailable for this account or credential-input choice. Refresh before granting access.');
      return rule;
    }
    if (element('connect-operation').value !== 'exact') throw operatorError('Choose a supported permission. No grant was sent.');
    const origin = element('connect-origin').value; const path = element('connect-path').value.trim();
    const methods = [...document.querySelectorAll('input[name="connect-method"]:checked')].map(input => input.value);
    const rule = {name: operatorPermissionName(element('connect-rule-name').value, methods, path), application_id: selectedApplication, credential_id: selectedCredential,
      upstream_url: origin.replace(/\/$/, '') + path,
      methods,
      credential_input: element('connect-credential-input').value, response_mode: element('connect-response-mode').value,
      response_fields: element('connect-response-mode').value === 'projected_json' ? fieldLines('connect-response-fields') : [],
      ...operatorRequestBodyInput(element('connect-request-body-mode').value, fieldLines('connect-request-fields'), catalog(), credential()),
      query_keys: fieldLines('connect-query-keys'), allowed_headers: fieldLines('connect-allowed-headers')};
    if (rule.credential_input === 'replace_exact') rule.placeholder = element('connect-placeholder').value;
    if (!catalog().allowed_upstreams.includes(origin) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        credential()?.legacy_upstream_origin && credential().legacy_upstream_origin !== origin || !supported(rule))
      throw operatorError('Choose an approved exact path and supported methods, content and credential-input choices. Exact dummy values must be printable ASCII with no outer spaces; selected-field responses require fields. Google permits only GET with no request body.');
    return rule;
  }
  element('connect-access-form').addEventListener('submit', event => {
    event.preventDefault(); if (step !== 2 || !writable() || checkpoint || !activePair() || !event.currentTarget.reportValidity()) return;
    try {
      const existing = element('connect-rule-choice').value !== 'new';
      const rule = existing ? matchingRules().find(item => item.id === element('connect-rule-choice').value) : draftRule();
      if (!supported(rule)) throw operatorError('The selected saved rule is unavailable or unsupported. Choose again; no permissions were changed.');
      review = {existing, rule: JSON.parse(JSON.stringify(rule)), revision: catalog().revision, policyHash: catalog().policy.policy_hash};
      message('Review the exact effective permissions before continuing.'); goto(3);
    } catch (error) { message(operatorMessage(error)); }
  });
  element('connect-grant').addEventListener('click', async () => {
    if (step !== 3 || !writable() || checkpoint || !reviewCurrent()) { renderReview(); return; }
    if (review.existing) {
      if (!matchingRules().some(item => item.id === review.rule.id)) return;
      selectedRule = review.rule.id; goto(4); return;
    }
    if (!workspace.ready('access_rules')) return;
    await workspace.mutate(isGmailRule(review.rule) ? 'access-rules/gmail-read' : 'access-rules',
      isGmailRule(review.rule) ? gmailRulePayload(review.rule) : {...review.rule}, 'connect-status', result => receipt(result, 'access_rules', 'access_rule')); render();
  });
  for (const id of ['connect-credential-auth-type', 'connect-application-choice', 'connect-rule-choice', 'connect-operation', 'connect-credential-input', 'connect-response-mode', 'connect-request-body-mode'])
    element(id).addEventListener('change', render);
  element('connect-credential-choice').addEventListener('change', () => {
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    render();
  });
  for (const [id, method] of [['connect-use-key', 'key'], ['connect-use-saved', 'saved']]) element(id).addEventListener('click', () => {
    if (step !== 0 || connectionMethod !== null || !writable() || checkpoint) return;
    connectionMethod = method;
    element('connect-credential-choice').value = ''; render();
  });
  element('connect-method-change').addEventListener('click', () => {
    if (step !== 0 || !['key', 'saved'].includes(connectionMethod) || !writable() || checkpoint) return;
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    connectionMethod = null; render();
  });
  element('connect-request-fields').addEventListener('input', renderForms);
  element('connect-query-keys').addEventListener('input', renderForms);
  element('connect-back').addEventListener('click', () => { if (step > 0 && step < 4 && !workspace.state.busy && !checkpoint) { review = null; goto(step - 1); } });
  element('connect-status-refresh').addEventListener('click', () => workspace.refresh({manual: true}));
  function resetDraft() {
    selectedCredential = ''; selectedApplication = ''; selectedRule = ''; review = null; checkpoint = null;
    connectionMethod = null; savedChoice = ''; beforeGoogle = null;
    for (const id of ['connect-credential-form', 'connect-application-form', 'connect-access-form']) element(id).reset();
    for (const id of ['connect-credential-choice', 'connect-application-choice', 'connect-rule-choice']) element(id).value = 'new';
    for (const id of ['connect-response-mode', 'connect-request-body-mode', 'connect-operation']) element(id).value = '';
    element('connect-restrictions').open = false;
    element('connect-credential-secret').value = ''; proxy.mount(null); step = 0;
  }
  element('connect-cancel').addEventListener('click', () => {
    if (workspace.state.busy || !window.confirm('Leave setup and discard this local draft? Saved credentials, applications and access rules remain. An uncertain operation must still be reconciled before another change. Any held one-time token remains under Applications until cleared or reloaded; save it before leaving the page. Nothing will be deleted, retried or renewed.')) return;
    resetDraft(); location.hash = 'overview';
  });
  element('connect-start-over').addEventListener('click', () => {
    if (workspace.state.busy || checkpoint || !window.confirm('Start another setup? Confirmed resources remain saved. Save any one-time token before creating another application. Nothing will be revoked.')) return;
    resetDraft(); message('Start a new setup. Existing resources and any held token remain.'); goto(0);
  });
  window.addEventListener('pagehide', () => { element('connect-credential-secret').value = ''; });
  workspace.subscribe(render);
  return {openGoogle({returning = false} = {}) {
    if (connectionMethod === 'google') return true;
    if (!returning && (!writable() || checkpoint)) return false;
    beforeGoogle = {step, method: connectionMethod};
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    connectionMethod = 'google'; goto(0); location.hash = 'connect'; return true;
  }, leaveGoogle() {
    if (connectionMethod !== 'google') return;
    const previous = beforeGoogle; beforeGoogle = null;
    connectionMethod = previous?.method || null; step = previous?.step || 0;
    render();
  }, selectGoogleCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id && value.status === 'active' && value.auth_type === 'google_oauth');
    if (!item || !writable() || checkpoint) return false;
    resetDraft(); selectedCredential = id; connectionMethod = 'saved'; savedChoice = id;
    element('connect-credential-choice').value = ''; renderInputs(); element('connect-credential-choice').value = id;
    message('Saved Google account selected. Choose an application; no access has been granted.'); goto(1); return true;
  }, show(active) {
    open = active;
    applications.mount(active ? element('connect-token-slot') : null);
    if (!active || step !== 4) proxy.mount(null);
    render();
  }};
}
