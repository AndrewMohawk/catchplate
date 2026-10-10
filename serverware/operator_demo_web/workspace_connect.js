// Guided composition of the same independent resources and mutation gate.
// Only public IDs/drafts live here; the applications controller owns all tokens.
function operatorConnectResourceChoices(items, reserved = []) {
  const actionLabels = reserved.map(value => value.replace(/\s+/g, ' ').trim());
  const options = items.map(item => ({id: item.id, name: (item.name +
    (item.auth_type === 'google_oauth' ? ' · ' + item.provider_account : '')).replace(/\s+/g, ' ').trim()}));
  let result = options.map(item => {
    const peers = options.filter(other => other.id !== item.id && other.name === item.name);
    if (!peers.length && !actionLabels.includes(item.name)) return item;
    let length = Math.min(8, item.id.length);
    while (length < item.id.length && peers.some(other => other.id.slice(0, length) === item.id.slice(0, length))) length++;
    return {id: item.id, name: item.name + ' · ' + item.id.slice(0, length)};
  });
  // A literal name may imitate a generated label. Prefix the exact ID only for
  // colliding entries; each pass converts another entry, bounded by list size.
  // Unique persisted UUIDs make these final prefixes distinct regardless of name.
  for (let pass = 0; pass < options.length; pass++) {
    const counts = new Map();
    for (const name of [...actionLabels, ...result.map(item => item.name)]) counts.set(name, (counts.get(name) || 0) + 1);
    if (result.every(item => counts.get(item.name) === 1)) break;
    result = result.map((item, index) => counts.get(item.name) > 1 ?
      {id: item.id, name: '[' + item.id + '] ' + options[index].name} : item);
  }
  return result;
}
function createConnectView(workspace, applications, proxy) {
  const steps = ['credential', 'application', 'access', 'review', 'setup'];
  const labels = ['Account or API key', 'Application', 'Permission', 'Review access', 'Client setup'];
  const actionLabels = {credential: 'Choose a saved connection', application: 'Create a new application', rule: 'Grant a new permission'};
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
  const accountSummary = textNode('div'); accountSummary.id = 'connect-google-account-summary';
  accountSummary.hidden = true; element('connect-progress').after(accountSummary);
  function renderGoogleAccount() {
    const id = step === 0 ? element('connect-credential-choice').value : selectedCredential;
    const item = catalog()?.credentials.find(item => item.id === id);
    const expanded = accountSummary.firstElementChild?.dataset.resourceId === id && accountSummary.querySelector('details')?.open;
    accountSummary.hidden = connectionMethod === 'google' || step === 0 && connectionMethod !== 'saved' || item?.auth_type !== 'google_oauth';
    accountSummary.replaceChildren();
    if (accountSummary.hidden) return;
    const card = operatorGoogleAccountCard(item, catalog());
    card.querySelector('details').open = Boolean(expanded);
    accountSummary.append(card);
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
      if (checkpoint.github && !isGithubCredential(item)) {
        message('The saved GitHub connection cannot be confirmed. Refresh saved state; do not submit again.'); return;
      }
      if (checkpoint.npm && !isNpmCredential(item)) {
        message('The saved npm connection cannot be confirmed. Refresh saved state; do not submit again.'); return;
      }
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
      if (isGithubRule(review?.rule) && (!githubRuleValid(item, credential()) ||
          !operatorExact(githubRulePayload(item), githubRulePayload(review.rule)))) {
        message('The saved GitHub permission does not match the reviewed repository and operation. Refresh; no repeat request was sent.'); return;
      }
      if (isNpmRule(review?.rule) && (!npmRuleValid(item, credential()) ||
          !operatorExact(npmRulePayload(item), npmRulePayload(review.rule)))) {
        message('The saved npm permission does not match the reviewed packages. Refresh; no repeat request was sent.'); return;
      }
      selectedRule = item.id; step = 4;
    }
    checkpoint = null; message('Saved resource confirmed in the refreshed catalog.');
  }
  function receipt(result, collection, key) {
    if (!result[key] || typeof result[key].id !== 'string' || !Number.isSafeInteger(result.revision))
      throw operatorError('The saved resource receipt was incomplete. Review saved state; do not repeat automatically.');
    checkpoint = {collection, id: result[key].id, revision: result.revision,
      ...(collection === 'credentials' && connectionMethod === 'github' ? {github: true} : {}),
      ...(collection === 'credentials' && connectionMethod === 'npm' ? {npm: true} : {})};
  }
  function renderInputs() {
    const value = catalog(); if (!value) return;
    if (['key', 'github', 'npm'].includes(connectionMethod)) choices('connect-credential-choice', [{id: 'new', name: 'New provider key'}], 'new');
    if (connectionMethod === 'saved') choices('connect-credential-choice', [{id: '', name: actionLabels.credential},
      ...operatorConnectResourceChoices(value.credentials.filter(item => item.status === 'active'), [actionLabels.credential])], savedChoice);
    choices('connect-application-choice', [...operatorConnectResourceChoices(value.applications.filter(item => item.status === 'active'), [actionLabels.application]), {id: 'new', name: actionLabels.application}], 'new');
    choices('connect-rule-choice', [{id: 'new', name: actionLabels.rule}, ...operatorConnectResourceChoices(matchingRules(), [actionLabels.rule])], 'new');
    choices('connect-origin', value.allowed_upstreams.map(origin => ({id: origin, name: origin})), value.allowed_upstreams[0]);
    choices('connect-credential-input', availableCredentialInputModes(value).map(id => ({id, name: operatorCredentialInputModes[id]})), 'insert');
    const responseChoices = responseFormChoices(value, element('connect-response-mode').value);
    choices('connect-response-mode', responseChoices, responseChoices[0]?.id);
    if (activePair()) {
      const bundle = gmailAvailable(value, credential());
      const github = isGithubCredential(credential());
      const npm = isNpmCredential(credential());
      choices('connect-operation', npm ? npmAvailable(value, credential()) ? [{id: operatorNpm.bundle, name: 'Read package metadata'}] : [] : github ? githubAvailable(value, credential()) ?
        [operatorGithub.read, operatorGithub.write].map(id => ({id, name: githubPermissionName(id)})) : [] :
        [...(bundle ? [{id: operatorGmail.bundle, name: 'Read Gmail'}] : []),
          {id: 'exact', name: 'Advanced: one exact endpoint'}], npm ? operatorNpm.bundle : github ? operatorGithub.read : bundle ? operatorGmail.bundle : 'exact');
    }
  }
  function renderForms() {
    const newCredential = ['key', 'github', 'npm'].includes(connectionMethod);
    const newApp = element('connect-application-choice').value === 'new';
    const newRule = element('connect-rule-choice').value === 'new';
    const gmail = newRule && element('connect-operation').value === operatorGmail.bundle;
    const github = newRule && (isGithubCredential(credential()) || isGithubRule({operation_bundle: element('connect-operation').value}));
    const npm = newRule && (isNpmCredential(credential()) || isNpmRule({operation_bundle: element('connect-operation').value}));
    const providerPreset = github || npm;
    fields('connect-saved-choice', connectionMethod === 'saved'); fields('connect-credential-new', newCredential);
    fields('connect-application-new', newApp); fields('connect-rule-new', newRule);
    fields('connect-credential-auth-group', connectionMethod === 'key');
    element('connect-github-token-note').hidden = connectionMethod !== 'github';
    element('connect-npm-token-note').hidden = connectionMethod !== 'npm';
    if (connectionMethod === 'github') {
      element('connect-credential-secret').setAttribute('pattern', '[A-Za-z0-9_]{1,8192}');
      element('connect-credential-secret').title = 'Use a GitHub token, not an App JWT or private key.';
    } else {
      element('connect-credential-secret').removeAttribute('pattern');
      element('connect-credential-secret').removeAttribute('title');
    }
    const custom = connectionMethod === 'key' && element('connect-credential-auth-type').value === 'header';
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
    renderOperatorCompatibility('connect-compatibility-content', providerPreset && !(review && step >= 3) ?
      {operation_bundle: element('connect-operation').value} : gmail && !(review && step >= 3) ? gmailRuleFields() : content);
    renderBasicCompatibility('connect', catalog(), credential());
    // Apply these last: nested legacy field renderers must not re-enable hidden
    // required controls. Switching permissions never clears the exact-rule draft.
    element('connect-operation-group').hidden = !newRule || credential()?.auth_type !== 'google_oauth' && !gmail && !providerPreset;
    fields('connect-exact-destination', newRule && !gmail && !providerPreset);
    element('connect-credential-input-group').hidden = !newRule || providerPreset;
    if (!newRule || providerPreset) for (const input of element('connect-credential-input-group').querySelectorAll('input,select,textarea')) input.disabled = true;
    fields('connect-github-repository', github);
    fields('connect-npm-packages-group', npm);
    element('connect-npm-summary').textContent = !npmAvailable(catalog(), credential()) ?
      'npm metadata lookup is unavailable: this deployment must advertise the preset and approve registry.npmjs.org. No fallback or grant is sent.' :
      !npmNewRuleAvailable(catalog(), selectedApplication) ?
      'This application already has an npm metadata permission or overlapping registry GET rule. Reuse its saved permission or review and explicitly revoke the conflicting rule before a new grant. Nothing is changed automatically.' :
      'Read package metadata for these exact packages only. Supports npm view and pacote.manifest; no install, publish, tarballs or npm audit. GET only, no request body or query parameters. No response-field setup.';
    element('connect-github-summary').textContent = !githubAvailable(catalog(), credential()) ?
      'GitHub permissions are unavailable: this deployment must advertise the preset and approve api.github.com. No fallback or grant is sent.' :
      githubPermissionName(element('connect-operation').value) + '. Named repository only; no edits, deletes or other APIs. The pinned client uses a fixed public dummy token; response content needs no setup.';
    element('connect-exact-content').hidden = !newRule || gmail || providerPreset;
    if (!newRule || gmail || providerPreset) for (const input of element('connect-exact-content').querySelectorAll('input,select,textarea')) input.disabled = true;
    element('connect-gmail-summary').hidden = !gmail;
    element('connect-gmail-summary').textContent = gmail && !gmailAvailable(catalog(), credential()) ?
      'Read Gmail is no longer advertised for this account. Refresh or explicitly choose another permission; no rule is changed automatically.' :
      'Read Gmail: list messages, follow pagination and read individual messages in this account. No age restriction or optional content filtering. No sending, changes, attachments, history or Calendar. GET only, no request body; bounded JSON responses only.';
    element('connect-credential-next').textContent = newCredential ? 'Save credential & continue' : 'Use saved credential';
    element('connect-credential-next').disabled = !newCredential && !catalog()?.credentials.some(item =>
      item.id === element('connect-credential-choice').value && item.status === 'active');
    element('connect-application-next').textContent = newApp ? 'Create app and show token' : 'Use this application';
    element('connect-application-proxy-default').textContent = newApplicationProxyAuthentication(catalog()).proxy_authentication ?
      'Proxy login: public application ID as username, this app’s token as password. Bearer also remains supported. Never use the provider key.' :
      'Proxy login: Bearer application token. Standard username/password login is not advertised by this deployment.';
    const selected = catalog()?.applications.find(item => item.id === element('connect-application-choice').value);
    element('connect-application-note').textContent = newApp ? '' : selected ?
      'Expires ' + new Date(selected.token_expires_at_epoch_ms).toLocaleString() + '. Use the token already configured in your app. If lost or expired, rotate explicitly in Applications; this flow does not retrieve or renew it.' : 'Select an available application.';
    element('connect-credential-fields').disabled = !['key', 'github', 'npm', 'saved'].includes(connectionMethod) || !writable() || Boolean(checkpoint) ||
      newCredential && !workspace.ready('credentials') || connectionMethod === 'github' && !catalog()?.capabilities.github ||
      connectionMethod === 'npm' && !catalog()?.capabilities.npm;
    element('connect-application-fields').disabled = !writable() || Boolean(checkpoint) || !credential() || newApp && !workspace.ready('applications');
    element('connect-access-fields').disabled = !writable() || Boolean(checkpoint) || !activePair() || newRule &&
      (!workspace.ready('access_rules') || !availableCredentialInputModes(catalog()).length ||
        (!gmail && !providerPreset && !availableResponseModes(catalog()).length) || !catalog()?.allowed_upstreams.length);
    element('connect-review').disabled = newRule && (gmail && !gmailAvailable(catalog(), credential()) || github && !githubAvailable(catalog(), credential()) ||
      npm && (!npmAvailable(catalog(), credential()) || !npmNewRuleAvailable(catalog(), selectedApplication)));
  }
  function reviewCurrent() {
    return review && activePair() && catalog()?.revision === review.revision && catalog()?.policy.policy_hash === review.policyHash && supported(review.rule);
  }
  function renderReview() {
    if (!review) return;
    const rows = [...operatorRuleCredentialRows(review.rule, credential()), ...operatorRuleRestrictions(review.rule)];
    element('connect-review-details').replaceChildren(...rows.flatMap(([name, value]) => [textNode('dt', name), textNode('dd', value)]));
    if (reviewCurrent()) {
      const appName = operatorConnectResourceChoices(catalog().applications.filter(item => item.status === 'active'), [actionLabels.application]).find(item => item.id === selectedApplication).name;
      const credentialName = operatorConnectResourceChoices(catalog().credentials.filter(item => item.status === 'active'), [actionLabels.credential]).find(item => item.id === selectedCredential).name;
      element('connect-review-context').textContent = `${appName} may use ${credentialName} only as follows.`;
    } else element('connect-review-context').textContent =
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
    element('connect-credential-form').hidden = !['key', 'github', 'npm', 'saved'].includes(connectionMethod);
    element('connect-credential-heading').textContent = connectionMethod === 'npm' ? 'Save an npm token' : connectionMethod === 'github' ? 'Save a GitHub token' : connectionMethod === 'key' ? 'Use an API key' : 'Use a saved connection';
    element('connect-google-slot').hidden = !googleOpen;
    element('connect-method-change').hidden = connectionMethod === null || googleOpen;
    element('connect-method-change').disabled = !writable() || Boolean(checkpoint);
    element('connect-use-key').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials');
    element('connect-use-github').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') || !catalog()?.capabilities.github;
    element('connect-use-npm').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') || !catalog()?.capabilities.npm;
    element('connect-npm-status').textContent = !catalog()?.capabilities.npm ? 'npm metadata lookup is not advertised by this deployment.' :
      catalog().capabilities.npm.destination_allowed && catalog().allowed_upstreams.includes(operatorNpm.origin) ?
        'npm: save one token and grant Read package metadata for named packages. npm view/pacote.manifest only; no install, publish, tarballs or npm audit. No provider lookup has been tested here.' :
        'An npm token can be saved, but metadata access cannot be granted until the operator approves registry.npmjs.org in deployment settings.';
    element('connect-github-status').textContent = !catalog()?.capabilities.github ? 'GitHub presets are not advertised by this deployment. AWS presets are not available here.' :
      catalog().capabilities.github.destination_allowed && catalog().allowed_upstreams.includes(operatorGithub.origin) ?
        'GitHub: save one token and grant repository-scoped issue permissions. Requires the paired proxy implementation; this page has not tested GitHub.' :
        'A GitHub token can be saved, but access cannot be granted until the operator approves api.github.com in deployment settings.';
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
    event.preventDefault(); if (step !== 0 || !['key', 'github', 'npm', 'saved'].includes(connectionMethod) || !writable() || checkpoint || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-credential-choice').value;
    if (connectionMethod === 'saved') {
      if (!catalog().credentials.some(item => item.id === choice && item.status === 'active')) return;
      savedChoice = choice; selectedCredential = choice; selectedApplication = ''; selectedRule = ''; review = null; goto(1); return;
    }
    if (!workspace.ready('credentials') || connectionMethod === 'github' && !catalog().capabilities.github || connectionMethod === 'npm' && !catalog().capabilities.npm) return;
    const body = ['github', 'npm'].includes(connectionMethod) ?
      {name: element('connect-credential-name').value.trim(), secret: element('connect-credential-secret').value} :
      {name: element('connect-credential-name').value.trim(), auth_type: element('connect-credential-auth-type').value,
      header_name: element('connect-credential-auth-type').value === 'bearer' ? 'Authorization' : element('connect-credential-header-name').value.trim(), secret: element('connect-credential-secret').value};
    element('connect-credential-secret').value = '';
    await workspace.mutate(connectionMethod === 'npm' ? 'credentials/npm-token' : connectionMethod === 'github' ? 'credentials/github-token' : 'credentials', body, 'connect-status',
      result => receipt(result, 'credentials', 'credential')); render();
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
    if (isNpmCredential(credential())) {
      if (!npmNewRuleAvailable(catalog(), selectedApplication)) throw operatorError('An existing npm metadata or overlapping registry GET rule conflicts. Reuse the saved permission or explicitly revoke the conflict before a new grant.');
      const packages = npmPackageInput(element('connect-npm-packages').value);
      const rule = {...npmRuleFields(packages), name: 'Read package metadata',
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('npm metadata lookup or the selected packages are unavailable. No grant was sent.');
      return rule;
    }
    if (isGithubCredential(credential())) {
      const repository = {owner: element('connect-github-owner').value.trim(), name: element('connect-github-repo').value.trim()};
      const bundle = element('connect-operation').value;
      const rule = {...githubRuleFields(bundle, repository), name: (githubPermissionName(bundle) + ' · ' + repository.owner + '/' + repository.name).slice(0, 128),
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('GitHub permissions or this repository configuration are unavailable. No grant was sent.');
      return rule;
    }
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
    await workspace.mutate(isNpmRule(review.rule) ? 'access-rules/npm-metadata' : isGithubRule(review.rule) ? 'access-rules/github' : isGmailRule(review.rule) ? 'access-rules/gmail-read' : 'access-rules',
      isNpmRule(review.rule) ? npmRulePayload(review.rule) : isGithubRule(review.rule) ? githubRulePayload(review.rule) : isGmailRule(review.rule) ? gmailRulePayload(review.rule) : {...review.rule},
      'connect-status', result => receipt(result, 'access_rules', 'access_rule')); render();
  });
  for (const id of ['connect-credential-auth-type', 'connect-application-choice', 'connect-rule-choice', 'connect-operation', 'connect-credential-input', 'connect-response-mode', 'connect-request-body-mode'])
    element(id).addEventListener('change', render);
  element('connect-credential-choice').addEventListener('change', () => {
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    render();
  });
  for (const [id, method] of [['connect-use-key', 'key'], ['connect-use-github', 'github'], ['connect-use-npm', 'npm'], ['connect-use-saved', 'saved']]) element(id).addEventListener('click', () => {
    if (step !== 0 || connectionMethod !== null || !writable() || checkpoint) return;
    if (method === 'github' && !catalog()?.capabilities.github) return;
    if (method === 'npm' && !catalog()?.capabilities.npm) return;
    if (['github', 'npm'].includes(method)) element('connect-credential-secret').value = '';
    connectionMethod = method;
    element('connect-credential-choice').value = ''; render();
  });
  element('connect-method-change').addEventListener('click', () => {
    if (step !== 0 || !['key', 'github', 'npm', 'saved'].includes(connectionMethod) || !writable() || checkpoint) return;
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    if (['github', 'npm'].includes(connectionMethod)) element('connect-credential-secret').value = '';
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
    if (!active && ['github', 'npm'].includes(connectionMethod)) element('connect-credential-secret').value = '';
    applications.mount(active ? element('connect-token-slot') : null);
    if (!active || step !== 4) proxy.mount(null);
    render();
  }};
}
