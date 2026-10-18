function operatorResponseLimits(mode) {
  return operatorResponseAllowsEmpty204(mode) ? 'JSON or empty 204 only; other empty responses are unsupported.' : 'JSON only; no empty/204 responses.';
}
function operatorResponseHeaderSummary(mode) {
  return mode === 'unfiltered_json_or_empty_v2' ?
    'Standard API metadata is checked and discarded; no extra response headers are forwarded.' :
    'This strict response profile rejects unlisted upstream headers; no extra response headers are forwarded.';
}
function operatorResponseHeaderDetails(mode) {
  return mode === 'unfiltered_json_or_empty_v2' ?
    'Ordinary upstream metadata, such as Date, Server and Cache-Control, is accepted within safety limits, checked for credential disclosure and discarded. This catalog does not select response headers to forward.' :
    'This older response profile rejects unlisted upstream headers, including ordinary Date, Server and Cache-Control metadata; it does not merely discard them. No response headers are selected for forwarding.';
}
function renderBasicCompatibility(prefix, catalog, credential) {
  const response = element(prefix + '-response-mode').value;
  const request = element(prefix + '-request-body-mode').value;
  const fields = fieldLines(prefix + '-request-fields');
  const available = availableResponseModes(catalog).includes(response) && availableRequestBodyChoices(catalog, credential).includes(request) &&
    !(request === 'preserve_json_v1' && fields.length) && !(credential?.auth_type === 'google_oauth' && fields.length);
  const body = request === 'preserve_json_v1' && !fields.length ? 'JSON requests up to 64 KiB' : fields.length ? 'Only declared JSON request fields' : 'No request body';
  const query = fieldLines(prefix + '-query-keys');
  element(prefix + '-basic-compatibility').textContent = !available ?
    'A selected content choice is unavailable or conflicts with field restrictions. Open Add restrictions to choose a supported option; nothing is changed automatically.' :
    (credential?.auth_type === 'google_oauth' ? 'Google permits GET with no request body. ' : body + '. ') +
    (response === 'projected_json' ? 'Selected response fields are required in Add restrictions. ' :
      (operatorResponseAllowsEmpty204(response) ? 'JSON responses or empty HTTP 204; no content filtering. ' : 'Nonempty JSON responses only; no content filtering. ')) +
    (query.length ? 'Only ' + query.length + ' named query parameter(s) allowed. ' : 'No query parameters. ') +
    (response === 'unfiltered_json_or_empty_v2' ? 'Standard response metadata is checked and discarded.' : 'Strict upstream-header limits apply; see Compatibility limits.');
  // Required legacy projection must never be hidden inside a closed disclosure.
  if (response === 'projected_json' && !fieldLines(prefix + '-response-fields').length) element(prefix + '-restrictions').open = true;
}
function operatorRequestBodySummary(rule) {
  if (Object.hasOwn(rule, 'request_body_mode')) return rule.request_body_mode === 'preserve_json_v1' && !rule.request_fields.length ?
    'JSON content preserved unchanged, up to 64 KiB; an empty body is also allowed. No field list required.' : 'Unsupported request-body configuration; cannot use.';
  return rule.request_fields.length ? 'JSON fields only: ' + rule.request_fields.join(', ') + '.' : 'No body, including POST, PUT and PATCH.';
}
function operatorResponseSummary(rule) {
  return (operatorResponseModes[rule.response_mode] || 'Choose a supported response mode') + '. ' +
    (operatorResponseKeepsJson(rule.response_mode) ? 'All JSON content (no field filtering), including errors.' :
      'Success fields: ' + (rule.response_fields.length ? rule.response_fields.join(', ') + '.' : 'none selected; cannot save.')) +
    ' ' + operatorResponseLimits(rule.response_mode) + ' ' + operatorResponseHeaderSummary(rule.response_mode);
}
function gmailAgePolicySummary(policy) {
  try { policy = gmailAgePolicy(policy); } catch (_) { return 'Choose a valid mail-age policy before reviewing access.'; }
  return policy.mode === 'unrestricted' ? 'Unrestricted. No age restriction or optional content filtering.' :
    'Only mail from the last ' + policy.max_age_days + ' day' + (policy.max_age_days === 1 ? '' : 's') +
    ', based on Gmail’s stored timestamp (internalDate), not the sender’s Date header. The window moves with time.';
}
function renderOperatorCompatibility(id, rule = {}) {
  if (isEcrRule(rule)) { renderEcrCompatibility(id); return; }
  if (isXPostRule(rule)) { renderXPostCompatibility(id); return; }
  if (isAlchemyRule(rule)) { renderAlchemyCompatibility(id); return; }
  if (isXRule(rule)) { renderXCompatibility(id); return; }
  if (isNpmInstallRule(rule)) { renderNpmInstallCompatibility(id); return; }
  if (isNpmPublishRule(rule)) { renderNpmPublishCompatibility(id); return; }
  if (isNpmRule(rule)) { renderNpmCompatibility(id); return; }
  if (isGithubRule(rule)) { renderGithubCompatibility(id, rule); return; }
  if (isGmailRule(rule)) {
    element(id).replaceChildren(...[
      'Read Gmail permits GET message lists, pagination and individual message reads for users/me. No request body, sending, modification, attachments, history, threads or Calendar operations. ' + gmailAgePolicySummary(rule.age_policy) + ' A search query is not an age policy.',
      rule.query_mode === 'orderedFormV1' ?
        'This permission accepts the supported Gmail query parameters in client order using ordinary form-query encoding. Values, repeated names and operation-specific parameter combinations remain bounded; this is not unrestricted SDK compatibility.' :
        'Retained legacy permission: strict canonical query encoding and ordering still apply. This permission has not been upgraded to ordinary query compatibility.',
      'Message reads support full or metadata JSON, not raw mail. Message IDs must come from the selected account. ' +
        (rule.age_policy?.mode === 'recent_internal_date_v1' ?
          'Restricted lists require maxResults of 1–32. Extra metadata checks verify every message’s stored timestamp; an old message or unverifiable age blocks the whole page instead of silently omitting messages. Individual reads are checked too.' :
          'Lists are bounded to at most 500 messages per response; your client follows nextPageToken and makes each message request itself.'),
      'Required JSON object responses only: HTTP 200 up to 1 MiB; errors 400, 401, 403, 404, 429, 500, 502, 503 and 504 up to 64 KiB. No empty 204, text, binary or streaming responses. Identity and credential-disclosure checks still apply; this is not optional field filtering.',
      'Standard response metadata is checked and discarded; no extra response headers are forwarded. ' +
        (rule.query_mode === 'orderedFormV1' ? 'Client compression offers are removed before forwarding; compressed responses remain unsupported. ' :
          'This retained permission requires absent or identity Accept-Encoding; compressed responses remain unsupported. ') +
        'Proxy activation and finite app-token validity remain required; this page has not tested Gmail or automatic token refresh.'
    ].map(value => textNode('p', value, 'small muted')));
    return;
  }
  const empty204 = operatorResponseAllowsEmpty204(rule.response_mode);
  element(id).replaceChildren(...[
    operatorResponseLimits(rule.response_mode) + ' Success bodies: at most 1 MiB; error bodies: at most 64 KiB. ' + operatorResponseHeaderDetails(rule.response_mode),
    'Only 200, 201, 202, ' + (empty204 ? '204, ' : '') + '400, 401, 403, 404, 409, 422, 429, 500, 502, 503 and 504 are allowed by this response profile.',
    ...(empty204 ? ['HTTP 204 must have no body, trailers, Content-Length or Transfer-Encoding. An admitted JSON Content-Type may be present or omitted. Other allowed statuses still require strict JSON; empty 200, 205 and redirects are not supported.'] : []),
    rule.request_body_mode === 'preserve_json_v1' ?
      'Request JSON is preserved byte-for-byte, with no field declarations, up to 64 KiB. Empty bodies are allowed. Nonempty bodies require application/json. Strict JSON rejects duplicate keys, invalid Unicode, non-finite or overflowing numbers, integer -0 and nesting deeper than 127 containers.' :
      'Without explicit JSON preservation, an empty request-field list forbids bodies; listed fields permit only their declared application/json content, up to 64 KiB.',
    'Form, multipart, text, binary, compressed bodies, streaming and HEAD are unsupported. Query names still need explicit permission and canonical ordering. Proxy authentication, provider credential handling and JSON Content-Type are separate from the client-header allowlist.',
    'Selected-field filtering applies to successful responses; error responses retain only error, code and message. Whole-JSON mode includes all JSON content, including errors, but does not remove size, status or transport limits.',
    'Choices reflect capabilities advertised by this workspace’s control-plane source, not negotiated proxy support. Wait for confirmation that the exact saved policy is loaded; activation is not proof of a successful upstream request.',
  ].map(value => textNode('p', value, 'small muted')));
}
function renderOperatorRequestBodyForm(prefix, catalog, credential, warningId, active = true) {
  const select = element(prefix + '-request-body-mode'); const input = element(prefix + '-request-fields');
  const modes = availableRequestBodyChoices(catalog, credential);
  if (catalog && credential) chooseModeOptions(select.id, modes.map(id => ({id, name: operatorRequestBodyChoices[id]})), 'Choose a request-body mode');
  const preserve = select.value === 'preserve_json_v1'; const hasFields = fieldLines(input.id).length > 0;
  const showFields = select.value === 'legacy_fields' || hasFields;
  element(prefix + '-request-fields-group').hidden = !showFields; input.disabled = !active || !showFields;
  const invalid = !modes.includes(select.value) ? 'This request-body choice is unavailable. Choose again.' :
    preserve && hasFields ? 'Clear the explicit request-field restrictions before preserving JSON content.' :
    credential?.auth_type === 'google_oauth' && hasFields ? 'Google permits GET with no request body. Clear the request fields.' : '';
  select.setCustomValidity(invalid);
  element(warningId).textContent = invalid || (credential?.auth_type === 'google_oauth' ?
    'This Google account profile permits GET with no request body only. Account consent does not configure a complete Gmail workflow.' : preserve ?
      'Keep your client’s JSON body unchanged, up to 64 KiB, or send no body. No field list is needed. Forms, binary and streaming are not supported.' :
      'No request body is permitted when the field list is empty, even for POST, PUT and PATCH. List fields only if you deliberately want to restrict a JSON body.');
}
function operatorRuleRestrictions(rule) {
  if (isEcrRule(rule)) return ecrRuleRestrictions(rule);
  if (isCommonAppRule(rule)) return commonAppRuleRestrictions(rule);
  if (isXPostRule(rule)) return xPostRuleRestrictions(rule);
  if (isAlchemyRule(rule)) return alchemyRuleRestrictions(rule);
  if (isXRule(rule)) return xRuleRestrictions(rule);
  if (isNpmInstallRule(rule)) return npmInstallRuleRestrictions(rule);
  if (isNpmPublishRule(rule)) return npmPublishRuleRestrictions(rule);
  if (isNpmRule(rule)) return npmRuleRestrictions(rule);
  if (isGithubRule(rule)) return githubRuleRestrictions(rule);
  if (isGmailRule(rule)) return [
    ['Permission', 'Read Gmail · this connected account'],
    ['Allowed operations', 'List messages, follow pagination and read individual messages (GET only; no request body).'],
    ['Excluded operations', 'Sending, modifications, attachments, history, threads and Calendar.'],
    ['Mail age', gmailAgePolicySummary(rule.age_policy)],
    ...(rule.age_policy?.mode === 'recent_internal_date_v1' ? [['Age verification',
      'List requests require maxResults 1–32. Extra metadata checks verify internalDate; an old message or unverifiable age blocks the whole page. A search query can narrow results but cannot authorize older mail.']] : []),
    ['Queries', rule.query_mode === 'orderedFormV1' ? 'Supported Gmail parameters in client order; bounded values and operation-specific limits.' : 'Retained legacy canonical query rules; no automatic upgrade.'],
    ['Response', 'Required JSON objects; up to 1 MiB success / 64 KiB error. No empty 204 or streaming. Standard metadata is checked and discarded.'],
  ];
  return [
    ['Destination / methods', (rule.upstream_url || 'Choose an exact destination') + ' · ' +
      (rule.methods.length ? rule.methods.join(', ') + ' only' : 'Choose a method')],
    ['Request body', operatorRequestBodySummary(rule)],
    ['Query parameters', rule.query_keys.length ? 'Names only: ' + rule.query_keys.join(', ') + '.' : 'None allowed.'],
    ['Client headers', rule.allowed_headers.length ? rule.allowed_headers.join(', ') : 'No extra client headers.'],
    ['Response', operatorResponseSummary(rule)],
  ];
}
function operatorRuleCredentialRows(rule, credential) {
  if (isEcrRule(rule)) return [['Client credential input', 'Public SDK dummy only. Catchplate signs the exact approved ECR requests; AWS secrets never leave the server.']];
  const rows = [['Client credential input', operatorCredentialInputModes[rule.credential_input] || 'Unsupported credential input']];
  try {
    const dummy = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
    if (dummy) rows.push(['Exact dummy header', dummy.name + ': ' + dummy.value]);
  } catch (_) { rows.push(['Client setup', 'Invalid credential input configuration']); }
  return rows;
}
function operatorGoogleAssignments(credential, catalog, status, includeIds = false) {
  const rules = catalog.access_rules.filter(rule => rule.credential_id === credential.id && rule.status === status);
  return [...new Set(rules.map(rule => rule.application_id))].map(id => {
    const application = catalog.applications.find(item => item.id === id);
    return (application?.name || 'Retained client') + (includeIds ? ' (' + id + ')' : '');
  }).join(', ') || 'None';
}
function operatorCredentialHasExpiredAppAccess(credential, catalog, now = Date.now()) {
  const linked = catalog.access_rules.filter(rule => rule.credential_id === credential.id);
  return linked.length > 0 && linked.every(rule => {
    const app = catalog.applications.find(item => item.id === rule.application_id);
    return app?.status === 'revoked' || app?.status === 'active' &&
      ['valid', 'expired'].includes(app.token_status) && Number.isSafeInteger(app.token_expires_at_epoch_ms) &&
      app.token_expires_at_epoch_ms > 0 && app.token_expires_at_epoch_ms <= now;
  });
}
function operatorCredentialUseRows(credential, catalog) {
  const rules = catalog.access_rules.filter(rule => rule.credential_id === credential.id && rule.status === 'active');
  const apps = [...new Set(rules.map(rule => rule.application_id))].map(id =>
    catalog.applications.find(item => item.id === id)?.name || 'Unavailable client');
  return [['Assigned clients', apps.join(', ') || 'No active saved assignments'],
    ['Saved permissions', rules.map(rule => rule.name + ' — ' + operatorRuleRestrictions(rule)[0][1]).join('; ') ||
      'None. Saving a credential alone grants no client access.']];
}
function operatorGoogleAccountRows(credential, catalog) {
  return [['Google account', credential.provider_account], ['Permission preset', credential.permission_preset],
    ['Granted Google scopes', credential.scopes.join(', ')],
    ['Saved active assignments', operatorGoogleAssignments(credential, catalog, 'active', true)],
    ['Former assignments', operatorGoogleAssignments(credential, catalog, 'revoked', true)]];
}
function operatorGoogleAccountNotice(credential) {
  return credential.status === 'quarantined' ?
    'Quarantined: unavailable for grants and client setup. Provider revocation is not proven. Former assignments are retained references, not current access. This is not a successful Google disconnect.' :
    'Saved Google account metadata, not a refresh-health check. Granted Google scopes do not grant access to applications; each app still needs its own exact access rule. Assignments listed here are saved configuration, not proof of proxy activation.';
}
function operatorGooglePermission(credential) {
  return credential.permission_preset === 'gmail_readonly' ? 'Read Gmail' : 'Unsupported permission preset';
}
function operatorAccountActivity(credential, catalog) {
  const activity = catalog.observed_activity;
  const account = activity?.status === 'available' ? activity.accounts.find(item => item.credential_id === credential.id) : null;
  const time = value => new Date(value).toLocaleString();
  const rows = [];
  if (activity) {
    const window = activity.window;
    rows.push(['Summary observed at', time(activity.observed_at_epoch_ms)],
      ['Audit scan', window.rows_scanned + ' of at most ' + window.row_limit + ' recent rows; ' + window.bytes_read + ' of at most ' + window.byte_limit + ' bytes'],
      ['Coverage', window.incomplete ? 'Incomplete evidence' : 'No omissions reported inside this bounded scan'],
      ['Older rows outside scan', window.has_older_rows ? 'Yes' : 'No'],
      ['Byte budget exhausted', window.byte_budget_exhausted ? 'Yes' : 'No'],
      ['Skipped or unmatched evidence', window.oversized_events + ' oversized; ' + window.invalid_events + ' invalid; ' + window.unmatched_responses + ' unmatched responses'],
      ['Audit-chain verification', 'Not checked']);
  }
  if (!account) return {status: 'unavailable', text: 'Activity unavailable.', rows};
  const notes = [];
  const response = account.last_successful_response;
  const describe = event => event ? time(event.recorded_at_epoch_ms) + ' · credential version ' + event.credential_version + ' · event ' + event.event_id : 'No matching event in this scan';
  if (response) notes.push('Proxy recorded a successful response ' + time(response.recorded_at_epoch_ms));
  rows.push(['Last successful response recorded by proxy', describe(response)]);
  if (response) {
    const app = catalog.applications.find(item => item.id === response.application_id);
    const rule = catalog.access_rules.find(item => item.id === response.rule_id);
    rows.push(['Response application', app.name + ' (' + app.id + ')'], ['Response access rule', rule.name + ' (' + rule.id + ')']);
  }
  if (['google_oauth', 'x_oauth'].includes(credential.auth_type)) {
    const latest = account.last_refresh_outcome === 'success' ? account.last_refresh_success : account.last_refresh_failure;
    if (latest) notes.push('Refresh ' + account.last_refresh_outcome + ' recorded ' + time(latest.recorded_at_epoch_ms));
    rows.push(['Last recorded refresh success', describe(account.last_refresh_success)],
      ['Last recorded refresh failure', credential.auth_type === 'x_oauth' ? 'Not available from the X observation source' : describe(account.last_refresh_failure)]);
  }
  const observed = notes.length > 0;
  let text = observed ? (credential.status !== 'active' ? 'Historical activity only: ' : '') + notes.join('. ') + '.' :
    'No matching activity in the scanned audit window.';
  if (activity.window.incomplete) text += ' Evidence incomplete.';
  return {status: activity.window.incomplete ? 'incomplete' : observed ? 'observed' : 'unobserved', text, rows};
}
function appendOperatorAccountActivity(card, details, credential, catalog) {
  const activity = operatorAccountActivity(credential, catalog);
  const summary = textNode('p', activity.text, 'small');
  summary.dataset.accountActivity = ''; summary.dataset.activityStatus = activity.status;
  card.append(summary);
  const evidence = textNode('div'); evidence.dataset.accountActivityDetails = '';
  const metadata = textNode('dl', undefined, 'metadata');
  metadata.append(...activity.rows.flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
  evidence.append(metadata, textNode('p',
    'Times are audit storage/receiver times, not provider event times. This bounded scan may omit older or pending audit records; no matching event does not mean never used. The audit chain has not been verified here. A proxy response record does not prove delivery to the client or completion of its job. Historical observations do not establish current account health, application-token validity or policy activation.', 'small muted'));
  details.append(evidence);
}
function operatorGoogleAccountCard(credential, catalog) {
  const known = credential.permission_preset === 'gmail_readonly';
  const quarantined = credential.status === 'quarantined';
  const badge = quarantined ? 'Quarantined · unusable' : known ? 'Saved' : 'Unsupported · unusable';
  const card = resourceCard(credential, badge, [['Google account', credential.provider_account],
    ['Permissions', operatorGooglePermission(credential)],
    ['Assigned clients', operatorGoogleAssignments(credential, catalog, 'active')]]);
  card.dataset.credentialType = 'google_oauth';
  const notice = textNode('p', quarantined ?
    'Unavailable for use. Google revocation is not proven.' : !known ?
    'Unsupported permission preset; do not use this account.' :
    'Historical observations do not confirm current account health or proxy activation.', 'small muted');
  notice.dataset.googleAccountNotice = '';
  const details = textNode('details'); details.dataset.googleIdentity = '';
  details.append(textNode('summary', 'Details'));
  const metadata = textNode('dl', undefined, 'metadata');
  const values = [['Permission preset', credential.permission_preset], ['Granted Google scopes', credential.scopes.join(', ')],
    ['Credential ID', credential.id], ['Provider subject', credential.provider_subject], ['OAuth client ID', credential.oauth_client_id],
    ['Active rules', String(credential.active_rule_count)],
    ['Saved active assignments', operatorGoogleAssignments(credential, catalog, 'active', true)],
    ['Former assignments', operatorGoogleAssignments(credential, catalog, 'revoked', true)]];
  if (quarantined) values.push(['Quarantined at', credential.quarantined_at], ['Provider revocation', 'Not proven']);
  metadata.append(...values.flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
  details.append(metadata, textNode('p', 'Account removal needs provider-aware cleanup; this screen does not disconnect Google.', 'small muted'));
  appendOperatorAccountActivity(card, details, credential, catalog);
  card.append(notice, details);
  return card;
}
function keyReplacementBindings(catalog) {
  const omit = (item, names) => Object.fromEntries(Object.entries(item).filter(([name]) => !names.includes(name)));
  // Clock-derived expiry and loaded-policy observations are not identity changes.
  return JSON.stringify({applications: catalog.applications.map(item => omit(item, ['token_status', 'access_status'])),
    access_rules: catalog.access_rules.map(item => omit(item, ['enforcement']))});
}
function keyReplacementIdentity(credential) {
  return JSON.stringify(Object.fromEntries(['id', 'name', 'status', 'created_at', 'revoked_at', 'auth_type',
    'header_name', 'app_preset', 'active_rule_count', 'legacy_upstream_origin'].map(name => [name, credential[name]])));
}
function createStaticKeyReplacementView(workspace) {
  const panel = element('credential-replace-panel'); const form = element('credential-replace-form');
  const secret = element('credential-replace-secret'); let draft = null;
  const caveat = 'Previously issued proxy leases and requests already in flight may still use the old key. Replacing it here does not revoke it at the provider.';
  const message = value => {
    const status = element('credential-action-status'); status.textContent = value;
    if (value && location.hash === '#credentials') status.scrollIntoView({block: 'nearest'});
  };
  const writable = () => Boolean(workspace.state.catalog && !workspace.state.busy && !workspace.state.uncertain);
  function review(id) {
    const catalog = workspace.state.catalog;
    const credential = catalog?.credentials.find(item => item.id === id);
    if (!staticKeyReplacementAvailable(catalog, credential)) return null;
    return {id, generation: credential.credential_generation, revision: catalog.revision,
      policyHash: catalog.policy.policy_hash, sequence: catalog.policy.sequence,
      identity: keyReplacementIdentity(credential), bindings: keyReplacementBindings(catalog),
      replacedAt: credential.key_replaced_at,
      capability: JSON.stringify(catalog.capabilities.static_key_replacement)};
  }
  function close() {
    secret.value = ''; draft = null; panel.hidden = true; element('credential-replace-fields').disabled = true;
  }
  function render() {
    if (draft && (!writable() || JSON.stringify(review(draft.id)) !== JSON.stringify(draft))) {
      close(); message('Saved state changed or became unavailable. The new key was cleared. Review the credential and open Replace key again; no request was retried.');
    }
    element('credential-replace-fields').disabled = !draft || !writable();
  }
  function open(id) {
    close(); if (!writable()) return;
    draft = review(id); if (!draft) return;
    const catalog = workspace.state.catalog;
    const names = operatorConnectResourceChoices(catalog.credentials.filter(item => item.status === 'active'));
    element('credential-replace-title').textContent = 'Replace key · ' + names.find(item => item.id === id).name;
    renderCredentialGuide('credential-replace-guide', credentialGuideFor(catalog.credentials.find(item => item.id === id)),
      {secret: 'credential-replace-secret'});
    const rules = catalog.access_rules.filter(item => item.status === 'active' && item.credential_id === id);
    const ids = new Set(rules.map(item => item.application_id));
    const apps = operatorConnectResourceChoices(catalog.applications.filter(item => ids.has(item.id)));
    element('credential-replace-count').textContent = apps.length + ' affected app' + (apps.length === 1 ? '' : 's') +
      ' · ' + rules.length + ' active access rule' + (rules.length === 1 ? '' : 's') + '. Existing permissions stay unchanged.';
    element('credential-replace-apps').replaceChildren(...(apps.length ? apps.map(item => {
      const row = textNode('li', item.name); row.dataset.applicationId = item.id; return row;
    }) : [textNode('li', 'No apps currently have access through this key.')]));
    message(''); panel.hidden = false; render(); secret.focus();
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!draft || !writable()) { secret.value = ''; return; }
    if (JSON.stringify(review(draft.id)) !== JSON.stringify(draft)) { render(); return; }
    if (!form.reportValidity()) return;
    const reviewed = draft;
    const body = {id: reviewed.id, expected_credential_generation: reviewed.generation, secret: secret.value};
    close(); // Never retain a secret in the form across the async mutation.
    element('credential-action-status').scrollIntoView({block: 'nearest'});
    let receipt = null;
    const accepted = await workspace.mutate('credentials/replace-key', body, 'credential-action-status', result => {
      const replacement = result.key_replacement; const credential = result.credential;
      if (!credential || keyReplacementIdentity(credential) !== reviewed.identity ||
          projectStaticKeyMetadata(credential).credential_generation !== reviewed.generation + 1 ||
          !Object.hasOwn(credential, 'key_replaced_at') || result.revision !== reviewed.revision + 1 ||
          result.policy?.policy_hash !== reviewed.policyHash || result.policy.sequence !== reviewed.sequence ||
          replacement?.previous_credential_generation !== reviewed.generation ||
          replacement.credential_generation !== reviewed.generation + 1 ||
          !['local_completed', 'local_unconfirmed'].includes(replacement.cache_invalidation) ||
          replacement.in_flight_requests !== 'not_recalled')
        throw operatorError('The replacement receipt could not be confirmed. Review saved state; do not assume rollback or repeat the request.');
      receipt = {generation: replacement.credential_generation, cache: replacement.cache_invalidation,
        replacedAt: credential.key_replaced_at};
    }).finally(() => { body.secret = ''; });
    if (!accepted) return; // Existing refresh/review uncertainty remains authoritative.
    const catalog = workspace.state.catalog;
    const current = catalog?.credentials.find(item => item.id === reviewed.id);
    const confirmed = receipt && current && catalog.revision === reviewed.revision + 1 &&
      catalog.policy.policy_hash === reviewed.policyHash && catalog.policy.sequence === reviewed.sequence &&
      keyReplacementIdentity(current) === reviewed.identity && keyReplacementBindings(catalog) === reviewed.bindings &&
      current.credential_generation === receipt.generation && current.key_replaced_at === receipt.replacedAt;
    const notice = (confirmed ? 'Replacement saved in Catchplate. App identities and saved access rules are unchanged. ' :
      'Replacement acknowledged, but the refreshed saved state could not be confirmed. Refresh and review it before another replacement; do not assume rollback. ') +
      (receipt?.cache === 'local_unconfirmed' ? 'Local cache invalidation was not confirmed. ' : '') + caveat;
    if (!confirmed) workspace.requireReview(notice);
    message(notice);
  });
  element('credential-replace-cancel').addEventListener('click', () => { close(); message('Replacement cancelled. No key was submitted.'); });
  window.addEventListener('hashchange', close);
  window.addEventListener('pagehide', close);
  return {open, render};
}
function createCredentialsView(workspace, actions = {}) {
  const replacement = createStaticKeyReplacementView(workspace);
  const githubAppReplacement = createGithubAppKeyReplacementView(workspace);
  const aws = createAwsCredentialsView(workspace);
  const templates = {github_token: {method: 'github', githubType: 'github_token_v1'},
    github_app: {method: 'github', githubType: 'github_app_v1'}, npm: {method: 'npm'}, manual: {method: 'key'},
    x: {method: 'x'}, alchemy: {method: 'alchemy'}};
  const add = template => {
    if (!workspace.ready('credentials') || !actions.add?.(template))
      element('credential-action-status').textContent = 'Another setup still needs review. Open Set up access to inspect its saved result before adding another credential.';
  };
  for (const [id, template] of Object.entries(templates))
    document.querySelector('[data-credential-provider="' + id + '"]').addEventListener('click', () => add(template));
  document.querySelector('[data-credential-provider="aws"]').addEventListener('click', () => {
    if (workspace.ready('credentials') && actions.canAdd?.()) aws.openAdd();
  });
  element('credential-x-account').addEventListener('click', () => {
    if (!workspace.state.catalog?.capabilities.x_oauth || !workspace.ready('credentials') || !actions.canAdd?.()) return;
    element('x-account-panel').scrollIntoView({block: 'nearest'});
    if (!element('x-account-name').value) element('x-account-name').value = 'My X account';
    element('x-account-name').focus();
  });
  function filterProviders() {
    const query = element('credential-provider-search').value.trim().toLowerCase(); let visible = 0;
    for (const button of element('credential-provider-picker').querySelectorAll('button')) {
      button.hidden = !button.textContent.toLowerCase().includes(query); if (!button.hidden) visible++;
    }
    element('credential-provider-empty').hidden = visible > 0;
  }
  element('credential-provider-search').addEventListener('input', filterProviders);
  // The save-only controller reconciles its checkpoint after catalog listeners.
  // Refresh its local availability when returning, without another API read.
  window.addEventListener('hashchange', () => {
    if (location.hash === '#credentials') renderProviders(workspace.state.catalog);
  });
  function renderProviders(catalog) {
    const ready = workspace.ready('credentials') && Boolean(actions.canAdd?.());
    const available = {github_token: Boolean(catalog?.capabilities.github), github_app: githubAppDestinationAvailable(catalog),
      npm: Boolean(catalog?.capabilities.npm), manual: true, aws: awsStorageAvailable(catalog),
      x: xDestinationAvailable(catalog), alchemy: alchemyDestinationAvailable(catalog), x_account: Boolean(catalog?.capabilities.x_oauth)};
    for (const [id, enabled] of Object.entries(available)) {
      const button = document.querySelector('[data-credential-provider="' + id + '"]');
      button.disabled = !ready || !enabled;
      button.title = enabled ? 'Save a credential; client permissions are configured separately.' : 'Not configured in this instance. Review provider and destination settings in Proxy setup.';
    }
    element('credential-common-providers').replaceChildren(...(catalog?.capabilities.common_apps?.presets || []).map(preset => {
      const button = textNode('button', preset.id === 'gemini' ? 'Gemini API key' : preset.label, 'secondary');
      button.type = 'button'; button.dataset.credentialApp = preset.id; button.disabled = !ready;
      button.title = preset.secret_label + '. Saving grants no access.';
      button.addEventListener('click', () => add({method: 'common', appPreset: preset.id})); return button;
    }));
    filterProviders();
  }
  element('credential-add').addEventListener('click', () => {
    if (element('credential-storage-type').value === 'manual' && workspace.ready('credentials') && !actions.add?.())
      element('credential-action-status').textContent = 'Another setup still needs review. Open Set up access to inspect its saved result before adding another credential.';
  });
  function render() {
    const catalog = workspace.state.catalog;
    replacement.render();
    githubAppReplacement.render();
    renderProviders(catalog);
    element('credential-fields').disabled = element('credential-storage-type').value !== 'manual' || !workspace.ready('credentials');
    if (!catalog) return;
    const entries = [], diagnostic = operatorDiagnosticResources(catalog);
    for (const credential of catalog.credentials) {
      const google = credential.auth_type === 'google_oauth';
      const xAccount = isXOAuthCredential(credential);
      const badge = credential.status === 'quarantined' ? 'Quarantined · unusable' : credential.status === 'active' ? 'Saved' : 'Revoked locally';
      const card = google ? operatorGoogleAccountCard(credential, catalog) : resourceCard(credential, badge,
        operatorCredentialUseRows(credential, catalog));
      if (isAwsCredential(credential)) card.dataset.credentialType = 'aws_sigv4_v1';
      if (!google) {
        if (isCommonAppCredential(credential)) {
          const preset = commonAppPreset(catalog, credential.app_preset);
          card.append(textNode('p', (preset?.label || credential.app_preset) +
            ' · Saved provider key. Use Set up access to choose a scoped operation. The key is not tested or renewed automatically.', 'small muted'));
          const missing = [...new Set((preset?.operations || []).map(item => item.origin))].filter(origin => !catalog.allowed_upstreams.includes(origin));
          if (missing.length) {
            const notice = textNode('p', 'Destination approval required: ' + missing.join(', ') + '. ', 'notice');
            const link = textNode('a', 'Review Proxy destinations'); link.href = '#proxy'; notice.append(link); card.append(notice);
          }
        }
        if (xAccount) card.append(textNode('p', credential.provider_account + ' · Connected X account. ' +
          (credential.status === 'active' ? 'Posting requires a separate permission and current paired gate. Saved consent is not proof of current entitlement or refresh health.' :
            'Unavailable locally. Provider cleanup is confirmed only by its operation result.'), 'small muted'));
        if (isAwsCredential(credential)) card.append(textNode('p', (ecrAvailable(catalog, credential) ?
          'Available for explicitly scoped ECR image publication with whole-image approval. ' : operatorAwsNotice + ' ') +
          'AWS validity and permissions have not been tested. No automatic renewal or generic header access.', 'small muted'));
        if (isAlchemyCredential(credential)) card.append(textNode('p',
          'Alchemy chain-status reads only. Stored API or access key, never a key-bearing URL. Validity and provider entitlement are not tested here; Catchplate does not renew this key.', 'small muted'));
        if (isXCredential(credential)) card.append(textNode('p',
          'X app-only username lookup only. Stored token; validity and provider entitlement are not tested here. No posting or user OAuth. Catchplate does not renew this token.', 'small muted'));
        if (isGithubCredential(credential)) card.append(textNode('p', isGithubAppCredential(credential) ?
          'GitHub App bound to ' + credential.github_app.repository.owner + '/' + credential.github_app.repository.name +
          (credential.status === 'active' ? '. Catchplate automatically renews scoped installation tokens using the stored private key. This page has not tested current renewal health; application proxy tokens have their own expiry.' :
            '. Revoked locally: unavailable for requests or token renewal here. This does not uninstall the App at GitHub.') :
          'GitHub issue presets only. Stored personal access token; validity and repository access are not tested here. Catchplate does not renew this token.', 'small muted'));
        if (isNpmCredential(credential)) card.append(textNode('p',
          catalog.capabilities.npm_install ?
            'Saved npm token. Explicit installation permissions require every package and dependency in their allowlist. Metadata and publishing permissions remain separate; provider validity is untested and this token is not renewed.' : catalog.capabilities.npm_publish ?
            'Saved npm token. Each app needs a separate metadata or publishing permission. Package access and token validity are not tested here; Catchplate does not renew this token.' :
            'npm metadata lookup only. Stored token; package access and token validity are not tested here. No install, publish, tarballs or npm audit. Catchplate does not renew this token.', 'small muted'));
        card.append(textNode('p', 'Saved assignments are configuration, not proof of a valid app token, provider key, or loaded proxy policy.', 'small muted'));
        const details = textNode('details'); details.dataset.credentialDetails = ''; details.append(textNode('summary', 'Details'));
        const identity = textNode('dl', undefined, 'metadata');
        for (const [label, value] of [['Credential ID', credential.id], ...(isAwsCredential(credential) ? awsCredentialRows(credential, catalog) : [
          ['Authentication', xAccount ? 'X user account OAuth' : isAlchemyCredential(credential) ? 'Alchemy API or access key' : isXCredential(credential) ? 'X app-only bearer token' : isNpmCredential(credential) ? 'npm token' : isGithubAppCredential(credential) ? 'GitHub App installation token' : isGithubCredential(credential) ? 'GitHub personal access token' : credential.auth_type === 'bearer' ? 'Bearer token' : 'Custom header'],
          ['Header name', credential.header_name]]), ['Active rules', String(credential.active_rule_count)],
          ['Saved at', credential.created_at || 'Unavailable']]) identity.append(textNode('dt', label), textNode('dd', value));
        details.append(identity);
        if (xAccount) for (const [label, value] of [['X account', credential.provider_account], ['X subject', credential.provider_subject],
          ['OAuth client', credential.oauth_client_id], ['Consent scopes', credential.scopes.join(', ')],
          ['Permission preset', 'Text-only posting; review shared daily limits in each posting permission']]) identity.append(textNode('dt', label), textNode('dd', value));
        if (isGithubAppCredential(credential)) {
          const binding = credential.github_app;
          for (const [label, value] of [['GitHub App ID', binding.app_id], ['Installation ID', binding.installation_id],
            ['Account ID', binding.account_id], ['Repository ID', binding.repository_id],
            ['Repository', binding.repository.owner + '/' + binding.repository.name],
            ['Maximum permission', githubPermissionName(binding.issues_permission === 'write' ? operatorGithub.write : operatorGithub.read)],
            ['Installation-token renewal', credential.status === 'active' ? 'Automatic; current health is not observed here' : 'Disabled by local revocation']])
            identity.append(textNode('dt', label), textNode('dd', value));
        }
        if (Object.hasOwn(credential, 'credential_generation')) {
          const metadata = textNode('dl', undefined, 'metadata'); metadata.dataset.keyReplacementDetails = '';
          for (const [label, value] of [[xAccount ? 'Credential generation' : 'Stored key generation', credential.credential_generation === null ? 'Unavailable after local revocation' : String(credential.credential_generation)],
            ...(!xAccount ? [['Last replacement saved', credential.key_replaced_at ? new Date(credential.key_replaced_at).toLocaleString() : 'No replacement recorded']] : [])])
            metadata.append(textNode('dt', label), textNode('dd', value));
          details.append(metadata);
        }
        appendOperatorAccountActivity(card, details, credential, catalog); card.append(details);
      }
      if (credential.legacy_upstream_origin) card.append(textNode('p', 'Migrated credential remains limited to ' + credential.legacy_upstream_origin + '.', 'small muted'));
      if (credential.status === 'active' && (!isAwsCredential(credential) || ecrAvailable(catalog, credential)) && typeof actions.use === 'function') {
        const use = textNode('button', 'Use with a client', 'secondary'); use.dataset.action = 'use-credential';
        use.disabled = workspace.state.busy || workspace.state.uncertain || !operatorCredentialCanSetUpAccess(credential, catalog);
        use.addEventListener('click', () => {
          if (!actions.use(credential.id)) element('credential-action-status').textContent =
            'This exact credential is unavailable for setup. Refresh and review its state and supported permissions; no request was sent.';
        }); card.append(use);
      }
      if (google && credential.status === 'active' && catalog.capabilities.google_reauthorization && typeof actions.reauthorize === 'function') {
        const button = textNode('button', 'Reauthorize Google', 'secondary'); button.dataset.action = 'reauthorize-google';
        button.disabled = workspace.state.busy || workspace.state.uncertain;
        button.addEventListener('click', () => actions.reauthorize(credential.id)); card.append(button);
      }
      if (xAccount && ['active', 'quarantined'].includes(credential.status) && typeof actions.disconnectX === 'function') {
        const button = textNode('button', 'Review X disconnect', 'secondary'); button.dataset.action = 'disconnect-x';
        button.disabled = workspace.state.busy || workspace.state.uncertain;
        button.addEventListener('click', () => actions.disconnectX(credential.id)); card.append(button);
      }
      if (credential.status === 'active' && !google && !xAccount) {
        if (awsReplaceAvailable(catalog, credential)) {
          const replace = textNode('button', 'Replace AWS credentials', 'secondary'); replace.dataset.action = 'replace-aws-credentials';
          replace.disabled = workspace.state.busy || workspace.state.uncertain;
          replace.addEventListener('click', () => aws.open(credential.id)); card.append(replace);
        }
        if (staticKeyReplacementAvailable(catalog, credential)) {
          const replace = textNode('button', 'Replace key', 'secondary'); replace.dataset.action = 'replace-key';
          replace.disabled = workspace.state.busy || workspace.state.uncertain;
          replace.addEventListener('click', () => replacement.open(credential.id)); card.append(replace);
        }
        if (githubAppKeyReplacementAvailable(catalog, credential)) {
          const replace = textNode('button', 'Replace GitHub App private key', 'secondary'); replace.dataset.action = 'replace-github-app-key';
          replace.disabled = workspace.state.busy || workspace.state.uncertain;
          replace.addEventListener('click', () => githubAppReplacement.open(credential.id)); card.append(replace);
        }
        const button = textNode('button', isAwsCredential(credential) ? 'Remove AWS credentials' : 'Revoke credential', 'secondary'); button.dataset.action = 'revoke-credential';
        button.disabled = workspace.state.busy || workspace.state.uncertain || credential.active_rule_count > 0 ||
          isAwsCredential(credential) && !awsStorageAvailable(catalog);
        button.addEventListener('click', () => {
          if (isAwsCredential(credential) && !awsStorageAvailable(workspace.state.catalog)) return;
          if (!window.confirm(isGithubAppCredential(credential) ? `Revoke GitHub App connection "${credential.name}" (${credential.id}) locally? This stops its use and token renewal here; it does not uninstall the App at GitHub.` :
            isAwsCredential(credential) ? `Remove AWS credentials "${credential.name}" (${credential.id}) from Catchplate? This does not revoke them at AWS.` :
            `Revoke locally stored credential "${credential.name}" (${credential.id})? This does not revoke the key at its provider.`)) return;
          workspace.mutate('credentials/revoke', {id: credential.id}, 'credential-action-status');
        }); card.append(button);
        if (credential.active_rule_count > 0) card.append(textNode('p', 'Revoke the referencing access rules first. Shared application identities are retained.', 'small muted'));
      }
      entries.push({card, group: credential.status === 'revoked' ? 'revoked' : diagnostic.credentials.has(credential.id) ? 'diagnostic' :
        operatorCredentialHasExpiredAppAccess(credential, catalog) ? 'expired' : 'current'});
    }
    renderResourceGroups('credentials-list', entries, 'No current credentials in the main list. Add a provider account or key above, or expand a retained group below to manage existing records.');
  }
  workspace.subscribe(render); return {render};
}
function createAccessRulesView(workspace, actions = {}) {
  const form = element('access-rule-form');
  function manualResources(catalog) {
    const diagnostics = operatorDiagnosticResources(catalog);
    const includeDiagnostics = element('rule-include-diagnostics').checked;
    return {
      applications: catalog.applications.filter(item => item.status === 'active' && (includeDiagnostics || !diagnostics.applications.has(item.id))),
      credentials: catalog.credentials.filter(item => item.status === 'active' && !isCommonAppCredential(item) && !isAwsCredential(item) &&
        !isGithubCredential(item) && !isNpmCredential(item) && !isXCredential(item) && !isXOAuthCredential(item) && !isAlchemyCredential(item) &&
        (includeDiagnostics || !diagnostics.credentials.has(item.id))),
      origins: catalog.allowed_upstreams.filter(origin => includeDiagnostics || origin !== 'https://demo-upstream:8443')
    };
  }
  element('rule-include-diagnostics').addEventListener('change', render);
  renderOperatorCompatibility('rule-compatibility-content');
  function renderSummary() {
    const catalog = workspace.state.catalog;
    const list = element('rule-effective-restrictions');
    if (!catalog) {
      renderBasicCompatibility('rule', null, null);
      element('rule-effective-context').textContent = 'Workspace status is unavailable. Refresh before reviewing or saving a rule.';
      list.replaceChildren(); return;
    }
    const application = catalog.applications.find(item => item.id === element('rule-application-id').value);
    const credential = catalog.credentials.find(item => item.id === element('rule-credential-id').value);
    element('rule-effective-context').textContent = application && credential ?
      application.name + ' may use ' + credential.name + ' only within the restrictions below. This draft is not yet saved or validated.' :
      'Choose an application and saved credential. This draft is not yet saved or validated.';
    const origin = element('rule-upstream-origin').value; const path = element('rule-path').value.trim();
    const draft = {upstream_url: origin && path ? origin.replace(/\/$/, '') + path : '',
      methods: [...document.querySelectorAll('input[name="rule-method"]:checked')].map(input => input.value),
      request_fields: fieldLines('rule-request-fields'), query_keys: fieldLines('rule-query-keys'), allowed_headers: fieldLines('rule-allowed-headers'),
      response_mode: element('rule-response-mode').value, response_fields: fieldLines('rule-response-fields')};
    const requestMode = element('rule-request-body-mode').value;
    if (requestMode && requestMode !== 'legacy_fields') draft.request_body_mode = requestMode;
    if (element('rule-approval-required').checked) draft.approval_mode = 'host_review_v1';
    const rows = [...operatorRuleRestrictions(draft), ...operatorApprovalRows(draft)];
    element('rule-approval-required').disabled = !operatorHostApprovalAvailable(catalog, draft) && !element('rule-approval-required').checked;
    element('rule-approval-help').textContent = operatorHostApprovalAvailable(catalog, draft) ?
      'Host-trusted: a server administrator can bypass this control. The first request stops with HTTP 428; approval permits one explicit retry of exactly the same request. No automatic replay.' :
      'Host-trusted approvals are unavailable until the app and proxy advertise matching support. Existing permissions are unchanged.';
    list.replaceChildren(...rows.flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
    renderOperatorCompatibility('rule-compatibility-content', draft);
    renderBasicCompatibility('rule', catalog, credential);
  }
  function renderRequestBody() {
    const catalog = workspace.state.catalog;
    renderOperatorRequestBodyForm('rule', catalog, catalog?.credentials.find(item => item.id === element('rule-credential-id').value), 'rule-body-default');
  }
  function renderCredentialInput() {
    const mode = element('rule-credential-input').value;
    const supported = availableCredentialInputModes(workspace.state.catalog).includes(mode);
    const replacing = supported && mode === 'replace_exact';
    const credential = workspace.state.catalog?.credentials.find(item => item.id === element('rule-credential-id').value);
    element('rule-placeholder-group').hidden = !replacing;
    element('rule-placeholder').disabled = !replacing;
    element('rule-placeholder').required = replacing;
    element('rule-placeholder').setCustomValidity('');
    element('rule-credential-input-help').textContent = !supported ? 'Refresh the workspace to load supported credential input choices. New rules are disabled until these are available.' :
      replacing ? 'Send exactly one matching dummy header. Missing, different or duplicate values are denied before the real credential is used.' :
      'Your client sends no provider credential header. Catchplate adds the saved credential after authorizing the request.';
    if (!replacing) return;
    try { element('rule-credential-header').textContent = credentialHeaderTarget(credential); }
    catch (_) {
      element('rule-credential-header').textContent = 'This saved credential does not support dummy header replacement.';
      element('rule-placeholder').setCustomValidity('Choose a saved credential with a supported header target.');
    }
    element('rule-placeholder').placeholder = element('rule-credential-header').textContent === 'Authorization' ? 'Bearer CATCHPLATE_DUMMY' : 'CATCHPLATE_DUMMY';
  }
  function renderResponseMode() {
    const mode = element('rule-response-mode').value;
    const supported = availableResponseModes(workspace.state.catalog).includes(mode);
    const projected = supported && mode === 'projected_json';
    element('rule-response-fields-group').hidden = !projected;
    element('rule-response-fields').disabled = !projected;
    element('rule-response-fields').required = projected;
    element('rule-response-limits').textContent = operatorResponseLimits(mode);
    element('rule-response-mode-help').textContent = !supported ? 'Refresh the workspace to load supported response modes. Saving is disabled until one is available.' :
      operatorResponseAllowsEmpty204(mode) ? 'Keeps bounded JSON success and error content unchanged, or an admitted empty HTTP 204. No response field list is needed. Destination, method and request restrictions still apply. ' + operatorResponseHeaderSummary(mode) :
      mode === 'unfiltered_json' ? 'Returns all content in a bounded nonempty JSON response, including errors. No response field list is needed. Empty responses remain unsupported.' :
      'Successful JSON responses contain only the fields you list below. Error responses retain only error, code and message fields. Destination, method and request restrictions still apply.';
  }
  element('rule-response-mode').addEventListener('change', renderResponseMode);
  for (const id of ['rule-credential-input', 'rule-credential-id']) element(id).addEventListener('change', renderCredentialInput);
  const renderDraft = () => { renderRequestBody(); renderSummary(); };
  form.addEventListener('input', renderDraft);
  form.addEventListener('change', renderDraft);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!workspace.ready('access_rules') || !form.reportValidity()) return;
    const catalog = workspace.state.catalog; const origin = element('rule-upstream-origin').value;
    const path = element('rule-path').value.trim();
    const responseMode = element('rule-response-mode').value;
    const responseFields = responseMode === 'projected_json' ? fieldLines('rule-response-fields') : [];
    const credentialInput = element('rule-credential-input').value;
    const placeholder = credentialInput === 'replace_exact' ? element('rule-placeholder').value : undefined;
    const credential = catalog.credentials.find(item => item.id === element('rule-credential-id').value);
    const permitted = manualResources(catalog);
    if (!permitted.applications.some(item => item.id === element('rule-application-id').value) ||
        !permitted.credentials.some(item => item.id === credential?.id) || !permitted.origins.includes(origin)) {
      element('access-rule-form-status').textContent = 'Choose an available client, credential and approved destination. Connection-check resources require the explicit advanced option.'; return;
    }
    try {
      if (isAwsCredential(credential)) throw new Error();
      if (!availableCredentialInputModes(catalog).includes(credentialInput)) throw new Error();
      clientCredentialInput({credentialInput, placeholder, credential});
    } catch (_) {
      element('access-rule-form-status').textContent = 'Choose a supported credential input. A dummy value must be 1–1024 printable ASCII characters with no leading or trailing spaces; use the complete header value.'; return;
    }
    const methods = [...document.querySelectorAll('input[name="rule-method"]:checked')].map(input => input.value);
    if (!catalog.allowed_upstreams.includes(origin) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        !methods.length || methods.some(method => !operatorMethods.includes(method)) || !availableResponseModes(catalog).includes(responseMode) ||
        responseMode === 'projected_json' && !responseFields.length) {
      element('access-rule-form-status').textContent = 'Choose an approved destination, exact path, supported method and response mode. Selected-field filtering also requires explicit response fields.'; return;
    }
    const body = {name: operatorPermissionName(element('rule-name').value, methods, path), application_id: element('rule-application-id').value,
      credential_id: element('rule-credential-id').value, upstream_url: origin.replace(/\/$/, '') + path, methods,
      response_mode: responseMode, response_fields: responseFields,
      credential_input: credentialInput, query_keys: fieldLines('rule-query-keys'), allowed_headers: fieldLines('rule-allowed-headers')};
    if (credentialInput === 'replace_exact') body.placeholder = placeholder;
    if (element('rule-approval-required').checked) body.approval_mode = 'host_review_v1';
    try { Object.assign(body, operatorRequestBodyInput(element('rule-request-body-mode').value, fieldLines('rule-request-fields'), catalog, credential)); }
    catch (error) { element('access-rule-form-status').textContent = operatorMessage(error); return; }
    if (!operatorRuleSupported(body, catalog)) {
      element('access-rule-form-status').textContent = 'Choose supported content modes and active resources. Google permits only GET with no request body.'; return;
    }
    await workspace.mutate('access-rules', body, 'access-rule-form-status');
  });
  function render() {
    const catalog = workspace.state.catalog;
    const choices = catalog ? manualResources(catalog) : {applications: [], credentials: [], origins: []};
    const responseModes = availableResponseModes(catalog);
    const credentialInputModes = availableCredentialInputModes(catalog);
    element('access-rule-fields').disabled = !workspace.ready('access_rules') || !choices.credentials.length ||
      !choices.applications.length || !choices.origins.length || !responseModes.length || !credentialInputModes.length;
    if (!catalog) { renderResponseMode(); renderCredentialInput(); renderRequestBody(); renderSummary(); return; }
    chooseModeOptions('rule-response-mode', responseFormChoices(catalog, element('rule-response-mode').value), 'No supported response mode available');
    renderResponseMode();
    chooseOptions('rule-application-id', [{id: '', name: choices.applications.length ? 'Choose a client' : 'Create a client first'},
      ...operatorConnectResourceChoices(choices.applications)], 'Create a client first');
    chooseOptions('rule-credential-id', [{id: '', name: choices.credentials.length ? 'Choose a saved credential' : 'Provider presets and ECR need Set up access'},
      ...operatorConnectResourceChoices(choices.credentials)], 'Provider presets and ECR need Set up access');
    chooseOptions('rule-credential-input', credentialInputModes.map(mode => ({id: mode, name: operatorCredentialInputModes[mode]})), 'No supported credential input available');
    renderCredentialInput();
    renderRequestBody();
    chooseOptions('rule-upstream-origin', [{id: '', name: 'Choose an approved destination'}, ...choices.origins.map(origin => ({id: origin, name: origin}))], 'No approved destination configured');
    renderSummary();
    const diagnostic = operatorDiagnosticResources(catalog);
    renderResourceGroups('access-rules-list', catalog.access_rules.map(rule => {
      const application = catalog.applications.find(item => item.id === rule.application_id);
      const credential = catalog.credentials.find(item => item.id === rule.credential_id);
      const enforced = workspace.loaded() && rule.enforcement === (rule.status === 'revoked' ? 'revoked' : 'active');
      const badge = rule.status === 'revoked' ? enforced ? 'Revoked · enforced' : 'Revoked · enforcement pending' : enforced ? 'Active' : 'Saved · activation pending';
      const card = resourceCard(rule, badge, [['Application', application?.name || rule.application_id], ['Credential', credential?.name || rule.credential_id],
        ...operatorRuleCredentialRows(rule, credential), ...operatorRuleRestrictions(rule), ...operatorApprovalRows(rule), ['Rule ID', rule.id]]);
      if (rule.status === 'active') {
        const configure = textNode('button', 'Open client setup', 'secondary'); configure.dataset.action = 'configure-rule';
        configure.disabled = workspace.state.busy || workspace.state.uncertain || application?.status !== 'active' ||
          !operatorRuleSupported(rule, catalog) || typeof actions.configure !== 'function';
        configure.addEventListener('click', () => {
          const current = workspace.state.catalog;
          const selected = current?.access_rules.find(item => item.id === rule.id && item.status === 'active');
          if (!selected || workspace.state.busy || workspace.state.uncertain || !operatorRuleSupported(selected, current) ||
              !actions.configure?.(selected.application_id, selected.id))
            element('rule-action-status').textContent = 'This exact permission is unavailable for client setup. Refresh and review saved state; no request was sent.';
        }); card.append(configure);
        const approval = textNode('button', rule.approval_mode === 'host_review_v1' ? 'Remove human approval requirement' : 'Require human approval', 'secondary');
        approval.dataset.action = 'change-approval';
        approval.hidden = isEcrRule(rule);
        approval.disabled = isEcrRule(rule) || workspace.state.busy || workspace.state.uncertain || !operatorHostApprovalAvailable(catalog, rule);
        approval.addEventListener('click', () => {
          const current = workspace.state.catalog?.access_rules.find(item => item.id === rule.id && item.status === 'active');
          if (!current || workspace.state.busy || workspace.state.uncertain || !operatorHostApprovalAvailable(workspace.state.catalog, current)) return;
          const mode = current.approval_mode === 'host_review_v1' ? 'automatic' : 'host_review_v1';
          if (!window.confirm(mode === 'automatic' ? 'Remove human approval from this permission? Matching requests will proceed without a decision after the proxy loads the change.' :
            'Require a human decision for each exact request? This is host-trusted: server administrators can bypass it. The first request stops with HTTP 428 and must be explicitly retried once after approval.')) return;
          workspace.mutate('access-rules/approval', {id: current.id, approval_mode: mode}, 'rule-action-status');
        }); card.append(approval);
        if (Object.hasOwn(rule, 'daily_post_attempt_limit')) card.append(textNode('p',
          'Human approval cannot currently be combined with an X daily posting-attempt limit. The saved quota remains in force.', 'small muted'));
        const button = textNode('button', 'Revoke access rule', 'secondary'); button.dataset.action = 'revoke-rule';
        button.disabled = workspace.state.busy || workspace.state.uncertain;
        button.addEventListener('click', () => {
          if (!window.confirm(`Revoke rule "${rule.name}" (${rule.id})? The application and saved credential remain. New requests are denied after the proxy loads the updated policy; already-dispatched requests cannot be recalled.`)) return;
          workspace.mutate('access-rules/revoke', {id: rule.id}, 'rule-action-status');
        }); card.append(button);
      }
      return {card, group: rule.status === 'revoked' ? 'revoked' : diagnostic.access_rules.has(rule.id) ? 'diagnostic' : 'current'};
    }), 'No current permissions in the main list. Saved credentials and clients alone grant no access. Expand retained groups below to review existing permissions.');
  }
  workspace.subscribe(render); return {render};
}
