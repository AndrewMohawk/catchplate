function operatorResponseLimits(mode) {
  return mode === 'unfiltered_json_or_empty_v1' ? 'JSON or empty 204 only; other empty responses are unsupported.' : 'JSON only; no empty/204 responses.';
}
function operatorRequestBodySummary(rule) {
  if (Object.hasOwn(rule, 'request_body_mode')) return rule.request_body_mode === 'preserve_json_v1' && !rule.request_fields.length ?
    'JSON content preserved unchanged, up to 64 KiB; an empty body is also allowed. No field list required.' : 'Unsupported request-body configuration; cannot use.';
  return rule.request_fields.length ? 'JSON fields only: ' + rule.request_fields.join(', ') + '.' : 'No body, including POST, PUT and PATCH.';
}
function operatorResponseSummary(rule) {
  return (operatorResponseModes[rule.response_mode] || 'Choose a supported response mode') + '. ' +
    (['unfiltered_json', 'unfiltered_json_or_empty_v1'].includes(rule.response_mode) ? 'All JSON content (no field filtering), including errors.' :
      'Success fields: ' + (rule.response_fields.length ? rule.response_fields.join(', ') + '.' : 'none selected; cannot save.')) +
    ' ' + operatorResponseLimits(rule.response_mode);
}
function renderOperatorCompatibility(id, rule = {}) {
  const empty204 = rule.response_mode === 'unfiltered_json_or_empty_v1';
  element(id).replaceChildren(...[
    operatorResponseLimits(rule.response_mode) + ' Success bodies: at most 1 MiB; error bodies: at most 64 KiB. Upstream response headers are not forwarded.',
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
    'This Google account profile permits GET with no request body only. Google connection remains unavailable here.' : preserve ?
      'Keep your client’s JSON body unchanged, up to 64 KiB, or send no body. No field list is needed. Forms, binary and streaming are not supported.' :
      'No request body is permitted when the field list is empty, even for POST, PUT and PATCH. List fields only if you deliberately want to restrict a JSON body.');
}
function operatorRuleRestrictions(rule) {
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
  const rows = [['Client credential input', operatorCredentialInputModes[rule.credential_input] || 'Unsupported credential input']];
  try {
    const dummy = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
    if (dummy) rows.push(['Exact dummy header', dummy.name + ': ' + dummy.value]);
  } catch (_) { rows.push(['Client setup', 'Invalid credential input configuration']); }
  return rows;
}
function operatorGoogleAccountRows(credential, catalog) {
  const rules = catalog.access_rules.filter(rule => rule.credential_id === credential.id);
  const names = status => [...new Set(rules.filter(rule => rule.status === status).map(rule => rule.application_id))].map(id => {
    const application = catalog.applications.find(item => item.id === id);
    return (application?.name || 'Retained application') + ' (' + id + ')';
  }).join(', ') || 'None';
  return [['Google account', credential.provider_account], ['Permission preset', credential.permission_preset],
    ['Granted Google scopes', credential.scopes.join(', ')],
    ['Saved active assignments', names('active')], ['Former assignments', names('revoked')]];
}
function operatorGoogleAccountNotice(credential) {
  return credential.status === 'quarantined' ?
    'Quarantined: unavailable for grants and client setup. Provider revocation is not proven. Former assignments are retained references, not current access. This is not a successful Google disconnect.' :
    'Saved Google account metadata, not a refresh-health check. Granted Google scopes do not grant access to applications; each app still needs its own exact access rule. Assignments listed here are saved configuration, not proof of proxy activation.';
}
function createCredentialsView(workspace) {
  const form = element('credential-form');
  element('credential-auth-type').addEventListener('change', () => {
    const custom = element('credential-auth-type').value === 'header';
    element('credential-header-field').hidden = !custom; element('credential-header-name').required = custom;
  });
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!workspace.ready('credentials') || !form.reportValidity()) return;
    const body = {name: element('credential-name').value.trim(), auth_type: element('credential-auth-type').value,
      header_name: element('credential-auth-type').value === 'bearer' ? 'Authorization' : element('credential-header-name').value.trim(),
      secret: element('credential-secret').value};
    element('credential-secret').value = '';
    await workspace.mutate('credentials', body, 'credential-form-status');
  });
  function render() {
    const catalog = workspace.state.catalog;
    element('credential-fields').disabled = !workspace.ready('credentials');
    if (!catalog) { element('credential-secret').value = ''; return; }
    renderCards('credentials-list', catalog.credentials.map(credential => {
      const google = credential.auth_type === 'google_oauth';
      const badge = credential.status === 'quarantined' ? 'Quarantined · unusable' : credential.status === 'active' ? 'Saved' : 'Revoked locally';
      const card = resourceCard(credential, badge,
        [['Authentication', google ? 'Google account (OAuth)' : credential.auth_type === 'bearer' ? 'Bearer token' : credential.header_name],
          ...(google ? operatorGoogleAccountRows(credential, catalog) : []),
          ['Active rules', String(credential.active_rule_count)], ['Credential ID', credential.id]]);
      if (google) {
        card.dataset.credentialType = 'google_oauth';
        const notice = textNode('p', operatorGoogleAccountNotice(credential), 'small muted'); notice.dataset.googleAccountNotice = '';
        const details = textNode('details'); details.dataset.googleIdentity = ''; details.append(textNode('summary', 'Google identity details'));
        const identity = textNode('dl', undefined, 'metadata');
        const values = [['Provider subject', credential.provider_subject], ['OAuth client ID', credential.oauth_client_id]];
        if (credential.status === 'quarantined') values.push(['Quarantined at', credential.quarantined_at], ['Provider revocation', 'Not proven']);
        identity.append(...values.flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
        details.append(identity); card.append(notice, details);
        card.append(textNode('p', 'Google account removal requires provider-aware cleanup. This interface does not start consent or cleanup; ordinary credential revocation is not applicable.', 'small muted'));
      }
      if (credential.legacy_upstream_origin) card.append(textNode('p', 'Migrated credential remains limited to ' + credential.legacy_upstream_origin + '.', 'small muted'));
      if (credential.status === 'active' && !google) {
        const button = textNode('button', 'Revoke credential', 'secondary'); button.dataset.action = 'revoke-credential';
        button.disabled = workspace.state.busy || workspace.state.uncertain || credential.active_rule_count > 0;
        button.addEventListener('click', () => {
          if (!window.confirm(`Revoke locally stored credential "${credential.name}" (${credential.id})? This does not revoke the key at its provider.`)) return;
          workspace.mutate('credentials/revoke', {id: credential.id}, 'credential-action-status');
        }); card.append(button);
        if (credential.active_rule_count > 0) card.append(textNode('p', 'Revoke the referencing access rules first. Shared application identities are retained.', 'small muted'));
      }
      return card;
    }), 'No saved credentials. Add a provider key above; no endpoint configuration is needed.');
  }
  window.addEventListener('pagehide', () => { element('credential-secret').value = ''; });
  workspace.subscribe(render); return {render};
}
function createAccessRulesView(workspace) {
  const form = element('access-rule-form');
  renderOperatorCompatibility('rule-compatibility-content');
  function renderSummary() {
    const catalog = workspace.state.catalog;
    const list = element('rule-effective-restrictions');
    if (!catalog) {
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
    const rows = operatorRuleRestrictions(draft);
    list.replaceChildren(...rows.flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
    renderOperatorCompatibility('rule-compatibility-content', draft);
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
      'Your client sends no provider credential header. Serverware adds the saved credential after authorizing the request.';
    if (!replacing) return;
    try { element('rule-credential-header').textContent = credentialHeaderTarget(credential); }
    catch (_) {
      element('rule-credential-header').textContent = 'This saved credential does not support dummy header replacement.';
      element('rule-placeholder').setCustomValidity('Choose a saved credential with a supported header target.');
    }
    element('rule-placeholder').placeholder = element('rule-credential-header').textContent === 'Authorization' ? 'Bearer SERVERWARE_DUMMY' : 'SERVERWARE_DUMMY';
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
      mode === 'unfiltered_json_or_empty_v1' ? 'Keeps bounded JSON success and error content unchanged, or an admitted empty HTTP 204. No response field list is needed. Destination, method and request restrictions still apply.' :
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
    try {
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
    const body = {name: element('rule-name').value.trim(), application_id: element('rule-application-id').value,
      credential_id: element('rule-credential-id').value, upstream_url: origin.replace(/\/$/, '') + path, methods,
      response_mode: responseMode, response_fields: responseFields,
      credential_input: credentialInput, query_keys: fieldLines('rule-query-keys'), allowed_headers: fieldLines('rule-allowed-headers')};
    if (credentialInput === 'replace_exact') body.placeholder = placeholder;
    try { Object.assign(body, operatorRequestBodyInput(element('rule-request-body-mode').value, fieldLines('rule-request-fields'), catalog, credential)); }
    catch (error) { element('access-rule-form-status').textContent = operatorMessage(error); return; }
    if (!operatorRuleSupported(body, catalog)) {
      element('access-rule-form-status').textContent = 'Choose supported content modes and active resources. Google permits only GET with no request body.'; return;
    }
    await workspace.mutate('access-rules', body, 'access-rule-form-status');
  });
  function render() {
    const catalog = workspace.state.catalog;
    const responseModes = availableResponseModes(catalog);
    const credentialInputModes = availableCredentialInputModes(catalog);
    element('access-rule-fields').disabled = !workspace.ready('access_rules') || !catalog?.credentials.some(item => item.status === 'active') ||
      !catalog?.applications.some(item => item.status === 'active') || !catalog?.allowed_upstreams.length || !responseModes.length || !credentialInputModes.length;
    if (!catalog) { renderResponseMode(); renderCredentialInput(); renderRequestBody(); renderSummary(); return; }
    chooseModeOptions('rule-response-mode', responseModes.map(mode => ({id: mode, name: operatorResponseModes[mode]})), 'No supported response mode available');
    renderResponseMode();
    chooseOptions('rule-application-id', catalog.applications.filter(item => item.status === 'active'), 'Create an application first');
    chooseOptions('rule-credential-id', catalog.credentials.filter(item => item.status === 'active'), 'Save a credential first');
    chooseOptions('rule-credential-input', credentialInputModes.map(mode => ({id: mode, name: operatorCredentialInputModes[mode]})), 'No supported credential input available');
    renderCredentialInput();
    renderRequestBody();
    chooseOptions('rule-upstream-origin', catalog.allowed_upstreams.map(origin => ({id: origin, name: origin})), 'No approved destination configured');
    renderSummary();
    renderCards('access-rules-list', catalog.access_rules.map(rule => {
      const application = catalog.applications.find(item => item.id === rule.application_id);
      const credential = catalog.credentials.find(item => item.id === rule.credential_id);
      const enforced = workspace.loaded() && rule.enforcement === (rule.status === 'revoked' ? 'revoked' : 'active');
      const badge = rule.status === 'revoked' ? enforced ? 'Revoked · enforced' : 'Revoked · enforcement pending' : enforced ? 'Active' : 'Saved · activation pending';
      const card = resourceCard(rule, badge, [['Application', application?.name || rule.application_id], ['Credential', credential?.name || rule.credential_id],
        ...operatorRuleCredentialRows(rule, credential), ...operatorRuleRestrictions(rule), ['Rule ID', rule.id]]);
      if (rule.status === 'active') {
        const button = textNode('button', 'Revoke access rule', 'secondary'); button.dataset.action = 'revoke-rule';
        button.disabled = workspace.state.busy || workspace.state.uncertain;
        button.addEventListener('click', () => {
          if (!window.confirm(`Revoke rule "${rule.name}" (${rule.id})? The application and saved credential remain. New requests are denied after the proxy loads the updated policy; already-dispatched requests cannot be recalled.`)) return;
          workspace.mutate('access-rules/revoke', {id: rule.id}, 'rule-action-status');
        }); card.append(button);
      }
      return card;
    }), 'No access rules. Saved credentials and applications alone grant no access.');
  }
  workspace.subscribe(render); return {render};
}
