// One versioned catalog for common API connections. Descriptors are public
// configuration, never credentials, provider verification or automatic grants.
function projectCommonAppsCapability(value) {
  if (value == null) return null;
  const text = item => typeof item === 'string' && item.length > 0 && item.length <= 8192;
  const names = items => Array.isArray(items) && items.length <= 64 && items.every(text);
  if (value.schema !== 'serverware.operatorCommonApps/v1' ||
      value.create_credential_path !== '/api/operator-demo/credentials' ||
      value.create_rule_path !== '/api/operator-demo/access-rules/common-app' ||
      !Array.isArray(value.presets) || value.presets.length > 64) return null;
  const ids = new Set();
  for (const preset of value.presets) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(preset?.id || '') || ids.has(preset.id) ||
        !['label', 'description', 'header_name', 'secret_label', 'secret_hint', 'sdk_auth_token', 'placeholder'].every(key => text(preset[key])) ||
        !['bearer', 'header'].includes(preset.auth_type) || typeof preset.destination_allowed !== 'boolean' ||
        !Array.isArray(preset.operations) || !preset.operations.length || preset.operations.length > 32) return null;
    ids.add(preset.id); const operations = new Set();
    for (const operation of preset.operations) {
      if (!/^[a-z][a-z0-9_]{0,95}$/.test(operation?.id || '') || operations.has(operation.id) ||
          !['label', 'description', 'origin', 'path_template', 'placeholder'].every(key => text(operation[key])) ||
          !operation.path_template.startsWith('/') || operation.path_template.startsWith('//') || /[?#\\\s]/.test(operation.path_template) ||
          !['methods', 'request_fields', 'query_keys', 'allowed_headers'].every(key => names(operation[key])) ||
          !operation.methods.length || operation.methods.some(method => !operatorMethods.includes(method)) ||
          operation.response_mode !== 'unfiltered_json_or_empty_v2' || operation.credential_input !== 'replace_exact' ||
          operation.placeholder !== preset.placeholder || !Array.isArray(operation.scope_fields) || operation.scope_fields.length > 16 ||
          Object.hasOwn(operation, 'available_for_creation') && typeof operation.available_for_creation !== 'boolean' ||
          Object.hasOwn(operation, 'request_body_mode') && operation.request_body_mode !== 'preserve_json_v1') return null;
      try { const origin = new URL(operation.origin); if (origin.protocol !== 'https:' || origin.origin !== operation.origin || origin.username || origin.password) return null; }
      catch (_) { return null; }
      const keys = new Set();
      for (const field of operation.scope_fields) {
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(field?.key || '') || keys.has(field.key) || !text(field.label) ||
            !['text', 'number'].includes(field.type) || field.required !== true ||
            field.pattern !== undefined && (typeof field.pattern !== 'string' || field.pattern.length > 512)) return null;
        keys.add(field.key);
      }
      operations.add(operation.id);
    }
  }
  return JSON.parse(JSON.stringify(value));
}
function commonAppPreset(catalog, id) { return catalog?.capabilities?.common_apps?.presets.find(item => item.id === id) || null; }
// Hide retired creation profiles without removing saved-rule descriptors.
function commonAppCreationOperations(preset) { return (preset?.operations || []).filter(item => item.available_for_creation !== false); }
function commonAppOperation(catalog, rule) { return commonAppPreset(catalog, rule?.app_preset)?.operations.find(item => item.id === rule.app_operation) || null; }
function commonAppAvailable(catalog, credential, operationId) {
  const preset = commonAppPreset(catalog, credential?.app_preset);
  return Boolean(preset && credential?.status === 'active' && !credential.connection_type &&
    credential.auth_type === preset.auth_type && credential.header_name === preset.header_name &&
    preset.operations.some(item => (!operationId || item.id === operationId) && catalog.allowed_upstreams.includes(item.origin)) &&
    availableResponseModes(catalog).includes('unfiltered_json_or_empty_v2') && availableCredentialInputModes(catalog).includes('replace_exact'));
}
function commonAppScope(operation, values) {
  if (!values || typeof values !== 'object' || Array.isArray(values) ||
      !operatorExact(Object.keys(values).sort(), operation.scope_fields.map(field => field.key).sort()))
    throw operatorError('Enter every scope for the selected permission.');
  const result = {};
  for (const field of operation.scope_fields) {
    const value = values[field.key];
    if (field.type === 'number' ? !Number.isSafeInteger(value) || field.min !== undefined && value < field.min || field.max !== undefined && value > field.max :
        typeof value !== 'string' || !value || value.length > 1024 || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value) || field.pattern && !new RegExp(field.pattern).test(value))
      throw operatorError('Enter a valid ' + field.label.toLowerCase() + '.');
    result[field.key] = value;
  }
  return result;
}
function commonAppRuleFields(preset, operationId, values) {
  const operation = preset?.operations.find(item => item.id === operationId);
  if (!operation) throw operatorError('Choose an advertised app permission.');
  const scope = commonAppScope(operation, values);
  const path = operation.path_template.replace(/\{([a-z][a-z0-9_]*)\}/g, (_, key) => {
    if (!Object.hasOwn(scope, key)) throw operatorError('The permission scope is incomplete.');
    return encodeURIComponent(scope[key]);
  });
  if (/[{}]/.test(path)) throw operatorError('The permission path is unsupported.');
  return {app_preset: preset.id, app_operation: operation.id, scope,
    upstream_url: operation.origin + path, methods: [...operation.methods], request_fields: [...operation.request_fields],
    response_fields: [], query_keys: [...operation.query_keys], allowed_headers: [...operation.allowed_headers],
    response_mode: operation.response_mode, credential_input: 'replace_exact', placeholder: operation.placeholder,
    ...(Object.hasOwn(operation, 'request_body_mode') ? {request_body_mode: operation.request_body_mode} : {})};
}
function commonAppRuleValid(rule, credential, catalog) {
  try {
    const preset = commonAppPreset(catalog, rule?.app_preset);
    if (!preset || credential?.app_preset !== preset.id || credential.connection_type ||
        credential.auth_type !== preset.auth_type || credential.header_name !== preset.header_name || Object.hasOwn(rule, 'operation_bundle')) return false;
    const expected = commonAppRuleFields(preset, rule.app_operation, rule.scope);
    return Object.entries(expected).every(([key, value]) => operatorExact(rule[key], value)) &&
      Object.hasOwn(rule, 'request_body_mode') === Object.hasOwn(expected, 'request_body_mode');
  } catch (_) { return false; }
}
function commonAppRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    app_preset: rule.app_preset, operation: rule.app_operation, scope: {...rule.scope}};
}
function commonAppScopeInputs(operation) {
  return Object.fromEntries(operation.scope_fields.map(field => {
    const value = element('connect-common-scope-' + field.key).value;
    return [field.key, field.type === 'number' && value !== '' ? Number(value) : value.trim()];
  }));
}
function renderCommonAppScopes(preset, operation, active) {
  const panel = element('connect-common-scopes'); const signature = JSON.stringify([preset?.id, operation]);
  if (panel.dataset.signature !== signature) {
    panel.replaceChildren(); panel.dataset.signature = signature;
    for (const field of operation?.scope_fields || []) {
      const id = 'connect-common-scope-' + field.key;
      const label = textNode('label', field.label); label.htmlFor = id;
      const input = textNode('input'); input.id = id; input.type = field.type; input.required = true;
      input.autocomplete = 'off'; input.spellcheck = false;
      if (field.type === 'text') input.maxLength = 1024;
      for (const key of ['pattern', 'min', 'max', 'placeholder']) if (field[key] !== undefined) input.setAttribute(key, String(field[key]));
      if (field.default !== undefined) input.value = String(field.default);
      panel.append(label, input);
    }
  }
  for (const input of panel.querySelectorAll('input')) input.disabled = !active;
}
function commonAppExample(value, scope) {
  if (Array.isArray(value)) return value.map(item => commonAppExample(item, scope));
  if (value && typeof value === 'object') {
    if (Object.keys(value).length === 1 && typeof value.$scope === 'string') {
      if (!Object.hasOwn(scope, value.$scope)) throw operatorError('The example scope is incomplete.');
      return scope[value.$scope];
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, commonAppExample(item, scope)]));
  }
  return value;
}
function commonAppRequest(rule, catalog) {
  const operation = commonAppOperation(catalog, rule);
  if (!operation) throw operatorError('This app permission is unavailable.');
  const credential = catalog.credentials.find(item => item.id === rule.credential_id);
  const dummy = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
  return {headers: {...(operation.request_headers || {}), [dummy.name]: dummy.value},
    query: commonAppExample(operation.example_query || {}, rule.scope),
    body: operation.example_body == null ? null : commonAppExample(operation.example_body, rule.scope)};
}
function commonAppRuleRestrictions(rule) {
  return [['App permission', rule.name || rule.app_preset + ' · ' + rule.app_operation],
    ['Exact destination', rule.methods.join(', ') + ' ' + rule.upstream_url],
    ['Enforced scope', Object.entries(rule.scope || {}).map(([key, value]) => key + ': ' + value).join(' · ') || 'Exact endpoint only'],
    ['Request fields', rule.request_fields.length ? rule.request_fields.join(', ') : 'No request body'],
    ['Compatibility', 'Buffered JSON only. No streaming, files, arbitrary endpoints or automatic retries. Provider account permissions still apply.']];
}
function commonAppCurlCommand(options, rule, catalog) {
  const request = commonAppRequest(rule, catalog);
  const query = Object.entries(request.query).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value)).join('&');
  let result = buildCurlCommand({...options, upstreamUrl: options.upstreamUrl + (query ? '?' + query : '')});
  const quoted = value => "'" + value.replace(/'/g, "'\\''") + "'";
  for (const [name, value] of Object.entries(request.headers)) {
    if (name.toLowerCase() === options.credential.header_name.toLowerCase()) continue;
    result += ' \\\n  --header ' + quoted(name + ': ' + value);
  }
  if (request.body !== null) result += ' \\\n  --header \'Content-Type: application/json\' \\\n  --data-binary ' + quoted(JSON.stringify(request.body));
  return '# Review the request below before running. It may create data or incur charges.\n' + result;
}
