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
      const card = resourceCard(credential, credential.status === 'active' ? 'Saved' : 'Revoked locally',
        [['Authentication', credential.auth_type === 'bearer' ? 'Bearer token' : credential.header_name],
          ['Active rules', String(credential.active_rule_count)], ['Credential ID', credential.id]]);
      if (credential.legacy_upstream_origin) card.append(textNode('p', 'Migrated credential remains limited to ' + credential.legacy_upstream_origin + '.', 'small muted'));
      if (credential.status === 'active') {
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
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!workspace.ready('access_rules') || !form.reportValidity()) return;
    const catalog = workspace.state.catalog; const origin = element('rule-upstream-origin').value;
    const path = element('rule-path').value.trim();
    const methods = [...document.querySelectorAll('input[name="rule-method"]:checked')].map(input => input.value);
    if (!catalog.allowed_upstreams.includes(origin) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        !methods.length || methods.some(method => !operatorMethods.includes(method)) || !fieldLines('rule-response-fields').length) {
      element('access-rule-form-status').textContent = 'Choose an approved destination, exact path, supported method and explicit response fields.'; return;
    }
    const body = {name: element('rule-name').value.trim(), application_id: element('rule-application-id').value,
      credential_id: element('rule-credential-id').value, upstream_url: origin.replace(/\/$/, '') + path, methods,
      request_fields: fieldLines('rule-request-fields'), response_fields: fieldLines('rule-response-fields'),
      query_keys: fieldLines('rule-query-keys'), allowed_headers: fieldLines('rule-allowed-headers')};
    await workspace.mutate('access-rules', body, 'access-rule-form-status');
  });
  function render() {
    const catalog = workspace.state.catalog;
    element('access-rule-fields').disabled = !workspace.ready('access_rules') || !catalog?.credentials.some(item => item.status === 'active') ||
      !catalog?.applications.some(item => item.status === 'active') || !catalog?.allowed_upstreams.length;
    if (!catalog) return;
    chooseOptions('rule-application-id', catalog.applications.filter(item => item.status === 'active'), 'Create an application first');
    chooseOptions('rule-credential-id', catalog.credentials.filter(item => item.status === 'active'), 'Save a credential first');
    chooseOptions('rule-upstream-origin', catalog.allowed_upstreams.map(origin => ({id: origin, name: origin})), 'No approved destination configured');
    renderCards('access-rules-list', catalog.access_rules.map(rule => {
      const application = catalog.applications.find(item => item.id === rule.application_id);
      const credential = catalog.credentials.find(item => item.id === rule.credential_id);
      const enforced = workspace.loaded() && rule.enforcement === (rule.status === 'revoked' ? 'revoked' : 'active');
      const badge = rule.status === 'revoked' ? enforced ? 'Revoked · enforced' : 'Revoked · enforcement pending' : enforced ? 'Active' : 'Saved · activation pending';
      const card = resourceCard(rule, badge, [['Application', application?.name || rule.application_id], ['Credential', credential?.name || rule.credential_id],
        ['Exact URL', rule.upstream_url], ['Methods', rule.methods.join(', ')], ['Response fields', rule.response_fields.join(', ')], ['Rule ID', rule.id]]);
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
