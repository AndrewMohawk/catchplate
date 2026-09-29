"""Purpose-specific durable Setup controls; page state is never authority."""

OAUTH_SETUP_HTML = r"""
          <section id="native-setup-controls" class="stack" hidden>
            <h3>Controlled Setup OAuth</h3>
            <p class="hint">Create a draft Setup with a fresh passkey, then use the native consent form. Account activation needs a different credential owner and a new requester assertion. Policy, canary, enrollment and final Setup completion remain separate.</p>
            <button id="native-setup-create" type="button">Review draft + fresh passkey + create once</button>
            <label>Retained Setup ID <input id="native-setup-session" maxlength="36" autocomplete="off"></label>
            <button id="native-setup-inspect" type="button" class="secondary">Inspect retained session only</button>
            <label>Staged pending credential ID <input id="native-setup-pending" maxlength="36" autocomplete="off"></label>
            <button id="native-setup-account" type="button" class="secondary">Inspect exact staged account</button>
            <pre id="native-setup-review">No current Setup original.</pre>
            <label><input id="native-setup-confirm" type="checkbox">I reviewed the account, scopes, application, session, owner and original expiry.</label>
            <label>Matching approval ID <input id="native-setup-approval" maxlength="64" autocomplete="off"></label>
            <button id="native-setup-request" type="button">Fresh requester passkey + request approval once</button>
            <button id="native-setup-decide" type="button">Distinct approver passkey + approve once</button>
            <button id="native-setup-activate" type="button">New requester passkey + activate once</button>
            <label>Retained Setup event ID <input id="native-setup-event" maxlength="36" autocomplete="off"></label>
            <button id="native-setup-settle" type="button" class="secondary">Settle completed audit row only</button>
            <p id="native-setup-status" class="hint" role="status" aria-live="polite">An uncertain submission is not retried. Keep the nonsecret session, pending, approval and event IDs for read-only inspection.</p>
          </section>
"""

OAUTH_SETUP_SCRIPT = r"""
    const nativeSetupSchema = 'serverware.oauthSetupApprovalOptions/v1';
    let nativeSetupHeld = null, nativeSetupBusy = false, nativeSetupCreateSpent = false;
    const nativeSetupAttempts = new Set();
    const nativeSetupId = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
    function nativeSetupMessage(text) { $('native-setup-status').textContent = text; }
    function nativeSetupBinding(value) {
      oauthConsentNeed(oauthConsentClosed(value, ['sessionId', 'revision', 'rowSha256', 'ownerId', 'currentAssigneeId', 'expiresAtEpochNs'])
        && nativeSetupId(value.sessionId) && oauthConsentDigest(value.rowSha256) && oauthConsentText(value.ownerId, 512)
        && (value.currentAssigneeId === null || oauthConsentText(value.currentAssigneeId, 512))
        && oauthConsentInteger(value.revision) <= 9223372036854775803n && oauthConsentInteger(value.expiresAtEpochNs) > 0n);
      return value;
    }
    function nativeSetupRemember(original) {
      const row = oauthConsentParse(original, 65536).value;
      oauthConsentNeed(nativeSetupId(row.id) && oauthConsentInteger(row.revision) <= 3n && typeof row.phase === 'string');
      const session = {};
      for (const [key, value] of Object.entries(row)) {
        session[key.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] = value instanceof OAuthConsentNumber ? Number(oauthConsentInteger(value)) : value;
      }
      rememberSetupSession(session); state.oauthSetupSessionId = row.id;
      $('native-setup-session').value = row.id;
      saveOAuthDraft(); renderSetupWorkflow(); return session;
    }
    async function nativeSetupFetch(path, body, operation, sent = null) {
      oauthConsentNeed(/^\/api\/setup\/oauth\/(?:sessions\/[0-9a-f-]{36}\/original|pending\/[0-9a-f-]{36}\/(?:activation-original|activate)|activation\/options)$/.test(path)
        || /^\/api\/control-plane\/approvals\/[A-Za-z0-9_-]{1,64}\/approve$/.test(path));
      const headers = {}; let original = null;
      if (body !== null) {
        const reply = await oauthConsentRequest('/api/csrf', null, operation);
        oauthConsentNeed(reply.status === 200 && reply.value.ok === true && reply.value.header === 'X-Serverware-CSRF-Token');
        headers['Content-Type'] = 'application/json'; headers[reply.value.header] = reply.value.token;
        original = oauthConsentCanonical(body); oauthConsentNeed(new TextEncoder().encode(original).length <= 196608);
      }
      operation.current(); if (sent) sent();
      const response = await fetch(path, {method: body === null ? 'GET' : 'POST', headers, body: original, credentials: 'same-origin',
        mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: operation.signal});
      const parsed = await oauthConsentRead(response, 1024 * 1024, operation);
      return {status: response.status, value: parsed.value};
    }
    async function nativeSetupPasskey(options, operation) {
      const key = options.publicKey;
      oauthConsentNeed(oauthConsentClosed(options, ['publicKey', 'serverware']) && key?.rpId === location.hostname
        && key.userVerification === 'required' && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
        && key.allowCredentials[0].type === 'public-key' && Date.parse(options.serverware.expiresAt) > Date.now());
      const timeout = oauthConsentInteger(key.timeout); oauthConsentNeed(timeout === 30000n || timeout === 120000n);
      const prepared = {publicKey: {...key, timeout: Number(timeout)}};
      const credential = await navigator.credentials.get({signal: operation.signal,
        publicKey: prepareRequestOptions(prepared)});
      operation.current(); oauthConsentNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.rawId.byteLength <= 3072 && credential.id === key.allowCredentials[0].id && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential); workloadIssuanceAssertionOriginal(assertion, prepared); return assertion;
    }
    async function nativeSetupCreate() {
      oauthConsentNeed(!nativeSetupBusy && !nativeSetupCreateSpent);
      const selection = currentSetupSelection(), provider = policyTemplates[selection.template]?.provider;
      oauthConsentNeed((state.oauthProviders || []).some(item => item.id === provider && item.consentProfile === nativeOAuthSetupSchema));
      let operation = null, assertion = null;
      try {
        operation = oauthConsentBegin(); nativeSetupBusy = true; await oauthConsentCookie(operation);
        const draft = await nativeOAuthRequest('/api/setup/oauth/create/draft', {provider, templateId: selection.template || null,
          principalId: selection.principalId || null, routeId: selection.routeId || null, expiresInSeconds: 3600}, operation);
        const args = draft.arguments, binding = args?.request;
        oauthConsentNeed(draft.apiVersion === 'serverware.oauthSetupCreate/v1' && draft.okForAction === false
          && args.action === 'credential.oauth.setup-create' && args.actor_id === operation.actor && args.approval_id === null
          && nativeSetupId(binding?.sessionId) && args.resource_id === binding.sessionId && binding.providerId === provider
          && binding.routePolicyDigest === null && args.payload_digest === await nativeOAuthHash(binding));
        $('native-setup-session').value = binding.sessionId;
        nativeSetupMessage('Draft session ' + binding.sessionId + '; this ID is only a recovery hint until committed.');
        oauthConsentNeed(window.confirm('Create draft Setup ' + binding.sessionId + '\nOwner: ' + operation.actor
          + '\nProvider: ' + provider + '\nTemplate: ' + selection.template + '\nPrincipal: ' + selection.principalId
          + '\nRoute: ' + selection.routeId + '\nThis does not authorize a policy or complete Setup.'));
        operation.current(); const schema = 'serverware.oauthSetupCreateOptions/v1';
        const options = await nativeOAuthRequest('/api/setup/oauth/create/options', {apiVersion: schema, arguments: args}, operation);
        oauthConsentNeed(options.serverware.schema === schema && options.serverware.operation === 'oauth.setup.create'
          && options.serverware.payloadDigest === args.payload_digest);
        assertion = await nativeSetupPasskey(options, operation); await oauthConsentCookie(operation);
        const result = await nativeOAuthRequest('/api/setup/oauth/create', {apiVersion: schema, arguments: args,
          mfa: {oauthSetupProfile: schema, assertion}}, operation, () => {nativeSetupCreateSpent = true;});
        oauthConsentNeed(result.ok === true && result.operation === 'oauth.setup.create' && result.auditState === 'controlled_pending'
          && typeof result.setupOriginal === 'string' && nativeSetupId(result.setupEventId));
        operation.current(); operation.close(); operation = null;
        const session = nativeSetupRemember(result.setupOriginal); oauthConsentNeed(session.id === binding.sessionId && session.phase === 'created' && session.revision === 0);
        $('native-setup-event').value = result.setupEventId;
        nativeSetupMessage('Draft committed. Audit remains pending. Use native consent; later Setup completion is not claimed.'); return session;
      } catch (error) {nativeSetupMessage(nativeSetupCreateSpent ? 'Create was submitted; outcome may be unknown. Inspect the retained session ID. Do not recreate automatically.' : 'Draft or passkey did not complete. No create was sent.'); throw error;}
      finally {assertion = null; operation?.close(); nativeSetupBusy = false;}
    }
    async function nativeSetupInspect(account = false) {
      let operation = null;
      try {
        oauthConsentNeed(!nativeSetupBusy); operation = oauthConsentBegin(); nativeSetupBusy = true; await oauthConsentCookie(operation);
        const id = $(account ? 'native-setup-pending' : 'native-setup-session').value.trim(); oauthConsentNeed(nativeSetupId(id));
        const reply = await nativeSetupFetch(account ? '/api/setup/oauth/pending/' + id + '/activation-original' : '/api/setup/oauth/sessions/' + id + '/original', null, operation);
        oauthConsentNeed(reply.status === 200); const value = reply.value;
        if (account) {
          oauthConsentNeed(value.apiVersion === 'serverware.oauthSetupActivationOriginal/v1' && value.action === 'credential.oauth.setup-activate'
            && value.resourceId === id && oauthConsentDigest(value.payloadDigest) && oauthConsentText(value.requesterId, 512));
          const bound = nativeSetupBinding(value.request?.setupBinding);
          oauthConsentNeed(bound.ownerId === value.requesterId && oauthConsentInteger(bound.revision) === 2n
            && value.request.pendingCredentialId === id && value.request.payloadDigest === value.payloadDigest
            && oauthConsentDigest(value.request.pendingRowSha256) && oauthConsentDigest(value.request.enrollmentSha256)
            && (state.oauthProviders || []).some(p => p.id === value.review?.provider && p.consentProfile === nativeOAuthSetupSchema)
            && BigInt(Date.now()) * 1000000n < oauthConsentInteger(bound.expiresAtEpochNs));
          nativeSetupHeld = {value, original: oauthConsentCanonical(value), scope: sessionActivationAuthScope()};
          $('native-setup-confirm').checked = false;
          $('native-setup-review').textContent = oauthConsentCanonical(value);
        } else {
          oauthConsentNeed(value.apiVersion === 'serverware.oauthSetupObservation/v1' && value.okForAction === false && value.completionClaimed === false);
          $('native-setup-review').textContent = oauthConsentCanonical(value);
          operation.current(); operation.close(); operation = null; nativeSetupRemember(value.setupOriginal);
        }
        nativeSetupMessage('Read-only original observed. This grants no retry, activation or completion.');
      } catch (_) {nativeSetupHeld = null; nativeSetupMessage('Observation unavailable or changed. Missing state is unknown, not successful completion.');}
      finally {operation?.close(); nativeSetupBusy = false;}
    }
    async function nativeSetupActivation(phase) {
      let operation = null, assertion = null, sent = false;
      try {
        const held = nativeSetupHeld; oauthConsentNeed(held && !nativeSetupBusy && $('native-setup-confirm').checked);
        operation = oauthConsentBegin(); nativeSetupBusy = true; const value = held.value, bound = value.request.setupBinding;
        const approval = $('native-setup-approval').value.trim(), key = phase + ':' + value.resourceId + ':' + approval;
        const current = () => {operation.current(); oauthConsentNeed(held === nativeSetupHeld && held.scope === sessionActivationAuthScope()
          && held.original === oauthConsentCanonical(value) && BigInt(Date.now()) * 1000000n < oauthConsentInteger(bound.expiresAtEpochNs));};
        current(); oauthConsentNeed(!nativeSetupAttempts.has(key) && ['request', 'decide', 'activate'].includes(phase)
          && (phase === 'request' ? approval === '' : /^[A-Za-z0-9_-]{1,64}$/.test(approval))
          && (phase === 'decide' ? value.requesterId !== operation.actor : value.requesterId === operation.actor));
        await oauthConsentCookie(operation);
        const request = {apiVersion: nativeSetupSchema, action: value.action, resourceId: value.resourceId,
          payloadDigest: value.payloadDigest, request: value.request, approvalId: phase === 'request' ? null : approval};
        const optionsReply = await nativeSetupFetch('/api/setup/oauth/activation/options', request, {...operation, current});
        const options = optionsReply.value, expected = {request: 'oauth.setup.activation-request', decide: 'oauth.setup.activation-decide', activate: 'oauth.setup.activate'}[phase];
        oauthConsentNeed(optionsReply.status === 200 && options.serverware?.schema === nativeSetupSchema
          && options.serverware.operation === expected && options.serverware.payloadDigest === value.payloadDigest);
        assertion = await nativeSetupPasskey(options, {...operation, current}); await oauthConsentCookie(operation); current();
        const mfa = {oauthActivationProfile: nativeSetupSchema, assertion}; if (phase === 'activate') mfa.approvalId = approval;
        const body = phase === 'decide' ? {note: null, mfa} : {mfa, setupSessionId: bound.sessionId, setupRevision: bound.revision};
        const reply = await nativeSetupFetch(phase === 'decide' ? '/api/control-plane/approvals/' + approval + '/approve' :
          '/api/setup/oauth/pending/' + value.resourceId + '/activate', body, {...operation, current}, () => {nativeSetupAttempts.add(key); sent = true;});
        if (phase === 'request') {
          const detail = reply.value.detail; oauthConsentNeed(reply.status === 428 && detail?.error === 'control_plane_approval_required'
            && detail.action === value.action && detail.resourceId === value.resourceId && detail.payloadDigest === value.payloadDigest
            && /^[A-Za-z0-9_-]{1,64}$/.test(detail.approvalId));
          $('native-setup-approval').value = detail.approvalId; nativeSetupMessage('Approval requested. A different credential owner must inspect and approve.');
        } else if (phase === 'decide') {
          oauthConsentNeed(reply.status === 200 && reply.value.id === approval && reply.value.action === value.action
            && reply.value.status === 'approved' && reply.value.approved_by === operation.actor);
          nativeSetupMessage('Distinct-person approval recorded. Requester still needs a new passkey and one activation submission.');
        } else {
          oauthConsentNeed(reply.status === 200 && reply.value.ok === true && reply.value.credential?.id === value.resourceId
            && reply.value.auditState === 'controlled_pending' && nativeSetupId(reply.value.setupEventId));
          current(); operation.close(); operation = null; nativeSetupRemember(reply.value.setupOriginal);
          $('native-setup-event').value = reply.value.setupEventId; nativeSetupHeld = null;
          nativeSetupMessage('Credential and Setup activation committed; audit pending. Policy and final Setup completion remain separate.');
        }
      } catch (_) {nativeSetupHeld = null; nativeSetupMessage(sent ? 'Submission outcome is uncertain. Keep its IDs and inspect; no retry was authorized.' : 'Approval context or passkey did not complete. No effect submission was sent.');}
      finally {assertion = null; operation?.close(); nativeSetupBusy = false;}
    }
    async function nativeSetupSettle() {
      let operation = null;
      try {
        const id = $('native-setup-event').value.trim(); oauthConsentNeed(nativeSetupId(id) && !nativeSetupBusy && !nativeSetupAttempts.has('settle:' + id));
        operation = oauthConsentBegin(); nativeSetupBusy = true; await oauthConsentCookie(operation);
        const result = await nativeOAuthRequest('/api/setup/oauth/audit-settle', {eventId: id}, operation, () => nativeSetupAttempts.add('settle:' + id));
        oauthConsentNeed(result.ok === true && result.eventId === id && result.auditState === 'audited');
        nativeSetupMessage('This event observed its completed authenticated audit row. This is not final Setup completion.');
      } catch (_) {nativeSetupMessage('Audit settle unavailable or uncertain. Inspect the retained event; no automatic resubmission.');}
      finally {operation?.close(); nativeSetupBusy = false;}
    }
    function renderNativeSetup() {
      const selected = (state.oauthProviders || []).some(p => p.consentProfile === nativeOAuthSetupSchema);
      $('native-setup-controls').hidden = !selected;
      if (nativeSetupHeld && nativeSetupHeld.scope !== sessionActivationAuthScope()) nativeSetupHeld = null;
      $('native-setup-create').disabled = nativeSetupBusy || nativeSetupCreateSpent;
    }
    function initNativeSetup() {
      $('native-setup-create').addEventListener('click', () => {void nativeSetupCreate().catch(() => {});});
      $('native-setup-inspect').addEventListener('click', () => {void nativeSetupInspect(false);});
      $('native-setup-account').addEventListener('click', () => {void nativeSetupInspect(true);});
      for (const phase of ['request', 'decide', 'activate']) $('native-setup-' + phase).addEventListener('click', () => {void nativeSetupActivation(phase);});
      $('native-setup-settle').addEventListener('click', () => {void nativeSetupSettle();});
      for (const id of ['native-setup-pending', 'native-setup-session']) $(id).addEventListener('input', () => {nativeSetupHeld = null;});
      const timer = setInterval(renderNativeSetup, 500);
      window.addEventListener('pagehide', () => {clearInterval(timer); nativeSetupHeld = null; nativeSetupCreateSpent = true;});
      renderNativeSetup();
    }
"""
