"""Cookie-only portal for the enrolled new-credential activation ceremony.

These controls retain display data and page-local attempt locks, not authority.
The controlled backend owns hardware authentication, distinct-person approval,
exact pending originals and atomic credential publication.
"""

OAUTH_ACTIVATION_HTML = r"""
          <section id="oauth-activation-workspace" class="stack" hidden>
            <h3>Review and activate an enrolled account</h3>
            <p id="oauth-activation-auth" class="hint"></p>
            <label for="oauth-activation-target">Pending credential ID</label>
            <input id="oauth-activation-target" maxlength="36" autocomplete="off" spellcheck="false">
            <button id="oauth-activation-inspect" type="button" class="secondary">Inspect exact account</button>
            <pre id="oauth-activation-review">No account inspected.</pre>
            <label><input id="oauth-activation-confirm" type="checkbox">I checked this account, application and every requested scope.</label>
            <button id="oauth-activation-request" type="button" disabled>Fresh passkey · request approval</button>
            <label for="oauth-activation-approval">Existing matching approval</label>
            <select id="oauth-activation-approval"><option value="">Inspect an account first</option></select>
            <p id="oauth-activation-pending" class="hint"></p>
            <button id="oauth-activation-continue" type="button" disabled>New requester passkey · activate once</button>
            <p id="oauth-activation-status" role="status" aria-live="polite"></p>
            <p class="hint">A different credential owner approves in the approval queue. Approval alone does not activate the account. Reloading or changing selection never grants permission to repeat an uncertain operation. No token plaintext, assertion or approval authority is saved in browser storage. Setup and reconnect are not supported by this profile.</p>
          </section>
"""

OAUTH_ACTIVATION_SCRIPT = r"""
    const oauthActivationAction = 'credential.oauth.activate';
    const oauthActivationProfile = 'serverware.oauthActivationApprovalOptions/v1';
    const oauthActivationOptionsPath = '/api/control-plane/mutations/webauthn/options';
    const oauthActivationApprovalFields = ['id', 'action', 'resource_id', 'payload_digest', 'status',
      'requester_id', 'requested_at', 'expires_at', 'approved_by', 'approved_at', 'consumed_by',
      'consumed_at', 'decision_note', 'approver_webauthn_credential_id', 'request'];
    let oauthActivationEpoch = 0, oauthActivationContext = null, oauthActivationSelected = null;
    let oauthActivationBusy = false, oauthActivationController = null, oauthActivationQueueView = null;
    const oauthActivationAttempts = new Set();
    const oauthActivationUnknown = new Set();
    const oauthActivationAcknowledgments = new Map();

    function oauthActivationNeed(ok) {
      if (!ok) throw new Error('Enrolled OAuth activation is blocked or its current context is unavailable. No automatic retry.');
    }
    function oauthActivationId(value) { return typeof value === 'string' && /^[0-9a-f-]{36}$/.test(value); }
    function oauthActivationApprovalId(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value); }
    function oauthActivationText(value, maximum = 4096) {
      return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && new TextEncoder().encode(value).byteLength <= maximum
        && !/[\u0000-\u001f\u007f-\u009f]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(value);
    }
    function oauthActivationExpiry(value) {
      oauthActivationNeed(oauthActivationText(value, 128) && /(?:Z|\+00:00)$/.test(value));
      const result = Date.parse(value);
      oauthActivationNeed(Number.isSafeInteger(result)); return result;
    }
    function oauthActivationActor() {
      const value = state.authStatus;
      oauthActivationNeed(enrolledOAuthProfile === 'enrolled-new-credential-v1' && !adminToken()
        && !oidcSessionStatusUnknown && window.isSecureContext && window.top === window
        && value?.authenticated === true && value.authMethod === 'oidc-session'
        && value.sessionState === 'active' && value.webauthnRequired === false
        && oauthActivationText(value.userId) && value.userId.startsWith('oidc:')
        && Array.isArray(value.roles) && value.roles.includes('credential_owner'));
      return value.userId;
    }
    function oauthActivationMessage(message, failed = false, report = true) {
      $('oauth-activation-status').textContent = message;
      $('oauth-activation-status').setAttribute('role', failed ? 'alert' : 'status');
      if (report) setStatus(message, failed ? 'error' : '');
    }
    function oauthActivationInvalidate(reason = 'Selection or authorization context changed.') {
      oauthActivationEpoch += 1;
      oauthActivationController?.abort();
      oauthActivationSelected = null;
      oauthActivationContext = sessionActivationAuthScope();
      $('oauth-activation-confirm').checked = false;
      $('oauth-activation-review').textContent = 'No current account inspection.';
      oauthActivationMessage(reason + ' Inspect again explicitly; page attempt locks remain.', false, false);
      renderOAuthActivation();
    }
    function oauthActivationBinding(value) {
      oauthActivationNeed(workloadIssuanceClosed(value, ['pendingCredentialId', 'pendingRowSha256', 'enrollmentSha256', 'payloadDigest'])
        && oauthActivationId(value.pendingCredentialId)
        && ['pendingRowSha256', 'enrollmentSha256', 'payloadDigest'].every(key => workloadIssuanceDigest(value[key])));
      return value;
    }
    function oauthActivationReviewBinding(value) {
      try { return {...oauthActivationBinding(value)}; }
      catch (_) { return {blocked: 'Exact enrolled activation binding unavailable.'}; }
    }
    function oauthActivationOriginal(reply, id) {
      const value = reply.value;
      oauthActivationNeed(reply.status === 200 && workloadIssuanceClosed(value,
        ['apiVersion', 'action', 'resourceId', 'payloadDigest', 'request', 'review', 'requesterId', 'expiresAt'])
        && value.apiVersion === 'serverware.oauthActivationOriginal/v1' && value.action === oauthActivationAction
        && value.resourceId === id && oauthActivationText(value.requesterId) && value.requesterId.startsWith('oidc:')
        && oauthActivationExpiry(value.expiresAt) > Date.now());
      const binding = oauthActivationBinding(value.request), review = value.review;
      oauthActivationNeed(binding.pendingCredentialId === id && binding.payloadDigest === value.payloadDigest);
      const fields = ['credential_type', 'provider', 'provider_subject', 'provider_account', 'scopes',
        'credential_name', 'metadata_keys', 'expires_at_epoch_ms', 'oauth_application_owner'];
      if (review?.provider === 'x') fields.push('x_app_id');
      oauthActivationNeed(workloadIssuanceClosed(review, fields) && review.credential_type === 'oauth2'
        && ['google', 'x'].includes(review.provider)
        && ['provider_subject', 'provider_account', 'credential_name'].every(key => oauthActivationText(review[key]))
        && Array.isArray(review.scopes) && review.scopes.length <= 256
        && review.scopes.every(scope => oauthActivationText(scope, 2048))
        && new Set(review.scopes).size === review.scopes.length
        && Array.isArray(review.metadata_keys) && review.metadata_keys.length <= 256
        && review.metadata_keys.every(key => oauthActivationText(key, 512))
        && (review.expires_at_epoch_ms === null || Number.isSafeInteger(review.expires_at_epoch_ms))
        && (review.provider !== 'x' || oauthActivationText(review.x_app_id, 2048)));
      const owner = review.oauth_application_owner;
      oauthActivationNeed(owner && owner.enrollmentSha256 === binding.enrollmentSha256
        && owner.providerId === review.provider && ['applicationId', 'deploymentId', 'clientId'].every(key => oauthActivationText(owner[key])));
      return value;
    }
    function oauthActivationSummary(original) {
      const review = original.review, owner = review.oauth_application_owner;
      return 'Credential: ' + original.resourceId + '\nName: ' + review.credential_name
        + '\nProvider: ' + review.provider + '\nAccount: ' + review.provider_account
        + '\nSubject: ' + review.provider_subject + '\nApplication: ' + owner.applicationId
        + '\nDeployment: ' + owner.deploymentId + '\nClient: ' + owner.clientId
        + '\nScopes:\n' + review.scopes.map(scope => '  ' + scope).join('\n')
        + '\nRequester: ' + original.requesterId + '\nPending row: ' + original.request.pendingRowSha256
        + '\nEnrollment: ' + original.request.enrollmentSha256 + '\nPayload: ' + original.payloadDigest
        + '\nPending expires: ' + original.expiresAt;
    }
    function oauthActivationApproval(row, original, status, queue = false) {
      const fields = queue ? [...oauthActivationApprovalFields, 'required_approver_roles', 'can_approve',
        'can_deny', 'approve_block_reason', 'deny_block_reason'] : oauthActivationApprovalFields;
      oauthActivationNeed(workloadIssuanceClosed(row, fields) && oauthActivationApprovalId(row.id)
        && row.action === oauthActivationAction && row.resource_id === original.resourceId
        && row.payload_digest === original.payloadDigest && row.requester_id === original.requesterId
        && row.status === status && row.decision_note === null
        && workloadIssuanceCanonical(oauthActivationBinding(row.request)) === workloadIssuanceCanonical(original.request)
        && oauthActivationExpiry(row.expires_at) > Date.now()
        && oauthActivationExpiry(row.requested_at) <= Date.now());
      if (status === 'pending') oauthActivationNeed(row.approved_by === null && row.approved_at === null
        && row.approver_webauthn_credential_id === null);
      else oauthActivationNeed(['approved', 'consumed'].includes(status) && oauthActivationText(row.approved_by)
        && row.approved_by !== original.requesterId && oauthActivationText(row.approver_webauthn_credential_id)
        && oauthActivationExpiry(row.approved_at) <= Date.now());
      oauthActivationNeed(status === 'consumed'
        ? row.consumed_by === original.requesterId && oauthActivationExpiry(row.consumed_at) <= Date.now()
        : row.consumed_by === null && row.consumed_at === null);
      return row;
    }
    function oauthActivationMatching(original) {
      return (state.controlPlaneApprovals || []).filter(row => {
        try { oauthActivationNeed(['pending', 'approved'].includes(row.status));
          oauthActivationApproval(row, original, row.status, true); return true; } catch (_) { return false; }
      });
    }
    function oauthActivationKey(phase, original, actor, approvalId = '') {
      return JSON.stringify([phase, original.resourceId, actor, approvalId]);
    }
    function oauthActivationTargetKey(original, actor) { return JSON.stringify([original.resourceId, actor]); }
    function renderOAuthActivation() {
      if (!$('oauth-activation-workspace')) return;
      $('oauth-activation-workspace').hidden = enrolledOAuthProfile === 'development';
      const scope = sessionActivationAuthScope();
      if (oauthActivationContext !== null && oauthActivationContext !== scope) {
        oauthActivationInvalidate('Actor, policy or credential trust changed.'); return;
      }
      oauthActivationContext = scope;
      let actor = null;
      try { actor = oauthActivationActor(); } catch (_) {}
      const original = oauthActivationSelected;
      let live = false;
      try { live = original !== null && original.resourceId === $('oauth-activation-target').value.trim()
        && oauthActivationExpiry(original.expiresAt) > Date.now(); } catch (_) {}
      const rows = live ? oauthActivationMatching(original) : [];
      const previous = $('oauth-activation-approval').value;
      const view = JSON.stringify(rows.map(row => [row.id, row.status, row.expires_at]));
      if (view !== oauthActivationQueueView) {
        $('oauth-activation-approval').replaceChildren(new Option('Select an existing matching approval', ''),
          ...rows.map(row => new Option(row.id + ' · ' + row.status + ' · expires ' + row.expires_at, row.id)));
        if (rows.some(row => row.id === previous)) $('oauth-activation-approval').value = previous;
        oauthActivationQueueView = view;
      }
      const selected = rows.find(row => row.id === $('oauth-activation-approval').value);
      const known = original && actor ? oauthActivationAcknowledgments.get(oauthActivationKey('request', original, actor)) : null;
      $('oauth-activation-auth').textContent = adminToken()
        ? 'Blocked: clear the entered bearer credential yourself and refresh the actual OIDC cookie status.'
        : actor ? 'Cookie credential owner: ' + actor + '. Admin alone does not qualify.'
          : 'An active OIDC cookie with the literal credential_owner role is required. This enrolled profile must be available.';
      const blocked = oauthActivationBusy || !actor;
      $('oauth-activation-inspect').disabled = blocked;
      $('oauth-activation-target').disabled = oauthActivationBusy;
      $('oauth-activation-confirm').disabled = oauthActivationBusy || !live;
      $('oauth-activation-approval').disabled = oauthActivationBusy || !live;
      const uncertain = live && actor && oauthActivationUnknown.has(oauthActivationTargetKey(original, actor));
      const ready = !blocked && !uncertain && live && original.requesterId === actor && $('oauth-activation-confirm').checked;
      $('oauth-activation-request').disabled = !ready || rows.length > 0
        || oauthActivationAttempts.has(original && oauthActivationKey('request', original, actor));
      $('oauth-activation-continue').disabled = !ready || selected?.status !== 'approved'
        || oauthActivationAttempts.has(original && oauthActivationKey('activate', original, actor, selected?.id));
      $('oauth-activation-pending').textContent = uncertain
        ? 'A submitted operation for this account and actor is unknown. Read-only inspection does not unlock another attempt.'
        : selected
        ? 'Approval ' + selected.id + ': ' + selected.status + (selected.status === 'approved'
          ? '. Approved by ' + selected.approved_by + '. A NEW requester passkey is still required.'
          : '. A different credential owner must approve in the queue.')
        : known ? 'Approval request acknowledged: ' + known + '. Refresh the approval queue, then explicitly select it.'
          : 'After a reload, inspect this pending ID and explicitly select its matching approval from the refreshed queue. Missing queue data is not permission to repeat an unknown action.';
    }
    function oauthActivationBegin() {
      oauthActivationNeed(!oauthActivationBusy);
      const actor = oauthActivationActor(), epoch = oauthActivationEpoch, scope = sessionActivationAuthScope();
      const controller = new AbortController();
      let deadline = performance.now() + 120000, expires = Date.now() + 120000, lastWall = Date.now(), lastMono = performance.now();
      let timer = setTimeout(() => controller.abort(), 120000);
      oauthActivationBusy = true; oauthActivationController = controller;
      const current = () => {
        const wall = Date.now(), mono = performance.now();
        oauthActivationNeed(!controller.signal.aborted && wall >= lastWall && wall < expires
          && mono >= lastMono && mono < deadline && epoch === oauthActivationEpoch
          && scope === sessionActivationAuthScope() && actor === oauthActivationActor());
        lastWall = wall; lastMono = mono;
      };
      renderOAuthActivation();
      return {actor, current, signal: controller.signal, sent: false, definite: false, key: null, targetKey: null,
        clip(value) {
          current(); expires = Math.min(expires, oauthActivationExpiry(value));
          deadline = Math.min(deadline, performance.now() + expires - Date.now());
          clearTimeout(timer); timer = setTimeout(() => controller.abort(), Math.max(0, deadline - performance.now())); current();
        }, close() {
          clearTimeout(timer); oauthActivationBusy = false; oauthActivationController = null; renderOAuthActivation();
        }};
    }
    async function oauthActivationRequest(path, body, operation, dispatch = false) {
      const get = body === null;
      oauthActivationNeed(get ? ['/api/auth/status', '/api/csrf'].includes(path)
        || /^\/api\/oauth\/pending\/[0-9a-f-]{36}\/activation-original$/.test(path)
        : path === oauthActivationOptionsPath || /^\/api\/oauth\/pending\/[0-9a-f-]{36}\/activate$/.test(path)
        || /^\/api\/control-plane\/approvals\/[A-Za-z0-9_-]{1,64}\/approve$/.test(path));
      let original = get ? null : JSON.stringify(body), csrf = null;
      oauthActivationNeed(get || new TextEncoder().encode(original).byteLength <= 32 * 1024);
      if (!get) {
        const reply = await oauthActivationRequest('/api/csrf', null, operation), value = reply.value;
        oauthActivationNeed(reply.status === 200 && workloadIssuanceClosed(value, ['ok', 'token', 'cookie', 'header'])
          && value.ok === true && oauthActivationText(value.token, 1024)
          && value.cookie === 'serverware_csrf' && value.header === 'X-Serverware-CSRF-Token');
        csrf = value.token;
      }
      operation.current();
      const controller = new AbortController(), abort = () => controller.abort();
      operation.signal.addEventListener('abort', abort, {once: true});
      const timer = setTimeout(abort, 30000);
      let reader = null, complete = false;
      try {
        if (dispatch) {
          oauthActivationNeed(operation.key !== null && !oauthActivationAttempts.has(operation.key));
          oauthActivationAttempts.add(operation.key); operation.sent = true;
        }
        const response = await fetch(path, {method: get ? 'GET' : 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: controller.signal,
          headers: get ? {} : {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf}, body: original});
        operation.current();
        const maximum = path === '/api/csrf' ? 4096 : 64 * 1024;
        oauthActivationNeed(response instanceof Response && response.body
          && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
        const length = response.headers.get('Content-Length');
        oauthActivationNeed(length === null || /^[0-9]+$/.test(length) && Number(length) <= maximum);
        reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', {fatal: true});
        let text = '', size = 0;
        for (;;) {
          operation.current(); const item = await reader.read(); operation.current();
          oauthActivationNeed(!controller.signal.aborted);
          if (item.done) { complete = true; break; }
          size += item.value.byteLength; oauthActivationNeed(size <= maximum);
          text += decoder.decode(item.value, {stream: true});
        }
        text += decoder.decode();
        // All echoed bindings are strings. Numeric review/metadata is display
        // data only, never reserialized into a request or treated as authority.
        const value = workloadIssuanceJson(text, true);
        operation.current(); return {status: response.status, value};
      } finally {
        clearTimeout(timer); operation.signal.removeEventListener('abort', abort);
        if (reader) { if (!complete) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); }
        original = null; csrf = null;
      }
    }
    async function oauthActivationCookie(operation) {
      const reply = await oauthActivationRequest('/api/auth/status', null, operation), value = reply.value;
      oauthActivationNeed(reply.status === 200 && workloadIssuanceClosed(value, ['authenticated', 'userId', 'roles',
        'authMethod', 'sessionState', 'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode'])
        && value.authenticated === true && value.userId === operation.actor && value.authMethod === 'oidc-session'
        && value.sessionState === 'active' && value.webauthnRequired === false
        && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
        && value.sessionActivationMode === state.authStatus.sessionActivationMode
        && typeof value.oidcBrowserLoginConfigured === 'boolean' && Array.isArray(value.roles)
        && value.roles.length <= 64 && value.roles.every(role => oauthActivationText(role, 128))
        && value.roles.includes('credential_owner') && new Set(value.roles).size === value.roles.length
        && JSON.stringify([...value.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
      operation.current();
    }
    async function oauthActivationReadOriginal(id, operation) {
      oauthActivationNeed(oauthActivationId(id));
      const original = oauthActivationOriginal(await oauthActivationRequest('/api/oauth/pending/' + id + '/activation-original', null, operation), id);
      operation.clip(original.expiresAt); return original;
    }
    async function oauthActivationInspect(id = $('oauth-activation-target').value.trim()) {
      let operation = null;
      try {
        oauthActivationNeed(!oauthActivationBusy && oauthActivationId(id));
        oauthActivationInvalidate('Explicit account inspection.'); $('oauth-activation-target').value = id;
        operation = oauthActivationBegin(); await oauthActivationCookie(operation);
        const original = await oauthActivationReadOriginal(id, operation);
        await oauthActivationCookie(operation);
        oauthActivationSelected = original;
        $('oauth-activation-review').textContent = oauthActivationSummary(original);
        $('oauth-activation-workspace').scrollIntoView({block: 'nearest'});
        oauthActivationMessage('Read-only account inspection complete. Check every scope before requesting approval.');
      } catch (_) { oauthActivationMessage('Inspection unavailable. No activation request was sent.', true); }
      finally { operation?.close(); }
    }
    async function oauthActivationAssertion(original, approvalId, phase, operation) {
      const body = {apiVersion: oauthActivationProfile, action: oauthActivationAction,
        resourceId: original.resourceId, payloadDigest: original.payloadDigest, request: {...original.request}};
      if (approvalId !== null) body.approvalId = approvalId;
      await oauthActivationCookie(operation);
      const reply = await oauthActivationRequest(oauthActivationOptionsPath, body, operation), options = reply.value;
      oauthActivationNeed(reply.status === 200 && workloadIssuanceClosed(options, ['publicKey', 'serverware']));
      const key = options.publicKey, context = options.serverware;
      const expected = {request: 'oauth-activation-approval.request', decide: 'oauth-activation-approval.decide', activate: 'oauth.pending.activate'}[phase];
      oauthActivationNeed(expected && workloadIssuanceClosed(context, ['schema', 'operation', 'operationId', 'challengeId',
        'credentialRecordId', 'payloadDigest', 'expiresAt']) && context.schema === oauthActivationProfile
        && context.operation === expected && context.payloadDigest === original.payloadDigest
        && workloadIssuanceDigest(context.operationId) && workloadIssuanceDigest(context.challengeId)
        && oauthActivationText(context.credentialRecordId, 256)
        && workloadIssuanceClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && key.timeout === 120000 && key.userVerification === 'required' && oauthActivationText(key.rpId, 253)
        && (window.location.hostname === key.rpId || window.location.hostname.endsWith('.' + key.rpId))
        && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
        && workloadIssuanceClosed(key.allowCredentials[0], ['type', 'id']) && key.allowCredentials[0].type === 'public-key');
      workloadIssuanceBase64(key.challenge, 1024); workloadIssuanceBase64(key.allowCredentials[0].id, 3072);
      operation.clip(context.expiresAt); await oauthActivationCookie(operation);
      oauthActivationNeed(navigator.credentials && typeof navigator.credentials.get === 'function');
      const credential = await navigator.credentials.get({publicKey: prepareRequestOptions(JSON.parse(JSON.stringify(options))), signal: operation.signal});
      operation.current(); oauthActivationNeed(credential !== null);
      const assertion = credentialToJson(credential), bytes = workloadIssuanceAssertionOriginal(assertion, options);
      bytes.fill(0); // This does not promise erasure of browser-owned key/assertion memory.
      const mfa = {oauthActivationProfile, assertion};
      if (phase === 'activate') mfa.approvalId = approvalId;
      oauthActivationNeed(new TextEncoder().encode(JSON.stringify(mfa)).byteLength <= 16 * 1024);
      await oauthActivationCookie(operation); return mfa;
    }
    function oauthActivationFailure(operation) {
      if (operation?.sent && !operation.definite) {
        oauthActivationUnknown.add(operation.targetKey);
        oauthActivationMessage('A submitted operation has an unknown outcome. This page blocks another attempt. Inspect retained server state; do not reload to retry.', true);
      } else if (operation?.definite) {
        oauthActivationMessage('The operation was acknowledged. The current cookie could not be rechecked; refresh session status and inspect server state. Do not repeat the operation.', true);
      } else oauthActivationMessage('No activation action was sent. Current account, approval or passkey authorization was unavailable.', true);
    }
    async function oauthActivationRun(phase, approvalId = null, note = null) {
      let operation = null, mfa = null;
      try {
        oauthActivationNeed(['request', 'activate', 'decide'].includes(phase) && !oauthActivationBusy && note === null);
        let reviewed = oauthActivationSelected, queueRow = null;
        if (phase === 'decide') {
          oauthActivationNeed(oauthActivationApprovalId(approvalId));
          queueRow = (state.controlPlaneApprovals || []).find(row => row.id === approvalId);
          oauthActivationNeed(queueRow?.action === oauthActivationAction && oauthActivationId(queueRow.resource_id));
        } else oauthActivationNeed(reviewed && $('oauth-activation-confirm').checked
          && reviewed.resourceId === $('oauth-activation-target').value.trim());
        operation = oauthActivationBegin(); await oauthActivationCookie(operation);
        const original = await oauthActivationReadOriginal(queueRow ? queueRow.resource_id : reviewed.resourceId, operation);
        if (phase === 'decide') {
          oauthActivationApproval(queueRow, original, 'pending', true);
          oauthActivationNeed(original.requesterId !== operation.actor);
          operation.clip(queueRow.expires_at);
          oauthActivationNeed(window.confirm('Approve this exact enrolled account for the requester?\n\n'
            + oauthActivationSummary(original) + '\nApproval: ' + approvalId + '\nApproval expires: ' + queueRow.expires_at));
        } else {
          oauthActivationNeed(original.requesterId === operation.actor
            && workloadIssuanceCanonical(original) === workloadIssuanceCanonical(reviewed));
          if (phase === 'activate') {
            oauthActivationNeed(oauthActivationApprovalId(approvalId));
            const row = oauthActivationMatching(original).find(item => item.id === approvalId);
            oauthActivationApproval(row, original, 'approved', true); operation.clip(row.expires_at);
          } else oauthActivationNeed(oauthActivationMatching(original).length === 0);
        }
        operation.key = oauthActivationKey(phase, original, operation.actor, approvalId || '');
        operation.targetKey = oauthActivationTargetKey(original, operation.actor);
        oauthActivationNeed(!oauthActivationAttempts.has(operation.key) && !oauthActivationUnknown.has(operation.targetKey));
        mfa = await oauthActivationAssertion(original, approvalId, phase, operation);
        operation.current();
        const reply = await oauthActivationRequest(phase === 'decide'
          ? '/api/control-plane/approvals/' + approvalId + '/approve'
          : '/api/oauth/pending/' + original.resourceId + '/activate', phase === 'decide' ? {note: null, mfa} : {mfa}, operation, true);
        mfa = null;
        if (phase === 'request') {
          const value = reply.value, detail = value?.detail;
          oauthActivationNeed(reply.status === 428 && workloadIssuanceClosed(value, ['detail'])
            && workloadIssuanceClosed(detail, ['error', 'approvalId', 'status', 'action', 'resourceId', 'payloadDigest', 'expiresAt', 'retry'])
            && detail.error === 'control_plane_approval_required' && detail.status === 'pending'
            && detail.action === oauthActivationAction && detail.resourceId === original.resourceId
            && detail.payloadDigest === original.payloadDigest && oauthActivationApprovalId(detail.approvalId)
            && oauthActivationExpiry(detail.expiresAt) > Date.now()
            && workloadIssuanceClosed(detail.retry, ['mfa.approvalId']) && detail.retry['mfa.approvalId'] === detail.approvalId);
          operation.definite = true;
          oauthActivationAcknowledgments.set(operation.key, detail.approvalId);
          await oauthActivationCookie(operation);
          oauthActivationMessage('Approval request acknowledged: ' + detail.approvalId + '. A separate credential owner must approve. This is not activation.');
        } else if (phase === 'decide') {
          oauthActivationNeed(reply.status === 200);
          const row = oauthActivationApproval(reply.value, original, 'approved');
          oauthActivationNeed(row.id === approvalId && row.approved_by === operation.actor);
          operation.definite = true; await oauthActivationCookie(operation);
          oauthActivationMessage('Approval acknowledged. The requester must select this approval and explicitly activate with a NEW passkey.');
        } else {
          const value = reply.value;
          oauthActivationNeed(reply.status === 200 && workloadIssuanceClosed(value, ['ok', 'credential', 'approval']) && value.ok === true);
          const row = oauthActivationApproval(value.approval, original, 'consumed'), credential = value.credential;
          oauthActivationNeed(row.id === approvalId && row.consumed_by === operation.actor
            && workloadIssuanceClosed(credential, ['id', 'name', 'kind', 'secret_kek_id', 'credential_version', 'secret_updated_at',
              'metadata', 'lifecycle_status', 'revocation_error', 'revocation_requested_at', 'created_at', 'updated_at'])
            && credential.id === original.resourceId && credential.kind === 'oauth2'
            && credential.credential_version === 1 && credential.lifecycle_status === 'active');
          operation.definite = true; await oauthActivationCookie(operation);
          oauthActivationMessage('Credential activation acknowledged for ' + original.resourceId + '. Refresh inventory explicitly. No upstream token was returned.');
        }
      } catch (_) { oauthActivationFailure(operation); }
      finally { mfa = null; operation?.close(); }
      return {uiHandled: true, acknowledged: operation?.definite === true,
        unknown: operation?.sent === true && !operation.definite};
    }
    function oauthActivationApprove(id, note) {
      if (note !== null) {
        oauthActivationMessage('Clear the decision note before approving. This exact enrolled profile does not accept a note; it will not be silently discarded.', true);
        return {uiHandled: true, blocked: true};
      }
      return oauthActivationRun('decide', id, note);
    }
    function initOAuthActivation() {
      $('oauth-activation-inspect').addEventListener('click', () => oauthActivationInspect());
      $('oauth-activation-target').addEventListener('input', () => oauthActivationInvalidate('Pending account selection changed.'));
      $('oauth-activation-confirm').addEventListener('change', () => {
        if (oauthActivationBusy) oauthActivationInvalidate('Account confirmation changed during a ceremony.');
        else renderOAuthActivation();
      });
      $('oauth-activation-approval').addEventListener('change', () => {
        if (oauthActivationBusy) oauthActivationInvalidate('Approval selection changed during a ceremony.');
        else renderOAuthActivation();
      });
      $('oauth-activation-request').addEventListener('click', () => oauthActivationRun('request'));
      $('oauth-activation-continue').addEventListener('click', () => oauthActivationRun('activate', $('oauth-activation-approval').value));
      window.addEventListener('pagehide', () => oauthActivationInvalidate('Page closed.'));
      setInterval(renderOAuthActivation, 1000);
      renderOAuthActivation();
    }
"""
