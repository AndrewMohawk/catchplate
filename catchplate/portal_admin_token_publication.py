"""Explicit cookie-only inspection/resolution UI for generated-token history.

The server owns all authorization and exact-file admission. Browser observations
and attempt locks are not permission, durable custody or successful runtime proof.
"""


ADMIN_TOKEN_PUBLICATION_HTML = r"""
      <section id="admin-publication-workspace" aria-labelledby="admin-publication-heading">
        <h2 id="admin-publication-heading">Resolve an interrupted admin-token publication</h2>
        <p class="hint">Use an active OIDC administrator cookie and a different administrator approver, each with a fresh passkey. This panel never sends an entered bearer token. Clear that credential explicitly before using this panel; existing sign-in controls remain available.</p>
        <div class="toolbar">
          <button id="admin-publication-inspect" type="button">Inspect publication history</button>
          <button id="admin-publication-show-auth" class="secondary" type="button">Show operator credential field</button>
          <button id="admin-publication-discard" class="secondary" type="button">Discard local selection and approval</button>
        </div>
        <p id="admin-publication-auth" class="hint" role="status"></p>
        <p class="hint">Inspection is data only. It exposes no token and cannot authorize repair or retry. An unknown response, existing resolution claim, malformed history or mismatched file stays blocked. Do not delete or rename journal files.</p>
        <label for="admin-publication-target">Inspected publication and exact intent</label>
        <select id="admin-publication-target"><option value="">Inspect, then select an attempt</option></select>
        <pre id="admin-publication-observation" class="hint" style="white-space:pre-wrap;overflow-wrap:anywhere">No history inspected.</pre>
        <label for="admin-publication-outcome">Explicit resolution outcome</label>
        <select id="admin-publication-outcome">
          <option value="">Choose an outcome</option>
          <option value="finalize-installed">Finalize the exact already-installed new token</option>
          <option value="abandon-uninstalled">Abandon the exact uninstalled attempt; leave the old token</option>
        </select>
        <label for="admin-publication-reason">Reason (optional; empty sends null, at most 500 characters)</label>
        <textarea id="admin-publication-reason" maxlength="500" rows="2" autocomplete="off"></textarea>
        <p class="hint">Neither outcome generates, renames, discloses or restores a token. A settled resolution only supplies a terminal anchor for a later independently authorized rotation. If the installed token was lost, independently usable OIDC administrator access is still required.</p>
        <div class="toolbar">
          <button id="admin-publication-request" type="button" disabled>Fresh passkey + request resolution approval</button>
          <button id="admin-publication-continue" type="button" disabled>After approval: new passkey + resolve once</button>
        </div>
        <p id="admin-publication-pending" class="hint" style="white-space:pre-wrap;overflow-wrap:anywhere"></p>
        <a href="#approval-workspace">Different operator: review the exact intent and outcome in Approvals</a>
        <p id="admin-publication-status" class="hint" role="status" aria-live="polite">No resolution submitted. Inspection and each authorization action require an explicit click.</p>
      </section>
"""


ADMIN_TOKEN_PUBLICATION_SCRIPT = r"""
    const adminPublicationAction = 'control_plane.token.publication.resolve';
    const adminPublicationPath = '/api/control-plane/tokens/admin/publication';
    const adminPublicationOptionsPath = '/api/control-plane/mutations/webauthn/options';
    const adminPublicationProfile = 'catchplate.publicationApprovalOptions/v1';
    const adminPublicationAttempts = new Set(), adminPublicationContinuations = new Set();
    const adminPublicationApprovalAttempts = new Set();
    let adminPublicationEpoch = 0, adminPublicationContext = null, adminPublicationBusy = false;
    let adminPublicationController = null, adminPublicationContact = false, adminPublicationUnknown = false;
    let adminPublicationRows = [], adminPublicationSelected = null, adminPublicationPending = null;

    function adminPublicationNeed(ok) {
      if (!ok) throw new Error('Publication data, authorization or current context is unavailable. No automatic retry is allowed.');
    }
    function adminPublicationClosed(value, fields) {
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
    }
    function adminPublicationId(value) { return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value); }
    function adminPublicationDigest(value) { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
    function adminPublicationText(value, maximum) {
      return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
    }
    function adminPublicationApprovalId(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value); }
    function adminPublicationScope() { return sessionActivationAuthScope(); }
    function adminPublicationActor() {
      const auth = state.authStatus;
      adminPublicationNeed(!adminToken() && !oidcSessionStatusUnknown && window.isSecureContext && window.top === window
        && auth?.authenticated === true && auth.authMethod === 'oidc-session' && auth.sessionState === 'active'
        && auth.webauthnRequired === false && adminPublicationText(auth.userId, 4096)
        && Array.isArray(auth.roles) && auth.roles.includes('admin'));
      return auth.userId;
    }
    function adminPublicationMessage(message, failed = false) {
      $('admin-publication-status').textContent = (adminPublicationUnknown ? 'A sent operation has an unknown outcome. ' : '') + message;
      $('admin-publication-status').setAttribute('role', failed ? 'alert' : 'status');
    }
    function adminPublicationInvalidate(reason = 'Selection or authentication changed.', clear = true) {
      adminPublicationEpoch += 1;
      if (adminPublicationContact) adminPublicationUnknown = true;
      adminPublicationController?.abort();
      adminPublicationPending = null;
      if (clear) {
        adminPublicationSelected = null; adminPublicationRows = [];
        $('admin-publication-target').replaceChildren(new Option('Inspect, then select an attempt', ''));
        $('admin-publication-observation').textContent = 'No current selection. Inspect again explicitly.';
        $('admin-publication-outcome').value = ''; $('admin-publication-reason').value = '';
      }
      adminPublicationContext = adminPublicationScope();
      adminPublicationMessage(reason + ' Pending approval was discarded; page attempt locks remain.', adminPublicationUnknown);
      renderAdminPublication();
    }
    function adminPublicationKey(row) { return row.publicationId + ':' + row.intentSha256; }
    function adminPublicationBinding() {
      const row = adminPublicationSelected, outcome = $('admin-publication-outcome').value;
      const reason = $('admin-publication-reason').value;
      adminPublicationNeed(row && ['intent', 'authorized', 'claimed', 'complete'].includes(row.state)
        && row.resolutionOutcome === null && ['finalize-installed', 'abandon-uninstalled'].includes(outcome)
        && reason.length <= 500 && !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(reason));
      // These observations only constrain the UI; the server checks retained
      // exact file bytes and identities before it admits either outcome.
      adminPublicationNeed(outcome === 'finalize-installed'
        ? row.currentFileMatches === 'new-original' && ['claimed', 'complete'].includes(row.state)
        : row.currentFileMatches === 'previous-original' && row.state !== 'complete');
      return Object.freeze({token: 'admin', publicationId: row.publicationId,
        intentSha256: row.intentSha256, outcome, reason: reason === '' ? null : reason});
    }
    function adminPublicationReview(value) {
      if (!adminPublicationClosed(value, ['token', 'publicationId', 'intentSha256', 'outcome', 'reason'])
          || value.token !== 'admin' || !adminPublicationId(value.publicationId)
          || !adminPublicationDigest(value.intentSha256)
          || !['finalize-installed', 'abandon-uninstalled'].includes(value.outcome)
          || !(value.reason === null || typeof value.reason === 'string' && value.reason.length <= 500)) {
        return {blocked: 'Exact publication resolution binding is unavailable.'};
      }
      return {token: 'admin', publicationId: value.publicationId, intentSha256: value.intentSha256,
        outcome: value.outcome, reason: value.reason};
    }
    function adminPublicationApproval(binding, digest, id, userId, status) {
      const row = (state.controlPlaneApprovals || []).find(item => item.id === id);
      adminPublicationNeed(row && row.action === adminPublicationAction && row.resource_id === 'admin-token'
        && row.payload_digest === digest && row.requester_id === userId && row.status === status
        && workloadIssuanceCanonical(adminPublicationReview(row.request)) === workloadIssuanceCanonical(binding)
        && adminPublicationText(row.expires_at, 128) && Number.isFinite(Date.parse(row.expires_at))
        && Date.parse(row.expires_at) > Date.now());
      if (status === 'approved') adminPublicationNeed(adminPublicationText(row.approved_by, 4096)
        && row.approved_by !== userId && adminPublicationText(row.approver_webauthn_credential_id, 4096));
      return row;
    }
    function renderAdminPublication() {
      if (!$('admin-publication-workspace')) return;
      const scope = adminPublicationScope();
      if (adminPublicationContext !== null && scope !== adminPublicationContext) {
        adminPublicationInvalidate('Actor, policy or credential trust changed.'); return;
      }
      adminPublicationContext = scope;
      let actor = null, binding = null, approved = false;
      try { actor = adminPublicationActor(); } catch (_) {}
      try { binding = adminPublicationBinding(); } catch (_) {}
      const pending = adminPublicationPending;
      if (pending && actor && binding) {
        try {
          adminPublicationNeed(pending.actor === actor && pending.binding === workloadIssuanceCanonical(binding));
          adminPublicationApproval(binding, pending.digest, pending.id, actor, 'approved'); approved = true;
        } catch (_) {}
      }
      $('admin-publication-auth').textContent = adminToken()
        ? 'Blocked: clear the entered bearer credential yourself, then refresh the actual OIDC cookie status.'
        : actor ? 'Cookie administrator: ' + actor + '. Each action rechecks the actual cookie.'
          : 'Blocked: an active, currently checked OIDC administrator cookie is required. Use the existing sign-in/session controls.';
      const blocked = adminPublicationBusy || !actor;
      $('admin-publication-inspect').disabled = blocked;
      $('admin-publication-target').disabled = adminPublicationBusy;
      $('admin-publication-outcome').disabled = adminPublicationBusy;
      $('admin-publication-reason').disabled = adminPublicationBusy;
      $('admin-publication-request').disabled = blocked || adminPublicationUnknown || !binding || pending !== null
        || adminPublicationAttempts.has(adminPublicationSelected && adminPublicationKey(adminPublicationSelected));
      $('admin-publication-continue').disabled = blocked || adminPublicationUnknown || !pending || !approved
        || adminPublicationContinuations.has(adminPublicationSelected && adminPublicationKey(adminPublicationSelected));
      $('admin-publication-pending').textContent = pending ? 'Approval ' + pending.id + '\nAction: ' + adminPublicationAction
        + '\nResource: admin-token\nPayload: ' + pending.digest + '\nExpires: ' + pending.expires
        + '\n' + (approved ? 'Approved by another administrator. Continue explicitly with a NEW requester passkey.'
          : 'Awaiting a matching, unexpired approval in the queue. No automatic continuation.') : 'No local approval continuation retained.';
    }
    function adminPublicationBegin() {
      adminPublicationNeed(!adminPublicationBusy);
      const actor = adminPublicationActor(), epoch = adminPublicationEpoch, scope = adminPublicationScope();
      const controller = new AbortController(), until = performance.now() + 120000;
      const timer = setTimeout(() => controller.abort(), 120000);
      adminPublicationBusy = true; adminPublicationController = controller; adminPublicationContact = false;
      const current = () => adminPublicationNeed(!controller.signal.aborted && performance.now() < until
        && epoch === adminPublicationEpoch && scope === adminPublicationScope() && actor === adminPublicationActor());
      renderAdminPublication();
      return {actor, current, signal: controller.signal, close() {
        clearTimeout(timer); adminPublicationBusy = false; adminPublicationContact = false;
        adminPublicationController = null; renderAdminPublication();
      }};
    }
    async function adminPublicationRead(response, maximum, current) {
      current();
      adminPublicationNeed(response instanceof Response && response.body
        && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const length = response.headers.get('Content-Length');
      adminPublicationNeed(length === null || /^[0-9]+$/.test(length) && Number(length) <= maximum);
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let text = '', size = 0, done = false;
      try {
        for (;;) {
          current(); const item = await reader.read(); current();
          if (item.done) { done = true; break; }
          size += item.value.byteLength; adminPublicationNeed(size <= maximum);
          text += decoder.decode(item.value, {stream: true});
        }
        text += decoder.decode();
        return workloadIssuanceJson(text); // Existing bounded duplicate-rejecting data parser, not issuance authority.
      } finally {
        if (!done) { try { await reader.cancel(); } catch (_) {} }
        reader.releaseLock(); text = '';
      }
    }
    async function adminPublicationRequest(path, body, operation, contact = null) {
      const {current, signal} = operation;
      const get = body === null;
      adminPublicationNeed(get ? [adminPublicationPath, '/api/auth/status', '/api/csrf'].includes(path)
        : [adminPublicationPath + '/resolve', adminPublicationOptionsPath].includes(path)
          || /^\/api\/control-plane\/approvals\/[A-Za-z0-9_-]{1,64}\/approve$/.test(path));
      let original = get ? null : JSON.stringify(body), csrf = null;
      adminPublicationNeed(get || new TextEncoder().encode(original).byteLength <= 32 * 1024);
      try {
        if (!get) {
          const reply = await adminPublicationRequest('/api/csrf', null, operation);
          const value = reply.value;
          adminPublicationNeed(reply.status === 200 && adminPublicationClosed(value, ['ok', 'token', 'cookie', 'header'])
            && value.ok === true && adminPublicationText(value.token, 1024)
            && value.cookie === 'catchplate_csrf' && value.header === 'X-Catchplate-CSRF-Token');
          csrf = value.token;
        }
        current(); if (contact) contact();
        const response = await fetch(path, {method: get ? 'GET' : 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal,
          headers: get ? {} : {'Content-Type': 'application/json', 'X-Catchplate-CSRF-Token': csrf}, body: original});
        const value = await adminPublicationRead(response, path === '/api/csrf' ? 4096 : 64 * 1024, current);
        return {status: response.status, value};
      } finally { original = null; csrf = null; }
    }
    async function adminPublicationCookie(operation) {
      const reply = await adminPublicationRequest('/api/auth/status', null, operation), value = reply.value;
      adminPublicationNeed(reply.status === 200 && adminPublicationClosed(value, ['authenticated', 'userId', 'roles',
        'authMethod', 'sessionState', 'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode'])
        && value.authenticated === true && value.userId === operation.actor && value.authMethod === 'oidc-session'
        && value.sessionState === 'active' && value.webauthnRequired === false
        && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
        && value.sessionActivationMode === state.authStatus.sessionActivationMode
        && typeof value.oidcBrowserLoginConfigured === 'boolean' && Array.isArray(value.roles)
        && value.roles.length <= 64 && value.roles.every(role => adminPublicationText(role, 128))
        && value.roles.includes('admin') && new Set(value.roles).size === value.roles.length
        && JSON.stringify([...value.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
      operation.current();
    }
    function adminPublicationObservation(reply) {
      const value = reply.value, phases = ['intent', 'authorized', 'claimed', 'complete', 'settled',
        'resolution-claimed', 'resolution-complete', 'resolution-settled'];
      adminPublicationNeed(reply.status === 200 && adminPublicationClosed(value, ['schema', 'state', 'automaticRetryAllowed', 'attempts'])
        && value.schema === 'catchplate.adminTokenPublicationObservation/v1' && value.automaticRetryAllowed === false
        && ['no-journal', 'interrupted', 'completed-history'].includes(value.state)
        && Array.isArray(value.attempts) && value.attempts.length <= 64
        && (value.state !== 'no-journal' || value.attempts.length === 0));
      const ids = new Set();
      return value.attempts.map(row => {
        adminPublicationNeed(adminPublicationClosed(row, ['publicationId', 'intentSha256', 'state', 'resolutionOutcome', 'currentFileMatches', 'approvalId'])
          && adminPublicationId(row.publicationId) && !ids.has(row.publicationId) && adminPublicationDigest(row.intentSha256)
          && phases.includes(row.state) && ['new-original', 'previous-original', 'different'].includes(row.currentFileMatches)
          && (row.approvalId === null || adminPublicationApprovalId(row.approvalId))
          && (row.state.startsWith('resolution-') ? ['finalize-installed', 'abandon-uninstalled'].includes(row.resolutionOutcome)
            : row.resolutionOutcome === null));
        ids.add(row.publicationId); return Object.freeze({...row});
      });
    }
    async function adminPublicationInspect() {
      let operation = null;
      try {
        adminPublicationNeed(!adminPublicationBusy);
        adminPublicationInvalidate('Explicit inspection refresh.');
        operation = adminPublicationBegin(); await adminPublicationCookie(operation);
        const rows = adminPublicationObservation(await adminPublicationRequest(adminPublicationPath, null, operation));
        await adminPublicationCookie(operation); operation.current(); adminPublicationRows = rows;
        $('admin-publication-target').replaceChildren(new Option('Select one inspected attempt', ''),
          ...rows.map(row => new Option(row.publicationId + ' · ' + row.state + ' · ' + row.currentFileMatches, row.publicationId)));
        $('admin-publication-observation').textContent = rows.length ? 'Select an attempt to inspect its exact intent digest.' : 'No retained publication attempts reported.';
        adminPublicationMessage('Read-only inspection completed. No resolution or retry is authorized by these observations.');
      } catch (_) {
        adminPublicationMessage('Inspection unavailable, blocked or changed. No token or raw error body is displayed; no resolution was sent.', true);
      } finally { operation?.close(); }
    }
    async function adminPublicationAssertion(binding, digest, operation, phase, approval = null) {
      adminPublicationNeed(['request', 'decide', 'consume'].includes(phase)
        && (phase === 'request' ? approval === null : approval && adminPublicationApprovalId(approval.id)
          && (phase === 'consume' ? approval.requester_id === operation.actor : approval.requester_id !== operation.actor)));
      const body = {apiVersion: adminPublicationProfile, action: adminPublicationAction,
        resourceId: 'admin-token', payloadDigest: digest, request: binding};
      // The actual server selects request/decide/consume from its retained row
      // and actor. Both continuing actors supply the exact approval ID.
      if (approval !== null) body.approvalId = approval.id;
      const reply = await adminPublicationRequest(adminPublicationOptionsPath, body, operation), options = reply.value;
      adminPublicationNeed(reply.status === 200 && adminPublicationClosed(options, ['publicKey', 'catchplate'])
        && adminPublicationClosed(options.catchplate, ['schema', 'operation', 'operationId', 'challengeId',
          'credentialRecordId', 'payloadDigest', 'expiresAt']));
      const authority = options.catchplate, key = options.publicKey;
      adminPublicationNeed(authority.schema === adminPublicationProfile && authority.operation === 'publication-approval.' + phase
        && adminPublicationDigest(authority.operationId) && authority.payloadDigest === digest
        && adminPublicationDigest(authority.challengeId) && adminPublicationText(authority.credentialRecordId, 256)
        && new TextEncoder().encode(authority.credentialRecordId).byteLength <= 256
        && adminPublicationText(authority.expiresAt, 128) && Number.isFinite(Date.parse(authority.expiresAt))
        && Date.parse(authority.expiresAt) > Date.now());
      adminPublicationNeed(adminPublicationClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && adminPublicationText(key.rpId, 253)
        && (location.hostname === key.rpId || location.hostname.endsWith('.' + key.rpId))
        && key.userVerification === 'required' && key.timeout === 120000
        && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1);
      // This is the opaque, genuinely issued authority challenge, never the
      // hash of a generic v1/v2 options payload or a local success verdict.
      workloadIssuanceBase64(key.challenge, 4096);
      const ids = key.allowCredentials.map(item => {
        adminPublicationNeed(adminPublicationClosed(item, ['type', 'id']) && item.type === 'public-key');
        workloadIssuanceBase64(item.id, 3072); return item.id;
      });
      adminPublicationNeed(window.PublicKeyCredential && navigator.credentials);
      const expires = Date.parse(authority.expiresAt), until = performance.now() + Math.min(key.timeout, expires - Date.now());
      const current = () => { operation.current(); adminPublicationNeed(Date.now() < expires && performance.now() < until); };
      await adminPublicationCookie(operation); current();
      const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions({publicKey:
        {...key, allowCredentials: key.allowCredentials.map(item => ({...item}))}})});
      current();
      adminPublicationNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.rawId.byteLength <= 3072 && ids.includes(credential.id) && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential);
      workloadIssuanceAssertionOriginal(assertion, options); // Shape/challenge/origin only; server verifies the signature.
      adminPublicationNeed(new TextEncoder().encode(JSON.stringify({publicationProfile: adminPublicationProfile,
        assertion, approvalId: 'x'.repeat(64)})).byteLength <= 16 * 1024);
      await adminPublicationCookie(operation); current();
      return assertion;
    }
    function adminPublicationRequired(reply, binding, digest) {
      const detail = reply.value?.detail;
      adminPublicationNeed(reply.status === 428 && adminPublicationClosed(reply.value, ['detail'])
        && adminPublicationClosed(detail, ['error', 'approvalId', 'status', 'action', 'resourceId', 'payloadDigest', 'expiresAt', 'retry'])
        && detail.error === 'control_plane_approval_required' && adminPublicationApprovalId(detail.approvalId)
        && ['pending', 'approved'].includes(detail.status) && detail.action === adminPublicationAction
        && detail.resourceId === 'admin-token' && detail.payloadDigest === digest
        && adminPublicationText(detail.expiresAt, 128) && Number.isFinite(Date.parse(detail.expiresAt))
        && Date.parse(detail.expiresAt) > Date.now() && adminPublicationClosed(detail.retry, ['mfa.approvalId'])
        && detail.retry['mfa.approvalId'] === detail.approvalId);
      return Object.freeze({id: detail.approvalId, expires: detail.expiresAt, digest,
        binding: workloadIssuanceCanonical(binding), actor: adminPublicationActor()});
    }
    async function adminPublicationResolve(continuing = false) {
      let operation = null, submitted = false, acknowledged = false, assertion = null;
      try {
        adminPublicationNeed(!adminPublicationBusy && !adminPublicationUnknown);
        const selected = adminPublicationSelected, binding = adminPublicationBinding(), original = workloadIssuanceCanonical(binding);
        const key = adminPublicationKey(selected), prior = adminPublicationPending;
        adminPublicationNeed(continuing ? prior !== null && !adminPublicationContinuations.has(key)
          : prior === null && !adminPublicationAttempts.has(key));
        operation = adminPublicationBegin();
        const baseCurrent = operation.current;
        operation.current = () => { baseCurrent(); adminPublicationNeed(adminPublicationSelected === selected
          && workloadIssuanceCanonical(adminPublicationBinding()) === original); };
        await adminPublicationCookie(operation);
        const rows = adminPublicationObservation(await adminPublicationRequest(adminPublicationPath, null, operation));
        adminPublicationNeed(rows.some(row => workloadIssuanceCanonical(row) === workloadIssuanceCanonical(selected)));
        const digest = await workloadIssuanceObjectHash(binding); operation.current();
        let approval = null;
        if (continuing) {
          adminPublicationNeed(prior.actor === operation.actor && prior.binding === original && prior.digest === digest
            && Date.parse(prior.expires) > Date.now());
          approval = adminPublicationApproval(binding, digest, prior.id, operation.actor, 'approved');
        }
        assertion = await adminPublicationAssertion(binding, digest, operation, continuing ? 'consume' : 'request', approval);
        if (continuing) adminPublicationApproval(binding, digest, prior.id, operation.actor, 'approved');
        const mfa = {publicationProfile: adminPublicationProfile, assertion};
        if (continuing) mfa.approvalId = prior.id;
        const body = {publicationId: binding.publicationId, intentSha256: binding.intentSha256,
          outcome: binding.outcome, reason: binding.reason, mfa};
        adminPublicationNeed(new TextEncoder().encode(JSON.stringify(mfa)).byteLength <= 16 * 1024);
        const reply = await adminPublicationRequest(adminPublicationPath + '/resolve', body, operation, () => {
          submitted = true; adminPublicationContact = true; adminPublicationAttempts.add(key);
          if (continuing) adminPublicationContinuations.add(key);
        });
        if (!continuing && reply.status === 428) {
          adminPublicationPending = adminPublicationRequired(reply, binding, digest); acknowledged = true;
          adminPublicationContact = false;
          adminPublicationMessage('Exact approval request recorded. A different administrator must approve; then explicitly continue with a NEW requester assertion. No resolution effect is claimed.');
        } else {
          const value = reply.value;
          adminPublicationNeed(reply.status === 200 && adminPublicationClosed(value, ['schema', 'ok', 'publicationId',
            'intentSha256', 'outcome', 'resolutionCompletionSha256', 'automaticRetryAllowed'])
            && value.schema === 'catchplate.adminTokenPublicationResolution/v1' && value.ok === true
            && value.publicationId === binding.publicationId && value.intentSha256 === binding.intentSha256
            && value.outcome === binding.outcome && adminPublicationDigest(value.resolutionCompletionSha256)
            && value.automaticRetryAllowed === false);
          acknowledged = true; adminPublicationContact = false; adminPublicationPending = null;
          adminPublicationMessage('Server reported settled ' + value.outcome + '. Completion: ' + value.resolutionCompletionSha256
            + '. No token was disclosed or renamed. Refresh inspection explicitly; any later rotation requires separate authorization.');
        }
      } catch (_) {
        if (submitted && !acknowledged) { adminPublicationUnknown = true; adminPublicationPending = null; }
        adminPublicationMessage(submitted ? 'Resolution response is refused, ambiguous or changed. Do not resubmit, change outcomes to retry, or clear the journal. Read-only inspection remains available.'
          : 'Fresh authorization or exact inspection did not finish. No resolution POST was sent by this click; no assertion is retained or automatically retried.', true);
      } finally { assertion = null; operation?.close(); }
    }
    async function adminPublicationApprove(id, note) {
      let operation = null, submitted = false, assertion = null;
      try {
        if (note !== null) {
          adminPublicationMessage('This purpose requires a null approval note. Clear the note field explicitly; the exact requester reason remains bound.', true);
          return {blocked: true};
        }
        adminPublicationNeed(!adminPublicationBusy && !adminPublicationUnknown
          && adminPublicationApprovalId(id) && !adminPublicationApprovalAttempts.has(id));
        const actor = adminPublicationActor(), item = (state.controlPlaneApprovals || []).find(row => row.id === id);
        const binding = adminPublicationReview(item?.request), original = workloadIssuanceCanonical(binding);
        adminPublicationNeed(!Object.hasOwn(binding, 'blocked') && item?.can_approve === true
          && adminPublicationText(item.requester_id, 4096) && item.requester_id !== actor
          && adminPublicationDigest(item.payload_digest));
        const held = Object.freeze({id, requester_id: item.requester_id, expires_at: item.expires_at, digest: item.payload_digest});
        adminPublicationApproval(binding, held.digest, id, held.requester_id, 'pending');
        if (!window.confirm('Approve this exact resolution, not a token retry?\nPublication: ' + binding.publicationId
            + '\nIntent: ' + binding.intentSha256 + '\nOutcome: ' + binding.outcome + '\nReason: ' + (binding.reason ?? '(none)'))) return {cancelled: true};
        operation = adminPublicationBegin(); const baseCurrent = operation.current;
        operation.current = () => {
          baseCurrent(); const row = adminPublicationApproval(binding, held.digest, id, held.requester_id, 'pending');
          adminPublicationNeed(row.can_approve === true && row.requester_id !== operation.actor
            && row.expires_at === held.expires_at && workloadIssuanceCanonical(adminPublicationReview(row.request)) === original);
        };
        await adminPublicationCookie(operation);
        adminPublicationNeed(await workloadIssuanceObjectHash(binding) === held.digest); operation.current();
        assertion = await adminPublicationAssertion(binding, held.digest, operation, 'decide', held);
        const reply = await adminPublicationRequest('/api/control-plane/approvals/' + id + '/approve',
          {note: null, mfa: {publicationProfile: adminPublicationProfile, assertion}}, operation, () => {
            submitted = true; adminPublicationContact = true; adminPublicationApprovalAttempts.add(id);
          });
        const approved = reply.value;
        adminPublicationNeed(reply.status === 200 && adminPublicationClosed(approved, ['id', 'action', 'resource_id',
          'payload_digest', 'status', 'requester_id', 'requested_at', 'expires_at', 'approved_by', 'approved_at',
          'consumed_by', 'consumed_at', 'decision_note', 'approver_webauthn_credential_id', 'request'])
          && approved.id === id && approved.action === adminPublicationAction && approved.resource_id === 'admin-token'
          && approved.payload_digest === held.digest && approved.status === 'approved' && approved.requester_id === held.requester_id
          && approved.expires_at === held.expires_at && approved.approved_by === operation.actor && approved.decision_note === null
          && adminPublicationText(approved.approver_webauthn_credential_id, 4096)
          && workloadIssuanceCanonical(adminPublicationReview(approved.request)) === original);
        adminPublicationContact = false;
        adminPublicationMessage('Approval recorded for this exact intent and outcome. The requester must continue explicitly with a new passkey. Approval alone does not resolve publication.');
        return {pending: true};
      } catch (_) {
        if (submitted) adminPublicationUnknown = true;
        adminPublicationMessage(submitted ? 'Approval response is unknown or changed. Inspect the queue; do not automatically resubmit.'
          : 'Fresh distinct-person approval did not finish. No approval POST was sent by this click.', true);
        return {blocked: true};
      } finally { assertion = null; operation?.close(); }
    }
    function initAdminPublication() {
      $('admin-publication-inspect').addEventListener('click', adminPublicationInspect);
      $('admin-publication-request').addEventListener('click', () => adminPublicationResolve(false));
      $('admin-publication-continue').addEventListener('click', () => adminPublicationResolve(true));
      $('admin-publication-discard').addEventListener('click', () => adminPublicationInvalidate('Explicit local discard.'));
      $('admin-publication-show-auth').addEventListener('click', () => {
        $('admin-token').hidden = false; $('admin-token').focus();
        adminPublicationMessage('Clear the existing password field yourself if it contains a bearer credential. This panel never clears or sends it.');
      });
      $('admin-publication-target').addEventListener('change', () => {
        adminPublicationInvalidate('Publication selection changed.', false);
        adminPublicationSelected = adminPublicationRows.find(row => row.publicationId === $('admin-publication-target').value) || null;
        $('admin-publication-outcome').value = ''; $('admin-publication-reason').value = '';
        const row = adminPublicationSelected;
        $('admin-publication-observation').textContent = row ? 'Publication: ' + row.publicationId + '\nIntent: ' + row.intentSha256
          + '\nObserved phase: ' + row.state + '\nCurrent file: ' + row.currentFileMatches
          + '\nResolution: ' + (row.resolutionOutcome ?? '(none)')
          + '\nData only; the server must admit the actual retained files.' : 'No attempt selected.';
        renderAdminPublication();
      });
      for (const id of ['admin-publication-outcome', 'admin-publication-reason']) {
        $(id).addEventListener('input', () => adminPublicationInvalidate('Outcome or exact reason changed.', false));
      }
      window.addEventListener('pagehide', () => adminPublicationInvalidate('Page left.'));
      renderAdminPublication();
    }
"""
