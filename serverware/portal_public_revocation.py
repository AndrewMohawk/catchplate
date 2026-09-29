"""Dedicated public revocation portal, not an authority or retry engine.

Only bounded intent/locator observations enter session storage. Assertions and
authentication material never do. Unknown sends are recovered read-only through
the retained originals; no reconstructed browser record authorizes an effect.
"""


PUBLIC_REVOCATION_HTML = r"""
      <section id="public-revocation-workspace" aria-labelledby="public-revocation-heading">
        <h2 id="public-revocation-heading">Revoke an operator passkey</h2>
        <p class="hint">Select your passkey above, or enter an exact record ID as an administrator. The server independently admits self/admin rights, configured MFA and any different-person approval. This panel never falls back to the legacy mutation loop.</p>
        <label for="public-revocation-target">Target passkey record ID</label>
        <input id="public-revocation-target" maxlength="1024" autocomplete="off">
        <button id="public-revocation-inspect" type="button">Inspect target and current policy</button>
        <pre id="public-revocation-context" style="white-space:pre-wrap;overflow-wrap:anywhere">No target inspected.</pre>
        <p class="hint">Revoking your last key may end this session and block further passkey actions. Keep independently usable administrator access for recovery. No replacement credential is created here.</p>
        <label for="public-revocation-reason">Exact revocation reason</label>
        <textarea id="public-revocation-reason" maxlength="500" rows="2" autocomplete="off"></textarea>
        <label for="public-revocation-credential">Your eligible MFA passkey (only when configured)</label>
        <select id="public-revocation-credential"><option value="">Inspect current policy first</option></select>
        <label for="public-revocation-approval">Approval ID (empty when approval is not required)</label>
        <input id="public-revocation-approval" maxlength="256" autocomplete="off">
        <div class="toolbar">
          <button id="public-revocation-request" type="button" disabled>Request different-admin approval once</button>
          <button id="public-revocation-decide" type="button" disabled>Approve selected request once</button>
          <button id="public-revocation-execute" class="danger" type="button" disabled>Authorize and revoke once</button>
        </div>
        <p class="hint">Each ceremony is explicit. An approved row is not revocation completion. Final execution independently proves and consumes the actual approval. A lost response never enables resubmission. This profile has no protected denial action; pending requests can expire.</p>
        <p id="public-revocation-status" role="status" aria-live="polite">No revocation submitted.</p>
        <h3>Recover a retained operation</h3>
        <p class="hint">These local locators are navigation hints, not authority. Copy them before leaving this browser. If the response was completely lost, look up the attempt using its retained options locator. Missing or malformed association means unknown, never rollback or permission to retry. Use another still-valid requester/admin session if this revocation ended your session.</p>
        <label for="public-revocation-history">This tab's retained operation hints (maximum 32)</label>
        <select id="public-revocation-history"><option value="">No local history</option></select>
        <button id="public-revocation-history-select" class="secondary" type="button">Select retained hints</button>
        <label for="public-revocation-recovery-target">Recovery target record ID</label>
        <input id="public-revocation-recovery-target" maxlength="1024" autocomplete="off">
        <label for="public-revocation-options">Options local digest</label>
        <input id="public-revocation-options" maxlength="71" autocomplete="off">
        <label for="public-revocation-attempt">Attempt local digest (if received)</label>
        <input id="public-revocation-attempt" maxlength="71" autocomplete="off">
        <div class="toolbar">
          <button id="public-revocation-lookup" class="secondary" type="button">Read retained options → attempt association</button>
          <button id="public-revocation-recover" class="secondary" type="button">Read authenticated outcome</button>
          <button id="public-revocation-copy" class="secondary" type="button">Copy recovery locators</button>
        </div>
        <pre id="public-revocation-observation" style="white-space:pre-wrap;overflow-wrap:anywhere">No outcome inspected. No execution retry control is provided.</pre>
      </section>
"""


PUBLIC_REVOCATION_SCRIPT = r"""
    const publicRevocationAction = 'webauthn.credential.revoke';
    const publicRevocationPrefix = 'serverware.publicWebAuthnRevocation';
    const publicRevocationStorage = 'serverware.publicRevocationHints.v1';
    let publicRevocationContext = null, publicRevocationDecision = null;
    let publicRevocationBusy = false, publicRevocationEpoch = 0, publicRevocationScope = null;
    let publicRevocationController = null, publicRevocationHistory = [], publicRevocationStorageFailed = false;
    const publicRevocationPrepared = new Set();

    function publicRevocationNeed(value, message = 'Revocation data or current authority is unavailable. No automatic retry.') {
      if (!value) throw new Error(message);
    }
    function publicRevocationClosed(value, fields) {
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
    }
    function publicRevocationText(value, maximum = 1024) {
      return typeof value === 'string' && value.length > 0 && [...value].length <= maximum
        && !/[\u0000]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(value);
    }
    function publicRevocationDigest(value) { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
    function publicRevocationSegment(value) {
      return publicRevocationText(value) && value !== '.' && value !== '..' && !/[\\/?#]/u.test(value);
    }
    function publicRevocationAuthScope() {
      // Authentication values remain only in memory; they are never a saved hint.
      return JSON.stringify([adminToken(), state.authStatus?.authenticated, state.authStatus?.userId,
        state.authStatus?.authMethod, state.authStatus?.sessionState, state.authStatus?.roles, oidcSessionStatusUnknown]);
    }
    function publicRevocationMessage(message, error = false) {
      $('public-revocation-status').textContent = message;
      $('public-revocation-status').setAttribute('role', error ? 'alert' : 'status');
    }
    function publicRevocationInvalidate(message) {
      publicRevocationEpoch += 1;
      publicRevocationController?.abort();
      publicRevocationContext = null; publicRevocationDecision = null;
      publicRevocationScope = publicRevocationAuthScope();
      if ($('public-revocation-status')) {
        publicRevocationMessage(message + ' Retained hints remain read-only; a sent operation stays uncertain.');
        renderPublicRevocation();
      }
    }
    function publicRevocationAuthChanged() {
      if (publicRevocationScope !== null && publicRevocationScope !== publicRevocationAuthScope()) {
        publicRevocationInvalidate('Authentication changed; inspect again explicitly.');
      }
    }
    function publicRevocationReview(value) {
      const fields = ['credential_record_id', 'credential_id_sha256', 'credential_user_id', 'label', 'attestation_root_sha256', 'reason'];
      if (!publicRevocationClosed(value, fields) || !publicRevocationText(value.credential_record_id)
          || !publicRevocationText(value.credential_user_id) || !publicRevocationDigest(value.credential_id_sha256)
          || !(value.attestation_root_sha256 === null || publicRevocationDigest(value.attestation_root_sha256))
          || typeof value.label !== 'string' || new TextEncoder().encode(value.label).length > 4096
          || !publicRevocationText(value.reason, 500)) return {blocked: 'Exact revocation target and reason unavailable.'};
      return Object.fromEntries(fields.map(key => [key, value[key]]));
    }
    function publicRevocationHint(value) {
      return publicRevocationClosed(value, ['kind', 'recordId', 'actorId', 'reason', 'approvalId', 'payloadDigest', 'optionsLocalDigest', 'attemptLocalDigest', 'status'])
        && ['execute', 'approval-request', 'approval-decide'].includes(value.kind)
        && publicRevocationText(value.recordId) && publicRevocationText(value.actorId)
        && publicRevocationText(value.reason, 500)
        && (value.approvalId === null || publicRevocationText(value.approvalId, 256))
        && publicRevocationDigest(value.optionsLocalDigest) && publicRevocationDigest(value.payloadDigest)
        && (value.attemptLocalDigest === null || publicRevocationDigest(value.attemptLocalDigest))
        && ['handoff-attempted', 'outcome-unknown', 'approval-row-observed', 'committed-observed'].includes(value.status);
    }
    function publicRevocationSave() {
      publicRevocationNeed(!publicRevocationStorageFailed && publicRevocationHistory.length <= 32
        && publicRevocationHistory.every(publicRevocationHint), 'Local recovery hints are unavailable. No effect will be sent.');
      const raw = JSON.stringify(publicRevocationHistory);
      publicRevocationNeed(new TextEncoder().encode(raw).length <= 128 * 1024);
      try {
        sessionStorage.setItem(publicRevocationStorage, raw);
        publicRevocationNeed(sessionStorage.getItem(publicRevocationStorage) === raw);
      } catch (error) {
        publicRevocationStorageFailed = true;
        throw new Error('Could not retain recovery hints. Do not resend; use the displayed options locator for read-only recovery.');
      }
    }
    function publicRevocationShowHint(hint) {
      $('public-revocation-recovery-target').value = hint.recordId;
      $('public-revocation-options').value = hint.optionsLocalDigest;
      $('public-revocation-attempt').value = hint.attemptLocalDigest || '';
    }
    function publicRevocationBlocked(kind, recordId, actorId) {
      return publicRevocationHistory.some(item => item.kind === kind && item.recordId === recordId && item.actorId === actorId);
    }
    function renderPublicRevocation() {
      const context = publicRevocationContext, target = context?.target, busy = publicRevocationBusy;
      const valid = target && target.recordId === $('public-revocation-target').value && !target.revoked;
      const mine = context && publicRevocationDecision === null;
      $('public-revocation-inspect').disabled = busy;
      for (const name of ['lookup', 'recover', 'history-select', 'copy']) $('public-revocation-' + name).disabled = busy;
      $('public-revocation-request').disabled = busy || publicRevocationStorageFailed || !valid || !mine
        || !context.policy.twoPersonRequired || publicRevocationBlocked('approval-request', target.recordId, context.actor.userId);
      $('public-revocation-decide').disabled = busy || publicRevocationStorageFailed || !valid || !publicRevocationDecision
        || publicRevocationBlocked('approval-decide', target.recordId, context.actor.userId);
      $('public-revocation-execute').disabled = busy || publicRevocationStorageFailed || !valid || !mine
        || publicRevocationBlocked('execute', target.recordId, context.actor.userId);
      for (const name of ['target', 'reason', 'credential', 'approval']) $('public-revocation-' + name).disabled = busy;
      const history = $('public-revocation-history'), selected = history.value;
      history.replaceChildren(new Option('Select retained read-only hints', ''));
      for (const item of publicRevocationHistory) history.add(new Option(`${item.kind} · ${item.recordId} · ${item.status}`, item.optionsLocalDigest));
      if (publicRevocationHistory.some(item => item.optionsLocalDigest === selected)) history.value = selected;
    }
    function publicRevocationOperation() {
      publicRevocationNeed(!publicRevocationBusy && window.isSecureContext && window.top === window && hasOperatorAuth());
      publicRevocationAuthChanged();
      publicRevocationBusy = true;
      const controller = new AbortController(), epoch = publicRevocationEpoch, scope = publicRevocationAuthScope();
      publicRevocationController = controller; publicRevocationScope = scope;
      const deadline = performance.now() + 30000, timer = setTimeout(() => controller.abort(), 30000);
      const operation = {controller, deadline, current() {
        publicRevocationNeed(epoch === publicRevocationEpoch && scope === publicRevocationAuthScope()
          && !controller.signal.aborted && performance.now() < deadline, 'The original browser operation ended. Any sent outcome remains unknown.');
      }, close() { clearTimeout(timer); publicRevocationBusy = false; publicRevocationController = null; renderPublicRevocation(); }};
      renderPublicRevocation();
      return operation;
    }
    async function publicRevocationPost(operation, path, body) {
      operation.current();
      publicRevocationNeed(path === '/api/webauthn/revocation/context'
        || path === '/api/control-plane/mutations/webauthn/options'
        || /^\/api\/webauthn\/credentials\/[^/?#]+\/(?:revoke|revocation\/(?:options|lookup|recover|approval\/request))$/.test(path)
        || /^\/api\/control-plane\/approvals\/[^/?#]+\/approve$/.test(path));
      const raw = JSON.stringify(body);
      publicRevocationNeed(new TextEncoder().encode(raw).length <= 65536);
      let csrf = null;
      if (!adminToken()) {
        if (!csrfToken) {
          const response = await fetch('/api/csrf', {credentials: 'same-origin', cache: 'no-store', redirect: 'error',
            signal: operation.controller.signal, headers: adminHeaders()});
          const value = await publicRevocationJson(operation, response);
          publicRevocationNeed(publicRevocationClosed(value, ['ok', 'token', 'cookie', 'header']) && value.ok === true
            && typeof value.token === 'string' && /^[A-Za-z0-9_-]{16,512}$/.test(value.token)
            && value.header === 'X-Serverware-CSRF-Token');
          csrfToken = value.token;
        }
        csrf = csrfToken;
      }
      operation.current();
      const response = await fetch(path, {method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: operation.controller.signal, headers: {'Content-Type': 'application/json', ...adminHeaders(),
          ...(csrf ? {'X-Serverware-CSRF-Token': csrf} : {})}, body: raw});
      return publicRevocationJson(operation, response);
    }
    async function publicRevocationJson(operation, response) {
      operation.current();
      publicRevocationNeed((response.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase() === 'application/json'
        && response.body, 'The response is not a bounded JSON observation. Any sent outcome remains unknown.');
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let count = 0, chunks = 0, text = '';
      try {
        while (true) {
          const next = await reader.read(); operation.current();
          if (next.done) break;
          count += next.value.byteLength; chunks += 1;
          publicRevocationNeed(count <= 192 * 1024 && chunks <= 512, 'Response exceeds the fixed observation bound. Outcome remains unknown.');
          text += decoder.decode(next.value, {stream: true});
        }
        text += decoder.decode();
      } finally { await reader.cancel().catch(() => {}); }
      const value = JSON.parse(text); operation.current();
      if (!response.ok) throw new ApiError(response.status, value);
      return value;
    }
    async function publicRevocationLoadContext(operation, recordId) {
      const value = await publicRevocationPost(operation, '/api/webauthn/revocation/context',
        {apiVersion: publicRevocationPrefix + 'ContextRequest/v1', recordId});
      publicRevocationNeed(publicRevocationClosed(value, ['apiVersion', 'actor', 'policy', 'eligibleCredentials', 'target', 'automaticRetryAllowed'])
        && value.apiVersion === publicRevocationPrefix + 'Context/v1' && value.automaticRetryAllowed === false
        && publicRevocationClosed(value.actor, ['userId', 'roles', 'authMethod']) && publicRevocationText(value.actor.userId)
        && publicRevocationText(value.actor.authMethod, 128) && Array.isArray(value.actor.roles)
        && value.actor.roles.length <= 32 && value.actor.roles.every(role => publicRevocationText(role, 128))
        && value.actor.roles.some(role => ['admin', 'approver'].includes(role))
        && publicRevocationClosed(value.policy, ['mfaRequired', 'twoPersonRequired', 'credentialPolicy'])
        && typeof value.policy.mfaRequired === 'boolean' && typeof value.policy.twoPersonRequired === 'boolean'
        && value.policy.credentialPolicy?.userVerification === 'required'
        && Object.keys(value.policy.credentialPolicy).every(key => ['userVerification', 'allowedAuthenticatorClasses', 'requireHardwareAttestation'].includes(key))
        && Array.isArray(value.eligibleCredentials) && value.eligibleCredentials.length <= 64);
      const policy = value.policy.credentialPolicy;
      publicRevocationNeed(!Object.hasOwn(policy, 'requireHardwareAttestation') || typeof policy.requireHardwareAttestation === 'boolean');
      publicRevocationNeed(!Object.hasOwn(policy, 'allowedAuthenticatorClasses') || Array.isArray(policy.allowedAuthenticatorClasses)
        && policy.allowedAuthenticatorClasses.length >= 1 && policy.allowedAuthenticatorClasses.length <= 32
        && policy.allowedAuthenticatorClasses.every(item => publicRevocationText(item, 128))
        && new Set(policy.allowedAuthenticatorClasses).size === policy.allowedAuthenticatorClasses.length);
      const ids = new Set();
      for (const item of value.eligibleCredentials) {
        publicRevocationNeed(publicRevocationClosed(item, ['recordId', 'label', 'credentialId'])
          && publicRevocationText(item.recordId) && typeof item.label === 'string' && new TextEncoder().encode(item.label).length <= 4096
          && typeof item.credentialId === 'string' && /^[A-Za-z0-9_-]{1,2048}$/.test(item.credentialId) && !ids.has(item.recordId));
        ids.add(item.recordId);
      }
      publicRevocationNeed(value.policy.mfaRequired || value.eligibleCredentials.length === 0);
      if (recordId === null) publicRevocationNeed(value.target === null);
      else {
        const target = value.target;
        publicRevocationNeed(publicRevocationClosed(target, ['recordId', 'userId', 'label', 'credentialIdSha256', 'attestationRootSha256', 'revoked'])
          && target.recordId === recordId && publicRevocationText(target.userId) && typeof target.label === 'string'
          && new TextEncoder().encode(target.label).length <= 4096 && publicRevocationDigest(target.credentialIdSha256)
          && (target.attestationRootSha256 === null || publicRevocationDigest(target.attestationRootSha256))
          && typeof target.revoked === 'boolean'
          && (target.userId === value.actor.userId || value.actor.roles.includes('admin')));
      }
      operation.current(); return value;
    }
    function publicRevocationDisplayContext(value) {
      publicRevocationContext = value;
      $('public-revocation-context').textContent = JSON.stringify({actor: value.actor, target: value.target,
        configuredPolicy: value.policy, notice: 'Read-only context. The effect independently checks actual current authority.'}, null, 2);
      const selector = $('public-revocation-credential'), selected = selector.value;
      selector.replaceChildren(new Option(value.policy.mfaRequired ? 'Choose your own eligible passkey' : 'MFA disabled by admitted policy — explicit null', ''));
      for (const item of value.eligibleCredentials) selector.add(new Option(`${item.label} · ${item.recordId}`, item.recordId));
      if (value.eligibleCredentials.some(item => item.recordId === selected)) selector.value = selected;
    }
    async function publicRevocationSelect(recordId) {
      publicRevocationNeed(publicRevocationSegment(recordId) && !publicRevocationBusy);
      const changed = $('public-revocation-target').value !== recordId;
      sessionActivationInvalidate('Public passkey revocation selected.');
      publicRevocationInvalidate('Target selection changed.');
      $('public-revocation-target').value = recordId;
      if (changed) { $('public-revocation-approval').value = ''; $('public-revocation-reason').value = ''; }
      const operation = publicRevocationOperation();
      try {
        publicRevocationDisplayContext(await publicRevocationLoadContext(operation, recordId));
        publicRevocationMessage('Review the exact target, enter the reason, and choose an explicit ceremony.');
        $('public-revocation-workspace').scrollIntoView({block: 'start'});
        return {uiHandled: true};
      } finally { operation.close(); }
    }
    async function publicRevocationSelectApproval(id) {
      const row = (state.controlPlaneApprovals || []).find(item => item.id === id);
      publicRevocationNeed(row && row.action === publicRevocationAction && row.status === 'pending' && row.can_approve === true);
      const review = publicRevocationReview(row.request);
      publicRevocationNeed(!review.blocked && review.credential_record_id === row.resource_id && publicRevocationDigest(row.payload_digest));
      await publicRevocationSelect(row.resource_id);
      publicRevocationNeed(publicRevocationContext.actor.roles.includes('admin') && publicRevocationContext.actor.userId !== row.requester_id);
      publicRevocationDecision = {id, requesterId: row.requester_id, payloadDigest: row.payload_digest, review};
      $('public-revocation-reason').value = review.reason; $('public-revocation-approval').value = id;
      publicRevocationMessage('Review this other operator’s exact target and reason; choose your MFA passkey if required, then Approve once. Approval does not execute revocation.');
      renderPublicRevocation(); return {uiHandled: true};
    }
    async function publicRevocationAssertion(operation, options, context, chosen) {
      if (!context.policy.mfaRequired) { publicRevocationNeed(options.challenge === null && chosen === null); return null; }
      const selected = context.eligibleCredentials.find(item => item.recordId === chosen), challenge = options.challenge;
      publicRevocationNeed(selected && publicRevocationClosed(challenge, ['authorityChallengeId', 'credentialRecordId', 'publicKey'])
        && publicRevocationText(challenge.authorityChallengeId) && challenge.credentialRecordId === chosen);
      const key = challenge.publicKey;
      publicRevocationNeed(publicRevocationClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && typeof key.challenge === 'string' && /^[A-Za-z0-9_-]{1,2048}$/.test(key.challenge)
        && typeof key.rpId === 'string' && (location.hostname === key.rpId || location.hostname.endsWith('.' + key.rpId))
        && key.userVerification === 'required' && Number.isInteger(key.timeout) && key.timeout > 0 && key.timeout <= 30000
        && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
        && publicRevocationClosed(key.allowCredentials[0], ['type', 'id'])
        && key.allowCredentials[0].type === 'public-key' && key.allowCredentials[0].id === selected.credentialId
        && window.PublicKeyCredential && navigator.credentials);
      operation.current();
      const request = prepareRequestOptions({publicKey: JSON.parse(JSON.stringify(key))});
      request.timeout = Math.max(1, Math.min(request.timeout, Math.floor(operation.deadline - performance.now())));
      const credential = await navigator.credentials.get({publicKey: request, signal: operation.controller.signal});
      operation.current();
      publicRevocationNeed(credential && credential.type === 'public-key' && credential.id === selected.credentialId);
      return {authorityChallengeId: challenge.authorityChallengeId, credentialRecordId: chosen, assertion: credentialToJson(credential)};
    }
    async function publicRevocationPayloadDigest(operation, context, reason) {
      const target = context.target;
      const value = {credential_record_id: target.recordId, credential_id_sha256: target.credentialIdSha256,
        credential_user_id: target.userId, label: target.label, attestation_root_sha256: target.attestationRootSha256, reason};
      // Exact Python ensure_ascii recipe, including DEL and UTF-16 surrogate
      // escape pairs. This is a display-binding check, never an authorization.
      const original = JSON.stringify(canonicalValue(value)).replace(/[\u007f-\uffff]/g,
        char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(original)));
      operation.current();
      return 'sha256:' + [...hash].map(byte => byte.toString(16).padStart(2, '0')).join('');
    }
    function publicRevocationApprovalRow(row, hint, imported = false) {
      publicRevocationNeed(row && publicRevocationText(row.id, 256) && row.action === publicRevocationAction
        && row.resource_id === hint.recordId && publicRevocationDigest(row.payload_digest)
        && ['pending', 'approved', 'consumed', 'expired', 'revoked', 'denied'].includes(row.status));
      const review = publicRevocationReview(row.request);
      publicRevocationNeed(!review.blocked && review.credential_record_id === hint.recordId && (imported || review.reason === hint.reason));
      if (!imported) publicRevocationNeed(row.payload_digest === hint.payloadDigest);
      if (!imported && hint.kind === 'approval-request') publicRevocationNeed(row.requester_id === hint.actorId);
      if (!imported && hint.kind === 'approval-decide') publicRevocationNeed(row.id === hint.approvalId && row.requester_id !== hint.actorId);
      return row;
    }
    function publicRevocationObservation(value, hint, imported = false) {
      publicRevocationNeed(value && publicRevocationDigest(value.localDigest) && value.localDigest === hint.attemptLocalDigest
        && value.automaticRetryAllowed === false);
      if (value.apiVersion === publicRevocationPrefix + 'Result/v1') {
        publicRevocationNeed(publicRevocationClosed(value, ['apiVersion', 'status', 'localDigest', 'ok', 'credential',
          'revokedGrantCount', 'revokedControlPlaneApprovalCount', 'revokedOidcBrowserSessionCount', 'invalidatedRegistrationChallengeCount', 'automaticRetryAllowed'])
          && (imported || hint.kind === 'execute') && value.status === 'committed-observed' && value.ok === true
          && value.credential?.id === hint.recordId && value.credential.active === false
          && ['revokedGrantCount', 'revokedControlPlaneApprovalCount', 'revokedOidcBrowserSessionCount', 'invalidatedRegistrationChallengeCount']
            .every(key => Number.isSafeInteger(value[key]) && value[key] >= 0 && value[key] <= 32));
        hint.status = 'committed-observed';
        publicRevocationMessage('Authenticated terminal completion observed. This is not another execution permission; this session may now be revoked.');
      } else if (value.apiVersion === publicRevocationPrefix + 'ApprovalResult/v1'
          || value.apiVersion === publicRevocationPrefix + 'ApprovalObservation/v1') {
        const observed = value.apiVersion.endsWith('ApprovalObservation/v1');
        publicRevocationNeed((imported || hint.kind !== 'execute') && publicRevocationClosed(value, observed
          ? ['apiVersion', 'localDigest', 'status', 'approval', 'committedObserved', 'revocationExecuted', 'automaticRetryAllowed']
          : ['apiVersion', 'localDigest', 'approval', 'revocationExecuted', 'automaticRetryAllowed'])
          && value.revocationExecuted === false && (!observed || value.committedObserved === false
            && ['approval-row-observed', 'outcome-unknown', 'locally-unattempted'].includes(value.status)));
        publicRevocationNeed(observed ? ((value.approval !== null) === (value.status === 'approval-row-observed'))
          : value.approval !== null);
        if (value.approval !== null) {
          const row = publicRevocationApprovalRow(value.approval, hint, imported);
          hint.approvalId = row.id; hint.status = 'approval-row-observed';
          if (!imported && hint.kind === 'approval-request') $('public-revocation-approval').value = row.id;
          publicRevocationMessage(`Approval row ${row.id}: ${row.status}. Revocation has NOT executed. The requester must select the target and explicitly authorize final execution after approval.`);
        } else { hint.status = 'outcome-unknown'; publicRevocationMessage('Approval outcome unknown. No resubmission is permitted.', true); }
      } else {
        publicRevocationNeed(publicRevocationClosed(value, ['apiVersion', 'localDigest', 'status', 'committedObserved', 'automaticRetryAllowed'])
          && value.apiVersion === publicRevocationPrefix + 'Observation/v1' && (imported || hint.kind === 'execute')
          && ['outcome-unknown', 'locally-unattempted'].includes(value.status) && value.committedObserved === false);
        hint.status = 'outcome-unknown'; publicRevocationMessage('Outcome unresolved. Local non-attempt is not remote absence or retry permission.', true);
      }
      $('public-revocation-observation').textContent = JSON.stringify(value, null, 2);
    }
    async function publicRevocationCeremony(kind) {
      publicRevocationNeed(['execute', 'approval-request', 'approval-decide'].includes(kind));
      const recordId = $('public-revocation-target').value, reason = $('public-revocation-reason').value;
      const approvalId = $('public-revocation-approval').value || null, selected = $('public-revocation-credential').value || null;
      publicRevocationNeed(publicRevocationSegment(recordId) && publicRevocationText(reason, 500)
        && (approvalId === null || publicRevocationText(approvalId, 256) && publicRevocationSegment(approvalId)));
      // Beginning the operation invalidates stale authentication context before
      // a selected approval is borrowed, not after it has been copied locally.
      const operation = publicRevocationOperation(), decision = publicRevocationDecision;
      let hint = null, mfa = null;
      try {
        const context = await publicRevocationLoadContext(operation, recordId);
        publicRevocationNeed(!context.target.revoked && !publicRevocationBlocked(kind, recordId, context.actor.userId)
          && !publicRevocationStorageFailed && publicRevocationHistory.length < 32);
        const chosen = context.policy.mfaRequired ? selected : null;
        publicRevocationNeed(!context.policy.mfaRequired || context.eligibleCredentials.some(item => item.recordId === chosen), 'Select your own eligible passkey; the target key is not implicitly your MFA credential.');
        if (kind === 'approval-decide') {
          publicRevocationNeed(decision && decision.id === approvalId && context.actor.roles.includes('admin')
            && context.actor.userId !== decision.requesterId && decision.review.reason === reason
            && decision.review.credential_record_id === recordId);
        } else publicRevocationNeed(decision === null);
        publicRevocationNeed(kind === 'execute' ? (context.policy.twoPersonRequired ? approvalId !== null : approvalId === null)
          : context.policy.twoPersonRequired && (kind === 'approval-request' ? approvalId === null : approvalId !== null));
        const payloadDigest = await publicRevocationPayloadDigest(operation, context, reason);
        const preparationKey = JSON.stringify([kind, recordId, context.actor.userId, reason, approvalId]);
        publicRevocationNeed(publicRevocationPrepared.size < 64 && !publicRevocationPrepared.has(preparationKey),
          'This page already began that ceremony or reached its preparation bound. Recover retained hints; do not repeat it.');
        publicRevocationPrepared.add(preparationKey);
        const options = await publicRevocationPost(operation, kind === 'execute'
          ? `/api/webauthn/credentials/${encodeURIComponent(recordId)}/revocation/options`
          : '/api/control-plane/mutations/webauthn/options', kind === 'execute'
          ? {apiVersion: publicRevocationPrefix + 'OptionsRequest/v1', reason, approvalId, credentialRecordId: chosen}
          : {apiVersion: publicRevocationPrefix + 'ApprovalOptionsRequest/v1', action: publicRevocationAction,
            resourceId: recordId, reason, approvalId, credentialRecordId: chosen});
        publicRevocationNeed(publicRevocationClosed(options, kind === 'execute'
          ? ['apiVersion', 'localDigest', 'recordId', 'payloadDigest', 'expiresAtEpochNs', 'mfaRequired', 'challenge', 'revocationExecuted', 'automaticRetryAllowed']
          : ['apiVersion', 'localDigest', 'operation', 'recordId', 'payloadDigest', 'approvalId', 'challenge', 'automaticRetryAllowed'])
          && options.apiVersion === publicRevocationPrefix + (kind === 'execute' ? 'OptionsResponse/v1' : 'ApprovalOptionsResponse/v1')
          && options.recordId === recordId && publicRevocationDigest(options.localDigest) && publicRevocationDigest(options.payloadDigest)
          && options.payloadDigest === payloadDigest
          && options.automaticRetryAllowed === false);
        if (kind === 'execute') publicRevocationNeed(options.mfaRequired === context.policy.mfaRequired && options.revocationExecuted === false
          && Number.isInteger(options.expiresAtEpochNs) && options.expiresAtEpochNs > 0);
        else publicRevocationNeed(options.approvalId === approvalId && options.operation === 'public-revocation-approval.'
          + (kind === 'approval-request' ? 'request' : 'decide') + (context.policy.mfaRequired ? '-asserted' : '-identity')
          && (kind !== 'approval-decide' || options.payloadDigest === decision.payloadDigest));
        const candidate = {kind, recordId, actorId: context.actor.userId, reason, approvalId, payloadDigest,
          optionsLocalDigest: options.localDigest, attemptLocalDigest: null, status: 'handoff-attempted'};
        publicRevocationShowHint(candidate);
        mfa = await publicRevocationAssertion(operation, options, context, chosen);
        operation.current();
        hint = candidate; publicRevocationHistory.push(hint);
        // Persist only bounded navigation hints BEFORE the one effect handoff.
        // Failure here also leaves the action blocked; no assertion is stored.
        publicRevocationSave(); renderPublicRevocation();
        const path = kind === 'execute' ? `/api/webauthn/credentials/${encodeURIComponent(recordId)}/revoke`
          : kind === 'approval-request' ? `/api/webauthn/credentials/${encodeURIComponent(recordId)}/revocation/approval/request`
          : `/api/control-plane/approvals/${encodeURIComponent(approvalId)}/approve`;
        const result = await publicRevocationPost(operation, path, kind === 'execute'
          ? {apiVersion: publicRevocationPrefix + 'ExecuteRequest/v1', localDigest: options.localDigest, reason, mfa}
          : {apiVersion: publicRevocationPrefix + 'ApprovalSubmitRequest/v1', localDigest: options.localDigest, mfa});
        mfa = null;
        publicRevocationNeed(publicRevocationDigest(result?.localDigest));
        hint.attemptLocalDigest = result.localDigest;
        publicRevocationObservation(result, hint); publicRevocationSave(); publicRevocationShowHint(hint);
        return {uiHandled: true};
      } catch (error) {
        if (hint) {
          hint.status = 'outcome-unknown';
          if (error instanceof ApiError && publicRevocationDigest(error.detail?.localDigest)
              && error.detail?.automaticRetryAllowed === false) hint.attemptLocalDigest = error.detail.localDigest;
          try { publicRevocationSave(); } catch (_) { /* Keep in-memory and displayed locator; no effect retry. */ }
          publicRevocationShowHint(hint);
          publicRevocationMessage('Outcome uncertain. Use the retained options locator and explicit read-only lookup/recovery; never repeat the effect.', true);
        } else publicRevocationMessage('Ceremony did not reach the browser effect handoff. No automatic continuation or retry. ' + error.message, true);
        return {uiHandled: true, blocked: true};
      } finally { mfa = null; operation.close(); }
    }
    async function publicRevocationRead(kind) {
      const recordId = $('public-revocation-recovery-target').value;
      const optionsLocalDigest = $('public-revocation-options').value, attemptLocalDigest = $('public-revocation-attempt').value;
      publicRevocationNeed(publicRevocationSegment(recordId) && (kind === 'lookup' ? publicRevocationDigest(optionsLocalDigest) : publicRevocationDigest(attemptLocalDigest)));
      const operation = publicRevocationOperation();
      try {
        const value = await publicRevocationPost(operation, `/api/webauthn/credentials/${encodeURIComponent(recordId)}/revocation/${kind}`,
          kind === 'lookup' ? {apiVersion: publicRevocationPrefix + 'LookupRequest/v1', optionsLocalDigest}
          : {apiVersion: publicRevocationPrefix + 'RecoveryRequest/v1', localDigest: attemptLocalDigest});
        if (kind === 'lookup') {
          publicRevocationNeed(publicRevocationClosed(value, ['apiVersion', 'recordId', 'optionsLocalDigest', 'attemptLocalDigest', 'kind', 'status', 'committedObserved', 'automaticRetryAllowed'])
            && value.apiVersion === publicRevocationPrefix + 'Lookup/v1' && value.recordId === recordId && value.optionsLocalDigest === optionsLocalDigest
            && ['execute', 'approval-request', 'approval-decide'].includes(value.kind) && value.committedObserved === false && value.automaticRetryAllowed === false
            && (value.attemptLocalDigest === null ? value.status === 'outcome-unknown'
              : publicRevocationDigest(value.attemptLocalDigest) && value.status === 'retained-association-observed'));
          $('public-revocation-attempt').value = value.attemptLocalDigest || '';
          const hint = publicRevocationHistory.find(item => item.optionsLocalDigest === optionsLocalDigest && item.recordId === recordId);
          if (hint && value.attemptLocalDigest !== null) {
            publicRevocationNeed(hint.kind === value.kind); hint.attemptLocalDigest = value.attemptLocalDigest; publicRevocationSave();
          }
          publicRevocationMessage(value.attemptLocalDigest === null ? 'No retained association was observed. Outcome remains unknown; do not resubmit.'
            : 'Actual retained association observed. Select Read authenticated outcome explicitly; no effect was repeated.');
        } else {
          const hint = publicRevocationHistory.find(item => item.attemptLocalDigest === attemptLocalDigest && item.recordId === recordId);
          if (hint) { publicRevocationObservation(value, hint); publicRevocationSave(); }
          else {
            // Imported locators have no trusted local intent. Validate only the
            // fixed observation scope; never turn their DTO into an action.
            publicRevocationNeed([publicRevocationPrefix + 'Result/v1', publicRevocationPrefix + 'Observation/v1',
              publicRevocationPrefix + 'ApprovalObservation/v1'].includes(value.apiVersion));
            publicRevocationObservation(value, {recordId, attemptLocalDigest, kind: 'imported'}, true);
          }
        }
        $('public-revocation-observation').textContent = JSON.stringify(value, null, 2);
        return {uiHandled: true};
      } catch (error) {
        publicRevocationMessage('Readback unresolved. Any prior outcome remains unknown; no execution was requested. ' + error.message, true);
        return {uiHandled: true, blocked: true};
      } finally { operation.close(); }
    }
    function initPublicRevocation() {
      try {
        const raw = sessionStorage.getItem(publicRevocationStorage);
        if (raw !== null) {
          publicRevocationNeed(raw.length <= 128 * 1024 && new TextEncoder().encode(raw).length <= 128 * 1024);
          const hints = JSON.parse(raw);
          publicRevocationNeed(Array.isArray(hints) && hints.length <= 32 && hints.every(publicRevocationHint)
            && new Set(hints.map(item => item.optionsLocalDigest)).size === hints.length);
          publicRevocationHistory = hints;
        }
      } catch (_) { publicRevocationStorageFailed = true; publicRevocationMessage('Saved hints are unavailable or malformed. Effects are disabled; manual read-only recovery remains available.', true); }
      publicRevocationScope = publicRevocationAuthScope();
      $('public-revocation-inspect').addEventListener('click', () => runUiAction('Inspect revocation target',
        () => publicRevocationSelect($('public-revocation-target').value)));
      for (const [button, kind] of [['request', 'approval-request'], ['decide', 'approval-decide'], ['execute', 'execute']]) {
        $('public-revocation-' + button).addEventListener('click', () => runUiAction('Public revocation ceremony', () => publicRevocationCeremony(kind)));
      }
      for (const name of ['lookup', 'recover']) $('public-revocation-' + name).addEventListener('click',
        () => runUiAction('Read revocation outcome', () => publicRevocationRead(name)));
      $('public-revocation-history-select').addEventListener('click', () => runUiAction('Select revocation hints', async () => {
        const hint = publicRevocationHistory.find(item => item.optionsLocalDigest === $('public-revocation-history').value);
        publicRevocationNeed(hint && !publicRevocationBusy); publicRevocationShowHint(hint);
        $('public-revocation-target').value = hint.recordId; $('public-revocation-reason').value = hint.reason;
        $('public-revocation-approval').value = hint.approvalId || '';
        publicRevocationInvalidate('Restored read-only hints. Inspect the target before any distinct next phase.');
        return {uiHandled: true};
      }));
      $('public-revocation-copy').addEventListener('click', () => runUiAction('Copy revocation locators', async () => {
        const recordId = $('public-revocation-recovery-target').value, optionsLocalDigest = $('public-revocation-options').value;
        const attemptLocalDigest = $('public-revocation-attempt').value || null;
        publicRevocationNeed(publicRevocationText(recordId) && publicRevocationDigest(optionsLocalDigest)
          && (attemptLocalDigest === null || publicRevocationDigest(attemptLocalDigest)));
        await navigator.clipboard.writeText(JSON.stringify({apiVersion: publicRevocationPrefix + 'RecoveryHints/v1',
          recordId, optionsLocalDigest, attemptLocalDigest}));
        publicRevocationMessage('Copied data-only locators. Keep them for a still-authorized requester/admin; they do not grant access.');
        return {uiHandled: true};
      }));
      $('public-revocation-target').addEventListener('input', () => {
        $('public-revocation-approval').value = '';
        publicRevocationInvalidate('Target changed; inspect its current identity.');
      });
      for (const name of ['reason', 'approval']) $('public-revocation-' + name).addEventListener('input', () => {
        if (publicRevocationBusy) publicRevocationInvalidate('Revocation intent changed during an operation.');
        publicRevocationDecision = null; renderPublicRevocation();
      });
      window.addEventListener('pagehide', () => publicRevocationInvalidate('Page is leaving. Any sent outcome remains unknown.'));
      renderPublicRevocation();
    }
"""
