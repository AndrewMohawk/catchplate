"""Small purpose-specific Setup association flow; browser state grants nothing."""

from catchplate.portal_setup_native import SETUP_NATIVE_POLICY_HTML, SETUP_NATIVE_POLICY_SCRIPT

SETUP_POLICY_HTML = r"""
          <details id="setup-policy-controls">
            <summary>Associate an activated Setup with a protected candidate</summary>
            <p class="hint">Requires the actual Setup owner with credential_owner, an active exact credential generation, its completed controlled binding audit and a completed protected native policy generation. OAuth and original static creation retain version 1. Rotated static generations additionally require their literal audited rotation provenance and separately selected rotation policy. This associates review data only: it does not load policy, complete Setup or make a proxy ready.</p>
            <button type="button" class="secondary" onclick="runUiAction('Select current Setup candidate context', setupPolicySelectCurrent)">Use selected Setup — review only</button>
            <label>Setup session ID <input id="setup-policy-session" maxlength="36" autocomplete="off"></label>
            <label>Exact current Setup revision <input id="setup-policy-revision" value="3" maxlength="19" inputmode="numeric" autocomplete="off"></label>
            <label>Static credential binding event ID (blank only for OAuth activation) <input id="setup-policy-binding-event" maxlength="36" autocomplete="off"></label>
            <button type="button" onclick="runUiAction('Read rotated Setup provenance', setupPolicyReadRotation)">Read selected rotated generation provenance</button>
            <label>Unchanged public rotation provenance (blank for version 1)<textarea id="setup-policy-provenance" maxlength="40960" spellcheck="false" autocomplete="off"></textarea></label>
            <label>Completed generation request ID <input id="setup-policy-generation" maxlength="36" autocomplete="off"></label>
            <button type="button" onclick="runUiAction('Review Setup candidate', setupPolicyDraft)">Read originals + draft review</button>
            <pre id="setup-policy-review">No retained draft.</pre>
            <label><input id="setup-policy-confirm" type="checkbox">I reviewed this exact owner, credential, principal, route, candidate and generation.</label>
            <button type="button" onclick="runUiAction('Bind Setup candidate', setupPolicyBind)">Fresh hardware passkey + bind once</button>
            <button type="button" class="secondary" onclick="runUiAction('Inspect Setup candidate', setupPolicyLookup)">Read retained association only</button>
            <p id="setup-policy-status" class="hint" role="status" aria-live="polite">Keep the nonsecret session and generation IDs. An uncertain submission is not retried.</p>
            <hr>
            <h4>Separately approved policy-file publication</h4>
            <p class="hint">The Setup owner also needs the literal policy_publisher role to request or consume publication. A DIFFERENT policy_publisher approves. credential_owner alone grants no publication authority. The exact reviewed Setup revision is retained, not advanced by this association.</p>
            <button type="button" onclick="runUiAction('Draft policy-file publication', setupPolicyFileDraft)">Read actual association + draft publication</button>
            <label>Exact data-only materialization draft or resolution binding for manual handoff (no passkeys or credentials)
              <textarea id="setup-policy-file-draft" class="policy-result" spellcheck="false" autocomplete="off"></textarea></label>
            <button type="button" class="secondary" onclick="runUiAction('Review publication draft', setupPolicyFileImport)">Review this same draft; do not create a replacement</button>
            <label>Exact approval ID <input id="setup-policy-file-approval" maxlength="36" autocomplete="off"></label>
            <label><input id="setup-policy-file-confirm" type="checkbox">I reviewed the exact publication binding and its displayed materialization or resolution purpose. Resolution does not retry materialization.</label>
            <pre id="setup-policy-file-review">No publication draft reviewed.</pre>
            <button type="button" onclick="runUiAction('Request policy publication approval', () => setupPolicyFileEffect('request'))">Requester passkey + request once (expects 428)</button>
            <button type="button" onclick="runUiAction('Approve policy publication', () => setupPolicyFileEffect('decide'))">Distinct publisher passkey + approve once</button>
            <button type="button" onclick="runUiAction('Execute reviewed policy-file purpose', () => setupPolicyFileEffect('consume'))">Requester NEW passkey + execute reviewed purpose once</button>
            <button type="button" class="secondary" onclick="runUiAction('Read publication journal', setupPolicyFileInspect)">Read publication journal; never unlock retry</button>
            <h5>Separate resolution of an uncertain ordinary publication</h5>
            <p class="hint">Read the journal, select its exact incomplete intent and explicitly request an outcome. The server checks retained file bytes and inode identity; file absence is not proof of nonexecution. Resolution uses separate publisher approval and never repeats a rename. Existing materialization attempt locks remain.</p>
            <label>Retained publication intent <select id="setup-policy-file-resolution-target"><option value="">Read the journal, then select an intent</option></select></label>
            <label>Requested resolution <select id="setup-policy-file-resolution-outcome"><option value="">Choose explicitly; no outcome is inferred</option><option value="finalize-installed">Finalize only if the exact file was installed</option><option value="abandon-uninstalled">Abandon only if the exact old file and staged original remain</option></select></label>
            <label>Resolution reason (optional) <textarea id="setup-policy-file-resolution-reason" maxlength="500"></textarea></label>
            <button type="button" class="secondary" onclick="runUiAction('Review separate policy-file resolution', setupPolicyFileResolveDraft)">Review this resolution; no effect</button>
            <button type="button" class="secondary" onclick="runUiAction('Observe installed Setup policy', setupPolicyInstalled)">Owner: observe CONTROL-PLANE loader only</button>
            <pre id="setup-policy-file-observation">No installation observation. nativeGateVerified: false.</pre>
            <p id="setup-policy-file-status" class="hint" role="status" aria-live="polite">No publication sent. Share only the unchanged data-only draft and nonsecret IDs; uncertain effects remain locked locally.</p>
            __SETUP_NATIVE_POLICY_HTML__
          </details>
""".replace("__SETUP_NATIVE_POLICY_HTML__", SETUP_NATIVE_POLICY_HTML)

SETUP_POLICY_SCRIPT = r"""
    const setupPolicyPrefix = '/api/setup/policy-candidate';
    const setupPolicyRequestSchema = 'catchplate.setupPolicyCandidateRequest/v1';
    const setupPolicyOptionsSchema = 'catchplate.setupPolicyCandidateOptions/v1';
    const setupPolicyMaximumResponse = 5 * 1024 * 1024;
    let setupPolicyHeld = null, setupPolicyBusy = false;
    function setupPolicyNeed(value) { if (!value) throw new Error('Setup candidate original or authority changed; inspect without retry.'); }
    function setupPolicyMessage(text) { $('setup-policy-status').textContent = text; }
    function setupPolicyMarker(actor, session) { return 'catchplate.setup-policy.submitted:' + actor + ':' + session; }
    function setupPolicyRevision() {
      const text = $('setup-policy-revision').value.trim();
      setupPolicyNeed(/^[1-9][0-9]{0,18}$/.test(text));
      const value = BigInt(text); setupPolicyNeed(value <= 9223372036854775803n); return value;
    }
    function setupPolicyProvenance(original) {
      const value = oauthConsentParse(original, 40960).value;
      setupPolicyNeed(oauthConsentClosed(value, ['apiVersion', 'rotationRequestDigest', 'nativeEvidenceOriginal'])
        && value.apiVersion === 'catchplate.staticCredentialRotationProvenance/v1'
        && oauthConsentDigest(value.rotationRequestDigest) && oauthConsentCanonical(value) === original);
      const native = oauthConsentParse(value.nativeEvidenceOriginal, 32768).value, statement = native.statement;
      setupPolicyNeed(oauthConsentClosed(native, ['statement', 'signature', 'nativeKeyEvidence'])
        && statement?.apiVersion === 'catchplate.nativeStaticCredentialRotationStatement/v1'
        && statement.operation === 'credential.static.rotate' && nativeSetupId(statement.credentialId));
      const version = oauthConsentInteger(statement.credentialVersion);
      setupPolicyNeed(version >= 2n && version <= 9223372036854775807n);
      return {credentialId: statement.credentialId, version, requestDigest: value.rotationRequestDigest};
    }
    async function setupPolicyProvenanceDigest(original) {
      const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(original));
      return 'sha256:' + Array.from(new Uint8Array(bytes), item => item.toString(16).padStart(2, '0')).join('');
    }
    function setupPolicySelectCurrent() {
      setupPolicyNeed(!setupPolicyBusy && !adminToken() && state.authStatus?.authenticated === true
        && state.authStatus?.authMethod === 'oidc-session' && state.authStatus.roles.includes('credential_owner'));
      const session = state.setupSession;
      setupPolicyNeed(session && nativeSetupId(session.id) && session.ownerId === state.authStatus.userId
        && [null, state.authStatus.userId].includes(session.currentAssigneeId)
        && session.status === 'active' && session.phase === 'credential_activated'
        && Number.isSafeInteger(session.credentialVersion) && session.credentialVersion >= 1
        && Number.isSafeInteger(session.revision));
      const revision = BigInt(session.revision);
      setupPolicyNeed(revision >= 1n && revision <= 9223372036854775803n);
      let eventId = '';
      if (session.oauthProvider) {
        setupPolicyNeed(revision === 3n && session.credentialVersion === 1 && session.oauthPendingCredentialId === session.credentialId);
      } else {
        setupPolicyNeed(session.oauthStateDigest === null && session.oauthPendingCredentialId === null);
        const events = (session.events || []).filter(event => event.session_id === session.id
          && event.transition === 'bind_credential' && event.created_at === session.updatedAt
          && event.event?.details?.authorityOperation === 'setup.session.bind-credential'
          && event.event?.binding_updates?.credential_id === session.credentialId
          && event.event?.binding_updates?.credential_version === session.credentialVersion);
        setupPolicyNeed(events.length === 1 && nativeSetupId(events[0].id)); eventId = events[0].id;
      }
      $('setup-policy-session').value = session.id;
      $('setup-policy-revision').value = revision.toString();
      $('setup-policy-binding-event').value = eventId;
      $('setup-policy-provenance').value = '';
      $('setup-policy-generation').value = '';
      setupPolicyHeld = null; $('setup-policy-confirm').checked = false;
      $('setup-policy-controls').open = true;
      $('setup-policy-generation').focus();
      setupPolicyMessage('Selected the actual Setup revision and binding locator only. Supply the completed protected generation request ID, then explicitly review; no binding or approval was submitted.');
    }
    function setupPolicyBegin(held = null) {
      setupPolicyNeed(!setupPolicyBusy && !adminToken() && state.authStatus?.authMethod === 'oidc-session'
        && state.authStatus?.authenticated === true && state.authStatus.roles.includes('credential_owner'));
      const actor = state.authStatus.userId, scope = sessionActivationAuthScope();
      const session = $('setup-policy-session').value.trim(), generation = $('setup-policy-generation').value.trim();
      const revision = setupPolicyRevision(), bindingEvent = $('setup-policy-binding-event').value.trim();
      const provenance = $('setup-policy-provenance').value;
      setupPolicyNeed(nativeSetupId(session));
      setupPolicyNeed(bindingEvent ? nativeSetupId(bindingEvent) : revision === 3n);
      setupPolicyNeed(!provenance || bindingEvent);
      const until = held ? held.until : performance.now() + 30000;
      const expires = held ? held.expires : Date.now() + 30000;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), Math.max(0, until - performance.now()));
      const operation = {actor, scope, session, generation, revision, bindingEvent, provenance, until, expires, signal: controller.signal, current() {
        setupPolicyNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
          && !adminToken() && state.authStatus?.authenticated === true && state.authStatus?.authMethod === 'oidc-session'
          && state.authStatus.userId === actor && state.authStatus.roles.includes('credential_owner')
          && sessionActivationAuthScope() === scope && $('setup-policy-session').value.trim() === session
          && $('setup-policy-generation').value.trim() === generation && setupPolicyRevision() === revision
          && $('setup-policy-binding-event').value.trim() === bindingEvent && $('setup-policy-provenance').value === provenance);
        if (held) setupPolicyNeed(setupPolicyHeld === held && held.actor === actor && held.scope === scope
          && held.session === session && held.generation === generation && held.revision === revision && held.bindingEvent === bindingEvent
          && held.provenance === provenance
          && BigInt(Date.now()) * 1000000n < held.epochExpiry);
      }, close() { clearTimeout(timer); controller.abort(); setupPolicyBusy = false; }};
      try { operation.current(); setupPolicyBusy = true; return operation; }
      catch (error) { clearTimeout(timer); controller.abort(); throw error; }
    }
    async function setupPolicyReadRotation() {
      const operation = setupPolicyBegin();
      const session = state.setupSession, identity = setupCredentialSessionIdentity(session);
      const current = () => {
        operation.current();
        setupPolicyNeed(state.setupSession === session && setupCredentialSessionIdentity(session) === identity
          && session?.id === operation.session && BigInt(session.revision) === operation.revision
          && !session.oauthProvider && Number.isSafeInteger(session.credentialVersion) && session.credentialVersion >= 2
          && nativeSetupId(session.credentialId) && operation.bindingEvent);
      };
      const read = staticRotationOperation(current);
      try {
        current();
        const value = await staticRotationRequest('predecessor', {credentialId: session.credentialId}, read);
        current();
        setupPolicyNeed(staticRotationClosed(value, ['apiVersion', 'okForAction', 'credentialId', 'credentialVersion',
          'originRequestDigest', 'provenanceOriginal', 'provenanceSha256'])
          && value.apiVersion === 'catchplate.staticCredentialProvenanceObservation/v1' && value.okForAction === false
          && value.credentialId === session.credentialId && typeof value.provenanceOriginal === 'string');
        const exact = staticRotationNumberView(staticRotationOriginals.get(value));
        const selected = setupPolicyProvenance(value.provenanceOriginal);
        setupPolicyNeed(selected.credentialId === session.credentialId && selected.version === BigInt(session.credentialVersion)
          && BigInt(exact.credentialVersion) === selected.version && selected.requestDigest === value.originRequestDigest
          && await setupPolicyProvenanceDigest(value.provenanceOriginal) === value.provenanceSha256);
        current(); read.check();
        $('setup-policy-provenance').value = value.provenanceOriginal;
        setupPolicyHeld = null; $('setup-policy-confirm').checked = false;
        setupPolicyMessage('Exact historical rotation provenance acquired. No fresh native proof, binding, approval, drain or rotation was requested. Review the candidate explicitly.');
      } finally { read.close(); operation.close(); }
    }
    async function setupPolicyRead(response, operation, maximum = setupPolicyMaximumResponse) {
      operation.current(); setupPolicyNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let original = '', size = 0, done = false;
      try {
        for (;;) { operation.current(); const chunk = await reader.read(); operation.current();
          if (chunk.done) { done = true; break; }
          size += chunk.value.byteLength; setupPolicyNeed(size <= maximum);
          original += decoder.decode(chunk.value, {stream: true});
        }
        original += decoder.decode(); return oauthConsentParse(original, maximum).value;
      } finally { if (!done) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); original = ''; }
    }
    async function setupPolicyPost(suffix, body, operation, sent = null) {
      setupPolicyNeed(['/draft', '/options', '/bind', '/lookup', '/materialize-draft', '/installed', '/native-installed'].includes(suffix));
      const csrfReply = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: operation.signal});
      const csrf = await setupPolicyRead(csrfReply, operation);
      setupPolicyNeed(csrfReply.ok && csrf.ok === true && csrf.header === 'X-Catchplate-CSRF-Token'
        && typeof csrf.token === 'string' && csrf.token.length <= 1024);
      let original = oauthConsentCanonical(body);
      setupPolicyNeed(new TextEncoder().encode(original).length <= 4 * 1024 * 1024 + 32768);
      try {
        operation.current(); if (sent) sent();
        const response = await fetch(setupPolicyPrefix + suffix, {method: 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        const value = await setupPolicyRead(response, operation, suffix === '/native-installed' ? 524288 : setupPolicyMaximumResponse);
        setupPolicyNeed(response.ok); return value;
      } finally { original = null; }
    }
    async function setupPolicyDraft() {
      const operation = setupPolicyBegin(); setupPolicyHeld = null; $('setup-policy-confirm').checked = false;
      try {
        setupPolicyNeed(nativeSetupId(operation.generation)
          && sessionStorage.getItem(setupPolicyMarker(operation.actor, operation.session)) === null);
        const staticBinding = operation.bindingEvent ? {credentialBindingEventId: operation.bindingEvent} : {};
        const rotated = operation.provenance ? setupPolicyProvenance(operation.provenance) : null;
        const provenanceBinding = rotated ? {credentialProvenanceOriginal: operation.provenance} : {};
        const version = rotated ? rotated.version : 1n;
        const result = await setupPolicyPost('/draft', {apiVersion: setupPolicyRequestSchema, sessionId: operation.session,
          expectedRevision: new OAuthConsentNumber(operation.revision.toString()), generationRequestId: operation.generation,
          ...staticBinding, ...provenanceBinding}, operation);
        setupPolicyNeed(oauthConsentClosed(result, ['apiVersion', 'okForAction', 'argumentsOriginal', 'review'])
          && result.apiVersion === setupPolicyRequestSchema && result.okForAction === false && typeof result.argumentsOriginal === 'string');
        const args = oauthConsentParse(result.argumentsOriginal, 2 * 1024 * 1024).value;
        const request = args.request, binding = nativeSetupBinding(request?.setupBinding), review = result.review;
        setupPolicyNeed(oauthConsentClosed(args, ['actor_id', 'control_plane_configuration_digest', 'credential_policy', 'request'])
          && oauthConsentClosed(request, ['setupBinding', 'credentialId', 'credentialVersion', 'generationClaimOriginal',
            'routePolicyDigest', 'assignmentDigest', 'issuedAtEpochNs', 'expiresAtEpochNs', ...Object.keys(staticBinding), ...Object.keys(provenanceBinding)])
          && oauthConsentClosed(review, ['principalId', 'routeId', 'credentialId', 'credentialVersion', 'policyHash',
            'routePolicyDigest', 'assignmentDigest', 'sessionId', 'setupRevision', 'continuationRevision', 'ownerId',
            'generationRequestId', 'generationPublicationDigest', 'candidateId', 'canaryId', 'expiresAtEpochNs', ...Object.keys(staticBinding),
            ...(rotated ? ['credentialProvenanceSha256'] : [])]));
        const claim = oauthConsentParse(request.generationClaimOriginal, 2 * 1024 * 1024).value;
        setupPolicyNeed(args.actor_id === operation.actor && binding.sessionId === operation.session && binding.ownerId === operation.actor
          && oauthConsentInteger(binding.revision) === operation.revision && oauthConsentInteger(request.credentialVersion) === version
          && claim.request_id === operation.generation && oauthConsentDigest(claim.publication_envelope_digest)
          && review.sessionId === operation.session && review.ownerId === operation.actor
          && review.generationRequestId === operation.generation && review.generationPublicationDigest === claim.publication_envelope_digest
          && review.credentialId === request.credentialId && oauthConsentInteger(review.credentialVersion) === version
          && review.routePolicyDigest === request.routePolicyDigest && review.assignmentDigest === request.assignmentDigest
          && oauthConsentInteger(review.setupRevision) === operation.revision && oauthConsentInteger(review.continuationRevision) === 0n
          && (!operation.bindingEvent || request.credentialBindingEventId === operation.bindingEvent
            && review.credentialBindingEventId === operation.bindingEvent));
        if (rotated) setupPolicyNeed(request.credentialProvenanceOriginal === operation.provenance
          && request.credentialId === rotated.credentialId
          && review.credentialProvenanceSha256 === await setupPolicyProvenanceDigest(operation.provenance));
        operation.current();
        const epochExpiry = oauthConsentInteger(request.expiresAtEpochNs);
        setupPolicyNeed(epochExpiry === oauthConsentInteger(review.expiresAtEpochNs)
          && BigInt(Date.now()) * 1000000n < epochExpiry && epochExpiry <= oauthConsentInteger(binding.expiresAtEpochNs));
        setupPolicyHeld = {original: result.argumentsOriginal, actor: operation.actor, scope: operation.scope,
          session: operation.session, generation: operation.generation, revision: operation.revision, bindingEvent: operation.bindingEvent,
          provenance: operation.provenance,
          until: operation.until, expires: operation.expires, epochExpiry};
        $('setup-policy-review').textContent = oauthConsentCanonical(review);
        setupPolicyMessage('Exact review retained briefly. Candidate binding still requires your fresh hardware passkey; original expiry is not renewed.');
      } catch (error) { setupPolicyHeld = null; setupPolicyMessage('No binding submitted. Check the exact current revision/generation, binding audit, required rotation provenance and completed policy generation. If a prior submission was uncertain, use lookup only.'); throw error; }
      finally { operation.close(); }
    }
    async function setupPolicyBind() {
      const held = setupPolicyHeld;
      setupPolicyNeed(held && $('setup-policy-confirm').checked);
      const operation = setupPolicyBegin(held); let assertion = null, sent = false;
      try {
        const marker = setupPolicyMarker(operation.actor, operation.session);
        setupPolicyNeed(sessionStorage.getItem(marker) === null);
        const options = await setupPolicyPost('/options', {apiVersion: setupPolicyOptionsSchema, argumentsOriginal: held.original}, operation);
        setupPolicyNeed(oauthConsentClosed(options, ['publicKey', 'catchplate'])
          && oauthConsentClosed(options.publicKey, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          && oauthConsentClosed(options.catchplate, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && options.catchplate.schema === setupPolicyOptionsSchema && options.catchplate.operation === 'setup.policy.bind-candidate'
          && oauthConsentDigest(options.catchplate.operationId) && oauthConsentDigest(options.catchplate.challengeId)
          && typeof options.catchplate.credentialRecordId === 'string'
          && new TextEncoder().encode(options.catchplate.credentialRecordId).length <= 256
          && options.catchplate.payloadDigest === await workloadIssuanceHash(new TextEncoder().encode(held.original)));
        assertion = await nativeSetupPasskey(options, operation);
        const result = await setupPolicyPost('/bind', {apiVersion: setupPolicyOptionsSchema, argumentsOriginal: held.original,
          mfa: {setupPolicyProfile: setupPolicyOptionsSchema, assertion}}, operation, () => {
            // Only nonsecret recovery IDs survive reload; never an assertion,
            // returned original or marker that could become server authority.
            sessionStorage.setItem(marker, operation.generation); setupPolicyNeed(sessionStorage.getItem(marker) === operation.generation); sent = true;
          });
        setupPolicyNeed(oauthConsentClosed(result, ['ok', 'operation', 'requestDigest', 'auditEventDigest', 'idempotentReplay', 'continuationOriginal'])
          && result.ok === true && result.operation === 'setup.policy.bind-candidate' && result.idempotentReplay === false
          && oauthConsentDigest(result.requestDigest) && oauthConsentDigest(result.auditEventDigest)
          && typeof result.continuationOriginal === 'string');
        const row = oauthConsentParse(result.continuationOriginal, 2170880).value;
        setupPolicyNeed(row.session_id === held.session && row.owner_id === held.actor && row.generation_request_id === held.generation
          && row.request_original === held.original && row.request_digest === result.requestDigest
          && row.phase === 'candidate_bound' && oauthConsentInteger(row.revision) === 0n);
        $('setup-policy-review').textContent = result.continuationOriginal;
        setupPolicyMessage('Exact candidate association retained. Policy loading, canary evidence, enrollment, final Setup and proxy readiness remain separate.');
      } catch (error) { setupPolicyMessage(sent ? 'Bind outcome may be unknown. Keep these IDs and use read-only lookup; no repeat was authorized.'
          : 'Passkey or original prerequisites did not complete. No bind was sent.'); throw error; }
      finally { assertion = null; setupPolicyHeld = null; $('setup-policy-confirm').checked = false; operation.close(); }
    }
    async function setupPolicyLookup() {
      const operation = setupPolicyBegin();
      try {
        const result = await setupPolicyPost('/lookup', {apiVersion: setupPolicyRequestSchema, sessionId: operation.session}, operation);
        setupPolicyNeed(oauthConsentClosed(result, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'continuationOriginal'])
          && result.apiVersion === 'catchplate.setupPolicyCandidateObservation/v1' && result.okForAction === false
          && result.automaticRetryAllowed === false);
        if (result.continuationOriginal === null) {
          setupPolicyMessage('No association observed. This is unknown after an interrupted submission, not permission to repeat it.');
        } else {
          const row = oauthConsentParse(result.continuationOriginal, 2170880).value;
          setupPolicyNeed(row.session_id === operation.session && row.owner_id === operation.actor && row.phase === 'candidate_bound'
            && oauthConsentInteger(row.revision) === 0n);
          $('setup-policy-review').textContent = result.continuationOriginal;
          setupPolicyMessage('Retained association observed read-only. It is not loaded policy, completed Setup, retry permission or proxy readiness.');
        }
      } finally { operation.close(); }
    }

    // Separate policy-file ceremonies. Data-only drafts/observations are never
    // bearer permissions; every effect uses the existing hardware authority.
    const setupFileOptions = 'catchplate.policyFileApprovalOptions/v1';
    const setupFileRequest = 'catchplate.setupPolicyMaterializationRequest/v1';
    const setupFileBase = '/api/policy/file-publication';
    let setupFileHeld = null;
    const setupFileBytes = value => new TextEncoder().encode(value);
    const setupFileId = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
    function setupFileMessage(text) { $('setup-policy-file-status').textContent = text; }
    function setupFileBegin(held = null, mode = 'materialize') {
      setupPolicyNeed(!setupPolicyBusy && window.isSecureContext && window.top === window && !adminToken()
        && state.authStatus?.authenticated === true && state.authStatus.authMethod === 'oidc-session'
        && state.authStatus.roles.includes('policy_publisher'));
      const actor = state.authStatus.userId, scope = sessionActivationAuthScope(), session = $('setup-policy-session').value.trim();
      const revisionText = $('setup-policy-revision').value.trim(), revision = mode === 'materialize' ? setupPolicyRevision() : null;
      const draft = $('setup-policy-file-draft').value, approval = $('setup-policy-file-approval').value.trim();
      const resolutionSelection = JSON.stringify(['target', 'outcome', 'reason'].map(name => $('setup-policy-file-resolution-' + name).value));
      setupPolicyNeed(['materialize', 'resolve', 'inspect'].includes(mode)
        && (nativeSetupId(session) || mode !== 'materialize' && session === ''));
      const controller = new AbortController(), until = performance.now() + 30000, expires = Date.now() + 30000;
      const timer = setTimeout(() => controller.abort(), 30000); setupPolicyBusy = true;
      return {actor, scope, session, revision, approval, signal: controller.signal, current() {
        setupPolicyNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
          && !adminToken() && state.authStatus?.authenticated === true && state.authStatus.authMethod === 'oidc-session'
          && state.authStatus.userId === actor && state.authStatus.roles.includes('policy_publisher')
          && sessionActivationAuthScope() === scope && $('setup-policy-session').value.trim() === session
          && $('setup-policy-revision').value.trim() === revisionText
          && $('setup-policy-file-draft').value === draft && $('setup-policy-file-approval').value.trim() === approval
          && JSON.stringify(['target', 'outcome', 'reason'].map(name => $('setup-policy-file-resolution-' + name).value)) === resolutionSelection);
        if (held) setupPolicyNeed(setupFileHeld === held && held.raw === draft && held.session === session
          && $('setup-policy-file-confirm').checked
          && (held.binding.kind !== 'resolve' || held.resolutionSelection === resolutionSelection));
      }, close() { clearTimeout(timer); controller.abort(); setupPolicyBusy = false; }};
    }
    async function setupFileCookie(operation) {
      const reply = await oauthConsentRequest('/api/auth/status', null, operation), value = reply.value;
      setupPolicyNeed(reply.status === 200 && value.authenticated === true && value.authMethod === 'oidc-session'
        && value.userId === operation.actor && value.sessionState === 'active' && value.webauthnRequired === false
        && Array.isArray(value.roles) && value.roles.length <= 64 && value.roles.includes('policy_publisher')
        && value.roles.every(role => oauthConsentText(role, 128)) && new Set(value.roles).size === value.roles.length
        && JSON.stringify([...value.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
      operation.current();
    }
    async function setupFileCall(path, body, operation, sent = null) {
      const get = body === null;
      setupPolicyNeed(get ? [setupFileBase, '/api/control-plane/approvals?limit=100'].includes(path)
        : [setupFileBase + '/webauthn/options', setupFileBase + '/materialize', setupFileBase + '/resolve'].includes(path)
          || /^\/api\/control-plane\/approvals\/[0-9a-f-]{36}\/approve$/.test(path));
      let original = null, csrf = null;
      try {
        if (!get) {
          const reply = await oauthConsentRequest('/api/csrf', null, operation), value = reply.value;
          setupPolicyNeed(reply.status === 200 && value.ok === true && value.header === 'X-Catchplate-CSRF-Token'
            && oauthConsentText(value.token, 1024)); csrf = value.token;
          original = oauthConsentCanonical(body); setupPolicyNeed(setupFileBytes(original).length <= 4227072);
        }
        operation.current(); if (sent) sent();
        const response = await fetch(path, {method: get ? 'GET' : 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: get ? {} : {'Content-Type': 'application/json', 'X-Catchplate-CSRF-Token': csrf}, body: original});
        return {status: response.status, ok: response.ok, value: await setupPolicyRead(response, operation)};
      } finally { original = null; csrf = null; }
    }
    function setupFileHistory(session, resolution = false) {
      const key = (resolution ? 'catchplate.setup-policy.file-resolution-attempts:' : 'catchplate.setup-policy.file-attempts:') + session;
      const raw = sessionStorage.getItem(key);
      setupPolicyNeed(raw === null || setupFileBytes(raw).length <= 65536);
      const rows = raw === null ? [] : oauthConsentParse(raw, 65536).value;
      setupPolicyNeed(Array.isArray(rows) && rows.length <= 32 && rows.every(row =>
        oauthConsentClosed(row, ['phase', 'publicationId', 'payloadDigest', 'approvalId', 'actorId', 'status'])
        && ['request', 'decide', 'consume'].includes(row.phase) && setupFileId(row.publicationId)
        && oauthConsentDigest(row.payloadDigest) && (row.approvalId === null || nativeSetupId(row.approvalId))
        && oauthConsentText(row.actorId, 512) && row.actorId.startsWith('oidc:')
        && ['unresolved', 'approval-observed', 'completion-observed'].includes(row.status)));
      return {key, rows};
    }
    function setupFileSave(history) {
      const raw = oauthConsentCanonical(history.rows);
      setupPolicyNeed(history.rows.length <= 32 && setupFileBytes(raw).length <= 65536);
      sessionStorage.setItem(history.key, raw); setupPolicyNeed(sessionStorage.getItem(history.key) === raw);
    }
    function setupFileBlocked(history, held, phase, approval) {
      return history.rows.some(row => row.phase === phase && (phase === 'request'
        || row.publicationId === held.body.publicationId || row.approvalId === approval));
    }
    function setupFileAttemptHistory(held, session) {
      return held.binding.kind === 'resolve' ? setupFileHistory(held.body.publicationId, true) : setupFileHistory(session);
    }
    async function setupFileJournal(operation) {
      const reply = await setupFileCall(setupFileBase, null, operation), value = reply.value;
      setupPolicyNeed(reply.ok && oauthConsentClosed(value, ['schema', 'fileSha256', 'automaticRetryAllowed',
        'incompletePublicationId', 'terminalSha256', 'attempts', 'terminalMatches'])
        && value.schema === 'catchplate.policyFilePublicationObservation/v1' && value.automaticRetryAllowed === false
        && (value.fileSha256 === null || oauthConsentDigest(value.fileSha256))
        && (value.terminalSha256 === null || oauthConsentDigest(value.terminalSha256))
        && (value.incompletePublicationId === null || setupFileId(value.incompletePublicationId))
        && typeof value.terminalMatches === 'boolean' && Array.isArray(value.attempts) && value.attempts.length <= 16
        && value.attempts.every(item => oauthConsentClosed(item, ['publicationId', 'intentSha256', 'binding', 'resolutionClaimed'])
          && setupFileId(item.publicationId) && oauthConsentDigest(item.intentSha256) && typeof item.resolutionClaimed === 'boolean'
          && item.binding?.publicationId === item.publicationId)
        && new Set(value.attempts.map(item => item.publicationId)).size === value.attempts.length);
      operation.current(); return value;
    }
    function setupFileResolutionIntent(observed, binding) {
      const matches = observed.attempts.filter(item => item.publicationId === binding.publicationId);
      setupPolicyNeed(observed.incompletePublicationId === binding.publicationId && matches.length === 1
        && matches[0].intentSha256 === binding.intentSha256 && matches[0].resolutionClaimed === false
        && matches[0].binding.kind === 'materialize');
      return oauthConsentCanonical(matches[0].binding);
    }
    async function setupFileResolutionAccept(raw, operation, observed = null) {
      setupPolicyNeed(setupFileBytes(raw).length <= 8192);
      const binding = oauthConsentParse(raw, 8192).value;
      setupPolicyNeed(oauthConsentClosed(binding, ['kind', 'publicationId', 'intentSha256', 'outcome', 'reason'])
        && binding.kind === 'resolve' && oauthConsentCanonical(binding) === raw && setupFileId(binding.publicationId)
        && oauthConsentDigest(binding.intentSha256) && ['finalize-installed', 'abandon-uninstalled'].includes(binding.outcome)
        && (binding.reason === null || typeof binding.reason === 'string' && Array.from(binding.reason).length <= 500));
      const materialOriginal = setupFileResolutionIntent(observed || await setupFileJournal(operation), binding);
      const digest = await workloadIssuanceHash(setupFileBytes(raw)); operation.current();
      const body = {publicationId: binding.publicationId, intentSha256: binding.intentSha256, outcome: binding.outcome, reason: binding.reason};
      $('setup-policy-file-review').textContent = 'SEPARATE RESOLUTION — data-only requested outcome, not proof of installation or permission to retry.\n'
        + 'Exact resolution binding:\n' + raw + '\nPayload digest: ' + digest + '\nRetained materialization binding:\n' + materialOriginal
        + '\nA current publisher requests; a different publisher approves; the same requester supplies a NEW passkey. The server alone checks the actual file outcome.';
      const resolutionSelection = JSON.stringify(['target', 'outcome', 'reason'].map(name => $('setup-policy-file-resolution-' + name).value));
      return {raw, session: operation.session, draft: {bindingOriginal: raw}, continuation: null, body, binding, digest, materialOriginal, resolutionSelection};
    }
    async function setupFileRecheckResolution(held, operation) {
      if (held.binding.kind !== 'resolve') return;
      setupPolicyNeed(setupFileResolutionIntent(await setupFileJournal(operation), held.binding) === held.materialOriginal);
      operation.current();
    }
    async function setupPolicyFileResolveDraft() {
      const operation = setupFileBegin(null, 'resolve'); setupFileHeld = null; $('setup-policy-file-confirm').checked = false;
      try {
        const publicationId = $('setup-policy-file-resolution-target').value, outcome = $('setup-policy-file-resolution-outcome').value;
        const reason = $('setup-policy-file-resolution-reason').value || null;
        setupPolicyNeed(setupFileId(publicationId) && ['finalize-installed', 'abandon-uninstalled'].includes(outcome));
        await setupFileCookie(operation);
        const observed = await setupFileJournal(operation), matches = observed.attempts.filter(item => item.publicationId === publicationId);
        setupPolicyNeed(matches.length === 1);
        const raw = oauthConsentCanonical({kind: 'resolve', publicationId, intentSha256: matches[0].intentSha256, outcome, reason});
        const held = await setupFileResolutionAccept(raw, operation, observed); operation.current();
        $('setup-policy-file-draft').value = raw; setupFileHeld = held;
        setupFileMessage('Resolution binding reviewed only. No outcome inferred or effect sent. Clear the approval ID yourself before a new request; share this unchanged binding and its actual approval ID for the separate ceremony.');
      } finally { operation.close(); }
    }
    async function setupFileAccept(raw, operation) {
      setupPolicyNeed(typeof raw === 'string' && setupFileBytes(raw).length <= setupPolicyMaximumResponse);
      const draft = oauthConsentParse(raw, setupPolicyMaximumResponse).value;
      if (draft?.kind === 'resolve') return setupFileResolutionAccept(raw, operation);
      setupPolicyNeed(oauthConsentClosed(draft, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'continuationOriginal', 'requestOriginal', 'bindingOriginal'])
        && draft.apiVersion === 'catchplate.setupPolicyMaterializationDraft/v1' && draft.okForAction === false && draft.automaticRetryAllowed === false);
      for (const [name, maximum] of [['continuationOriginal', 2170880], ['requestOriginal', 1400000], ['bindingOriginal', 8192]]) {
        setupPolicyNeed(typeof draft[name] === 'string' && /^[\x00-\x7f]*$/.test(draft[name])
          && setupFileBytes(draft[name]).length <= maximum);
      }
      const continuation = oauthConsentParse(draft.continuationOriginal, 2170880).value;
      const setupOriginal = oauthConsentParse(continuation.setup_original, 65536).value;
      setupPolicyNeed(setupOriginal.id === operation.session && oauthConsentInteger(setupOriginal.revision) === operation.revision);
      const body = oauthConsentParse(draft.requestOriginal, 1400000).value, binding = oauthConsentParse(draft.bindingOriginal, 8192).value;
      setupPolicyNeed(oauthConsentCanonical(body) === draft.requestOriginal && oauthConsentCanonical(binding) === draft.bindingOriginal
        && oauthConsentClosed(body, ['publicationId', 'policyOriginalBase64url', 'artifactEnvelopeSha256', 'expectedFileSha256', 'reason'])
        && oauthConsentClosed(binding, ['kind', 'publicationId', 'reason', 'policyOriginalSha256', 'policyId', 'sequence',
          'rollbackEpoch', 'policyHash', 'policyBundleSha256', 'expectedFileSha256', 'artifactEnvelopeSha256'])
        && setupFileId(body.publicationId) && body.reason === null && binding.reason === null && binding.kind === 'materialize'
        && binding.publicationId === body.publicationId && oauthConsentDigest(body.expectedFileSha256)
        && binding.expectedFileSha256 === body.expectedFileSha256 && oauthConsentDigest(body.artifactEnvelopeSha256)
        && binding.artifactEnvelopeSha256 === body.artifactEnvelopeSha256 && oauthConsentText(binding.policyId, 256)
        && ['policyOriginalSha256', 'policyHash', 'policyBundleSha256'].every(name => oauthConsentDigest(binding[name])));
      for (const name of ['sequence', 'rollbackEpoch']) setupPolicyNeed(oauthConsentInteger(binding[name]) > 0n && oauthConsentInteger(binding[name]) <= 9223372036854775807n);
      setupPolicyNeed(continuation.session_id === operation.session && continuation.phase === 'candidate_bound'
        && oauthConsentInteger(continuation.revision) === 0n && oauthConsentText(continuation.owner_id, 512)
        && continuation.owner_id.startsWith('oidc:') && continuation.artifact_envelope_digest === binding.artifactEnvelopeSha256
        && continuation.policy_hash === binding.policyHash && nativeSetupId(continuation.generation_request_id));
      const encoded = body.policyOriginalBase64url;
      setupPolicyNeed(typeof encoded === 'string' && encoded.length > 0 && encoded.length <= 1398102 && /^[A-Za-z0-9_-]+$/.test(encoded));
      const binary = atob(encoded.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - encoded.length % 4) % 4));
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      setupPolicyNeed(bytes.length <= 1048576 && btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '') === encoded
        && await workloadIssuanceHash(bytes) === binding.policyOriginalSha256);
      const digest = await workloadIssuanceHash(setupFileBytes(draft.bindingOriginal)); operation.current();
      const held = {raw, session: operation.session, draft, continuation, body, binding, digest};
      $('setup-policy-file-review').textContent = 'Data-only review; signatures and permission are checked by the real server owners.\n'
        + 'Setup owner: ' + continuation.owner_id + '\nCandidate: ' + continuation.candidate_id + '\nExact binding:\n'
        + draft.bindingOriginal + '\nPayload digest: ' + digest + '\nExact signed policy bytes (decoded):\n'
        + new TextDecoder('utf-8', {fatal: true}).decode(bytes);
      return held;
    }
    async function setupPolicyFileDraft() {
      const operation = setupFileBegin(); setupFileHeld = null; $('setup-policy-file-confirm').checked = false;
      try {
        setupPolicyNeed(state.authStatus.roles.includes('credential_owner') && setupFileHistory(operation.session).rows.length === 0);
        await setupFileCookie(operation);
        const draft = await setupPolicyPost('/materialize-draft', {apiVersion: setupFileRequest, sessionId: operation.session,
          expectedRevision: new OAuthConsentNumber(operation.revision.toString())}, operation);
        const raw = oauthConsentCanonical(draft), held = await setupFileAccept(raw, operation);
        setupPolicyNeed(held.continuation.owner_id === operation.actor); operation.current();
        $('setup-policy-file-draft').value = raw; setupFileHeld = held;
        setupFileMessage('Exact draft retained in this page only. Review it, then request approval once; share the SAME data-only draft with a different publisher.');
      } finally { operation.close(); }
    }
    async function setupPolicyFileImport() {
      const raw = $('setup-policy-file-draft').value;
      const resolving = oauthConsentParse(raw, setupPolicyMaximumResponse).value?.kind === 'resolve';
      const operation = setupFileBegin(null, resolving ? 'resolve' : 'materialize'); setupFileHeld = null; $('setup-policy-file-confirm').checked = false;
      try { await setupFileCookie(operation); setupFileHeld = await setupFileAccept(raw, operation);
        setupFileMessage('Data-only draft reviewed. An approval phase also requires the actual authenticated approval row and a fresh hardware assertion.');
      } finally { operation.close(); }
    }
    async function setupFileApproval(held, phase, operation) {
      setupPolicyNeed(nativeSetupId(operation.approval));
      const reply = await setupFileCall('/api/control-plane/approvals?limit=100', null, operation);
      setupPolicyNeed(reply.ok && Array.isArray(reply.value) && reply.value.length <= 100);
      const matches = reply.value.filter(row => row?.id === operation.approval); setupPolicyNeed(matches.length === 1);
      const row = matches[0];
      // The authenticated listing exposes parsed `request`, not request_json.
      // Exact-integer canonicalization must reproduce the reviewed binding and
      // its stored digest; real effect owners still check the DB original.
      const resolving = held.binding.kind === 'resolve';
      setupPolicyNeed(row.action === (resolving ? 'policy.file.resolve' : 'policy.file.materialize') && row.resource_id === 'active-policy-file'
        && row.payload_digest === held.digest && row.request && oauthConsentCanonical(row.request) === held.draft.bindingOriginal
        && (resolving || row.requester_id === held.continuation.owner_id) && oauthConsentText(row.requester_id, 512)
        && row.requester_id.startsWith('oidc:')
        && typeof row.expires_at === 'string' && row.expires_at.length <= 128 && Date.parse(row.expires_at) > Date.now());
      setupPolicyNeed(phase === 'decide' ? row.status === 'pending' && row.requester_id !== operation.actor && row.approved_by === null
        : row.status === 'approved' && row.requester_id === operation.actor && oauthConsentText(row.approved_by, 512) && row.approved_by !== operation.actor);
      return row;
    }
    async function setupPolicyFileEffect(phase) {
      setupPolicyNeed(['request', 'decide', 'consume'].includes(phase) && setupFileHeld && $('setup-policy-file-confirm').checked);
      const held = setupFileHeld, operation = setupFileBegin(held, held.binding.kind === 'resolve' ? 'resolve' : 'materialize'); let assertion = null, sent = false;
      try {
        const resolving = held.binding.kind === 'resolve', action = resolving ? 'policy.file.resolve' : 'policy.file.materialize';
        const history = setupFileAttemptHistory(held, operation.session);
        setupPolicyNeed(!setupFileBlocked(history, held, phase, operation.approval) && history.rows.length < 32);
        await setupFileCookie(operation); await setupFileRecheckResolution(held, operation);
        const row = phase === 'request' ? null : await setupFileApproval(held, phase, operation);
        if (!resolving && phase !== 'decide') setupPolicyNeed(held.continuation.owner_id === operation.actor && state.authStatus.roles.includes('credential_owner'));
        if (phase === 'request') setupPolicyNeed(operation.approval === '');
        const optionsBody = {apiVersion: setupFileOptions, action, resourceId: 'active-policy-file',
          payloadDigest: held.digest, request: held.binding}; if (row) optionsBody.approvalId = row.id;
        const optionsReply = await setupFileCall(setupFileBase + '/webauthn/options', optionsBody, operation);
        const options = optionsReply.value, proof = options?.catchplate;
        setupPolicyNeed(optionsReply.ok && oauthConsentClosed(options, ['publicKey', 'catchplate'])
          && oauthConsentClosed(proof, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && proof.schema === setupFileOptions && proof.operation === 'policy-file-approval.' + phase
          && proof.payloadDigest === held.digest && oauthConsentDigest(proof.operationId) && oauthConsentDigest(proof.challengeId)
          && oauthConsentText(proof.credentialRecordId, 256));
        assertion = await nativeSetupPasskey(options, operation);
        // Refresh the same real approval immediately before the effect; never
        // take a UI flag, draft, row status from storage or missing row as permission.
        if (row) await setupFileApproval(held, phase, operation);
        await setupFileRecheckResolution(held, operation);
        const mfa = {publicationProfile: setupFileOptions, assertion}; if (phase === 'consume') mfa.approvalId = row.id;
        const path = phase === 'decide' ? '/api/control-plane/approvals/' + row.id + '/approve' : setupFileBase + (resolving ? '/resolve' : '/materialize');
        const body = phase === 'decide' ? {note: null, mfa} : {...held.body, mfa};
        let marker;
        const reply = await setupFileCall(path, body, operation, () => {
          const current = setupFileAttemptHistory(held, operation.session);
          setupPolicyNeed(!setupFileBlocked(current, held, phase, operation.approval) && current.rows.length < 32);
          marker = {phase, publicationId: held.body.publicationId, payloadDigest: held.digest,
            approvalId: row?.id || null, actorId: operation.actor, status: 'unresolved'};
          current.rows.push(marker); setupFileSave(current); sent = true;
          history.rows = current.rows;
        });
        if (phase === 'request') {
          const detail = reply.value?.detail;
          setupPolicyNeed(reply.status === 428 && detail?.error === 'control_plane_approval_required' && nativeSetupId(detail.approvalId)
            && detail.status === 'pending' && detail.action === action && detail.resourceId === 'active-policy-file' && detail.payloadDigest === held.digest);
          marker.approvalId = detail.approvalId; marker.status = 'approval-observed'; setupFileSave(history);
          $('setup-policy-file-approval').value = detail.approvalId;
          setupFileMessage('Pending approval observed, not completion. Give the same reviewed binding and approval ID to a DIFFERENT policy_publisher.');
        } else if (phase === 'decide') {
          setupPolicyNeed(reply.ok && reply.value.id === row.id && reply.value.status === 'approved'
            && reply.value.requester_id === row.requester_id && reply.value.approved_by === operation.actor && reply.value.payload_digest === held.digest);
          marker.status = 'approval-observed'; setupFileSave(history);
          setupFileMessage('Distinct publisher approval observed. The original requester must review this SAME draft and approval, then provide a NEW consume assertion.');
        } else {
          const value = reply.value;
          setupPolicyNeed(reply.ok && oauthConsentClosed(value, ['schema', 'ok', 'publicationId', 'completionSha256', 'outcome', 'automaticRetryAllowed'])
            && value.schema === 'catchplate.policyFilePublicationResult/v1' && value.ok === true && value.publicationId === held.body.publicationId
            && oauthConsentDigest(value.completionSha256) && value.outcome === (resolving ? held.binding.outcome : 'materialized') && value.automaticRetryAllowed === false);
          marker.status = 'completion-observed'; setupFileSave(history);
          setupFileMessage((resolving ? 'Resolution completion observed; materialization was not repeated and its old attempt locks remain. ' : 'Materializer completion observed. ')
            + 'This is NOT native gate verification, proxy readiness, action authorization or Setup completion. Use the separate installed observation.');
        }
      } catch (error) { setupFileMessage(sent ? 'Outcome may be unresolved. Keep the nonsecret IDs and inspect only; the dispatched ceremony remains locked and must not be resent.'
          : 'No materialization/resolution/approval effect sent. Required role, unchanged intent, approval or fresh passkey was unavailable.'); throw error;
      } finally { assertion = null; setupFileHeld = null; $('setup-policy-file-confirm').checked = false; operation.close(); }
    }
    async function setupPolicyFileInspect() {
      const operation = setupFileBegin(null, 'inspect');
      try { await setupFileCookie(operation); const value = await setupFileJournal(operation);
        $('setup-policy-file-observation').textContent = oauthConsentCanonical(value);
        const target = $('setup-policy-file-resolution-target'), selected = target.value;
        const candidates = value.attempts.filter(item => item.publicationId === value.incompletePublicationId
          && item.resolutionClaimed === false && item.binding.kind === 'materialize');
        target.innerHTML = '<option value="">Select the exact incomplete ordinary intent</option>' + candidates.map(item =>
          `<option value="${esc(item.publicationId)}">${esc(item.publicationId)} / ${esc(item.intentSha256)}</option>`).join('');
        target.value = candidates.some(item => item.publicationId === selected) ? selected : '';
        setupFileMessage('Read-only bounded journal observation. Missing or incomplete publication remains unknown; no local marker was cleared and no retry was authorized.');
      } finally { operation.close(); }
    }
    async function setupPolicyInstalled() {
      const operation = setupPolicyBegin();
      try {
        await oauthConsentCookie(operation);
        const value = await setupPolicyPost('/installed', {apiVersion: setupFileRequest, sessionId: operation.session,
          expectedRevision: new OAuthConsentNumber(operation.revision.toString())}, operation);
        setupPolicyNeed(oauthConsentClosed(value, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'nativeGateVerified', 'observationOriginal'])
          && value.apiVersion === 'catchplate.setupPolicyInstalledObservation/v1' && value.okForAction === false
          && value.automaticRetryAllowed === false && value.nativeGateVerified === false && typeof value.observationOriginal === 'string');
        const observed = oauthConsentParse(value.observationOriginal, 131072).value;
        setupPolicyNeed(oauthConsentClosed(observed, ['schema', 'scope', 'okForAction', 'automaticRetryAllowed', 'nativeGateVerified',
          'setupSessionId', 'continuationSha256', 'publicationId', 'completionSha256', 'policyFileSha256', 'policyFileIdentity',
          'assignment', 'journalOriginals', 'approvalOriginal', 'settlementAuditOriginal', 'observedAtEpochNs'])
          && observed.schema === 'catchplate.setupLoadedPolicyObservation/v1' && observed.scope === 'control-plane-loaded-policy-only'
          && observed.okForAction === false && observed.automaticRetryAllowed === false && observed.nativeGateVerified === false
          && observed.setupSessionId === operation.session && setupFileId(observed.publicationId)
          && ['continuationSha256', 'completionSha256', 'policyFileSha256'].every(name => oauthConsentDigest(observed[name]))
          && Array.isArray(observed.policyFileIdentity) && observed.policyFileIdentity.length === 9
          && oauthConsentClosed(observed.assignment, ['principalId', 'routeId', 'credentialId', 'credentialVersion', 'policyHash', 'routePolicyDigest'])
          && oauthConsentInteger(observed.observedAtEpochNs) > 0n && oauthConsentInteger(observed.observedAtEpochNs) <= 9223372036854775807n);
        if (oauthConsentInteger(observed.assignment.credentialVersion) !== 1n) {
          const lookup = await setupPolicyPost('/lookup', {apiVersion: setupPolicyRequestSchema, sessionId: operation.session}, operation);
          setupPolicyNeed(oauthConsentClosed(lookup, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'continuationOriginal'])
            && lookup.apiVersion === 'catchplate.setupPolicyCandidateObservation/v1' && lookup.okForAction === false
            && lookup.automaticRetryAllowed === false && typeof lookup.continuationOriginal === 'string'
            && await setupPolicyProvenanceDigest(lookup.continuationOriginal) === observed.continuationSha256);
          const row = oauthConsentParse(lookup.continuationOriginal, 2170880).value;
          const args = oauthConsentParse(row.request_original, 2 * 1024 * 1024).value, request = args.request;
          setupPolicyNeed(oauthConsentClosed(request, ['setupBinding', 'credentialId', 'credentialVersion', 'generationClaimOriginal',
            'routePolicyDigest', 'assignmentDigest', 'issuedAtEpochNs', 'expiresAtEpochNs', 'credentialBindingEventId', 'credentialProvenanceOriginal']));
          const provenance = setupPolicyProvenance(request.credentialProvenanceOriginal);
          setupPolicyNeed(row.session_id === operation.session && row.credential_id === observed.assignment.credentialId
            && request.credentialId === row.credential_id && provenance.credentialId === row.credential_id
            && oauthConsentInteger(row.credential_version) === provenance.version
            && oauthConsentInteger(request.credentialVersion) === provenance.version
            && oauthConsentInteger(observed.assignment.credentialVersion) === provenance.version);
          operation.current();
        }
        $('setup-policy-file-observation').textContent = 'CONTROL-PLANE loader only — nativeGateVerified: false.\n' + value.observationOriginal;
        setupFileMessage('Actual control-plane loaded observation only. Native immutable policy/startup enrollment is separate; this grants no action, proxy readiness, retry or Setup completion.');
      } finally { operation.close(); }
    }
""" + SETUP_NATIVE_POLICY_SCRIPT
