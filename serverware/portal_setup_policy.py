"""Small purpose-specific Setup association flow; browser state grants nothing."""

SETUP_POLICY_HTML = r"""
          <details id="setup-policy-controls">
            <summary>Associate an activated Setup with a protected candidate</summary>
            <p class="hint">Requires the actual Setup owner with credential_owner, activated revision 3, completed activation audit, an active credential and a completed protected native generation. This binds review data only: it does not load policy, complete Setup or make a proxy ready.</p>
            <label>Setup session ID <input id="setup-policy-session" maxlength="36" autocomplete="off"></label>
            <label>Completed generation request ID <input id="setup-policy-generation" maxlength="36" autocomplete="off"></label>
            <button type="button" onclick="runUiAction('Review Setup candidate', setupPolicyDraft)">Read originals + draft review</button>
            <pre id="setup-policy-review">No retained draft.</pre>
            <label><input id="setup-policy-confirm" type="checkbox">I reviewed this exact owner, credential, principal, route, candidate and generation.</label>
            <button type="button" onclick="runUiAction('Bind Setup candidate', setupPolicyBind)">Fresh hardware passkey + bind once</button>
            <button type="button" class="secondary" onclick="runUiAction('Inspect Setup candidate', setupPolicyLookup)">Read retained association only</button>
            <p id="setup-policy-status" class="hint" role="status" aria-live="polite">Keep the nonsecret session and generation IDs. An uncertain submission is not retried.</p>
          </details>
"""

SETUP_POLICY_SCRIPT = r"""
    const setupPolicyPrefix = '/api/setup/policy-candidate';
    const setupPolicyRequestSchema = 'serverware.setupPolicyCandidateRequest/v1';
    const setupPolicyOptionsSchema = 'serverware.setupPolicyCandidateOptions/v1';
    const setupPolicyMaximumResponse = 5 * 1024 * 1024;
    let setupPolicyHeld = null, setupPolicyBusy = false;
    function setupPolicyNeed(value) { if (!value) throw new Error('Setup candidate original or authority changed; inspect without retry.'); }
    function setupPolicyMessage(text) { $('setup-policy-status').textContent = text; }
    function setupPolicyMarker(actor, session) { return 'serverware.setup-policy.submitted:' + actor + ':' + session; }
    function setupPolicyBegin(held = null) {
      setupPolicyNeed(!setupPolicyBusy && !adminToken() && state.authStatus?.authMethod === 'oidc-session'
        && state.authStatus?.authenticated === true && state.authStatus.roles.includes('credential_owner'));
      const actor = state.authStatus.userId, scope = sessionActivationAuthScope();
      const session = $('setup-policy-session').value.trim(), generation = $('setup-policy-generation').value.trim();
      setupPolicyNeed(nativeSetupId(session));
      const until = held ? held.until : performance.now() + 30000;
      const expires = held ? held.expires : Date.now() + 30000;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), Math.max(0, until - performance.now()));
      const operation = {actor, scope, session, generation, until, expires, signal: controller.signal, current() {
        setupPolicyNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
          && !adminToken() && state.authStatus?.authenticated === true && state.authStatus?.authMethod === 'oidc-session'
          && state.authStatus.userId === actor && state.authStatus.roles.includes('credential_owner')
          && sessionActivationAuthScope() === scope && $('setup-policy-session').value.trim() === session
          && $('setup-policy-generation').value.trim() === generation);
        if (held) setupPolicyNeed(setupPolicyHeld === held && held.actor === actor && held.scope === scope
          && held.session === session && held.generation === generation
          && BigInt(Date.now()) * 1000000n < held.epochExpiry);
      }, close() { clearTimeout(timer); controller.abort(); setupPolicyBusy = false; }};
      try { operation.current(); setupPolicyBusy = true; return operation; }
      catch (error) { clearTimeout(timer); controller.abort(); throw error; }
    }
    async function setupPolicyRead(response, operation) {
      operation.current(); setupPolicyNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let original = '', size = 0, done = false;
      try {
        for (;;) { operation.current(); const chunk = await reader.read(); operation.current();
          if (chunk.done) { done = true; break; }
          size += chunk.value.byteLength; setupPolicyNeed(size <= setupPolicyMaximumResponse);
          original += decoder.decode(chunk.value, {stream: true});
        }
        original += decoder.decode(); return oauthConsentParse(original, setupPolicyMaximumResponse).value;
      } finally { if (!done) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); original = ''; }
    }
    async function setupPolicyPost(suffix, body, operation, sent = null) {
      setupPolicyNeed(['/draft', '/options', '/bind', '/lookup'].includes(suffix));
      const csrfReply = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: operation.signal});
      const csrf = await setupPolicyRead(csrfReply, operation);
      setupPolicyNeed(csrfReply.ok && csrf.ok === true && csrf.header === 'X-Serverware-CSRF-Token'
        && typeof csrf.token === 'string' && csrf.token.length <= 1024);
      let original = oauthConsentCanonical(body);
      setupPolicyNeed(new TextEncoder().encode(original).length <= 4 * 1024 * 1024 + 32768);
      try {
        operation.current(); if (sent) sent();
        const response = await fetch(setupPolicyPrefix + suffix, {method: 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        const value = await setupPolicyRead(response, operation);
        setupPolicyNeed(response.ok); return value;
      } finally { original = null; }
    }
    async function setupPolicyDraft() {
      const operation = setupPolicyBegin(); setupPolicyHeld = null; $('setup-policy-confirm').checked = false;
      try {
        setupPolicyNeed(nativeSetupId(operation.generation)
          && sessionStorage.getItem(setupPolicyMarker(operation.actor, operation.session)) === null);
        const result = await setupPolicyPost('/draft', {apiVersion: setupPolicyRequestSchema, sessionId: operation.session,
          expectedRevision: 3, generationRequestId: operation.generation}, operation);
        setupPolicyNeed(oauthConsentClosed(result, ['apiVersion', 'okForAction', 'argumentsOriginal', 'review'])
          && result.apiVersion === setupPolicyRequestSchema && result.okForAction === false && typeof result.argumentsOriginal === 'string');
        const args = oauthConsentParse(result.argumentsOriginal, 2 * 1024 * 1024).value;
        const request = args.request, binding = nativeSetupBinding(request?.setupBinding), review = result.review;
        setupPolicyNeed(oauthConsentClosed(args, ['actor_id', 'control_plane_configuration_digest', 'credential_policy', 'request'])
          && oauthConsentClosed(request, ['setupBinding', 'credentialId', 'credentialVersion', 'generationClaimOriginal',
            'routePolicyDigest', 'assignmentDigest', 'issuedAtEpochNs', 'expiresAtEpochNs'])
          && oauthConsentClosed(review, ['principalId', 'routeId', 'credentialId', 'credentialVersion', 'policyHash',
            'routePolicyDigest', 'assignmentDigest', 'sessionId', 'setupRevision', 'continuationRevision', 'ownerId',
            'generationRequestId', 'generationPublicationDigest', 'candidateId', 'canaryId', 'expiresAtEpochNs']));
        const claim = oauthConsentParse(request.generationClaimOriginal, 2 * 1024 * 1024).value;
        setupPolicyNeed(args.actor_id === operation.actor && binding.sessionId === operation.session && binding.ownerId === operation.actor
          && oauthConsentInteger(binding.revision) === 3n && oauthConsentInteger(request.credentialVersion) === 1n
          && claim.request_id === operation.generation && oauthConsentDigest(claim.publication_envelope_digest)
          && review.sessionId === operation.session && review.ownerId === operation.actor
          && review.generationRequestId === operation.generation && review.generationPublicationDigest === claim.publication_envelope_digest
          && review.credentialId === request.credentialId && oauthConsentInteger(review.credentialVersion) === 1n
          && review.routePolicyDigest === request.routePolicyDigest && review.assignmentDigest === request.assignmentDigest
          && oauthConsentInteger(review.setupRevision) === 3n && oauthConsentInteger(review.continuationRevision) === 0n);
        const epochExpiry = oauthConsentInteger(request.expiresAtEpochNs);
        setupPolicyNeed(epochExpiry === oauthConsentInteger(review.expiresAtEpochNs)
          && BigInt(Date.now()) * 1000000n < epochExpiry && epochExpiry <= oauthConsentInteger(binding.expiresAtEpochNs));
        setupPolicyHeld = {original: result.argumentsOriginal, actor: operation.actor, scope: operation.scope,
          session: operation.session, generation: operation.generation, until: operation.until, expires: operation.expires, epochExpiry};
        $('setup-policy-review').textContent = oauthConsentCanonical(review);
        setupPolicyMessage('Exact review retained briefly. Candidate binding still requires your fresh hardware passkey; original expiry is not renewed.');
      } catch (error) { setupPolicyHeld = null; setupPolicyMessage('No binding submitted. Check activated revision 3, completed audit, current credential and completed generation. If a prior submission was uncertain, use lookup only.'); throw error; }
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
        setupPolicyNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
          && oauthConsentClosed(options.publicKey, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          && oauthConsentClosed(options.serverware, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && options.serverware.schema === setupPolicyOptionsSchema && options.serverware.operation === 'setup.policy.bind-candidate'
          && oauthConsentDigest(options.serverware.operationId) && oauthConsentDigest(options.serverware.challengeId)
          && typeof options.serverware.credentialRecordId === 'string'
          && new TextEncoder().encode(options.serverware.credentialRecordId).length <= 256
          && options.serverware.payloadDigest === await workloadIssuanceHash(new TextEncoder().encode(held.original)));
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
          && result.apiVersion === 'serverware.setupPolicyCandidateObservation/v1' && result.okForAction === false
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
"""
