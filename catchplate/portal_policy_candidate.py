"""Explicit controlled generation caller, separate from legacy staging/Setup."""

POLICY_CANDIDATE_HTML = r"""
          <details>
            <summary>Controlled native candidate generation</summary>
            <p class="hint">Requires independently admitted intake policy and already protected signed candidate, assignment, load receipt and native handoff. This publishes one shadow generation, not active policy or completed Setup. The legacy stage button is unchanged.</p>
            <label for="controlled-candidate-handoff">Exact candidate handoff JSON (policyAuthorityCandidateHandoff/v1; signed bundle included)</label>
            <textarea id="controlled-candidate-handoff" class="policy-result" spellcheck="false" autocomplete="off"></textarea>
            <button type="button" onclick="runUiAction('Controlled generation', controlledCandidatePublish)">Fresh publisher passkey + publish once</button>
            <label for="controlled-candidate-request">Retained request ID</label>
            <input id="controlled-candidate-request" maxlength="36" autocomplete="off">
            <button type="button" class="secondary" onclick="runUiAction('Inspect controlled generation', controlledCandidateLookup)">Read exact retained state only</button>
            <button type="button" class="secondary" onclick="runUiAction('Recover retained publication', controlledCandidateRecover)">Read native receipt + persist once</button>
            <p class="hint">Recovery never publishes again. It requires the exact receipt still retained in the same native process and the original claim's remaining 30-second window. Expired claims or unavailable receipts stay unresolved; this is not crash recovery.</p>
            <p id="controlled-candidate-status" class="hint" role="status">No controlled generation submitted.</p>
          </details>
"""

POLICY_CANDIDATE_SCRIPT = r"""
    const controlledCandidatePrefix = '/api/policy/authority/candidates/controlled-generation';
    const controlledCandidateSchema = 'catchplate.policyCandidateIntakeRequest/v1';
    const controlledCandidateOptions = 'catchplate.policyCandidateIntakeOptions/v1';
    let controlledCandidateBusy = false;
    const controlledCandidateSpent = new Set();
    const controlledCandidateRecoverySpent = new Set();
    function controlledCandidateNeed(value) { if (!value) throw new Error('Controlled candidate original or current authority changed; no retry.'); }
    function controlledCandidateBegin() {
      controlledCandidateNeed(!controlledCandidateBusy && !adminToken() && state.authStatus?.authMethod === 'oidc-session'
        && state.authStatus?.authenticated === true && state.authStatus.roles.includes('policy_publisher'));
      const actor = state.authStatus.userId, scope = sessionActivationAuthScope(), raw = $('controlled-candidate-handoff').value;
      const controller = new AbortController(), until = performance.now() + 30000, expires = Date.now() + 30000;
      const timer = setTimeout(() => controller.abort(), 30000); controlledCandidateBusy = true;
      return {signal: controller.signal, current() {
        controlledCandidateNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
          && !adminToken() && state.authStatus.userId === actor && sessionActivationAuthScope() === scope
          && $('controlled-candidate-handoff').value === raw);
      }, close() { clearTimeout(timer); controller.abort(); controlledCandidateBusy = false; }};
    }
    async function controlledCandidateRead(response, operation) {
      operation.current(); controlledCandidateNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let text = '', size = 0, done = false;
      try {
        for (;;) { operation.current(); const chunk = await reader.read(); operation.current();
          if (chunk.done) { done = true; break; }
          size += chunk.value.byteLength; controlledCandidateNeed(size <= 4 * 1024 * 1024);
          text += decoder.decode(chunk.value, {stream: true});
        }
        text += decoder.decode(); return oauthConsentParse(text, 4 * 1024 * 1024).value;
      } finally { if (!done) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); text = ''; }
    }
    async function controlledCandidatePost(suffix, body, operation, sent = null) {
      controlledCandidateNeed(['/draft', '/options', '/publish', '/lookup', '/recover'].includes(suffix));
      const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.signal});
      const csrf = await controlledCandidateRead(csrfResponse, operation);
      controlledCandidateNeed(csrfResponse.ok && csrf.ok === true && csrf.header === 'X-Catchplate-CSRF-Token'
        && typeof csrf.token === 'string' && csrf.token.length <= 1024);
      let original = oauthConsentCanonical(body);
      controlledCandidateNeed(new TextEncoder().encode(original).length <= 3 * 1024 * 1024 + 32768);
      try {
        operation.current(); if (sent) sent();
        const response = await fetch(controlledCandidatePrefix + suffix, {method: 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        const value = await controlledCandidateRead(response, operation);
        controlledCandidateNeed(response.ok); return value;
      } finally { original = null; }
    }
    async function controlledCandidatePublish() {
      const operation = controlledCandidateBegin(); let original = null, assertion = null, requestId = null;
      try {
        const handoff = oauthConsentParse($('controlled-candidate-handoff').value, 1024 * 1024).value;
        requestId = handoff.requestId;
        controlledCandidateNeed(handoff.apiVersion === 'catchplate.policyAuthorityCandidateHandoff/v1'
          && typeof requestId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)
          && !controlledCandidateSpent.has(requestId));
        $('controlled-candidate-request').value = requestId;
        const draft = await controlledCandidatePost('/draft', {apiVersion: controlledCandidateSchema, handoff}, operation);
        controlledCandidateNeed(oauthConsentClosed(draft, ['apiVersion', 'okForAction', 'argumentsOriginal'])
          && draft.apiVersion === controlledCandidateSchema && draft.okForAction === false && typeof draft.argumentsOriginal === 'string');
        original = draft.argumentsOriginal;
        const bound = oauthConsentParse(original, 3 * 1024 * 1024).value;
        controlledCandidateNeed(bound.actor_id === state.authStatus.userId
          && oauthConsentParse(bound.request.managementRequestOriginal, 1024 * 1024).value.requestId === requestId);
        const options = await controlledCandidatePost('/options', {apiVersion: controlledCandidateOptions, argumentsOriginal: original}, operation);
        controlledCandidateNeed(oauthConsentClosed(options, ['publicKey', 'catchplate'])
          && oauthConsentClosed(options.publicKey, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          && oauthConsentClosed(options.catchplate, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && options.catchplate.schema === controlledCandidateOptions
          && options.catchplate.operation === 'policy.candidate.generation-claim'
          && /^sha256:[0-9a-f]{64}$/.test(options.catchplate.operationId)
          && /^sha256:[0-9a-f]{64}$/.test(options.catchplate.challengeId)
          && typeof options.catchplate.credentialRecordId === 'string'
          && options.catchplate.credentialRecordId.length > 0
          && new TextEncoder().encode(options.catchplate.credentialRecordId).length <= 256
          && options.catchplate.payloadDigest === await workloadIssuanceHash(new TextEncoder().encode(original)));
        assertion = await nativeSetupPasskey(options, operation);
        const result = await controlledCandidatePost('/publish', {apiVersion: controlledCandidateOptions, argumentsOriginal: original,
          mfa: {policyCandidateProfile: controlledCandidateOptions, assertion}}, operation, () => controlledCandidateSpent.add(requestId));
        controlledCandidateNeed(oauthConsentClosed(result, ['apiVersion', 'automaticRetryAllowed', 'requestId', 'publication'])
          && result.apiVersion === 'catchplate.policyCandidateGenerationResult/v1' && result.automaticRetryAllowed === false
          && result.requestId === requestId && result.publication?.ok === true);
        $('controlled-candidate-status').textContent = 'Exact native generation retained. This is not activation, file publication, canary completion or Setup completion.';
      } catch (error) {
        $('controlled-candidate-status').textContent = requestId && controlledCandidateSpent.has(requestId)
          ? 'Submission outcome may be unknown. Keep this request ID and use read-only inspection; never repeat contact.'
          : 'No completed generation confirmed. No automatic retry was made.';
        throw error;
      } finally { original = null; assertion = null; operation.close(); }
    }
    async function controlledCandidateLookup() {
      const operation = controlledCandidateBegin();
      try {
        const result = await controlledCandidatePost('/lookup', {apiVersion: controlledCandidateSchema,
          requestId: $('controlled-candidate-request').value}, operation);
        controlledCandidateNeed(oauthConsentClosed(result, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'claimOriginal', 'publicationOriginal'])
          && result.apiVersion === 'catchplate.policyCandidateGenerationObservation/v1' && result.okForAction === false
          && result.automaticRetryAllowed === false);
        $('controlled-candidate-status').textContent = result.publicationOriginal !== null ? 'Stored publication found. Read-only observation; no contact repeated.'
          : result.claimOriginal !== null ? 'Claim retained without a known stored publication. Contact remains uncertain and cannot be retried.'
          : 'No claim observed. Absence is not permission to repeat an uncertain submission.';
      } finally { operation.close(); }
    }
    async function controlledCandidateRecover() {
      const operation = controlledCandidateBegin();
      let marker = null;
      try {
        const requestId = $('controlled-candidate-request').value;
        controlledCandidateNeed(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId));
        marker = 'catchplate.policyCandidateRecovery/v1:' + state.authStatus.userId + ':' + requestId;
        controlledCandidateNeed(!controlledCandidateRecoverySpent.has(marker) && sessionStorage.getItem(marker) === null);
        const result = await controlledCandidatePost('/recover', {apiVersion: controlledCandidateSchema, requestId}, operation, () => {
          // Public attempt identity only; never clear uncertainty or store a receipt/assertion.
          sessionStorage.setItem(marker, 'attempted'); controlledCandidateRecoverySpent.add(marker);
        });
        const publication = result.publication;
        controlledCandidateNeed(oauthConsentClosed(result, ['apiVersion', 'automaticRetryAllowed', 'requestId', 'publication'])
          && result.apiVersion === 'catchplate.policyCandidateGenerationResult/v1' && result.automaticRetryAllowed === false
          && result.requestId === requestId && oauthConsentClosed(publication, ['ok', 'apiVersion', 'requestId', 'replayId',
            'managementHandoffId', 'canaryId', 'candidateId', 'instanceId', 'bootIdSha256', 'requestPayloadSha256', 'generationId',
            'publicationEnvelopeSha256', 'publicationPayloadSha256', 'verificationReceiptSha256', 'attestationChainSha256',
            'signingKeySpkiSha256', 'recovered']) && publication.ok === true && publication.recovered === true
          && publication.apiVersion === 'catchplate.policyAuthorityCandidateHandoffResult/v2' && publication.requestId === requestId);
        $('controlled-candidate-status').textContent = 'Exact retained publication found and its controlled outcome confirmed. No native publication repeated. This is not activation, canary completion or Setup completion.';
      } catch (error) {
        $('controlled-candidate-status').textContent = marker && controlledCandidateRecoverySpent.has(marker)
          ? 'Recovery outcome may be unknown. Use read-only inspection only; do not publish again or repeat this recovery action. An expired claim or absent retained receipt remains unresolved.'
          : 'Recovery unavailable or already attempted. Read-only inspection remains available; no publication was repeated.';
        throw error;
      } finally { operation.close(); }
    }
"""
