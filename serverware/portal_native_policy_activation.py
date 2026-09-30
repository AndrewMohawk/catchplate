"""Explicit operator continuation for the protected native activation owner.

The page keeps original strings intact, grants no authority, and never retries
an effect. Browser markers contain only nonsecret locators, not assertions.
"""

NATIVE_POLICY_ACTIVATION_HTML = r"""
          <details id="native-activation-controls">
            <summary>Native policy activation · review, two-person approval and publication</summary>
            <p class="hint">Requires completed native readiness, an independently configured activation service, and two enrolled policy publishers. Publication does not hot-reload the gate, install a CA, or complete Setup. Use the same exact approval across these steps.</p>
            <ol><li>Requester reviews readiness and requests approval with a hardware passkey.</li><li>A different publisher reviews and approves with their own passkey.</li><li>Requester reviews again and publishes once with a new passkey.</li><li>After audit delivery, explicitly record the publication evidence and finalize.</li></ol>
            <label for="native-activation-readiness">Retained native readiness request ID</label>
            <input id="native-activation-readiness" maxlength="36" autocomplete="off" oninput="nativeActivationInvalidate()">
            <label for="native-activation-generation">Exact generation publication envelope SHA-256</label>
            <input id="native-activation-generation" maxlength="71" autocomplete="off" oninput="nativeActivationInvalidate()">
            <label for="native-activation-approval">Approval ID (share this nonsecret locator with the other publisher)</label>
            <input id="native-activation-approval" maxlength="36" autocomplete="off" oninput="nativeActivationInvalidate()">
            <label for="native-activation-phase">Next explicit action</label>
            <select id="native-activation-phase" onchange="nativeActivationInvalidate()">
              <option value="request">1 · Request approval</option><option value="decide">2 · Distinct publisher approves</option>
              <option value="publish">3 · Requester publishes once</option><option value="record-inclusion">4 · Record publication audit evidence</option>
              <option value="finalize">5 · Finalize verified publication</option>
            </select>
            <button type="button" class="secondary" onclick="runUiAction('Review native activation', nativeActivationReview)">Read current originals and review selected action</button>
            <pre id="native-activation-review">No reviewed native activation. A draft is not permission.</pre>
            <details><summary>Exact original submitted for this action</summary><textarea id="native-activation-original" class="policy-result" readonly></textarea></details>
            <label><input id="native-activation-confirm" type="checkbox">I reviewed the exact actor, policies, generation, approval, expiry and selected action.</label>
            <button id="native-activation-submit" type="button" disabled onclick="runUiAction('Native activation', nativeActivationSubmit)">Perform reviewed action once</button>
            <p id="native-activation-status" class="hint" role="status" aria-live="polite">No action submitted. Each effect is separate; there is no automatic retry.</p>
            <details><summary>Publication evidence for explicit audit settlement</summary>
              <p class="hint">A successful publication fills this in memory. Keep this signed operational evidence private. It is not a retry token. If it is missing after an interruption, use authenticated inspection; do not fabricate it or publish again.</p>
              <label for="native-activation-handoff">Exact publication handoff (nativeRequest and publicationOriginal)</label>
              <textarea id="native-activation-handoff" class="policy-result" spellcheck="false" autocomplete="off" oninput="nativeActivationInvalidate()"></textarea>
            </details>
            <button type="button" class="secondary" onclick="runUiAction('Inspect native activation', nativeActivationLookup)">Read approval/preparation/finalization only</button>
            <button type="button" class="secondary" onclick="runUiAction('Restore native request locator', nativeActivationRestore)">Restore this requester's submitted approval ID</button>
            <p class="hint">Enter the original readiness request ID to restore its nonsecret browser hint after reload. A predicted approval ID is not evidence of a committed request. Inspect it without submitting again.</p>
            <pre id="native-activation-observation">Not inspected. Missing records never prove noncommit or unlock retry.</pre>
          </details>
"""

NATIVE_POLICY_ACTIVATION_SCRIPT = r"""
    const nativeActivationPrefix = '/api/policy/authority/native-activations';
    const nativeActivationProfile = 'serverware.nativePolicyActivationHttp/v1';
    const nativeActivationLocatorProfile = 'serverware.nativePolicyActivationLocator/v1';
    const nativeActivationLimit = 8 * 1024 * 1024;
    const nativeActivationPhases = ['request', 'decide', 'publish', 'record-inclusion', 'finalize'];
    let nativeActivationHeld = null, nativeActivationBusy = false;
    const nativeActivationSpent = new Set();
    function nativeActivationNeed(value) { if (!value) throw new Error('Native activation original, session or deadline changed. Inspect; no automatic retry.'); }
    function nativeActivationInvalidate() {
      nativeActivationHeld = null; $('native-activation-confirm').checked = false;
      $('native-activation-submit').disabled = true; $('native-activation-original').value = '';
      $('native-activation-review').textContent = 'Review the selected action and current originals again.';
    }
    function nativeActivationSelection() {
      return {phase: $('native-activation-phase').value, readiness: $('native-activation-readiness').value.trim(),
        generation: $('native-activation-generation').value.trim(), approval: $('native-activation-approval').value.trim(),
        handoff: $('native-activation-handoff').value};
    }
    function nativeActivationBegin(held = null) {
      nativeActivationNeed(!nativeActivationBusy && !adminToken() && state.authStatus?.authenticated === true
        && state.authStatus.authMethod === 'oidc-session' && state.authStatus.roles.includes('policy_publisher'));
      const actor = state.authStatus.userId, scope = sessionActivationAuthScope(), selection = nativeActivationSelection();
      const selected = JSON.stringify(selection), until = Math.min(performance.now() + 30000, held ? held.until : Infinity);
      const expires = Math.min(Date.now() + 30000, held ? held.expires : Infinity);
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), Math.max(0, until - performance.now()));
      const operation = {actor, scope, selection, until, expires, signal: controller.signal, current() {
        nativeActivationNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
          && !adminToken() && state.authStatus?.authenticated === true && state.authStatus.authMethod === 'oidc-session'
          && state.authStatus.userId === actor && state.authStatus.roles.includes('policy_publisher')
          && sessionActivationAuthScope() === scope && JSON.stringify(nativeActivationSelection()) === selected);
        if (held) nativeActivationNeed(nativeActivationHeld === held && held.actor === actor && held.scope === scope
          && held.selected === selected && $('native-activation-original').value === held.original
          && BigInt(Date.now()) * 1000000n < held.epochExpiry);
      }, close() { clearTimeout(timer); controller.abort(); nativeActivationBusy = false; }};
      try { operation.current(); nativeActivationBusy = true; return operation; }
      catch (error) { clearTimeout(timer); controller.abort(); throw error; }
    }
    async function nativeActivationRead(response, operation) {
      operation.current(); nativeActivationNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let original = '', bytes = 0, done = false;
      try {
        for (;;) { operation.current(); const part = await reader.read(); operation.current();
          if (part.done) { done = true; break; }
          bytes += part.value.byteLength; nativeActivationNeed(bytes <= nativeActivationLimit);
          original += decoder.decode(part.value, {stream: true});
        }
        original += decoder.decode(); return oauthConsentParse(original, nativeActivationLimit).value;
      } finally { if (!done) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); original = ''; }
    }
    async function nativeActivationPost(suffix, body, operation, beforeSend = null) {
      nativeActivationNeed(['draft', 'options', 'lookup', 'request-locator', ...nativeActivationPhases].includes(suffix));
      const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: operation.signal});
      const csrf = await nativeActivationRead(csrfResponse, operation);
      nativeActivationNeed(csrfResponse.ok && csrf.ok === true && csrf.header === 'X-Serverware-CSRF-Token'
        && typeof csrf.token === 'string' && csrf.token.length > 0 && csrf.token.length <= 1024);
      let original = oauthConsentCanonical(body);
      nativeActivationNeed(new TextEncoder().encode(original).byteLength <= nativeActivationLimit);
      try {
        operation.current(); if (beforeSend) beforeSend();
        const response = await fetch(nativeActivationPrefix + '/' + suffix, {method: 'POST', mode: 'same-origin',
          credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        const value = await nativeActivationRead(response, operation); nativeActivationNeed(response.ok); return value;
      } finally { original = null; }
    }
    function nativeActivationMarker(actor, selection) {
      const locator = selection.phase === 'request' ? selection.readiness : selection.approval;
      nativeActivationNeed(nativeSetupId(locator));
      return 'serverware.native-activation.submitted:' + actor + ':' + selection.phase + ':' + locator;
    }
    function nativeActivationHintKey(actor, readiness) {
      nativeActivationNeed(typeof actor === 'string' && actor.startsWith('oidc:') && nativeSetupId(readiness));
      return 'serverware.native-activation.locator:' + actor + ':' + readiness;
    }
    function nativeActivationLocator(value, actor, readiness) {
      nativeActivationNeed(oauthConsentClosed(value, ['apiVersion', 'actorId', 'activationId', 'readinessRequestId',
        'approvalId', 'argumentsSha256', 'requestDigest', 'okForAction', 'automaticRetryAllowed'])
        && value.apiVersion === nativeActivationLocatorProfile && value.actorId === actor && value.readinessRequestId === readiness
        && nativeSetupId(value.activationId) && nativeSetupId(value.approvalId)
        && /^sha256:[0-9a-f]{64}$/.test(value.argumentsSha256) && /^sha256:[0-9a-f]{64}$/.test(value.requestDigest)
        && value.okForAction === false && value.automaticRetryAllowed === false);
      return value;
    }
    async function nativeActivationReview() {
      nativeActivationInvalidate(); const operation = nativeActivationBegin();
      try {
        const s = operation.selection; nativeActivationNeed(nativeActivationPhases.includes(s.phase));
        const body = {apiVersion: nativeActivationProfile, phase: s.phase};
        if (s.phase === 'request') {
          nativeActivationNeed(nativeSetupId(s.readiness) && /^sha256:[0-9a-f]{64}$/.test(s.generation));
          Object.assign(body, {readinessRequestId: s.readiness, generationPublicationEnvelopeSha256: s.generation});
        } else {
          nativeActivationNeed(nativeSetupId(s.approval)); body.approvalId = s.approval;
          if (s.phase === 'record-inclusion') {
            const handoff = oauthConsentParse(s.handoff, nativeActivationLimit).value;
            nativeActivationNeed(oauthConsentClosed(handoff, ['nativeRequest', 'publicationOriginal'])
              && handoff.nativeRequest?.apiVersion === 'serverware.nativePolicyActivationRequest/v1'
              && typeof handoff.publicationOriginal === 'string');
            Object.assign(body, handoff);
          }
        }
        const marker = nativeActivationMarker(operation.actor, s);
        nativeActivationNeed(!nativeActivationSpent.has(marker) && sessionStorage.getItem(marker) === null);
        const draft = await nativeActivationPost('draft', body, operation);
        nativeActivationNeed(oauthConsentClosed(draft, ['apiVersion', 'phase', 'okForAction', 'automaticRetryAllowed', 'argumentsOriginal'])
          && draft.apiVersion === nativeActivationProfile && draft.phase === s.phase && draft.okForAction === false
          && draft.automaticRetryAllowed === false && typeof draft.argumentsOriginal === 'string');
        const args = oauthConsentParse(draft.argumentsOriginal, nativeActivationLimit).value, intent = args.request;
        nativeActivationNeed(args.actor_id === operation.actor && nativeSetupId(intent.activationId)
          && (s.phase === 'request' ? intent.readinessRequestId === s.readiness
            && intent.generationPublicationEnvelopeSha256 === s.generation : args.approval_id === s.approval));
        let locator = null;
        if (s.phase === 'request') {
          locator = nativeActivationLocator(await nativeActivationPost('request-locator', {apiVersion: nativeActivationProfile,
            phase: 'request', argumentsOriginal: draft.argumentsOriginal}, operation), operation.actor, s.readiness);
          nativeActivationNeed(locator.activationId === intent.activationId
            && locator.argumentsSha256 === await workloadIssuanceHash(new TextEncoder().encode(draft.argumentsOriginal)));
        }
        const epochExpiry = oauthConsentInteger(intent.expiresAtUnixNanos);
        // Settlement is a distinct current operation and may follow expiry of
        // publication permission; never renew or resend the original publish.
        const assertionPhase = ['request', 'decide', 'publish'].includes(s.phase);
        const reviewExpiry = assertionPhase ? epochExpiry : BigInt(Date.now() + 300000) * 1000000n;
        nativeActivationNeed(reviewExpiry > BigInt(Date.now()) * 1000000n);
        const reviewMs = Math.min(300000, Number((reviewExpiry - BigInt(Date.now()) * 1000000n) / 1000000n));
        nativeActivationNeed(Number.isSafeInteger(reviewMs) && reviewMs > 0);
        operation.current();
        // Data-only human review may outlast the draft HTTP call. The next
        // actual action gets a fresh <=30s transport window, rechecks current
        // server authority, and still cannot outlive original intent expiry.
        nativeActivationHeld = {actor: operation.actor, scope: operation.scope, selected: JSON.stringify(s), phase: s.phase,
          original: draft.argumentsOriginal, marker, intent, locator, until: performance.now() + reviewMs, expires: Date.now() + reviewMs,
          epochExpiry: reviewExpiry};
        $('native-activation-review').textContent = 'Actor: ' + operation.actor + '\nAction: ' + s.phase
          + '\nApproval: ' + (args.approval_id || locator.approvalId + ' (predicted locator only; not a committed request)')
          + '\nExact activation intent:\n' + oauthConsentCanonical(intent);
        $('native-activation-original').value = draft.argumentsOriginal;
        $('native-activation-submit').disabled = false;
        $('native-activation-status').textContent = 'Review ready for this original window only. No action has been authorized or sent.';
      } finally { operation.close(); }
    }
    async function nativeActivationSubmit() {
      const held = nativeActivationHeld; nativeActivationNeed(held && $('native-activation-confirm').checked);
      const operation = nativeActivationBegin(held); let assertion = null, result = null;
      try {
        nativeActivationNeed(!nativeActivationSpent.has(held.marker) && sessionStorage.getItem(held.marker) === null);
        const body = {apiVersion: nativeActivationProfile, phase: held.phase, argumentsOriginal: held.original};
        if (['request', 'decide', 'publish'].includes(held.phase)) {
          const options = await nativeActivationPost('options', body, operation);
          nativeActivationNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
            && oauthConsentClosed(options.publicKey, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
            && oauthConsentClosed(options.serverware, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
            && options.serverware.schema === nativeActivationProfile
            && options.serverware.operation === 'native-policy-activation.' + (held.phase === 'publish' ? 'consume' : held.phase)
            && /^sha256:[0-9a-f]{64}$/.test(options.serverware.operationId) && /^sha256:[0-9a-f]{64}$/.test(options.serverware.challengeId)
            && typeof options.serverware.credentialRecordId === 'string' && options.serverware.credentialRecordId.length > 0
            && new TextEncoder().encode(options.serverware.credentialRecordId).byteLength <= 256
            && options.serverware.payloadDigest === await workloadIssuanceHash(new TextEncoder().encode(held.original)));
          assertion = await nativeSetupPasskey(options, operation);
          body.mfa = {nativePolicyActivationProfile: nativeActivationProfile, assertion};
        }
        operation.current(); nativeActivationNeed($('native-activation-confirm').checked);
        result = await nativeActivationPost(held.phase, body, operation, () => {
          if (held.locator) {
            // Nonsecret IDs and digests only, persisted before contact. Never
            // retain the actual assertion, original arguments or PREPARE here.
            sessionStorage.setItem(nativeActivationHintKey(operation.actor, operation.selection.readiness), oauthConsentCanonical(held.locator));
          }
          sessionStorage.setItem(held.marker, 'submitted'); nativeActivationSpent.add(held.marker);
          $('native-activation-submit').disabled = true;
        });
        nativeActivationNeed(oauthConsentClosed(result, ['apiVersion', 'phase', 'automaticRetryAllowed', 'result', 'nativeRequest', 'publicationOriginal'])
          && result.apiVersion === nativeActivationProfile && result.phase === held.phase && result.automaticRetryAllowed === false
          && result.result?.ok === true && result.result.idempotentReplay === false
          && result.result.operation === 'native-policy-activation.' + (held.phase === 'publish' ? 'consume' : held.phase)
          && nativeSetupId(result.result.approval?.id)
          && result.result.approval.request?.activationId === held.intent.activationId);
        if (held.locator) nativeActivationNeed(result.result.approval.id === held.locator.approvalId
          && result.result.requestDigest === held.locator.requestDigest);
        if (held.phase === 'publish') nativeActivationNeed(result.nativeRequest?.apiVersion === 'serverware.nativePolicyActivationRequest/v1'
          && result.nativeRequest.requestId === held.intent.activationId && typeof result.publicationOriginal === 'string'
          && result.publicationOriginal.length > 0);
        else nativeActivationNeed(result.nativeRequest === null && result.publicationOriginal === null);
        operation.current();
        $('native-activation-approval').value = result.result.approval.id;
        if (held.phase === 'publish') $('native-activation-handoff').value = oauthConsentCanonical({
          nativeRequest: result.nativeRequest, publicationOriginal: result.publicationOriginal});
        nativeActivationInvalidate();
        $('native-activation-status').textContent = held.phase + ' retained for approval ' + result.result.approval.id
          + '. Choose and review the next separate step. This is not completed Setup or a restarted native gate.';
      } catch (error) {
        if (held.locator && nativeActivationSpent.has(held.marker)) $('native-activation-approval').value = held.locator.approvalId;
        $('native-activation-status').textContent = nativeActivationSpent.has(held.marker)
          ? 'Submission may have committed. Keep approval/readiness/activation locators and inspect; never repeat this effect.'
          : 'No completed action confirmed. No automatic retry was made; review current originals before another explicit action.';
        throw error;
      } finally { assertion = null; result = null; operation.close(); nativeActivationHeld = null; $('native-activation-submit').disabled = true; }
    }
    async function nativeActivationLookup() {
      const operation = nativeActivationBegin();
      try {
        nativeActivationNeed(nativeSetupId(operation.selection.approval));
        const result = await nativeActivationPost('lookup', {apiVersion: nativeActivationProfile, approvalId: operation.selection.approval}, operation);
        nativeActivationNeed(oauthConsentClosed(result, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'approvalOriginal',
          'preparationOriginal', 'finalizationOriginal', 'effectHoldOriginal']) && result.apiVersion === nativeActivationProfile
          && result.okForAction === false && result.automaticRetryAllowed === false);
        for (const field of ['approvalOriginal', 'preparationOriginal', 'finalizationOriginal', 'effectHoldOriginal'])
          nativeActivationNeed(result[field] === null || typeof result[field] === 'string');
        $('native-activation-observation').textContent = oauthConsentCanonical(result);
        $('native-activation-status').textContent = 'Read-only protected observation. No native contact, approval, publication or retry was performed.';
      } finally { operation.close(); }
    }
    function nativeActivationRestore() {
      nativeActivationInvalidate(); const operation = nativeActivationBegin();
      try {
        const raw = sessionStorage.getItem(nativeActivationHintKey(operation.actor, operation.selection.readiness));
        nativeActivationNeed(typeof raw === 'string' && raw.length <= 4096);
        const locator = nativeActivationLocator(oauthConsentParse(raw, 4096).value, operation.actor, operation.selection.readiness);
        operation.current();
        $('native-activation-approval').value = locator.approvalId;
        $('native-activation-observation').textContent = 'Untrusted local navigation hint only:\n' + oauthConsentCanonical(locator);
        $('native-activation-status').textContent = 'Approval ID restored. Read its authenticated retained state; this hint never proves commitment or permits retry.';
      } finally { operation.close(); }
    }
"""
