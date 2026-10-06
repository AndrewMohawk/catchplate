"""Review a genuine server-selected native publication and associate it once."""

SETUP_NATIVE_CANARY_HTML = r"""
            <hr>
            <details id="setup-native-canary-controls">
              <summary>Associate the completed native policy publication with Setup</summary>
              <p class="hint">Uses the Setup session ID above, its issued certificate and authenticated CA readback. The server selects the actual completed native publication and audits; this form accepts no uploaded readiness claim. Both credential_owner and policy_author are required.</p>
              <button type="button" onclick="runUiAction('Review native publication association', setupNativeCanaryDraft)">Review server-selected publication</button>
              <pre id="setup-native-canary-review">No current publication association reviewed.</pre>
              <label><input id="setup-native-canary-confirm" type="checkbox">I reviewed this exact Setup session, credential, policy and completed native publication.</label>
              <button type="button" onclick="runUiAction('Associate native publication once', setupNativeCanaryRecord)">Fresh requester passkey + associate once</button>
              <button type="button" class="secondary" onclick="runUiAction('Read native publication association', setupNativeCanaryLookup)">Read retained association</button>
              <button type="button" class="secondary" onclick="setupNativeCanaryClear()">Clear page-held review</button>
              <pre id="setup-native-canary-result">No native publication association observed.</pre>
              <p id="setup-native-canary-status" class="hint" role="status" aria-live="polite">Association is not measured host proof, proxy readiness or completed Setup. An uncertain submission permits read-only lookup, never automatic retry.</p>
            </details>
"""

SETUP_NATIVE_CANARY_SCRIPT = r"""
    const setupCanaryRequest = 'serverware.setupNativeCanaryRequest/v1';
    let setupCanaryHeld = null, setupCanaryEpoch = 0, setupCanaryOperation = null, setupCanaryContact = false;
    function setupCanaryNeed(value) {
      if (!value) throw new Error('Native publication context or originals changed. Read retained state; do not repeat an uncertain association.');
    }
    function setupCanaryMessage(value) { $('setup-native-canary-status').textContent = value; }
    function setupNativeCanaryClear() {
      setupCanaryEpoch++; setupCanaryOperation?.abort(); setupCanaryHeld = null;
      $('setup-native-canary-confirm').checked = false;
      $('setup-native-canary-review').textContent = 'No current publication association reviewed.';
      $('setup-native-canary-result').textContent = 'No current association observation.';
      setupCanaryMessage(setupCanaryContact ? 'In-flight association may have committed. Review discarded; read retained state only. Submission marker remains.'
        : 'Page-held review discarded. Original lifetimes and nonsecret submission markers are unchanged.');
    }
    function setupCanaryBegin() {
      const base = setupEnrollmentBegin(), epoch = setupCanaryEpoch;
      const operation = {...base, current() { base.current(); setupCanaryNeed(epoch === setupCanaryEpoch); },
        close() { base.close(); if (setupCanaryOperation === operation) setupCanaryOperation = null; }};
      setupCanaryOperation = operation; return operation;
    }
    function setupCanaryMarker(operation) { return 'serverware.setup-native-canary:' + operation.actor + ':' + operation.session; }
    async function setupCanaryPost(phase, body, operation, beforeContact = null) {
      setupCanaryNeed(['draft', 'options', 'record', 'lookup'].includes(phase));
      const original = oauthConsentCanonical(body);
      setupCanaryNeed(new TextEncoder().encode(original).byteLength <= 32768);
      operation.current();
      const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: operation.signal});
      const csrf = await setupPolicyRead(csrfResponse, operation, 4096);
      setupCanaryNeed(csrfResponse.ok && oauthConsentClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
        && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token' && workloadIssuanceText(csrf.token, 1024));
      operation.current(); if (beforeContact) beforeContact();
      const response = await fetch('/api/setup/native-canary/' + phase, {method: 'POST', credentials: 'same-origin', mode: 'same-origin',
        redirect: 'error', cache: 'no-store', signal: operation.signal,
        headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: original});
      const value = await setupPolicyRead(response, operation, 65536);
      operation.current(); return {status: response.status, value};
    }
    function setupCanaryReply(reply, status, name, fields) {
      const v = reply.value;
      setupCanaryNeed(reply.status === status && oauthConsentClosed(v, ['apiVersion', 'status', 'okForAction', 'automaticRetryAllowed',
        'nativeHostVerified', 'enrollmentComplete', 'proxyReady', ...fields])
        && v.apiVersion === 'serverware.setupNativeCanaryResponse/v1' && v.status === name
        && v.okForAction === false && v.automaticRetryAllowed === false && v.nativeHostVerified === false
        && v.enrollmentComplete === false && v.proxyReady === false); return v;
    }
    async function setupCanaryArguments(original, operation) {
      const v = setupNativeOriginal(original, 16384), r = v.request;
      const rotated = r?.apiVersion === 'serverware.setupNativeCanaryAssociation/v2';
      setupCanaryNeed(oauthConsentClosed(v, ['actor_id', 'control_plane_configuration_digest', 'credential_policy', 'request'])
        && v.actor_id === operation.actor && oauthConsentDigest(v.control_plane_configuration_digest)
        && v.credential_policy && typeof v.credential_policy === 'object' && !Array.isArray(v.credential_policy)
        && oauthConsentClosed(r, ['apiVersion', 'sessionId', 'setupSha256', 'continuationSha256', 'enrollmentSha256',
          'installationSha256', 'canaryId', 'finalizationSha256', 'publicationSha256', 'policyHash', 'activationPolicySha256',
          'credentialId', 'credentialVersion', 'enrollmentApprovalId', 'nativeApprovalId', 'auditIds', 'issuedAtEpochNs', 'expiresAtEpochNs',
          ...(rotated ? ['rotationAuditId'] : [])])
        && r.apiVersion === (rotated ? 'serverware.setupNativeCanaryAssociation/v2' : 'serverware.setupNativeCanaryAssociation/v1')
        && r.sessionId === operation.session
        && workloadIssuanceText(r.canaryId, 256) && nativeSetupId(r.credentialId) && nativeSetupId(r.enrollmentApprovalId)
        && nativeSetupId(r.nativeApprovalId) && (rotated ? nativeSetupId(r.rotationAuditId)
          && oauthConsentInteger(r.credentialVersion) >= 2n && oauthConsentInteger(r.credentialVersion) <= 9223372036854775807n
          : oauthConsentInteger(r.credentialVersion) === 1n)
        && ['setupSha256', 'continuationSha256', 'enrollmentSha256', 'installationSha256', 'finalizationSha256',
          'publicationSha256', 'policyHash', 'activationPolicySha256'].every(key => oauthConsentDigest(r[key]))
        && Array.isArray(r.auditIds) && r.auditIds.length === 9 && r.auditIds.every(nativeSetupId)
        && new Set(r.auditIds).size === 9 && JSON.stringify(r.auditIds) === JSON.stringify([...r.auditIds].sort()));
      const before = oauthConsentInteger(r.issuedAtEpochNs), after = oauthConsentInteger(r.expiresAtEpochNs);
      setupCanaryNeed(before > 0n && before < after && after - before <= 30000000000n && after <= 9223372036854775807n);
      if (rotated) {
        const chain = await setupEnrollmentRotationLookup({...r, ownerId: operation.actor}, operation);
        setupCanaryNeed(chain.rotationAuditId === r.rotationAuditId);
      }
      return v;
    }
    function setupCanaryCurrent(held, operation) {
      operation.current();
      setupCanaryNeed(setupCanaryHeld === held && held.actor === operation.actor && held.scope === operation.scope
        && held.session === operation.session && performance.now() < held.until
        && BigInt(Date.now()) * 1000000n < held.expires);
    }
    async function setupNativeCanaryDraft() {
      const operation = setupCanaryBegin(); setupCanaryHeld = null; $('setup-native-canary-confirm').checked = false;
      $('setup-native-canary-review').textContent = 'Reading the server-selected publication; no current review accepted.';
      try {
        setupCanaryNeed(sessionStorage.getItem(setupCanaryMarker(operation)) === null);
        await setupEnrollmentCookie(operation);
        const v = setupCanaryReply(await setupCanaryPost('draft', {apiVersion: setupCanaryRequest, sessionId: operation.session}, operation),
          200, 'draft', ['argumentsOriginal', 'argumentsSha256', 'review']);
        const args = await setupCanaryArguments(v.argumentsOriginal, operation), request = args.request;
        const fields = ['sessionId', 'canaryId', 'policyHash', 'credentialId', 'credentialVersion', 'enrollmentSha256',
          'installationSha256', 'finalizationSha256', 'publicationSha256', 'expiresAtEpochNs'];
        setupCanaryNeed(oauthConsentClosed(v.review, fields) && fields.every(key =>
          oauthConsentCanonical(v.review[key]) === oauthConsentCanonical(request[key]))
          && oauthConsentDigest(v.argumentsSha256)
          && await workloadIssuanceHash(new TextEncoder().encode(v.argumentsOriginal)) === v.argumentsSha256);
        const expires = oauthConsentInteger(request.expiresAtEpochNs), remaining = expires - BigInt(Date.now()) * 1000000n;
        setupCanaryNeed(remaining > 0n && remaining <= 30000000000n);
        operation.current();
        setupCanaryHeld = {original: v.argumentsOriginal, digest: v.argumentsSha256, request, expires,
          until: performance.now() + Number(remaining / 1000000n), actor: operation.actor, scope: operation.scope, session: operation.session};
        $('setup-native-canary-review').textContent = oauthConsentCanonical({...v.review, argumentsSha256: v.argumentsSha256});
        setupCanaryMessage('Review this exact server-selected history. The short association window does not renew any certificate, installation grant or native effect.');
      } finally { operation.close(); }
    }
    async function setupCanaryPasskey(options, operation, digest) {
      const key = options?.publicKey, s = options?.serverware;
      setupCanaryNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
        && oauthConsentClosed(s, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest'])
        && s.schema === 'serverware.setupNativeCanaryOptions/v1' && s.operation === 'setup.native-canary.record'
        && s.payloadDigest === digest && oauthConsentDigest(s.operationId) && oauthConsentDigest(s.challengeId) && nativeSetupId(s.credentialRecordId)
        && oauthConsentClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && key.rpId === location.hostname && key.userVerification === 'required' && oauthConsentInteger(key.timeout) === 30000n
        && workloadIssuanceBase64(key.challenge, 32).byteLength === 32 && Array.isArray(key.allowCredentials)
        && key.allowCredentials.length === 1 && oauthConsentClosed(key.allowCredentials[0], ['type', 'id'])
        && key.allowCredentials[0].type === 'public-key');
      workloadIssuanceBase64(key.allowCredentials[0].id, 3072);
      const prepared = {publicKey: {...key, timeout: 30000}};
      operation.current();
      const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions(prepared)});
      operation.current();
      setupCanaryNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.id === key.allowCredentials[0].id && credential.rawId.byteLength <= 3072 && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential);
      setupCanaryNeed(workloadIssuanceAssertionOriginal(assertion, prepared).byteLength <= 16384); return assertion;
    }
    function setupCanaryPublic(v, request = null) {
      setupCanaryNeed(oauthConsentClosed(v, ['revision', 'phase', 'canaryId', 'policyHash', 'finalizationSha256',
        'publicationSha256', 'requestDigest', 'associatedAtEpochNs']) && oauthConsentInteger(v.revision) === 0n
        && v.phase === 'canary_publication_associated' && workloadIssuanceText(v.canaryId, 256)
        && ['policyHash', 'finalizationSha256', 'publicationSha256', 'requestDigest'].every(key => oauthConsentDigest(v[key]))
        && oauthConsentInteger(v.associatedAtEpochNs) > 0n);
      if (request) setupCanaryNeed(['canaryId', 'policyHash', 'finalizationSha256', 'publicationSha256'].every(key => v[key] === request[key])
        && oauthConsentInteger(request.issuedAtEpochNs) <= oauthConsentInteger(v.associatedAtEpochNs)
        && oauthConsentInteger(v.associatedAtEpochNs) < oauthConsentInteger(request.expiresAtEpochNs));
      return v;
    }
    async function setupNativeCanaryRecord() {
      const held = setupCanaryHeld; setupCanaryNeed(held && $('setup-native-canary-confirm').checked);
      const operation = setupCanaryBegin(); let sent = false, assertion = null;
      const scoped = {...operation, current() { setupCanaryCurrent(held, operation); setupCanaryNeed($('setup-native-canary-confirm').checked); }};
      try {
        scoped.current(); setupCanaryNeed(sessionStorage.getItem(setupCanaryMarker(operation)) === null);
        await setupEnrollmentCookie(scoped);
        const body = {apiVersion: setupCanaryRequest, argumentsOriginal: held.original};
        const v = setupCanaryReply(await setupCanaryPost('options', body, scoped), 200, 'fresh-assertion-required', ['options']);
        assertion = await setupCanaryPasskey(v.options, scoped, held.digest); await setupEnrollmentCookie(scoped);
        const result = setupCanaryReply(await setupCanaryPost('record', {...body, assertion}, scoped, () => {
          scoped.current(); const marker = setupCanaryMarker(operation); setupCanaryNeed(sessionStorage.getItem(marker) === null);
          sessionStorage.setItem(marker, held.digest); setupCanaryNeed(sessionStorage.getItem(marker) === held.digest);
          sent = true; setupCanaryContact = true;
        }), 201, 'canary-publication-associated', ['association']);
        const observed = setupCanaryPublic(result.association, held.request);
        scoped.current(); $('setup-native-canary-result').textContent = oauthConsentCanonical(observed);
        setupCanaryHeld = null;
        setupCanaryMessage('The server retained this native publication association. No measured-host, proxy-readiness or final Setup claim is made.');
      } catch (error) {
        setupCanaryMessage(sent ? 'Association outcome is uncertain. Read retained state only; do not resubmit or renew this attempt.'
          : 'Review or fresh passkey did not complete. No association submission was sent.'); throw error;
      } finally { assertion = null; setupCanaryContact = false; $('setup-native-canary-confirm').checked = false; operation.close(); }
    }
    async function setupNativeCanaryLookup() {
      const operation = setupCanaryBegin();
      try {
        await setupEnrollmentCookie(operation);
        const v = setupCanaryReply(await setupCanaryPost('lookup', {apiVersion: setupCanaryRequest, sessionId: operation.session}, operation),
          200, 'observation', ['association', 'associationOriginal']);
        setupCanaryNeed((v.association === null) === (v.associationOriginal === null));
        if (v.association !== null) {
          const row = setupNativeOriginal(v.associationOriginal, 32768);
          setupCanaryNeed(oauthConsentClosed(row, ['session_id', 'revision', 'phase', 'owner_id', 'setup_sha256', 'continuation_sha256',
            'enrollment_sha256', 'installation_sha256', 'canary_id', 'finalization_sha256', 'publication_sha256', 'policy_hash',
            'request_original', 'request_digest', 'configuration_digest', 'audit_event_digest', 'associated_at'])
            && row.session_id === operation.session && row.owner_id === operation.actor
            && oauthConsentInteger(row.revision) === 0n && row.phase === 'canary_publication_associated');
          const args = await setupCanaryArguments(row.request_original, operation);
          setupCanaryNeed(row.configuration_digest === args.control_plane_configuration_digest
            && row.request_digest === v.association.requestDigest && row.canary_id === v.association.canaryId
            && row.policy_hash === v.association.policyHash && row.finalization_sha256 === v.association.finalizationSha256
            && row.publication_sha256 === v.association.publicationSha256);
          setupCanaryPublic(v.association, args.request);
        }
        operation.current(); $('setup-native-canary-result').textContent = oauthConsentCanonical(v.association);
        setupCanaryMessage(v.association === null ? 'No association observed. This does not clear a submission marker or authorize retry.'
          : 'Historical association observed. No contact repeated, expiry renewed, or current proxy readiness established.');
      } finally { operation.close(); }
    }
    $('setup-policy-session').addEventListener('input', setupNativeCanaryClear);
    window.addEventListener('pagehide', setupNativeCanaryClear);
"""
