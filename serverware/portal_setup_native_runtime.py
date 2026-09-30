"""Manual original capture handoff into protected Setup; no browser proxy call."""

SETUP_NATIVE_RUNTIME_HTML = r"""
            <hr>
            <details id="setup-native-runtime-controls">
              <summary>Record one native request/response capture for Setup</summary>
              <p class="hint">Uses the Setup session ID above after certificate issuance, authenticated CA readback and native policy association. Both credential_owner and policy_author are required. The server selects the independently approved collector, native runtime and fixed empty-body GET scope; this page never contacts the proxy or creates a success claim.</p>
              <label><input id="setup-native-runtime-prepare-confirm" type="checkbox">Prepare one evidence attempt for this exact Setup under its independently selected scope. I understand that an uncertain submission cannot be retried.</label>
              <button type="button" onclick="runUiAction('Prepare native runtime evidence once', setupNativeRuntimePrepare)">Fresh requester passkey + prepare once</button>
              <button type="button" class="secondary" onclick="runUiAction('Read native runtime evidence state', setupNativeRuntimeLookup)">Read retained state and recover exact bundle</button>
              <pre id="setup-native-runtime-review">No retained evidence attempt.</pre>
              <p class="hint">Review the exact target below before an independently authorized operator uses the existing buffered native proof client. These public originals are not request authorization or new trust roots. Do not upload private keys. Recovery or download never authorizes repeating an uncertain proxy request.</p>
              <div class="toolbar">
                <button id="setup-native-runtime-download-attempt" type="button" class="secondary" disabled onclick="runUiAction('Download exact runtime attempt', () => setupNativeRuntimeDownload('attempt'))">Attempt original</button>
                <button id="setup-native-runtime-download-scope" type="button" class="secondary" disabled onclick="runUiAction('Download exact runtime scope', () => setupNativeRuntimeDownload('scope'))">Scope original</button>
                <button id="setup-native-runtime-download-expectations" type="button" class="secondary" disabled onclick="runUiAction('Download exact native expectations', () => setupNativeRuntimeDownload('expectations'))">Native expectations original</button>
              </div>
              <label for="setup-native-runtime-capture">Exact nativeResponseCapture/v2 buffered capture file (at most 512 KiB, original whitespace preserved)</label>
              <input id="setup-native-runtime-capture" type="file" accept="application/json,.json" autocomplete="off">
              <button type="button" class="secondary" onclick="runUiAction('Review native runtime capture', setupNativeRuntimeReview)">Review original capture binding</button>
              <pre id="setup-native-runtime-capture-review">No capture reviewed.</pre>
              <label><input id="setup-native-runtime-complete-confirm" type="checkbox">I reviewed this exact attempt, nonce, request and capture. The server must independently verify all original signatures, quote, receipt and current bindings.</label>
              <button type="button" onclick="runUiAction('Record native runtime evidence once', setupNativeRuntimeComplete)">Submit exact capture once</button>
              <button type="button" class="secondary" onclick="setupNativeRuntimeClear()">Clear page-held originals</button>
              <pre id="setup-native-runtime-result">No retained native runtime evidence.</pre>
              <p id="setup-native-runtime-status" class="hint" role="status" aria-live="polite">Evidence recording is not measured host proof, proxy readiness or completed Setup. One-use evidence consumption does not enforce a single upstream contact; never infer permission to rerun the collector.</p>
            </details>
"""

SETUP_NATIVE_RUNTIME_SCRIPT = r"""
    const setupRuntimeRequest = 'serverware.setupNativeRuntimeRequest/v1';
    let setupRuntimeBundle = null, setupRuntimeCapture = null, setupRuntimeEpoch = 0;
    let setupRuntimeOperation = null, setupRuntimeContact = false;
    function setupRuntimeNeed(value) {
      if (!value) throw new Error('Native runtime context or exact originals changed. Read retained state; do not retry an uncertain attempt.');
    }
    function setupRuntimeMessage(value) { $('setup-native-runtime-status').textContent = value; }
    function setupRuntimeDownloads(enabled) {
      ['attempt', 'scope', 'expectations'].forEach(name => { $('setup-native-runtime-download-' + name).disabled = !enabled; });
    }
    function setupNativeRuntimeClear() {
      setupRuntimeEpoch++; setupRuntimeOperation?.abort(); setupRuntimeBundle = null;
      if (setupRuntimeCapture) setupRuntimeCapture.bytes.fill(0);
      setupRuntimeCapture = null; setupRuntimeDownloads(false);
      $('setup-native-runtime-capture').value = '';
      $('setup-native-runtime-prepare-confirm').checked = false; $('setup-native-runtime-complete-confirm').checked = false;
      $('setup-native-runtime-review').textContent = 'No page-held evidence attempt.';
      $('setup-native-runtime-capture-review').textContent = 'No current capture review.';
      $('setup-native-runtime-result').textContent = 'No current retained-evidence observation.';
      setupRuntimeMessage(setupRuntimeContact ? 'An in-flight submission may have committed. Read retained state only; nonsecret markers remain.'
        : 'Page-held originals discarded. Original deadlines and nonsecret attempt markers are unchanged.');
    }
    function setupRuntimeBegin() {
      const base = setupEnrollmentBegin(), epoch = setupRuntimeEpoch;
      const operation = {...base, current() { base.current(); setupRuntimeNeed(epoch === setupRuntimeEpoch); },
        close() { base.close(); if (setupRuntimeOperation === operation) setupRuntimeOperation = null; }};
      setupRuntimeOperation = operation; return operation;
    }
    function setupRuntimeContext(held, operation) {
      operation.current(); setupRuntimeNeed(held && held.actor === operation.actor && held.authScope === operation.scope && held.session === operation.session);
    }
    function setupRuntimeMarker(operation, phase) {
      return 'serverware.setup-native-runtime:' + operation.actor + ':' + operation.session + ':' + phase;
    }
    function setupRuntimeMark(operation, phase, digest) {
      const key = setupRuntimeMarker(operation, phase); operation.current();
      setupRuntimeNeed(oauthConsentDigest(digest) && sessionStorage.getItem(key) === null);
      sessionStorage.setItem(key, digest); setupRuntimeNeed(sessionStorage.getItem(key) === digest);
      setupRuntimeContact = true;
    }
    async function setupRuntimePost(phase, body, operation, beforeContact = null) {
      setupRuntimeNeed(['options', 'prepare', 'complete', 'lookup'].includes(phase));
      let original = oauthConsentCanonical(body), csrf = null;
      setupRuntimeNeed(new TextEncoder().encode(original).byteLength <= 768 * 1024);
      try {
        operation.current();
        const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
          cache: 'no-store', signal: operation.signal});
        csrf = await setupPolicyRead(csrfResponse, operation, 4096);
        setupRuntimeNeed(csrfResponse.ok && oauthConsentClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
          && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token' && workloadIssuanceText(csrf.token, 1024));
        operation.current(); if (beforeContact) beforeContact();
        const response = await fetch('/api/setup/native-runtime/' + phase, {method: 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        return {status: response.status, value: await setupPolicyRead(response, operation, 128 * 1024)};
      } finally { original = null; csrf = null; }
    }
    function setupRuntimeReply(reply, status, name, fields) {
      const v = reply.value;
      setupRuntimeNeed(reply.status === status && oauthConsentClosed(v, ['apiVersion', 'status', 'okForAction', 'automaticRetryAllowed',
        'nativeHostVerified', 'enrollmentComplete', 'proxyReady', ...fields]) && v.apiVersion === 'serverware.setupNativeRuntimeResponse/v1'
        && v.status === name && v.okForAction === false && v.automaticRetryAllowed === false && v.nativeHostVerified === false
        && v.enrollmentComplete === false && v.proxyReady === false); return v;
    }
    function setupRuntimePublic(v) {
      setupRuntimeNeed(oauthConsentClosed(v, ['revision', 'phase', 'attemptSha256', 'captureSha256', 'prepareRequestDigest', 'completeRequestDigest'])
        && oauthConsentDigest(v.attemptSha256) && oauthConsentDigest(v.prepareRequestDigest));
      const revision = oauthConsentInteger(v.revision);
      setupRuntimeNeed(revision === 0n ? v.phase === 'capture_outcome_unknown' && v.captureSha256 === null && v.completeRequestDigest === null
        : revision === 1n && v.phase === 'runtime_evidence_recorded' && oauthConsentDigest(v.captureSha256) && oauthConsentDigest(v.completeRequestDigest));
      return v;
    }
    function setupRuntimeAssignment(v) {
      const fields = ['holderId', 'bootId', 'keyId', 'controlPlaneResponseSigningKeyId', 'releaseRecordSha256', 'policyHash',
        'configurationSha256', 'caCertificateSha256', 'caPublicKeySpkiSha256', 'expectedBinaryDigest', 'expectedPcrs',
        'expectedEif', 'expectedModuleId', 'maxAgeSeconds', 'futureSkewSeconds'];
      setupRuntimeNeed(oauthConsentClosed(v, fields) && workloadIssuanceBase64(v.bootId, 32).byteLength === 32
        && fields.filter(key => !['bootId', 'expectedPcrs', 'expectedEif', 'expectedModuleId', 'maxAgeSeconds', 'futureSkewSeconds'].includes(key))
          .every(key => oauthConsentDigest(v[key])) && workloadIssuanceText(v.expectedModuleId, 256)
        && typeof v.expectedEif === 'string' && /^sha384:[0-9a-f]{96}$/.test(v.expectedEif)
        && v.expectedPcrs && typeof v.expectedPcrs === 'object' && !Array.isArray(v.expectedPcrs)
        && Object.keys(v.expectedPcrs).length >= 3 && Object.keys(v.expectedPcrs).length <= 32
        && ['PCR0', 'PCR1', 'PCR2'].every(key => Object.hasOwn(v.expectedPcrs, key))
        && Object.entries(v.expectedPcrs).every(([key, value]) => /^PCR(?:[0-9]|[12][0-9]|3[01])$/.test(key)
          && typeof value === 'string' && /^sha384:[0-9a-f]{96}$/.test(value)) && v.expectedPcrs.PCR0 === v.expectedEif
        && oauthConsentInteger(v.maxAgeSeconds) >= 1n && oauthConsentInteger(v.maxAgeSeconds) <= 300n
        && oauthConsentInteger(v.futureSkewSeconds) >= 0n && oauthConsentInteger(v.futureSkewSeconds) <= 30n);
      return v;
    }
    async function setupRuntimeReadBundle(v, publicValue, operation) {
      const row = setupRuntimePublic(publicValue);
      setupRuntimeNeed(oauthConsentClosed(v, ['attemptOriginal', 'scopeOriginal', 'expectationsOriginal']));
      const attempt = setupNativeOriginal(v.attemptOriginal, 8192), scope = setupNativeOriginal(v.scopeOriginal, 32768);
      const expected = setupNativeOriginal(v.expectationsOriginal, 16384);
      setupRuntimeNeed(oauthConsentClosed(attempt, ['apiVersion', 'attemptId', 'sessionId', 'associationSha256', 'scopeSha256', 'nonce',
        'principalId', 'routeId', 'policyHash', 'credentialId', 'credentialVersion', 'clientRequestSha256', 'issuedAtEpochNs', 'expiresAtEpochNs'])
        && attempt.apiVersion === 'serverware.setupNativeRuntimeAttempt/v1' && nativeSetupId(attempt.attemptId)
        && attempt.sessionId === operation.session && nativeSetupId(attempt.credentialId) && oauthConsentInteger(attempt.credentialVersion) === 1n
        && workloadIssuanceText(attempt.principalId, 1024) && workloadIssuanceText(attempt.routeId, 1024)
        && workloadIssuanceBase64(attempt.nonce, 32).byteLength === 32
        && ['associationSha256', 'scopeSha256', 'policyHash', 'clientRequestSha256'].every(key => oauthConsentDigest(attempt[key]))
        && oauthConsentClosed(scope, ['sessionId', 'principalId', 'routeId', 'credentialId', 'credentialVersion', 'clientRequest', 'serverInstanceId',
          'collectorPublicKeyPem', 'controlPlanePublicKeyPem', 'nativeAssignment', 'issuedAtEpochNs', 'expiresAtEpochNs', 'maximumAttemptNanos',
          'responseRuntimeManifestSha256', 'responseProvenanceSha256'])
        && ['sessionId', 'principalId', 'routeId', 'credentialId'].every(key => scope[key] === attempt[key])
        && oauthConsentInteger(scope.credentialVersion) === 1n && workloadIssuanceText(scope.serverInstanceId, 1024)
        && typeof scope.collectorPublicKeyPem === 'string' && scope.collectorPublicKeyPem.length <= 16384
        && typeof scope.controlPlanePublicKeyPem === 'string' && scope.controlPlanePublicKeyPem.length <= 16384
        && oauthConsentDigest(scope.responseRuntimeManifestSha256) && oauthConsentDigest(scope.responseProvenanceSha256));
      const assignment = setupRuntimeAssignment(scope.nativeAssignment), request = scope.clientRequest;
      setupRuntimeNeed(oauthConsentClosed(request, ['apiVersion', 'method', 'scheme', 'authority', 'path', 'query', 'headers', 'body_sha256'])
        && request.apiVersion === 'serverware.clientProofRequest/v1' && request.method === 'GET' && request.scheme === 'https'
        && workloadIssuanceText(request.authority, 256) && workloadIssuanceText(request.path, 4096) && request.path.startsWith('/')
        && Array.isArray(request.query) && request.query.length === 0 && oauthConsentClosed(request.headers, [])
        && request.body_sha256 === 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        && assignment.policyHash === attempt.policyHash);
      const expectedFields = Object.keys(assignment).filter(key => key !== 'holderId');
      setupRuntimeNeed(oauthConsentClosed(expected, ['apiVersion', 'statementProfile', 'nonce', ...expectedFields])
        && expected.apiVersion === 'serverware.nativeResponseAttestationExpectations/v2'
        && expected.statementProfile === 'serverware.nativeResponseStatements/v1' && expected.nonce === attempt.nonce
        && expectedFields.every(key => oauthConsentCanonical(expected[key]) === oauthConsentCanonical(assignment[key])));
      const before = oauthConsentInteger(attempt.issuedAtEpochNs), expires = oauthConsentInteger(attempt.expiresAtEpochNs);
      setupRuntimeNeed(before > 0n && before < expires && expires <= 9223372036854775807n && expires - before <= 300000000000n
        && oauthConsentInteger(scope.issuedAtEpochNs) <= before && expires <= oauthConsentInteger(scope.expiresAtEpochNs)
        && expires - before <= oauthConsentInteger(scope.maximumAttemptNanos)
        && await workloadIssuanceHash(new TextEncoder().encode(v.attemptOriginal)) === row.attemptSha256
        && await workloadIssuanceHash(new TextEncoder().encode(v.scopeOriginal)) === attempt.scopeSha256
        && await workloadIssuanceHash(new TextEncoder().encode(oauthConsentCanonical(request))) === attempt.clientRequestSha256);
      operation.current();
      const remaining = expires - BigInt(Date.now()) * 1000000n;
      const liveRemaining = remaining > 0n && remaining <= 300000000000n ? remaining : 0n;
      return {...v, attempt, scope, row, expires, until: performance.now() + Number(liveRemaining / 1000000n),
        actor: operation.actor, authScope: operation.scope, session: operation.session};
    }
    function setupRuntimeShow(held) {
      setupRuntimeDownloads(true);
      $('setup-native-runtime-review').textContent = oauthConsentCanonical({sessionId: held.session, phase: held.row.phase,
        attemptId: held.attempt.attemptId, attemptSha256: held.row.attemptSha256, scopeSha256: held.attempt.scopeSha256,
        principalId: held.attempt.principalId, routeId: held.attempt.routeId, credentialId: held.attempt.credentialId,
        policyHash: held.attempt.policyHash, clientRequest: held.scope.clientRequest, serverInstanceId: held.scope.serverInstanceId,
        nativeKeyId: held.scope.nativeAssignment.keyId, expiresAtEpochNs: held.attempt.expiresAtEpochNs});
    }
    async function setupRuntimePasskey(options, operation) {
      const key = options?.publicKey, s = options?.serverware;
      setupRuntimeNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
        && oauthConsentClosed(s, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest'])
        && s.schema === 'serverware.setupNativeRuntimeOptions/v1' && s.operation === 'setup.native-runtime.prepare'
        && oauthConsentDigest(s.operationId) && oauthConsentDigest(s.challengeId) && oauthConsentDigest(s.payloadDigest) && nativeSetupId(s.credentialRecordId)
        && oauthConsentClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && key.rpId === location.hostname && key.userVerification === 'required' && oauthConsentInteger(key.timeout) === 30000n
        && workloadIssuanceBase64(key.challenge, 32).byteLength === 32 && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
        && oauthConsentClosed(key.allowCredentials[0], ['type', 'id']) && key.allowCredentials[0].type === 'public-key');
      workloadIssuanceBase64(key.allowCredentials[0].id, 3072);
      setupRuntimeMessage('Fresh setup.native-runtime.prepare assertion for the server-selected original arguments: ' + s.payloadDigest
        + '. This does not contact or authorize a proxy request.');
      const prepared = {publicKey: {...key, timeout: 30000}};
      operation.current();
      const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions(prepared)});
      operation.current();
      setupRuntimeNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer && credential.rawId.byteLength <= 3072
        && credential.id === key.allowCredentials[0].id && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential);
      setupRuntimeNeed(workloadIssuanceAssertionOriginal(assertion, prepared).byteLength <= 16384);
      return {assertion, digest: s.payloadDigest};
    }
    async function setupNativeRuntimePrepare() {
      setupRuntimeNeed($('setup-native-runtime-prepare-confirm').checked && setupRuntimeBundle === null);
      const operation = setupRuntimeBegin(); let sent = false, evidence = null;
      const scoped = {...operation, current() { operation.current(); setupRuntimeNeed($('setup-native-runtime-prepare-confirm').checked); }};
      try {
        scoped.current(); setupRuntimeNeed(sessionStorage.getItem(setupRuntimeMarker(operation, 'prepare')) === null);
        await setupEnrollmentCookie(scoped);
        const body = {apiVersion: setupRuntimeRequest, sessionId: operation.session};
        const options = setupRuntimeReply(await setupRuntimePost('options', body, scoped), 200, 'fresh-assertion-required', ['options']);
        evidence = await setupRuntimePasskey(options.options, scoped); await setupEnrollmentCookie(scoped);
        const v = setupRuntimeReply(await setupRuntimePost('prepare', {...body, assertion: evidence.assertion}, scoped, () => {
          setupRuntimeMark(scoped, 'prepare', evidence.digest); sent = true;
        }), 201, 'capture-outcome-unknown', ['runtime', 'bundle']);
        const held = await setupRuntimeReadBundle(v.bundle, v.runtime, scoped);
        setupRuntimeNeed(held.row.phase === 'capture_outcome_unknown'); scoped.current();
        setupRuntimeBundle = held; setupRuntimeShow(held);
        setupRuntimeMessage('One protected evidence attempt retained. Review the exact target and original deadline before independent operator action. No proxy contact or successful request is claimed.');
      } catch (error) {
        setupRuntimeBundle = null; setupRuntimeDownloads(false);
        setupRuntimeMessage(sent ? 'Preparation outcome is uncertain. Read retained state to recover its exact bundle; do not prepare again.'
          : 'Fresh assertion or current Setup scope unavailable. No preparation submission was sent.'); throw error;
      } finally { evidence = null; setupRuntimeContact = false; $('setup-native-runtime-prepare-confirm').checked = false; operation.close(); }
    }
    function setupRuntimeLive(held, operation) {
      setupRuntimeContext(held, operation);
      setupRuntimeNeed(setupRuntimeBundle === held && held.row.phase === 'capture_outcome_unknown'
        && performance.now() < held.until && BigInt(Date.now()) * 1000000n < held.expires);
    }
    async function setupNativeRuntimeReview() {
      const operation = setupRuntimeBegin(), held = setupRuntimeBundle;
      if (setupRuntimeCapture) setupRuntimeCapture.bytes.fill(0);
      setupRuntimeCapture = null; $('setup-native-runtime-complete-confirm').checked = false;
      $('setup-native-runtime-capture-review').textContent = 'Reading original capture; no current review accepted.';
      let bytes = null;
      try {
        setupRuntimeLive(held, operation); await setupEnrollmentCookie(operation);
        const list = $('setup-native-runtime-capture').files; setupRuntimeNeed(list?.length === 1);
        const file = list[0]; setupRuntimeNeed(file.size >= 2 && file.size <= 512 * 1024);
        bytes = new Uint8Array(await file.arrayBuffer()); setupRuntimeLive(held, operation);
        setupRuntimeNeed(bytes.byteLength === file.size && $('setup-native-runtime-capture').files?.[0] === file);
        const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);
        const artifact = oauthConsentParse(text, 512 * 1024).value, proof = artifact?.runtime_proof, statement = proof?.server_statement;
        setupRuntimeNeed(oauthConsentClosed(artifact, ['apiVersion', 'kind', 'resultScope', 'okForAction', 'environment', 'captureMode',
          'external_capture', 'runtime_proof', 'native_verification', 'collector_signature'])
          && artifact.apiVersion === 'serverware.nativeResponseCapture/v2' && artifact.kind === 'ServerwareNativeResponseCapture'
          && artifact.resultScope === 'local-capture-and-native-quote-only' && artifact.okForAction === false
          && artifact.environment === 'native-unadmitted' && artifact.captureMode === 'buffered'
          && oauthConsentClosed(proof, ['apiVersion', 'kind', 'server_statement', 'server_statement_sha256', 'server_signature', 'native_attestation'])
          && proof.apiVersion === 'serverware.nativeResponseRuntimeProof/v2' && proof.kind === 'ServerwareNativeResponseRuntimeProof'
          && oauthConsentDigest(proof.server_statement_sha256)
          && oauthConsentClosed(statement, ['apiVersion', 'issued_at_unix', 'client_nonce', 'principal_id', 'route_id', 'request_digest', 'operation_digest',
            'runtime_manifest_digest', 'data_plane_binary_digest', 'release_digest', 'server_instance', 'tls_channel_binding', 'client_request_digest',
            'release_authority', 'control_plane_authorization_receipt', 'upstream_response', 'policy_digest', 'response'])
          && statement.apiVersion === 'serverware.nativeProxyResponseStatement/v1'
          && statement.client_nonce === held.attempt.nonce && statement.client_request_digest === held.attempt.clientRequestSha256
          && statement.principal_id === held.attempt.principalId && statement.route_id === held.attempt.routeId && statement.policy_digest === held.attempt.policyHash
          && statement.data_plane_binary_digest === held.scope.nativeAssignment.expectedBinaryDigest
          && statement.runtime_manifest_digest === held.scope.responseRuntimeManifestSha256 && statement.release_digest === held.scope.responseProvenanceSha256
          && oauthConsentDigest(statement.request_digest) && oauthConsentDigest(statement.operation_digest)
          && oauthConsentClosed(statement.response, ['status', 'selected_headers', 'selected_headers_digest', 'body_digest'])
          && oauthConsentInteger(statement.response.status) >= 200n && oauthConsentInteger(statement.response.status) <= 299n
          && oauthConsentDigest(statement.response.body_digest));
        const digest = await workloadIssuanceHash(bytes); setupRuntimeLive(held, operation);
        setupRuntimeNeed($('setup-native-runtime-capture').files?.[0] === file);
        setupRuntimeCapture = {bytes, digest, file, held, actor: operation.actor, authScope: operation.scope, session: operation.session}; bytes = null;
        $('setup-native-runtime-capture-review').textContent = oauthConsentCanonical({attemptSha256: held.row.attemptSha256, captureSha256: digest,
          serverStatementSha256: proof.server_statement_sha256, requestSha256: statement.request_digest, operationSha256: statement.operation_digest,
          responseStatus: statement.response.status, responseBodySha256: statement.response.body_digest});
        setupRuntimeMessage('Original capture binding reviewed structurally only. Uploaded verdicts are not authority; the server must verify original collector/native signatures, Nitro evidence, CP receipt and current protected state.');
      } catch (error) {
        setupRuntimeMessage('No capture accepted for page-held review. No completion submission or proxy request was sent.'); throw error;
      } finally { if (bytes) bytes.fill(0); operation.close(); }
    }
    function setupRuntimeResult(original, row, held) {
      const v = setupNativeOriginal(original, 8192);
      const digests = ['attemptSha256', 'captureSha256', 'serverStatementSha256', 'requestSha256', 'operationSha256', 'dispatchReceiptSha256',
        'responseBodySha256', 'collectorKeyId', 'nativeKeyId', 'attestationDocumentSha256'];
      setupRuntimeNeed(oauthConsentClosed(v, ['apiVersion', 'resultScope', 'okForAction', 'nativeHostVerified', 'enrollmentComplete', 'proxyReady',
        'responseStatus', ...digests]) && v.apiVersion === 'serverware.setupNativeRuntimeEvidence/v1'
        && v.resultScope === 'trusted-collector-and-native-signatures-only' && v.okForAction === false && v.nativeHostVerified === false
        && v.enrollmentComplete === false && v.proxyReady === false && digests.every(key => oauthConsentDigest(v[key]))
        && oauthConsentInteger(v.responseStatus) >= 200n && oauthConsentInteger(v.responseStatus) <= 299n
        && row.phase === 'runtime_evidence_recorded' && v.attemptSha256 === row.attemptSha256 && v.captureSha256 === row.captureSha256
        && v.attemptSha256 === held.row.attemptSha256 && v.nativeKeyId === held.scope.nativeAssignment.keyId);
      return v;
    }
    async function setupNativeRuntimeComplete() {
      const capture = setupRuntimeCapture; setupRuntimeNeed(capture && $('setup-native-runtime-complete-confirm').checked);
      const operation = setupRuntimeBegin(); let sent = false;
      const scoped = {...operation, current() { setupRuntimeLive(capture.held, operation); setupRuntimeContext(capture, operation);
        setupRuntimeNeed(setupRuntimeCapture === capture && $('setup-native-runtime-capture').files?.[0] === capture.file
          && $('setup-native-runtime-complete-confirm').checked); }};
      try {
        scoped.current(); setupRuntimeNeed(sessionStorage.getItem(setupRuntimeMarker(operation, 'complete')) === null);
        await setupEnrollmentCookie(scoped);
        const v = setupRuntimeReply(await setupRuntimePost('complete', {apiVersion: setupRuntimeRequest, sessionId: operation.session,
          captureOriginalBase64url: bytesToB64(capture.bytes)}, scoped, () => {
            setupRuntimeMark(scoped, 'complete', capture.digest); sent = true;
          }), 200, 'runtime-evidence-recorded', ['runtime', 'resultOriginal']);
        const row = setupRuntimePublic(v.runtime); setupRuntimeNeed(row.captureSha256 === capture.digest
          && row.prepareRequestDigest === capture.held.row.prepareRequestDigest);
        setupRuntimeResult(v.resultOriginal, row, capture.held); scoped.current();
        $('setup-native-runtime-result').textContent = v.resultOriginal;
        setupRuntimeBundle = {...capture.held, row}; setupRuntimeShow(setupRuntimeBundle);
        capture.bytes.fill(0); setupRuntimeCapture = null; $('setup-native-runtime-capture').value = '';
        $('setup-native-runtime-capture-review').textContent = 'Exact capture recorded; page-held upload bytes discarded.';
        setupRuntimeMessage('The server retained this exact verified capture result. Its scope is trusted collector plus native signatures only; nativeHostVerified, enrollmentComplete and proxyReady remain false.');
      } catch (error) {
        setupRuntimeMessage(sent ? 'Completion outcome is uncertain. Read retained state only; do not resubmit or repeat the proxy request.'
          : 'Original capture or lifetime unavailable. No completion submission was sent.'); throw error;
      } finally { setupRuntimeContact = false; $('setup-native-runtime-complete-confirm').checked = false; operation.close(); }
    }
    async function setupNativeRuntimeLookup() {
      const operation = setupRuntimeBegin(); setupRuntimeBundle = null; setupRuntimeDownloads(false);
      if (setupRuntimeCapture) setupRuntimeCapture.bytes.fill(0);
      setupRuntimeCapture = null; $('setup-native-runtime-complete-confirm').checked = false;
      $('setup-native-runtime-review').textContent = 'Reading retained state; no current attempt accepted.';
      $('setup-native-runtime-capture-review').textContent = 'No current capture reviewed.';
      try {
        await setupEnrollmentCookie(operation);
        const v = setupRuntimeReply(await setupRuntimePost('lookup', {apiVersion: setupRuntimeRequest, sessionId: operation.session}, operation),
          200, 'observation', ['runtime', 'bundle', 'resultOriginal']);
        if (v.runtime === null) {
          setupRuntimeNeed(v.bundle === null && v.resultOriginal === null);
          $('setup-native-runtime-result').textContent = 'No retained attempt observed. This does not clear a submission marker or authorize retry.';
        } else {
          const held = await setupRuntimeReadBundle(v.bundle, v.runtime, operation);
          if (held.row.phase === 'runtime_evidence_recorded') setupRuntimeResult(v.resultOriginal, held.row, held);
          else setupRuntimeNeed(v.resultOriginal === null);
          operation.current(); setupRuntimeBundle = held; setupRuntimeShow(held);
          $('setup-native-runtime-result').textContent = v.resultOriginal === null ? 'Evidence attempt remains unresolved; no successful request is claimed.' : v.resultOriginal;
        }
        setupRuntimeMessage('Read-only historical state recovered. Downloads and lookup do not renew the original deadline, clear markers, authorize proxy contact or establish current readiness.');
      } catch (error) {
        setupRuntimeBundle = null; setupRuntimeDownloads(false);
        $('setup-native-runtime-result').textContent = 'No retained-state observation accepted.';
        setupRuntimeMessage('Lookup unavailable or changed. Keep the original attempt; do not infer failure or repeat the collector.'); throw error;
      } finally { operation.close(); }
    }
    function setupNativeRuntimeDownload(kind) {
      const held = setupRuntimeBundle;
      setupRuntimeNeed(!setupEnrollmentBusy && held && setupEnrollmentAuth('requester') === held.actor
        && sessionActivationAuthScope() === held.authScope && $('setup-policy-session').value.trim() === held.session);
      const selected = {attempt: ['setup-native-runtime-attempt.json', held.attemptOriginal],
        scope: ['setup-native-runtime-scope.json', held.scopeOriginal], expectations: ['setup-native-runtime-expectations.json', held.expectationsOriginal]}[kind];
      setupRuntimeNeed(selected);
      const url = URL.createObjectURL(new Blob([new TextEncoder().encode(selected[1])], {type: 'application/json'}));
      const link = document.createElement('a'); link.href = url; link.download = selected[0];
      try { link.click(); } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      setupRuntimeMessage('Exact ' + kind + ' download requested for the approved operator workflow. No request has been sent by this page; historical recovery grants neither fresh contact nor retry permission.');
    }
    $('setup-policy-session').addEventListener('input', setupNativeRuntimeClear);
    $('setup-native-runtime-capture').addEventListener('change', () => {
      setupRuntimeEpoch++; setupRuntimeOperation?.abort();
      if (setupRuntimeCapture) setupRuntimeCapture.bytes.fill(0);
      setupRuntimeCapture = null; $('setup-native-runtime-complete-confirm').checked = false;
      $('setup-native-runtime-capture-review').textContent = 'Capture selection changed; review the original file again.';
    });
    window.addEventListener('pagehide', setupNativeRuntimeClear);
"""
