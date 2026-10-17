"""Explicit native Setup enrollment UI; browser state grants no authority.

The protected Setup routes own every transition and independent issuer check.
Exact enrollment originals stay in page memory, never browser storage or logs.
"""

SETUP_NATIVE_ENROLLMENT_HTML = r"""
            <hr>
            <details id="setup-native-enrollment-controls">
              <summary>Enroll a native workload for this Setup</summary>
              <p class="hint">Uses the Setup session ID above. The requester needs both credential_owner and policy_author. A different approver reviews the same intent and uses a fresh hardware passkey. Certificate issuance does not prove CA installation, proxy authentication or completed Setup.</p>
              <label for="setup-native-enrollment-grant">Independent native issuance grant (JSON, at most 32 KiB)</label>
              <input id="setup-native-enrollment-grant" type="file" accept="application/json,.json" autocomplete="off">
              <label for="setup-native-enrollment-packet">Original native enrollment packet v2 (JSON, at most 512 KiB)</label>
              <input id="setup-native-enrollment-packet" type="file" accept="application/json,.json" autocomplete="off">
              <label for="setup-native-enrollment-request">Original signed bootstrap CSR request (JSON, at most 64 KiB)</label>
              <input id="setup-native-enrollment-request" type="file" accept="application/json,.json" autocomplete="off">
              <p class="hint">Keep the private key on the workload host. Select only the exact enrollment originals; never a private-key file. These files are not copied to browser storage or logs.</p>
              <button type="button" onclick="runUiAction('Review native Setup enrollment', setupEnrollmentDraft)">Requester: read binding and prepare review</button>
              <pre id="setup-native-enrollment-review">No native enrollment intent retained.</pre>
              <label for="setup-native-enrollment-handoff">Exact enrollment intent for an explicit operator handoff
                <textarea id="setup-native-enrollment-handoff" class="policy-result" spellcheck="false" autocomplete="off"></textarea></label>
              <p class="hint">The handoff contains capability-bearing enrollment originals. Share it only with the authorized approver through your approved operator channel; do not paste it into public chat, tickets or logs.</p>
              <button type="button" class="secondary" onclick="runUiAction('Review native enrollment handoff', setupEnrollmentImport)">Review this unchanged intent</button>
              <label for="setup-native-enrollment-approval">Exact approval ID
                <input id="setup-native-enrollment-approval" maxlength="64" autocomplete="off"></label>
              <label><input id="setup-native-enrollment-confirm" type="checkbox">I reviewed the exact Setup, requester, principal, issuer, request and signed grant binding.</label>
              <div class="toolbar">
                <button type="button" onclick="runUiAction('Request native enrollment approval', () => setupEnrollmentEffect('request'))">Requester passkey + request once</button>
                <button type="button" onclick="runUiAction('Approve native enrollment', () => setupEnrollmentEffect('decide'))">Different approver passkey + approve once</button>
                <button type="button" onclick="runUiAction('Issue native enrollment certificate', () => setupEnrollmentEffect('issue'))">Requester NEW passkey + issue once</button>
              </div>
              <button type="button" class="secondary" onclick="runUiAction('Inspect native enrollment', setupEnrollmentLookup)">Read retained state only; never retry issuance</button>
              <button id="setup-native-enrollment-download" type="button" class="secondary" disabled onclick="runUiAction('Download native enrollment certificate', setupEnrollmentDownload)">Download exact issued certificate</button>
              <button type="button" class="secondary" onclick="setupEnrollmentClear()">Clear page-held originals and result</button>
              <pre id="setup-native-enrollment-observation">No retained enrollment observation.</pre>
              <p id="setup-native-enrollment-status" class="hint" role="status" aria-live="polite">No request submitted. Unknown outcomes remain fenced; reading state or clearing this form never authorizes another issuance.</p>
            </details>
"""

SETUP_NATIVE_ENROLLMENT_SCRIPT = r"""
    const setupEnrollmentPrefix = '/api/setup/native-enrollment';
    const setupEnrollmentRequestSchema = 'catchplate.setupNativeEnrollmentRequest/v1';
    const setupEnrollmentResponseSchema = 'catchplate.setupNativeEnrollmentResponse/v1';
    const setupEnrollmentFileIds = ['setup-native-enrollment-grant', 'setup-native-enrollment-packet', 'setup-native-enrollment-request'];
    let setupEnrollmentHeld = null, setupEnrollmentCertificate = null, setupEnrollmentBusy = false;
    let setupEnrollmentEpoch = 0, setupEnrollmentController = null, setupEnrollmentContact = false;
    let setupEnrollmentUnknown = false;
    function setupEnrollmentNeed(value) {
      if (!value) throw new Error('Native Setup enrollment context changed or is unavailable. Inspect retained state; do not retry an uncertain issuance.');
    }
    function setupEnrollmentMessage(text) {
      $('setup-native-enrollment-status').textContent = (setupEnrollmentUnknown ? 'A prior submission remains uncertain. ' : '') + text;
    }
    function setupEnrollmentAuth(role) {
      const value = state.authStatus;
      setupEnrollmentNeed(!adminToken() && window.isSecureContext && window.top === window
        && value?.authenticated === true && value.authMethod === 'oidc-session' && value.sessionState === 'active'
        && value.webauthnRequired === false && workloadIssuanceText(value.userId, 4096) && Array.isArray(value.roles));
      const required = role === 'approver' ? ['approver'] : ['credential_owner', 'policy_author'];
      setupEnrollmentNeed(required.every(item => value.roles.includes(item)));
      return value.userId;
    }
    function setupEnrollmentClear() {
      setupEnrollmentEpoch++;
      if (setupEnrollmentContact) setupEnrollmentUnknown = true;
      setupEnrollmentController?.abort(); setupEnrollmentHeld = null;
      if (setupEnrollmentCertificate) setupEnrollmentCertificate.bytes.fill(0);
      setupEnrollmentCertificate = null;
      [...setupEnrollmentFileIds, 'setup-native-enrollment-handoff'].forEach(id => { $(id).value = ''; });
      $('setup-native-enrollment-confirm').checked = false;
      $('setup-native-enrollment-download').disabled = true;
      $('setup-native-enrollment-review').textContent = 'No native enrollment intent retained.';
      setupEnrollmentMessage('Page-held originals and certificate were discarded. Nonsecret submission markers and original authority lifetimes are unchanged.');
    }
    function setupEnrollmentBegin(role = 'requester') {
      setupEnrollmentNeed(!setupEnrollmentBusy);
      const actor = setupEnrollmentAuth(role), scope = sessionActivationAuthScope(), epoch = setupEnrollmentEpoch;
      const session = $('setup-policy-session').value.trim(); setupEnrollmentNeed(nativeSetupId(session));
      const controller = new AbortController(), until = performance.now() + 30000, expires = Date.now() + 30000;
      const timer = setTimeout(() => controller.abort(), 30000);
      const operation = {actor, scope, session, role, signal: controller.signal,
        abort() { controller.abort(); },
        current() { setupEnrollmentNeed(!controller.signal.aborted && epoch === setupEnrollmentEpoch
          && performance.now() < until && Date.now() < expires && setupEnrollmentAuth(role) === actor
          && sessionActivationAuthScope() === scope && $('setup-policy-session').value.trim() === session); },
        close() { clearTimeout(timer); controller.abort(); setupEnrollmentBusy = false;
          if (setupEnrollmentController === controller) setupEnrollmentController = null; }
      };
      try { operation.current(); setupEnrollmentBusy = true; setupEnrollmentController = controller; return operation; }
      catch (error) { clearTimeout(timer); controller.abort(); throw error; }
    }
    async function setupEnrollmentCookie(operation) {
      operation.current();
      const response = await fetch('/api/auth/status', {credentials: 'same-origin', mode: 'same-origin',
        redirect: 'error', cache: 'no-store', signal: operation.signal});
      const value = await setupPolicyRead(response, operation, 16384);
      setupEnrollmentNeed(response.ok && oauthConsentClosed(value, ['authenticated', 'userId', 'roles', 'authMethod',
        'sessionState', 'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode']) && value.authenticated === true
        && value.userId === operation.actor && value.authMethod === 'oidc-session' && value.sessionState === 'active'
        && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
        && value.sessionActivationMode === state.authStatus.sessionActivationMode
        && value.webauthnRequired === false && typeof value.oidcBrowserLoginConfigured === 'boolean'
        && Array.isArray(value.roles)
        && value.roles.every(item => workloadIssuanceText(item, 128)) && new Set(value.roles).size === value.roles.length
        && JSON.stringify([...value.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
      operation.current();
    }
    async function setupEnrollmentPost(suffix, body, operation, contact = null) {
      setupEnrollmentNeed(['/draft', '/options', '/request', '/decide', '/issue', '/lookup'].includes(suffix));
      let original = oauthConsentCanonical(body), csrf = null;
      setupEnrollmentNeed(new TextEncoder().encode(original).byteLength <= 3 * 1024 * 1024);
      try {
        operation.current();
        const reply = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal});
        csrf = await setupPolicyRead(reply, operation, 4096);
        setupEnrollmentNeed(reply.ok && oauthConsentClosed(csrf, ['ok', 'token', 'cookie', 'header'])
          && csrf.ok === true && csrf.cookie === 'catchplate_csrf' && csrf.header === 'X-Catchplate-CSRF-Token'
          && workloadIssuanceText(csrf.token, 1024));
        operation.current(); if (contact) contact();
        const response = await fetch(setupEnrollmentPrefix + suffix, {method: 'POST', mode: 'same-origin',
          credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        return {status: response.status, value: await setupPolicyRead(response, operation, 3 * 1024 * 1024)};
      } finally { original = null; csrf = null; }
    }
    function setupEnrollmentResponse(reply, status, stateName, fields) {
      const value = reply.value;
      setupEnrollmentNeed(reply.status === status && oauthConsentClosed(value, ['apiVersion', 'status',
        'automaticRetryAllowed', 'caInstalled', 'enrollmentComplete', 'proxyReady', ...fields])
        && value.apiVersion === setupEnrollmentResponseSchema && value.status === stateName
        && value.automaticRetryAllowed === false && value.caInstalled === false
        && value.enrollmentComplete === false && value.proxyReady === false);
      return value;
    }
    // These are literal acquisition joins, not signature admission or a fresh
    // permission. Historical lookups retain the original expiry unchanged.
    function setupEnrollmentStoredEpoch(value) {
      setupEnrollmentNeed(typeof value === 'string');
      const match = /^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value);
      setupEnrollmentNeed(match !== null);
      const seconds = Date.parse(match[1] + 'T' + match[2] + 'Z');
      setupEnrollmentNeed(Number.isSafeInteger(seconds) && seconds > 0);
      return BigInt(seconds) * 1000000n + BigInt((match[3] || '').padEnd(9, '0'));
    }
    async function setupEnrollmentRotation(original, operation, expected) {
      const row = setupNativeOriginal(original, 2170880);
      setupEnrollmentNeed(oauthConsentClosed(row, ['session_id', 'revision', 'phase', 'owner_id', 'setup_original', 'setup_sha256',
        'credential_id', 'credential_version', 'generation_request_id', 'generation_claim_sha256', 'generation_publication_digest',
        'candidate_id', 'canary_id', 'artifact_envelope_digest', 'assignment_envelope_digest', 'policy_hash', 'route_policy_digest',
        'assignment_digest', 'request_original', 'request_digest', 'configuration_digest', 'created_at', 'expires_at'])
        && row.session_id === operation.session && oauthConsentInteger(row.revision) === 0n && row.phase === 'candidate_bound'
        && row.credential_id === expected.credentialId
        && ['setup_sha256', 'generation_claim_sha256', 'generation_publication_digest', 'artifact_envelope_digest',
          'assignment_envelope_digest', 'policy_hash', 'route_policy_digest', 'assignment_digest', 'request_digest',
          'configuration_digest'].every(key => oauthConsentDigest(row[key]))
        && oauthConsentInteger(row.credential_version) === oauthConsentInteger(expected.credentialVersion)
        && oauthConsentInteger(row.credential_version) >= 2n && oauthConsentInteger(row.credential_version) <= 9223372036854775807n
        && await workloadIssuanceHash(new TextEncoder().encode(original)) === expected.continuationSha256);
      const args = setupNativeOriginal(row.request_original, 2 * 1024 * 1024), request = args.request;
      setupEnrollmentNeed(oauthConsentClosed(args, ['actor_id', 'control_plane_configuration_digest', 'credential_policy', 'request'])
        && args.actor_id === row.owner_id && args.control_plane_configuration_digest === row.configuration_digest
        && oauthConsentClosed(request, ['setupBinding', 'credentialId', 'credentialVersion', 'generationClaimOriginal', 'routePolicyDigest',
          'assignmentDigest', 'issuedAtEpochNs', 'expiresAtEpochNs', 'credentialBindingEventId', 'credentialProvenanceOriginal'])
        && nativeSetupId(request.credentialBindingEventId) && request.credentialId === row.credential_id
        && oauthConsentInteger(request.credentialVersion) === oauthConsentInteger(row.credential_version)
        && request.routePolicyDigest === row.route_policy_digest && request.assignmentDigest === row.assignment_digest
        && await workloadIssuanceHash(new TextEncoder().encode(request.generationClaimOriginal)) === row.generation_claim_sha256);
      const setup = setupNativeOriginal(row.setup_original, 65536), binding = nativeSetupBinding(request.setupBinding);
      setupEnrollmentNeed(oauthConsentClosed(setup, ['id', 'owner_id', 'current_assignee_id', 'status', 'phase', 'revision', 'template_id', 'principal_id',
        'route_id', 'route_policy_digest', 'credential_id', 'credential_version', 'policy_hash', 'assignment_digest', 'oauth_provider',
        'oauth_state_digest', 'oauth_pending_credential_id', 'canary_id', 'enrollment_session_id', 'enrollment_packet_digest', 'verifier_nonce_hash',
        'enrollment_verifier_receipt_digest', 'enrollment_verifier_key_id', 'attestation_challenge_digest', 'attestation_challenge_issued_at',
        'attestation_challenge_expires_at', 'attestation_challenge_value', 'runtime_evidence_digest', 'hardware_assurance_digest',
        'hardware_verification_receipt_digest', 'hardware_verifier_key_id', 'release_identity_digest', 'current_host_identity_digest',
        'proxy_server_statement_digest', 'trust_profile_digest', 'completion_identity_digest', 'final_authority_key_id', 'final_consumption_id',
        'final_receipt_digest', 'created_at', 'updated_at', 'expires_at', 'terminal_at'])
        && setup.id === row.session_id && setup.owner_id === row.owner_id && setup.credential_id === row.credential_id
        && oauthConsentInteger(setup.credential_version) === oauthConsentInteger(row.credential_version)
        && setup.phase === 'credential_activated' && setup.status === 'active' && setup.terminal_at === null
        && oauthConsentInteger(setup.revision) >= 1n && setup.expires_at === row.expires_at
        && ['oauth_provider', 'oauth_state_digest', 'oauth_pending_credential_id', 'policy_hash', 'assignment_digest', 'canary_id',
          'enrollment_session_id'].every(key => setup[key] === null)
        && binding.sessionId === setup.id && binding.ownerId === setup.owner_id && binding.currentAssigneeId === setup.current_assignee_id
        && oauthConsentInteger(binding.revision) === oauthConsentInteger(setup.revision)
        && oauthConsentInteger(binding.expiresAtEpochNs) === setupEnrollmentStoredEpoch(setup.expires_at)
        && binding.rowSha256 === row.setup_sha256
        && await workloadIssuanceHash(new TextEncoder().encode(row.setup_original)) === row.setup_sha256);
      const provenance = setupNativeOriginal(request.credentialProvenanceOriginal, 40 * 1024);
      setupEnrollmentNeed(oauthConsentClosed(provenance, ['apiVersion', 'rotationRequestDigest', 'nativeEvidenceOriginal'])
        && provenance.apiVersion === 'catchplate.staticCredentialRotationProvenance/v1' && oauthConsentDigest(provenance.rotationRequestDigest));
      const evidence = setupNativeOriginal(provenance.nativeEvidenceOriginal, 32768), statement = evidence.statement;
      setupEnrollmentNeed(oauthConsentClosed(evidence, ['statement', 'signature', 'nativeKeyEvidence'])
        && oauthConsentClosed(statement, ['apiVersion', 'operation', 'holderId', 'bootId', 'keyId', 'controlPlaneResponseSigningKeyId',
          'deploymentId', 'instanceId', 'controlPlaneConfigurationDigest', 'actorId', 'credentialId', 'credentialVersion', 'intentSha256',
          'generationSha256', 'inputSha256', 'secretKekId', 'generationCreatedAtEpochNs', 'challenge', 'policyHash', 'dataPlaneBinarySha256',
          'intakeOrigin', 'portalOrigin', 'ingressLeafCertificateSha256', 'ingressLeafSpkiSha256', 'issuedAtEpochNs', 'expiresAtEpochNs',
          'previousCredentialVersion', 'previousCredentialSha256', 'previousCurrentnessOriginRequestDigest', 'previousProvenanceSha256',
          'predecessorBarrierSha256', 'predecessorCurrentnessRootSha256'])
        && statement.apiVersion === 'catchplate.nativeStaticCredentialRotationStatement/v1' && statement.operation === 'credential.static.rotate'
        && statement.credentialId === row.credential_id && oauthConsentInteger(statement.credentialVersion) === oauthConsentInteger(row.credential_version)
        && oauthConsentInteger(statement.previousCredentialVersion) >= 1n
        && oauthConsentInteger(statement.previousCredentialVersion) + 1n === oauthConsentInteger(statement.credentialVersion)
        && ['holderId', 'keyId', 'controlPlaneResponseSigningKeyId', 'controlPlaneConfigurationDigest', 'intentSha256',
          'generationSha256', 'inputSha256', 'policyHash', 'dataPlaneBinarySha256', 'ingressLeafCertificateSha256', 'ingressLeafSpkiSha256',
          'previousCredentialSha256', 'previousCurrentnessOriginRequestDigest', 'previousProvenanceSha256', 'predecessorBarrierSha256',
          'predecessorCurrentnessRootSha256'].every(key => oauthConsentDigest(statement[key]))
        && oauthConsentInteger(statement.generationCreatedAtEpochNs) > 0n
        && oauthConsentInteger(statement.generationCreatedAtEpochNs) <= oauthConsentInteger(statement.issuedAtEpochNs)
        && oauthConsentInteger(statement.issuedAtEpochNs) < oauthConsentInteger(statement.expiresAtEpochNs)
        && oauthConsentInteger(statement.expiresAtEpochNs) - oauthConsentInteger(statement.issuedAtEpochNs) <= 30000000000n
        && typeof evidence.signature === 'string' && /^ed25519:[A-Za-z0-9_-]{86}$/.test(evidence.signature)
        && oauthConsentClosed(evidence.nativeKeyEvidence, ['apiVersion', 'responseProofPublicKey', 'attestationDocumentB64'])
        && evidence.nativeKeyEvidence.apiVersion === 'catchplate.nativeResponseProofKeyEvidence/v1'
        && workloadIssuanceBase64(evidence.nativeKeyEvidence.responseProofPublicKey, 32).byteLength === 32
        && workloadIssuanceBase64(evidence.nativeKeyEvidence.attestationDocumentB64, 12288).byteLength > 0);
      const joins = {sessionId: row.session_id, ownerId: row.owner_id, setupSha256: row.setup_sha256,
        assignmentSha256: row.assignment_digest, policyHash: row.policy_hash, routePolicyDigest: row.route_policy_digest,
        principalId: setup.principal_id, routeId: setup.route_id};
      setupEnrollmentNeed(Object.keys(joins).every(key => !(key in expected) || expected[key] === joins[key]));
      // Source-fixed core.deterministic_uuid for the actual rotation outbox.
      const identity = await workloadIssuanceHash(new TextEncoder().encode(oauthConsentCanonical({
        schema: 'catchplate.policyAuthorityDeterministicIdentity/v1', operation: 'credential.static.rotate',
        requestDigest: provenance.rotationRequestDigest, purpose: 'metadata-audit-outbox'})));
      const digits = identity.slice(7, 39).split(''); digits[12] = '5'; digits[16] = ((parseInt(digits[16], 16) & 3) | 8).toString(16);
      const compact = digits.join(''), rotationAuditId = [compact.slice(0, 8), compact.slice(8, 12), compact.slice(12, 16),
        compact.slice(16, 20), compact.slice(20)].join('-');
      const provenanceSha256 = await workloadIssuanceHash(new TextEncoder().encode(request.credentialProvenanceOriginal));
      operation.current(); return {row, request, setup, binding, provenance, provenanceSha256, rotationAuditId};
    }
    async function setupEnrollmentRotationLookup(expected, operation) {
      const reply = await setupPolicyPost('/lookup', {apiVersion: setupPolicyRequestSchema, sessionId: operation.session}, operation);
      setupEnrollmentNeed(oauthConsentClosed(reply, ['apiVersion', 'okForAction', 'automaticRetryAllowed', 'continuationOriginal'])
        && reply.apiVersion === 'catchplate.setupPolicyCandidateObservation/v1' && reply.okForAction === false
        && reply.automaticRetryAllowed === false && typeof reply.continuationOriginal === 'string');
      return setupEnrollmentRotation(reply.continuationOriginal, operation, expected);
    }
    async function setupEnrollmentIntentOriginal(original, operation) {
      const value = setupNativeOriginal(original, 1200000);
      const rotated = value.apiVersion === 'catchplate.setupNativeEnrollmentIntent/v2';
      setupEnrollmentNeed(oauthConsentClosed(value, ['apiVersion', 'sessionId', 'ownerId', 'setupSha256',
        'continuationSha256', 'assignmentSha256', 'policyHash', 'routePolicyDigest', 'principalId', 'credentialId',
        'credentialVersion', 'issuerBootstrap', 'authorization', 'packet', 'request', 'issuedAtEpochNs', 'expiresAtEpochNs',
        ...(rotated ? ['continuationOriginal'] : [])])
        && value.apiVersion === (rotated ? 'catchplate.setupNativeEnrollmentIntent/v2' : 'catchplate.setupNativeEnrollmentIntent/v1')
        && value.sessionId === operation.session
        && nativeSetupId(value.credentialId) && workloadIssuanceText(value.ownerId, 1024) && value.ownerId.startsWith('oidc:')
        && workloadIssuanceNativePrincipal(value.principalId)
        && (rotated ? oauthConsentInteger(value.credentialVersion) >= 2n && oauthConsentInteger(value.credentialVersion) <= 9223372036854775807n
          : oauthConsentInteger(value.credentialVersion) === 1n)
        && ['setupSha256', 'continuationSha256', 'assignmentSha256', 'policyHash', 'routePolicyDigest'].every(name => oauthConsentDigest(value[name])));
      const issued = oauthConsentInteger(value.issuedAtEpochNs), expires = oauthConsentInteger(value.expiresAtEpochNs);
      setupEnrollmentNeed(issued > 0n && issued < expires && expires - issued <= 300000000000n
        && expires <= 9223372036854775807n);
      if (rotated) {
        const chain = await setupEnrollmentRotation(value.continuationOriginal, operation, value);
        setupEnrollmentNeed(expires <= oauthConsentInteger(chain.binding.expiresAtEpochNs));
      }
      return value;
    }
    async function setupEnrollmentIntent(original, operation) {
      const value = await setupEnrollmentIntentOriginal(original, operation), expires = oauthConsentInteger(value.expiresAtEpochNs);
      setupEnrollmentNeed(BigInt(Date.now()) * 1000000n < expires);
      const bootstrap = workloadIssuanceBase64(value.issuerBootstrap, 131072);
      setupEnrollmentNeed(bootstrap.byteLength > 0);
      const files = ['authorization', 'packet', 'request'].map((name, index) =>
        new Blob([workloadIssuanceBase64(value[name], [32768, 524288, 65536][index])]));
      const issuance = await workloadIssuanceOriginals(files, () => operation.current(), workloadIssuanceProfiles.native);
      operation.current();
      setupEnrollmentNeed(issuance.binding.principalId === value.principalId);
      const digest = await workloadIssuanceHash(new TextEncoder().encode(original)); operation.current();
      return {original, value, digest, issuance, actor: operation.actor, scope: operation.scope,
        session: operation.session, expires};
    }
    function setupEnrollmentShow(held) {
      const value = held.value, binding = held.issuance.binding;
      // Only the fixed nonsecret review projection is displayed here. Raw
      // enrollment originals remain in the explicit handoff control only.
      $('setup-native-enrollment-review').textContent = oauthConsentCanonical({sessionId: value.sessionId,
        ownerId: value.ownerId, principalId: value.principalId, credentialId: value.credentialId,
        credentialVersion: value.credentialVersion, policyHash: value.policyHash,
        assignmentSha256: value.assignmentSha256, intentSha256: held.digest,
        authorizationSha256: binding.authorizationDigest, requestSha256: binding.requestDigest,
        issuerCertificateSha256: binding.issuerCertificateDigest, expiresAtEpochNs: value.expiresAtEpochNs});
      $('setup-native-enrollment-handoff').value = held.original;
      $('setup-native-enrollment-confirm').checked = false;
    }
    async function setupEnrollmentDraft() {
      const operation = setupEnrollmentBegin(); setupEnrollmentHeld = null;
      try {
        const files = setupEnrollmentFileIds.map((id, index) => {
          const selected = $(id).files;
          setupEnrollmentNeed(selected?.length === 1 && selected[0].size >= 2
            && selected[0].size <= [32768, 524288, 65536][index]); return selected[0];
        });
        const current = () => { operation.current(); setupEnrollmentNeed(files.every((file, index) =>
          $(setupEnrollmentFileIds[index]).files?.[0] === file)); };
        const scoped = {...operation, current}; await setupEnrollmentCookie(scoped);
        const captured = await workloadIssuanceOriginals(files, current, workloadIssuanceProfiles.native);
        const value = setupEnrollmentResponse(await setupEnrollmentPost('/draft', {
          apiVersion: setupEnrollmentRequestSchema, sessionId: operation.session,
          authorization: captured.body.authorization, packet: captured.body.packet, request: captured.body.request,
        }, scoped), 200, 'draft', ['intentOriginal', 'intentSha256']);
        const held = await setupEnrollmentIntent(value.intentOriginal, scoped);
        setupEnrollmentNeed(held.digest === value.intentSha256 && held.value.ownerId === operation.actor
          && held.value.authorization === captured.body.authorization.base64Url
          && held.value.packet === captured.body.packet.base64Url && held.value.request === captured.body.request.base64Url);
        setupEnrollmentHeld = held; setupEnrollmentShow(held);
        setupEnrollmentMessage('Exact native enrollment intent retained for review. No approval or issuance was submitted; its original expiry is unchanged.');
      } catch (error) {
        setupEnrollmentHeld = null; setupEnrollmentMessage('No enrollment intent admitted. Check the current Setup binding, exact native originals and requester roles.'); throw error;
      } finally { operation.close(); }
    }
    async function setupEnrollmentImport() {
      const original = $('setup-native-enrollment-handoff').value;
      const header = setupNativeOriginal(original, 1200000);
      const role = header.ownerId === state.authStatus?.userId ? 'requester' : 'approver';
      const operation = setupEnrollmentBegin(role); setupEnrollmentHeld = null;
      try {
        await setupEnrollmentCookie(operation);
        const held = await setupEnrollmentIntent(original, operation);
        setupEnrollmentNeed($('setup-native-enrollment-handoff').value === original
          && (role === 'approver' ? held.value.ownerId !== operation.actor : held.value.ownerId === operation.actor));
        setupEnrollmentHeld = held; setupEnrollmentShow(held);
        setupEnrollmentMessage('Same exact intent retained for explicit review. Import creates no approval, issuer contact, renewed expiry or retry permission.');
      } catch (error) {
        setupEnrollmentHeld = null; setupEnrollmentMessage('This handoff could not be admitted in the current operator and Setup context.'); throw error;
      } finally { operation.close(); }
    }
    async function setupEnrollmentPasskey(options, held, phase, operation) {
      const key = options?.publicKey, value = options?.catchplate;
      const expected = {request: 'setup.native-enrollment.request', decide: 'setup.native-enrollment.decide', issue: 'setup.native-enrollment.prepare'}[phase];
      setupEnrollmentNeed(oauthConsentClosed(options, ['publicKey', 'catchplate'])
        && oauthConsentClosed(value, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'intentSha256'])
        && value.schema === 'catchplate.setupNativeEnrollmentOptions/v1' && value.operation === expected
        && value.intentSha256 === held.digest && oauthConsentDigest(value.operationId) && oauthConsentDigest(value.challengeId)
        && nativeSetupId(value.credentialRecordId)
        && oauthConsentClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && key.rpId === location.hostname && key.userVerification === 'required' && oauthConsentInteger(key.timeout) === 30000n
        && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
        && oauthConsentClosed(key.allowCredentials[0], ['type', 'id']) && key.allowCredentials[0].type === 'public-key'
        && workloadIssuanceBase64(key.challenge, 32).byteLength === 32);
      workloadIssuanceBase64(key.allowCredentials[0].id, 3072);
      const prepared = {publicKey: {...key, timeout: 30000}};
      operation.current();
      const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions(prepared)});
      operation.current();
      setupEnrollmentNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.rawId.byteLength <= 3072 && credential.id === key.allowCredentials[0].id
        && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential);
      setupEnrollmentNeed(workloadIssuanceAssertionOriginal(assertion, prepared).byteLength <= 16384); return assertion;
    }
    function setupEnrollmentPublic(value) {
      setupEnrollmentNeed(oauthConsentClosed(value, ['revision', 'phase', 'intentSha256', 'assignmentSha256',
        'certificateSha256', 'approvalId', 'prepareRequestDigest', 'completeRequestDigest'])
        && ['intentSha256', 'assignmentSha256', 'prepareRequestDigest'].every(name => oauthConsentDigest(value[name]))
        && nativeSetupId(value.approvalId));
      const revision = oauthConsentInteger(value.revision);
      setupEnrollmentNeed(revision === 0n ? value.phase === 'issuance_unknown' && value.certificateSha256 === null
        && value.completeRequestDigest === null : revision === 1n && value.phase === 'certificate_issued'
        && oauthConsentDigest(value.certificateSha256) && oauthConsentDigest(value.completeRequestDigest));
      return value;
    }
    async function setupEnrollmentRetainCertificate(value, operation, held = null, approvalId = null) {
      const row = setupEnrollmentPublic(value.enrollment), association = value.association, wrapper = value.certificate;
      setupEnrollmentNeed(row.phase === 'certificate_issued'
        && oauthConsentClosed(association, ['schema', 'authorizationDigest', 'requestDigest', 'issuerCertificateDigest', 'certificateSha256', 'serialNumber'])
        && association.schema === 'catchplate.workloadIdentityIssuerResponse/v1'
        && ['authorizationDigest', 'requestDigest', 'issuerCertificateDigest', 'certificateSha256'].every(name => oauthConsentDigest(association[name]))
        && typeof association.serialNumber === 'string' && /^[1-9a-f][0-9a-f]{0,39}$/.test(association.serialNumber)
        && association.certificateSha256 === row.certificateSha256
        && oauthConsentClosed(wrapper, ['base64Url', 'byteCount', 'bytesDigest']) && wrapper.bytesDigest === row.certificateSha256);
      if (held) setupEnrollmentNeed(row.intentSha256 === held.digest && row.assignmentSha256 === held.value.assignmentSha256
        && association.authorizationDigest === held.issuance.binding.authorizationDigest
        && association.requestDigest === held.issuance.binding.requestDigest
        && association.issuerCertificateDigest === held.issuance.binding.issuerCertificateDigest
        && association.serialNumber === held.issuance.serialNumber && row.approvalId === approvalId);
      const bytes = workloadIssuanceBase64(wrapper.base64Url, 65536);
      setupEnrollmentNeed(bytes.byteLength >= 2 && BigInt(bytes.byteLength) === oauthConsentInteger(wrapper.byteCount)
        && await workloadIssuanceHash(bytes) === wrapper.bytesDigest);
      operation.current();
      if (setupEnrollmentCertificate) setupEnrollmentCertificate.bytes.fill(0);
      setupEnrollmentCertificate = {bytes, digest: wrapper.bytesDigest, actor: operation.actor,
        scope: operation.scope, session: operation.session, intentSha256: row.intentSha256};
      $('setup-native-enrollment-download').disabled = false;
    }
    async function setupEnrollmentEffect(phase) {
      setupEnrollmentNeed(['request', 'decide', 'issue'].includes(phase) && !setupEnrollmentUnknown);
      const held = setupEnrollmentHeld;
      setupEnrollmentNeed(held && $('setup-native-enrollment-confirm').checked);
      const operation = setupEnrollmentBegin(phase === 'decide' ? 'approver' : 'requester');
      const approvalId = phase === 'request' ? null : $('setup-native-enrollment-approval').value.trim();
      let assertion = null, sent = false;
      const current = () => {
        operation.current(); setupEnrollmentNeed(setupEnrollmentHeld === held && held.scope === operation.scope
          && held.actor === operation.actor && held.session === operation.session
          && $('setup-native-enrollment-handoff').value === held.original && $('setup-native-enrollment-confirm').checked
          && BigInt(Date.now()) * 1000000n < held.expires
          && (phase === 'decide' ? held.value.ownerId !== operation.actor : held.value.ownerId === operation.actor)
          && (phase === 'request' ? $('setup-native-enrollment-approval').value.trim() === ''
            : nativeSetupId(approvalId) && $('setup-native-enrollment-approval').value.trim() === approvalId));
      };
      const scoped = {...operation, current};
      const marker = 'catchplate.setup-native-enrollment:' + operation.actor + ':' + operation.session + ':' + phase;
      try {
        current(); setupEnrollmentNeed(sessionStorage.getItem(marker) === null);
        await setupEnrollmentCookie(scoped);
        const options = setupEnrollmentResponse(await setupEnrollmentPost('/options', {apiVersion: setupEnrollmentRequestSchema,
          intentOriginal: held.original, phase, approvalId}, scoped), 200, 'fresh-assertion-required', ['options', 'phase', 'approvalId', 'intentSha256']);
        setupEnrollmentNeed(options.phase === phase && options.approvalId === approvalId && options.intentSha256 === held.digest);
        assertion = await setupEnrollmentPasskey(options.options, held, phase, scoped);
        await setupEnrollmentCookie(scoped);
        const reply = await setupEnrollmentPost('/' + phase, {apiVersion: setupEnrollmentRequestSchema,
          intentOriginal: held.original, approvalId, assertion}, scoped, () => {
            // Persist nonsecret IDs/digests only, before first possible effect.
            // Reading state, a new draft and clearing the form never remove it.
            const pin = held.digest + ':' + (approvalId || 'request');
            setupEnrollmentNeed(sessionStorage.getItem(marker) === null);
            sessionStorage.setItem(marker, pin); setupEnrollmentNeed(sessionStorage.getItem(marker) === pin);
            sent = true; setupEnrollmentContact = true;
          });
        if (phase === 'issue') {
          const value = setupEnrollmentResponse(reply, 201, 'certificate-issued', ['certificate', 'association', 'enrollment']);
          await setupEnrollmentRetainCertificate(value, scoped, held, approvalId);
          $('setup-native-enrollment-observation').textContent = oauthConsentCanonical(value.enrollment);
          setupEnrollmentMessage('Certificate issuance was recorded for this Setup. Download the exact certificate and admit it locally against the retained request/key and independent issuer. CA installation, proxy authentication and completed Setup remain unproven.');
          setupEnrollmentHeld = null;
        } else {
          const value = setupEnrollmentResponse(reply, phase === 'request' ? 428 : 200,
            phase === 'request' ? 'approval-required' : 'approved', ['approvalId', 'intentSha256']);
          setupEnrollmentNeed(value.intentSha256 === held.digest && nativeSetupId(value.approvalId)
            && (phase === 'request' || value.approvalId === approvalId));
          $('setup-native-enrollment-approval').value = value.approvalId;
          setupEnrollmentMessage(phase === 'request'
            ? 'Approval requested. Share the unchanged intent and approval ID through your authorized operator handoff. A different approver must review it; no certificate has been issued.'
            : 'Distinct-operator approval recorded. The requester must use a NEW passkey and explicitly issue once; approval itself does not issue a certificate.');
        }
        setupEnrollmentContact = false;
      } catch (error) {
        if (sent) { setupEnrollmentUnknown = true; setupEnrollmentHeld = null; }
        setupEnrollmentMessage(sent ? 'Submission outcome is uncertain. Keep the Setup/approval IDs and read retained state only; do not repeat the effect.'
          : 'Review, current binding or passkey did not complete. No effect submission was sent.'); throw error;
      } finally { assertion = null; setupEnrollmentContact = false; $('setup-native-enrollment-confirm').checked = false; operation.close(); }
    }
    async function setupEnrollmentLookup() {
      const operation = setupEnrollmentBegin();
      if (setupEnrollmentCertificate) setupEnrollmentCertificate.bytes.fill(0);
      setupEnrollmentCertificate = null; $('setup-native-enrollment-download').disabled = true;
      try {
        await setupEnrollmentCookie(operation);
        const value = setupEnrollmentResponse(await setupEnrollmentPost('/lookup', {apiVersion: setupEnrollmentRequestSchema,
          sessionId: operation.session}, operation), 200, 'observation', ['enrollment', 'certificate', 'association']);
        if (value.enrollment === null) {
          setupEnrollmentNeed(value.certificate === null && value.association === null);
          $('setup-native-enrollment-observation').textContent = 'No retained issuance row observed. This is not permission to repeat a submitted request.';
        } else {
          const row = setupEnrollmentPublic(value.enrollment);
          if (row.phase === 'certificate_issued') await setupEnrollmentRetainCertificate(value, operation);
          else setupEnrollmentNeed(value.certificate === null && value.association === null);
          $('setup-native-enrollment-observation').textContent = oauthConsentCanonical(row);
        }
        setupEnrollmentMessage('Read-only historical observation. An already-issued certificate may be downloaded without another issuer contact, including after its original issuance window. Submission markers remain; no CA installation, current certificate validity, proxy readiness or completed Setup is claimed.');
      } catch (error) {
        $('setup-native-enrollment-observation').textContent = 'No current retained-state observation was accepted.';
        setupEnrollmentMessage('Observation unavailable or changed. An absent response is not a failed issuance and grants no retry.'); throw error;
      } finally { operation.close(); }
    }
    function setupEnrollmentDownload() {
      const held = setupEnrollmentCertificate;
      setupEnrollmentNeed(!setupEnrollmentBusy && held && held.bytes instanceof Uint8Array
        && setupEnrollmentAuth('requester') === held.actor && sessionActivationAuthScope() === held.scope
        && $('setup-policy-session').value.trim() === held.session);
      const url = URL.createObjectURL(new Blob([held.bytes], {type: 'application/x-pem-file'}));
      const link = document.createElement('a'); link.href = url; link.download = 'setup-native-workload-certificate.pem';
      try { link.click(); } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      setupEnrollmentMessage('Download requested for certificate ' + held.digest + '. Pin and admit these bytes on the workload host using its retained request/key and independent issuer. Browser download completion and CA installation are not verified.');
    }
    function setupEnrollmentInputsChanged() {
      setupEnrollmentEpoch++; if (setupEnrollmentContact) setupEnrollmentUnknown = true;
      setupEnrollmentController?.abort(); setupEnrollmentHeld = null;
      if (setupEnrollmentCertificate) setupEnrollmentCertificate.bytes.fill(0);
      setupEnrollmentCertificate = null; $('setup-native-enrollment-download').disabled = true;
      $('setup-native-enrollment-confirm').checked = false;
      $('setup-native-enrollment-review').textContent = 'Selection changed; review the exact intent again. Submission markers are unchanged.';
    }
    setupEnrollmentFileIds.forEach(id => $(id).addEventListener('change', setupEnrollmentInputsChanged));
    $('setup-native-enrollment-handoff').addEventListener('input', setupEnrollmentInputsChanged);
    $('setup-policy-session').addEventListener('input', setupEnrollmentInputsChanged);
    window.addEventListener('pagehide', setupEnrollmentClear);
"""
