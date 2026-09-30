"""Explicit native CA installer handoff; only the backend authenticates readback."""

SETUP_NATIVE_CA_HTML = r"""
            <hr>
            <details id="setup-native-ca-controls">
              <summary>Prepare and record authenticated host CA installation</summary>
              <p class="hint">Uses the Setup session ID above and its already-issued native certificate. Both credential_owner and policy_author are required. A separately authorized host installer performs the installation; this browser never installs a CA, receives private keys or signs a success receipt.</p>
              <label for="setup-native-ca-grant">Independent CA-installation grant (JSON, at most 32 KiB)</label>
              <input id="setup-native-ca-grant" type="file" accept="application/json,.json" autocomplete="off">
              <label for="setup-native-ca-host-key">Independently provisioned host observation key ID (SPKI sha256)</label>
              <input id="setup-native-ca-host-key" maxlength="71" autocomplete="off" spellcheck="false">
              <button type="button" onclick="runUiAction('Review CA installation grant', setupNativeCaReviewGrant)">Review exact installation grant</button>
              <pre id="setup-native-ca-review">No CA-installation grant reviewed.</pre>
              <label><input id="setup-native-ca-prepare-confirm" type="checkbox">I reviewed this exact host, destination, replacement policy, CA and target request.</label>
              <button type="button" onclick="runUiAction('Prepare CA installation once', setupNativeCaPrepare)">Fresh requester passkey + prepare once</button>
              <button type="button" class="secondary" onclick="runUiAction('Read CA installation state', setupNativeCaLookup)">Read retained state and recover exact handoff</button>
              <p class="hint">Download the three unchanged originals only for your approved nativeBootstrapClient/v10 installation on the intended host. The handoff can contain capability-bearing originals: use your authorized operator channel, never public chat, tickets or logs. Downloading, recovery and expiry do not authorize retrying an uncertain host installation.</p>
              <div class="toolbar">
                <button id="setup-native-ca-download-prepared" type="button" class="secondary" disabled onclick="runUiAction('Download CA preparation', () => setupNativeCaDownload('prepared'))">Prepared original</button>
                <button id="setup-native-ca-download-enrollment" type="button" class="secondary" disabled onclick="runUiAction('Download exact enrollment', () => setupNativeCaDownload('enrollment'))">Issued enrollment original</button>
                <button id="setup-native-ca-download-grant" type="button" class="secondary" disabled onclick="runUiAction('Download installation grant', () => setupNativeCaDownload('grant'))">Installation grant original</button>
              </div>
              <pre id="setup-native-ca-handoff">No retained host-installer handoff.</pre>
              <label for="setup-native-ca-observation">Exact host readback (at most 32 KiB) or nativeBootstrapClient/v10 capture (at most 1.5 MiB)</label>
              <input id="setup-native-ca-observation" type="file" accept="application/json,.json" autocomplete="off">
              <button type="button" class="secondary" onclick="runUiAction('Review host CA readback', setupNativeCaReviewObservation)">Review exact host readback</button>
              <pre id="setup-native-ca-readback">No host readback reviewed.</pre>
              <label><input id="setup-native-ca-complete-confirm" type="checkbox">I reviewed the exact prepared attempt and host readback. The server must independently authenticate both host and workload signatures.</label>
              <button type="button" onclick="runUiAction('Record authenticated CA readback', setupNativeCaComplete)">Submit readback once for authentication</button>
              <button type="button" class="secondary" onclick="setupNativeCaClear()">Clear page-held originals</button>
              <pre id="setup-native-ca-result">No authenticated CA-installation observation.</pre>
              <p id="setup-native-ca-status" class="hint" role="status" aria-live="polite">No CA action submitted. Authenticated trusted-host-local readback is not measured native-host proof, proxy readiness or completed Setup.</p>
            </details>
"""

SETUP_NATIVE_CA_SCRIPT = r"""
    const setupCaRequest = 'serverware.setupNativeCaInstallationRequest/v1';
    const setupCaResponse = 'serverware.setupNativeCaInstallationResponse/v1';
    let setupCaGrantReview = null, setupCaBundle = null, setupCaReadback = null;
    let setupCaEpoch = 0, setupCaOperation = null, setupCaContact = false;
    function setupCaNeed(value) {
      if (!value) throw new Error('CA-installation context or exact originals changed. Inspect retained state; do not repeat an uncertain effect.');
    }
    function setupCaMessage(value) { $('setup-native-ca-status').textContent = value; }
    function setupCaDownloads(enabled) {
      ['prepared', 'enrollment', 'grant'].forEach(name => { $('setup-native-ca-download-' + name).disabled = !enabled; });
    }
    function setupNativeCaClear(clearInputs = true) {
      setupCaEpoch++; setupCaOperation?.abort();
      setupCaGrantReview = null; setupCaBundle = null; setupCaReadback = null; setupCaDownloads(false);
      if (clearInputs) ['setup-native-ca-grant', 'setup-native-ca-host-key', 'setup-native-ca-observation'].forEach(id => { $(id).value = ''; });
      $('setup-native-ca-prepare-confirm').checked = false; $('setup-native-ca-complete-confirm').checked = false;
      $('setup-native-ca-review').textContent = 'No current CA-installation grant review.';
      $('setup-native-ca-handoff').textContent = 'No page-held host-installer handoff.';
      $('setup-native-ca-readback').textContent = 'No current host readback review.';
      $('setup-native-ca-result').textContent = 'No current authenticated observation.';
      setupCaMessage(setupCaContact ? 'An in-flight submission may have committed. Originals discarded; read retained state only. Submission markers remain.'
        : 'Page-held originals discarded. Original lifetimes and nonsecret submission markers are unchanged.');
    }
    function setupCaBegin() {
      const base = setupEnrollmentBegin(), epoch = setupCaEpoch;
      const operation = {...base, current() { base.current(); setupCaNeed(epoch === setupCaEpoch); },
        close() { base.close(); if (setupCaOperation === operation) setupCaOperation = null; }};
      setupCaOperation = operation; return operation;
    }
    function setupCaContext(value, operation) {
      setupCaNeed(value && value.actor === operation.actor && value.scope === operation.scope && value.session === operation.session);
    }
    async function setupCaPost(phase, body, operation, contact = null) {
      setupCaNeed(['options', 'prepare', 'complete', 'lookup'].includes(phase));
      let original = oauthConsentCanonical(body), csrf = null;
      setupCaNeed(new TextEncoder().encode(original).byteLength <= 3 * 1024 * 1024);
      try {
        operation.current();
        const response = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
          cache: 'no-store', signal: operation.signal});
        csrf = await setupPolicyRead(response, operation, 4096);
        setupCaNeed(response.ok && oauthConsentClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
          && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token' && workloadIssuanceText(csrf.token, 1024));
        operation.current(); if (contact) contact();
        const reply = await fetch('/api/setup/native-ca/' + phase, {method: 'POST', credentials: 'same-origin',
          mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: {'Content-Type': 'application/json', [csrf.header]: csrf.token}, body: original});
        return {status: reply.status, value: await setupPolicyRead(reply, operation, 2 * 1024 * 1024)};
      } finally { original = null; csrf = null; }
    }
    function setupCaReply(reply, status, name, fields) {
      const v = reply.value;
      setupCaNeed(reply.status === status && oauthConsentClosed(v, ['apiVersion', 'status', 'automaticRetryAllowed',
        'nativeHostVerified', 'enrollmentComplete', 'proxyReady', ...fields]) && v.apiVersion === setupCaResponse
        && v.status === name && v.automaticRetryAllowed === false && v.nativeHostVerified === false
        && v.enrollmentComplete === false && v.proxyReady === false);
      return v;
    }
    function setupCaMarker(operation, phase) {
      return 'serverware.setup-native-ca:' + operation.actor + ':' + operation.session + ':' + phase;
    }
    function setupCaMark(operation, phase, pin) {
      const marker = setupCaMarker(operation, phase); operation.current();
      setupCaNeed(sessionStorage.getItem(marker) === null);
      sessionStorage.setItem(marker, pin); setupCaNeed(sessionStorage.getItem(marker) === pin);
      setupCaContact = true; // nonsecret digest only, before first possible write
    }
    async function setupCaFile(id, operation, nativeCapture = false) {
      const list = $(id).files; setupCaNeed(list?.length === 1);
      const file = list[0], maximum = nativeCapture ? 1536 * 1024 : 32768;
      setupCaNeed(file.size >= 2 && file.size <= maximum);
      let text = new TextDecoder('utf-8', {fatal: true}).decode(await file.arrayBuffer());
      operation.current(); setupCaNeed($(id).files?.[0] === file);
      if (nativeCapture) {
        const capture = oauthConsentParse(text, maximum).value;
        if (capture?.apiVersion === 'serverware.nativeBootstrapClientCapture/v10') {
          setupCaNeed(oauthConsentClosed(capture, ['apiVersion', 'resultScope', 'okForAction', 'configurationSha256',
            'requestSha256', 'endpoint', 'challengeSource', 'evidenceBase64url', 'verification', 'installation',
            'setupInstallationObservationOriginal']) && capture.resultScope === 'local-authenticated-setup-ca-readback'
            && capture.okForAction === false && capture.challengeSource === 'independently-pinned'
            && typeof capture.setupInstallationObservationOriginal === 'string');
          // Consume the actual producer's exact embedded string, never its
          // unsigned installation/verification diagnostic or a rebuilt receipt.
          text = capture.setupInstallationObservationOriginal;
        }
      }
      setupNativeOriginal(text, 32768); // canonical, duplicate-free ASCII; never reencode
      const bytes = new TextEncoder().encode(text), digest = await workloadIssuanceHash(bytes);
      operation.current(); setupCaNeed($(id).files?.[0] === file);
      return {file, text, digest, wrapper: {base64Url: bytesToB64(bytes), byteCount: bytes.byteLength, bytesDigest: digest}};
    }
    function setupCaGrant(text, live) {
      const v = setupNativeOriginal(text, 32768), p = v.payload;
      setupCaNeed(oauthConsentClosed(v, ['schema', 'payload', 'signature'])
        && v.schema === 'serverware.signedNativeCaInstallationAuthorization/v1'
        && oauthConsentClosed(p, ['schema', 'sourceRevision', 'purpose', 'trustMode', 'authorizationId', 'setupSha256',
          'delegationSha256', 'targetRequestSha256', 'runtimeCaCertificateSha256', 'runtimeCaSpkiSha256',
          'caInstall', 'networkOwner', 'machineIdSha256', 'journal', 'issuedAtEpochNs', 'expiresAtEpochNs'])
        && p.schema === 'serverware.nativeCaInstallationAuthorization/v1' && p.purpose === 'native-ca-installation'
        && p.trustMode === 'trusted-host-local' && typeof v.signature === 'string' && v.signature.startsWith('ed25519:')
        && workloadIssuanceBase64(v.signature.slice(8), 64).byteLength === 64
        && ['setupSha256', 'delegationSha256', 'targetRequestSha256', 'runtimeCaCertificateSha256',
          'runtimeCaSpkiSha256', 'machineIdSha256'].every(key => oauthConsentDigest(p[key])));
      setupCaNeed(oauthConsentClosed(p.networkOwner, ['hostId', 'bootId', 'namespaceDevice', 'namespaceInode', 'ownerUid'])
        && workloadIssuanceText(p.networkOwner.hostId, 128) && nativeSetupId(p.networkOwner.bootId)
        && oauthConsentClosed(p.caInstall, ['profile', 'capabilityId', 'capabilityTokenSha256', 'expiresAtEpochMs',
          'destinationPath', 'ownerUid', 'ownerGid', 'fileMode', 'replaceExisting', 'expectedExistingCertificateSha256'])
        && p.caInstall.profile === 'native-ca-install-association-v1' && typeof p.caInstall.replaceExisting === 'boolean'
        && workloadIssuanceText(p.caInstall.destinationPath, 4096) && p.caInstall.destinationPath.startsWith('/'));
      const before = oauthConsentInteger(p.issuedAtEpochNs), after = oauthConsentInteger(p.expiresAtEpochNs);
      setupCaNeed(before > 0n && before < after && after - before <= 300000000000n);
      if (live) setupCaNeed(before <= BigInt(Date.now()) * 1000000n && BigInt(Date.now()) * 1000000n < after);
      return p; // structural review only; independent backend and host verify signatures
    }
    async function setupNativeCaReviewGrant() {
      const operation = setupCaBegin(); setupCaGrantReview = null;
      $('setup-native-ca-review').textContent = 'Reading this exact grant; no current review accepted.';
      $('setup-native-ca-prepare-confirm').checked = false;
      try {
        await setupEnrollmentCookie(operation);
        const captured = await setupCaFile('setup-native-ca-grant', operation);
        const hostKeyId = $('setup-native-ca-host-key').value.trim(); setupCaNeed(oauthConsentDigest(hostKeyId));
        const grant = setupCaGrant(captured.text, true);
        setupCaGrantReview = {...captured, grant, hostKeyId, actor: operation.actor, scope: operation.scope, session: operation.session};
        $('setup-native-ca-review').textContent = oauthConsentCanonical({sessionId: operation.session, hostKeyId,
          grantSha256: captured.digest, host: grant.networkOwner, machineIdSha256: grant.machineIdSha256,
          destinationPath: grant.caInstall.destinationPath, replaceExisting: grant.caInstall.replaceExisting,
          expectedExistingCertificateSha256: grant.caInstall.expectedExistingCertificateSha256,
          runtimeCaCertificateSha256: grant.runtimeCaCertificateSha256, targetRequestSha256: grant.targetRequestSha256,
          expiresAtEpochNs: grant.expiresAtEpochNs});
        $('setup-native-ca-prepare-confirm').checked = false;
        setupCaMessage('Exact grant reviewed structurally. No signature authority, preparation or installation is claimed.');
      } finally { operation.close(); }
    }
    async function setupCaPasskey(options, operation) {
      const key = options?.publicKey, s = options?.serverware;
      setupCaNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
        && oauthConsentClosed(s, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId'])
        && s.schema === 'serverware.setupNativeCaInstallationOptions/v1' && s.operation === 'setup.native-ca.prepare'
        && oauthConsentDigest(s.operationId) && oauthConsentDigest(s.challengeId) && nativeSetupId(s.credentialRecordId)
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
      setupCaNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.id === key.allowCredentials[0].id && credential.rawId.byteLength <= 3072
        && bytesToB64(credential.rawId) === credential.id);
      const assertion = credentialToJson(credential);
      setupCaNeed(workloadIssuanceAssertionOriginal(assertion, prepared).byteLength <= 16384); return assertion;
    }
    function setupCaPublic(v) {
      setupCaNeed(oauthConsentClosed(v, ['revision', 'phase', 'preparedSha256', 'enrollmentSha256', 'observationSha256',
        'prepareRequestDigest', 'completeRequestDigest'])
        && ['preparedSha256', 'enrollmentSha256', 'prepareRequestDigest'].every(key => oauthConsentDigest(v[key])));
      const revision = oauthConsentInteger(v.revision);
      setupCaNeed(revision === 0n ? v.phase === 'installation_unknown' && v.observationSha256 === null && v.completeRequestDigest === null
        : revision === 1n && v.phase === 'ca_readback_authenticated' && oauthConsentDigest(v.observationSha256) && oauthConsentDigest(v.completeRequestDigest));
      return v;
    }
    async function setupCaRetainBundle(v, operation, reviewed = null) {
      setupCaNeed(oauthConsentClosed(v, ['preparedOriginal', 'preparedSha256', 'enrollmentOriginal', 'enrollmentSha256', 'installationAuthorization']));
      const prepared = setupNativeOriginal(v.preparedOriginal, 8192), enrollment = setupNativeOriginal(v.enrollmentOriginal, 1500000);
      setupCaNeed(oauthConsentClosed(prepared, ['apiVersion', 'attemptId', 'sessionId', 'enrollmentSha256', 'intentSha256',
        'certificateSha256', 'associationSha256', 'installationAuthorizationSha256', 'hostKeyId', 'nonceSha256',
        'issuedAtEpochNs', 'expiresAtEpochNs']) && prepared.apiVersion === 'serverware.setupNativeCaInstallationPrepared/v1'
        && nativeSetupId(prepared.attemptId) && prepared.sessionId === operation.session
        && ['enrollmentSha256', 'intentSha256', 'certificateSha256', 'associationSha256', 'installationAuthorizationSha256',
          'hostKeyId', 'nonceSha256'].every(key => oauthConsentDigest(prepared[key])));
      const issued = oauthConsentInteger(prepared.issuedAtEpochNs), expires = oauthConsentInteger(prepared.expiresAtEpochNs);
      setupCaNeed(issued > 0n && issued < expires && expires - issued <= 300000000000n
        && expires <= 9223372036854775807n && prepared.enrollmentSha256 === v.enrollmentSha256
        && await workloadIssuanceHash(new TextEncoder().encode(v.preparedOriginal)) === v.preparedSha256
        && await workloadIssuanceHash(new TextEncoder().encode(v.enrollmentOriginal)) === v.enrollmentSha256);
      setupCaNeed(oauthConsentClosed(enrollment, ['session_id', 'revision', 'phase', 'owner_id', 'intent_original', 'intent_sha256',
        'approval_id', 'approval_original', 'prepare_request_digest', 'certificate_original', 'certificate_sha256', 'association_original',
        'complete_request_digest', 'configuration_digest', 'created_at', 'expires_at', 'completed_at'])
        && enrollment.session_id === operation.session && enrollment.owner_id === operation.actor
        && oauthConsentInteger(enrollment.revision) === 1n && enrollment.phase === 'certificate_issued'
        && enrollment.intent_sha256 === prepared.intentSha256 && enrollment.certificate_sha256 === prepared.certificateSha256
        && await workloadIssuanceHash(new TextEncoder().encode(enrollment.intent_original)) === prepared.intentSha256
        && await workloadIssuanceHash(new TextEncoder().encode(enrollment.association_original)) === prepared.associationSha256);
      const intent = setupNativeOriginal(enrollment.intent_original, 1200000);
      setupCaNeed(intent.apiVersion === 'serverware.setupNativeEnrollmentIntent/v1' && intent.sessionId === operation.session
        && intent.ownerId === operation.actor && expires <= oauthConsentInteger(intent.expiresAtEpochNs)
        && await workloadIssuanceHash(workloadIssuanceBase64(enrollment.certificate_original, 65536)) === prepared.certificateSha256);
      const wrapper = v.installationAuthorization;
      setupCaNeed(oauthConsentClosed(wrapper, ['base64Url', 'byteCount', 'bytesDigest']));
      const bytes = workloadIssuanceBase64(wrapper.base64Url, 32768);
      setupCaNeed(BigInt(bytes.byteLength) === oauthConsentInteger(wrapper.byteCount)
        && wrapper.bytesDigest === prepared.installationAuthorizationSha256 && await workloadIssuanceHash(bytes) === wrapper.bytesDigest);
      const grantOriginal = new TextDecoder('utf-8', {fatal: true}).decode(bytes), grant = setupCaGrant(grantOriginal, false);
      setupCaNeed(issued >= oauthConsentInteger(grant.issuedAtEpochNs) && expires <= oauthConsentInteger(grant.expiresAtEpochNs));
      if (reviewed) setupCaNeed(wrapper.bytesDigest === reviewed.digest && grantOriginal === reviewed.text && prepared.hostKeyId === reviewed.hostKeyId);
      operation.current();
      setupCaBundle = {...v, prepared, enrollment, grant, grantOriginal, expires, actor: operation.actor, scope: operation.scope, session: operation.session};
      setupCaReadback = null; $('setup-native-ca-complete-confirm').checked = false; setupCaDownloads(true);
      $('setup-native-ca-handoff').textContent = oauthConsentCanonical({sessionId: operation.session, attemptId: prepared.attemptId,
        preparedSha256: v.preparedSha256, enrollmentSha256: v.enrollmentSha256, hostKeyId: prepared.hostKeyId,
        installationAuthorizationSha256: wrapper.bytesDigest, expiresAtEpochNs: prepared.expiresAtEpochNs});
    }
    async function setupNativeCaPrepare() {
      const held = setupCaGrantReview; setupCaNeed(held && $('setup-native-ca-prepare-confirm').checked);
      const operation = setupCaBegin(); let sent = false, assertion = null;
      const current = () => { operation.current(); setupCaContext(held, operation);
        setupCaNeed(setupCaGrantReview === held && $('setup-native-ca-grant').files?.[0] === held.file
          && $('setup-native-ca-host-key').value.trim() === held.hostKeyId && $('setup-native-ca-prepare-confirm').checked);
        setupCaGrant(held.text, true); };
      const scoped = {...operation, current};
      try {
        current(); setupCaNeed(sessionStorage.getItem(setupCaMarker(operation, 'prepare')) === null);
        await setupEnrollmentCookie(scoped);
        const body = {apiVersion: setupCaRequest, sessionId: operation.session, installationAuthorization: held.wrapper, hostKeyId: held.hostKeyId};
        const options = setupCaReply(await setupCaPost('options', body, scoped), 200, 'fresh-assertion-required', ['options']);
        assertion = await setupCaPasskey(options.options, scoped); await setupEnrollmentCookie(scoped);
        const v = setupCaReply(await setupCaPost('prepare', {...body, assertion}, scoped, () => {
          setupCaMark(scoped, 'prepare', held.digest); sent = true;
        }), 201, 'installation-outcome-unknown', ['preparedOriginal', 'preparedSha256', 'enrollmentOriginal', 'enrollmentSha256', 'installationAuthorization']);
        await setupCaRetainBundle({preparedOriginal: v.preparedOriginal, preparedSha256: v.preparedSha256,
          enrollmentOriginal: v.enrollmentOriginal, enrollmentSha256: v.enrollmentSha256, installationAuthorization: v.installationAuthorization}, scoped, held);
        setupCaMessage('Precontact preparation retained. Download exact originals for the authorized host installer. No installation is claimed; its original expiry is unchanged.');
      } catch (error) {
        setupCaMessage(sent ? 'Preparation outcome is uncertain. Use read-only lookup to recover an existing bundle; do not prepare again.'
          : 'Grant review or fresh passkey did not complete. No preparation submission was sent.'); throw error;
      } finally { assertion = null; setupCaContact = false; $('setup-native-ca-prepare-confirm').checked = false; operation.close(); }
    }
    function setupCaObservation(text, bundle) {
      const v = setupNativeOriginal(text, 32768), p = v.payload;
      const digests = ['preparedSha256', 'enrollmentSha256', 'certificateSha256', 'associationSha256', 'installationAuthorizationSha256',
        'nativeSetupSha256', 'targetRequestSha256', 'runtimeCaCertificateSha256', 'machineIdSha256', 'operationSha256',
        'reservationSha256', 'hostSigningKeyId', 'workloadSpkiSha256'];
      setupCaNeed(oauthConsentClosed(v, ['payload', 'signature', 'workloadSignature'])
        && oauthConsentClosed(p, ['apiVersion', 'purpose', 'trustMode', ...digests, 'hostId', 'bootId', 'namespaceDevice',
          'namespaceInode', 'destinationPath', 'destinationIdentity', 'observedBeforeEpochNs', 'observedAfterEpochNs'])
        && p.apiVersion === 'serverware.nativeSetupCaInstallObservation/v1' && p.purpose === 'setup-ca-installation-readback'
        && p.trustMode === 'trusted-host-local' && digests.every(key => oauthConsentDigest(p[key]))
        && typeof v.signature === 'string' && v.signature.startsWith('ed25519:')
        && workloadIssuanceBase64(v.signature.slice(8), 64).byteLength === 64
        && typeof v.workloadSignature === 'string' && v.workloadSignature.startsWith('ecdsa-p256-sha256:')
        && workloadIssuanceBase64(v.workloadSignature.slice(18), 80).byteLength > 0);
      const g = bundle.grant, expected = {preparedSha256: bundle.preparedSha256, enrollmentSha256: bundle.enrollmentSha256,
        certificateSha256: bundle.prepared.certificateSha256, associationSha256: bundle.prepared.associationSha256,
        installationAuthorizationSha256: bundle.prepared.installationAuthorizationSha256, hostSigningKeyId: bundle.prepared.hostKeyId,
        nativeSetupSha256: g.setupSha256, targetRequestSha256: g.targetRequestSha256, runtimeCaCertificateSha256: g.runtimeCaCertificateSha256,
        machineIdSha256: g.machineIdSha256, hostId: g.networkOwner.hostId, bootId: g.networkOwner.bootId,
        destinationPath: g.caInstall.destinationPath};
      setupCaNeed(Object.entries(expected).every(([key, value]) => p[key] === value)
        && oauthConsentInteger(p.namespaceDevice) === oauthConsentInteger(g.networkOwner.namespaceDevice)
        && oauthConsentInteger(p.namespaceInode) === oauthConsentInteger(g.networkOwner.namespaceInode)
        && oauthConsentClosed(p.destinationIdentity, ['device', 'inode', 'mode', 'uid', 'gid', 'size', 'mtimeSeconds', 'mtimeNanos', 'ctimeSeconds', 'ctimeNanos'])
        && Object.values(p.destinationIdentity).every(value => { oauthConsentInteger(value); return true; })
        && oauthConsentInteger(p.destinationIdentity.mode) === 420n
        && oauthConsentInteger(p.destinationIdentity.uid) === oauthConsentInteger(g.caInstall.ownerUid)
        && oauthConsentInteger(p.destinationIdentity.gid) === oauthConsentInteger(g.caInstall.ownerGid));
      const before = oauthConsentInteger(p.observedBeforeEpochNs), after = oauthConsentInteger(p.observedAfterEpochNs);
      setupCaNeed(oauthConsentInteger(bundle.prepared.issuedAtEpochNs) <= before && before <= after && after < bundle.expires);
      return p; // signatures are authenticated only by the independent server
    }
    async function setupNativeCaReviewObservation() {
      const operation = setupCaBegin(), bundle = setupCaBundle; setupCaReadback = null;
      $('setup-native-ca-readback').textContent = 'Reading this exact observation; no current readback review accepted.';
      $('setup-native-ca-complete-confirm').checked = false;
      try {
        setupCaContext(bundle, operation); await setupEnrollmentCookie(operation);
        const selected = await setupCaFile('setup-native-ca-observation', operation, true);
        const payload = setupCaObservation(selected.text, bundle);
        operation.current(); setupCaNeed(setupCaBundle === bundle);
        setupCaReadback = {...selected, bundle, actor: operation.actor, scope: operation.scope, session: operation.session};
        $('setup-native-ca-readback').textContent = oauthConsentCanonical({preparedSha256: payload.preparedSha256,
          observationSha256: selected.digest, hostId: payload.hostId, hostSigningKeyId: payload.hostSigningKeyId,
          destinationPath: payload.destinationPath, destinationIdentity: payload.destinationIdentity,
          runtimeCaCertificateSha256: payload.runtimeCaCertificateSha256, observedAfterEpochNs: payload.observedAfterEpochNs});
        $('setup-native-ca-complete-confirm').checked = false;
        setupCaMessage('Readback matches the reviewed handoff structurally. Its host and workload signatures are NOT yet authenticated by this review.');
      } finally { operation.close(); }
    }
    async function setupNativeCaComplete() {
      const held = setupCaReadback; setupCaNeed(held && $('setup-native-ca-complete-confirm').checked);
      const operation = setupCaBegin(); let sent = false;
      const current = () => { operation.current(); setupCaContext(held, operation);
        setupCaNeed(setupCaReadback === held && setupCaBundle === held.bundle && $('setup-native-ca-observation').files?.[0] === held.file
          && $('setup-native-ca-complete-confirm').checked && BigInt(Date.now()) * 1000000n < held.bundle.expires); };
      const scoped = {...operation, current};
      try {
        current(); setupCaNeed(sessionStorage.getItem(setupCaMarker(operation, 'complete')) === null); await setupEnrollmentCookie(scoped);
        const v = setupCaReply(await setupCaPost('complete', {apiVersion: setupCaRequest, sessionId: operation.session,
          observationOriginal: held.text}, scoped, () => { setupCaMark(scoped, 'complete', held.digest); sent = true; }),
          200, 'ca-readback-authenticated', ['installation']);
        const row = setupCaPublic(v.installation);
        setupCaNeed(row.phase === 'ca_readback_authenticated' && row.observationSha256 === held.digest
          && row.preparedSha256 === held.bundle.preparedSha256 && row.enrollmentSha256 === held.bundle.enrollmentSha256);
        $('setup-native-ca-result').textContent = oauthConsentCanonical(row);
        setupCaMessage('Server authenticated and retained the exact host/workload readback. Trust mode remains trusted-host-local; nativeHostVerified, enrollmentComplete and proxyReady remain false.');
      } catch (error) {
        setupCaMessage(sent ? 'Readback submission outcome is uncertain. Inspect retained state; do not resubmit or repeat host installation.'
          : 'Readback context is unavailable or expired. No completion submission was sent.'); throw error;
      } finally { setupCaContact = false; $('setup-native-ca-complete-confirm').checked = false; operation.close(); }
    }
    async function setupNativeCaLookup() {
      const operation = setupCaBegin(); setupCaBundle = null; setupCaReadback = null; setupCaDownloads(false);
      $('setup-native-ca-handoff').textContent = 'Reading retained handoff; no current bundle accepted.';
      $('setup-native-ca-readback').textContent = 'No current host readback reviewed.';
      $('setup-native-ca-complete-confirm').checked = false;
      try {
        await setupEnrollmentCookie(operation);
        const v = setupCaReply(await setupCaPost('lookup', {apiVersion: setupCaRequest, sessionId: operation.session}, operation),
          200, 'observation', ['installation', 'observationOriginal', 'bundle']);
        if (v.installation === null) {
          setupCaNeed(v.observationOriginal === null && v.bundle === null);
          $('setup-native-ca-result').textContent = 'No retained CA attempt observed. This is not permission to repeat a submitted preparation or host action.';
        } else {
          const row = setupCaPublic(v.installation); await setupCaRetainBundle(v.bundle, operation);
          setupCaNeed(row.preparedSha256 === setupCaBundle.preparedSha256 && row.enrollmentSha256 === setupCaBundle.enrollmentSha256);
          if (row.phase === 'ca_readback_authenticated') {
            setupCaObservation(v.observationOriginal, setupCaBundle);
            setupCaNeed(await workloadIssuanceHash(new TextEncoder().encode(v.observationOriginal)) === row.observationSha256);
            operation.current();
          } else setupCaNeed(v.observationOriginal === null);
          $('setup-native-ca-result').textContent = oauthConsentCanonical(row);
        }
        setupCaMessage('Historical read-only state recovered. Exact handoff downloads do not renew expiry, reset attempts or authorize repeating an uncertain host install. No native-host, proxy or final Setup readiness is claimed.');
      } catch (error) {
        setupCaBundle = null; setupCaReadback = null; setupCaDownloads(false);
        $('setup-native-ca-result').textContent = 'No current retained-state observation accepted.';
        setupCaMessage('Lookup unavailable or changed. Keep original attempt information; do not infer that installation failed or repeat it.'); throw error;
      } finally { operation.close(); }
    }
    function setupNativeCaDownload(kind) {
      const held = setupCaBundle;
      setupCaNeed(!setupEnrollmentBusy && held && setupEnrollmentAuth('requester') === held.actor
        && sessionActivationAuthScope() === held.scope && $('setup-policy-session').value.trim() === held.session);
      const selected = {prepared: ['setup-native-ca-prepared.json', held.preparedOriginal],
        enrollment: ['setup-native-ca-enrollment.json', held.enrollmentOriginal], grant: ['setup-native-ca-authorization.json', held.grantOriginal]}[kind];
      setupCaNeed(selected);
      const url = URL.createObjectURL(new Blob([new TextEncoder().encode(selected[1])], {type: 'application/json'}));
      const link = document.createElement('a'); link.href = url; link.download = selected[0];
      try { link.click(); } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      setupCaMessage('Download requested for the exact ' + kind + ' original. Use only the authorized host installation workflow. Browser download completion and host installation are not verified; original expiry and attempt markers remain.');
    }
    ['setup-native-ca-grant', 'setup-native-ca-host-key', 'setup-policy-session'].forEach(id =>
      $(id).addEventListener(id === 'setup-native-ca-grant' ? 'change' : 'input', () => setupNativeCaClear(false)));
    $('setup-native-ca-observation').addEventListener('change', () => {
      setupCaEpoch++; setupCaOperation?.abort(); setupCaReadback = null;
      $('setup-native-ca-complete-confirm').checked = false; $('setup-native-ca-readback').textContent = 'Readback selection changed; review again.';
    });
    window.addEventListener('pagehide', () => setupNativeCaClear());
"""
