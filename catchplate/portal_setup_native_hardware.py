"""Manual native challenge and independent receipt handoff, never final readiness."""

SETUP_NATIVE_HARDWARE_HTML = r"""
            <hr>
            <details>
              <summary>Verify native enclave hardware and the original proxy evidence</summary>
              <p class="hint">After recorded native runtime evidence, this separately authorized step reserves one protected attempt and contacts the fixed native management endpoint once. Independent hardware and proxy verifiers must check the originals. The host CA association remains trusted-host-local, not measured Linux-host evidence.</p>
              <label><input id="setup-hardware-prepare-confirm" type="checkbox">Reserve this exact Setup attempt and make one native hardware challenge contact. An unknown outcome must not be retried.</label>
              <button type="button" onclick="runUiAction('Prepare native hardware challenge once', setupHardwarePrepare)">Fresh requester passkey + challenge once</button>
              <button type="button" class="secondary" onclick="runUiAction('Read native hardware attempt', setupHardwareLookup)">Read retained state, without recontact</button>
              <pre id="setup-hardware-review">No retained hardware attempt.</pre>
              <button id="setup-hardware-download-request" type="button" class="secondary" disabled onclick="runUiAction('Download exact independent verifier request', () => setupHardwareDownload('request'))">Independent verifier request</button>
              <button id="setup-hardware-download-evidence" type="button" class="secondary" disabled onclick="runUiAction('Download exact native evidence', () => setupHardwareDownload('evidence'))">Native evidence original</button>
              <p class="hint">Use only the independently approved external verifier channel. The public bundle contains certificate, authority and approval originals; it contains no private key. The browser neither signs nor supplies trust. No new proxy request is performed here.</p>
              <label>Retained native evidence (optional if already page-held; canonical original, at most64KiB)</label>
              <input id="setup-hardware-evidence" type="file" accept="application/json,.json" autocomplete="off">
              <label>Independent hardware-verifier receipt (canonical original, at most16KiB)</label>
              <input id="setup-hardware-hardware" type="file" accept="application/json,.json" autocomplete="off">
              <label>Independent proxy-verifier receipt (canonical original, at most16KiB)</label>
              <input id="setup-hardware-proxy" type="file" accept="application/json,.json" autocomplete="off">
              <label><input id="setup-hardware-complete-confirm" type="checkbox">Submit these exact originals once. The server must verify both independent signatures and current protected state.</label>
              <button type="button" onclick="runUiAction('Consume independent hardware receipts once', setupHardwareComplete)">Complete this evidence step once</button>
              <button type="button" class="secondary" onclick="setupHardwareClear()">Clear page-held originals</button>
              <pre id="setup-hardware-result">No completed hardware/proxy evidence.</pre>
              <p id="setup-hardware-status" class="hint" role="status" aria-live="polite">Not measured-host proof, final Setup or proxy readiness. Nonsecret attempt markers are tab-local convenience; the protected server reservation is authoritative.</p>
            </details>
"""

SETUP_NATIVE_HARDWARE_SCRIPT = r"""
    const setupHardwareRequest = 'catchplate.setupNativeHardwareRequest/v1';
    let setupHardwareHeld = null, setupHardwareEpoch = 0, setupHardwareOperation = null, setupHardwareContact = false;
    function setupHardwareNeed(v) { if (!v) throw new Error('Native hardware originals or context differ. Read retained state; never retry uncertain contact.'); }
    function setupHardwareMessage(v) { $('setup-hardware-status').textContent = v; }
    function setupHardwareButtons() {
      $('setup-hardware-download-request').disabled = !setupHardwareHeld?.verifierRequestOriginal;
      $('setup-hardware-download-evidence').disabled = !setupHardwareHeld?.evidenceOriginal;
    }
    function setupHardwareClear() {
      setupHardwareEpoch++; setupHardwareOperation?.abort(); setupHardwareHeld = null; setupHardwareButtons();
      ['evidence','hardware','proxy'].forEach(name => { $('setup-hardware-' + name).value = ''; });
      ['prepare','complete'].forEach(name => { $('setup-hardware-' + name + '-confirm').checked = false; });
      $('setup-hardware-review').textContent = 'No page-held hardware attempt.';
      $('setup-hardware-result').textContent = 'No current completion observation.';
      setupHardwareMessage(setupHardwareContact ? 'An operation may have committed. Read retained state only; markers remain.'
        : 'Page-held originals discarded. No attempt marker or original deadline was reset.');
    }
    function setupHardwareBegin() {
      const base = setupEnrollmentBegin(), epoch = setupHardwareEpoch;
      const op = {...base, current() { base.current(); setupHardwareNeed(epoch === setupHardwareEpoch); },
        close() { base.close(); if (setupHardwareOperation === op) setupHardwareOperation = null; }};
      setupHardwareOperation = op; return op;
    }
    function setupHardwareMark(op, phase, digest) {
      op.current(); const key = 'catchplate.setup-native-hardware:' + op.actor + ':' + op.session + ':' + phase;
      setupHardwareNeed(oauthConsentDigest(digest) && sessionStorage.getItem(key) === null);
      sessionStorage.setItem(key, digest); setupHardwareNeed(sessionStorage.getItem(key) === digest); setupHardwareContact = true;
    }
    async function setupHardwarePost(phase, body, op, contact = null) {
      setupHardwareNeed(['options','prepare','complete','lookup'].includes(phase));
      let original = oauthConsentCanonical(body);
      setupHardwareNeed(new TextEncoder().encode(original).byteLength <= 131072);
      try {
        op.current(); const response = await fetch('/api/csrf', {credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:op.signal});
        const csrf = await setupPolicyRead(response,op,4096);
        setupHardwareNeed(response.ok && oauthConsentClosed(csrf,['ok','token','cookie','header']) && csrf.ok === true
          && csrf.cookie === 'catchplate_csrf' && csrf.header === 'X-Catchplate-CSRF-Token' && workloadIssuanceText(csrf.token,1024));
        op.current(); if (contact) contact();
        const reply = await fetch('/api/setup/native-hardware/' + phase, {method:'POST',credentials:'same-origin',mode:'same-origin',
          redirect:'error',cache:'no-store',signal:op.signal,headers:{'Content-Type':'application/json',[csrf.header]:csrf.token},body:original});
        return {status:reply.status,value:await setupPolicyRead(reply,op,4*1024*1024)};
      } finally { original = null; }
    }
    function setupHardwareReply(reply,code,status,fields) {
      const v = reply.value;
      setupHardwareNeed(reply.status === code && oauthConsentClosed(v,['apiVersion','status','okForAction','automaticRetryAllowed',
        'measuredHost','enrollmentComplete','proxyReady','hostAssociationTrust',...fields])
        && v.apiVersion === 'catchplate.setupNativeHardwareResponse/v1' && v.status === status && v.okForAction === false
        && v.automaticRetryAllowed === false && v.measuredHost === false && v.enrollmentComplete === false && v.proxyReady === false
        && v.hostAssociationTrust === 'trusted-host-local'); return v;
    }
    function setupHardwarePublic(v) {
      setupHardwareNeed(oauthConsentClosed(v,['revision','phase','attemptSha256','prepareRequestDigest','completeRequestDigest'])
        && oauthConsentDigest(v.attemptSha256) && oauthConsentDigest(v.prepareRequestDigest));
      const rev = oauthConsentInteger(v.revision);
      setupHardwareNeed(rev === 0n ? v.phase === 'hardware_outcome_unknown' && v.completeRequestDigest === null
        : rev === 1n && v.phase === 'hardware_proxy_verified' && oauthConsentDigest(v.completeRequestDigest)); return v;
    }
    async function setupHardwareBundle(bundle,record,op) {
      setupHardwareNeed(oauthConsentClosed(bundle,['inputsOriginal','attemptOriginal','evidenceOriginal','verifierRequestOriginal']));
      const inputs = setupNativeOriginal(bundle.inputsOriginal,4*1024*1024), attempt = setupNativeOriginal(bundle.attemptOriginal,8192), row = setupHardwarePublic(record);
      const rotated = attempt.apiVersion === 'catchplate.setupNativeHardwareAttempt/v2';
      setupHardwareNeed(oauthConsentClosed(inputs,['actor_id','control_plane_configuration_digest','credential_policy','maximum_attempt_nanos',
        'association_original','runtime_original','enrollment_original','installation_original','scope_original']));
      setupHardwareNeed(oauthConsentClosed(attempt,['apiVersion','attemptId','sessionId','ownerId','associationSha256','runtimeSha256','enrollmentSha256',
        'installationSha256','scopeSha256','nonce','policyHash','principalId','routeId','credentialId','credentialVersion','issuedAtEpochNs','expiresAtEpochNs',
        ...(rotated ? ['continuationSha256','credentialProvenanceSha256'] : [])])
        && attempt.apiVersion === (rotated ? 'catchplate.setupNativeHardwareAttempt/v2' : 'catchplate.setupNativeHardwareAttempt/v1')
        && nativeSetupId(attempt.attemptId) && attempt.sessionId === op.session
        && attempt.ownerId === op.actor && inputs.actor_id === op.actor
        && (rotated ? oauthConsentInteger(attempt.credentialVersion) >= 2n && oauthConsentInteger(attempt.credentialVersion) <= 9223372036854775807n
          && oauthConsentDigest(attempt.continuationSha256) && oauthConsentDigest(attempt.credentialProvenanceSha256)
          : oauthConsentInteger(attempt.credentialVersion) === 1n)
        && workloadIssuanceBase64(attempt.nonce,32).byteLength === 32);
      setupHardwareNeed(await workloadIssuanceHash(new TextEncoder().encode(bundle.attemptOriginal)) === row.attemptSha256);
      for (const [name,field] of [['associationSha256','association_original'],['runtimeSha256','runtime_original'],['enrollmentSha256','enrollment_original'],
          ['installationSha256','installation_original'],['scopeSha256','scope_original']]) {
        setupNativeOriginal(inputs[field],4*1024*1024);
        setupHardwareNeed(await workloadIssuanceHash(new TextEncoder().encode(inputs[field])) === attempt[name]); op.current();
      }
      if (rotated) {
        const enrollment = setupNativeOriginal(inputs.enrollment_original,1500000);
        const intent = await setupEnrollmentIntentOriginal(enrollment.intent_original,op);
        setupHardwareNeed(intent.apiVersion === 'catchplate.setupNativeEnrollmentIntent/v2');
        const chain = await setupEnrollmentRotation(intent.continuationOriginal,op,attempt);
        const association = setupNativeOriginal(inputs.association_original,32768), scope = setupNativeOriginal(inputs.scope_original,32768);
        setupHardwareNeed(chain.provenanceSha256 === attempt.credentialProvenanceSha256
          && association.continuation_sha256 === attempt.continuationSha256 && association.enrollment_sha256 === attempt.enrollmentSha256
          && scope.apiVersion === 'catchplate.setupNativeRuntimeRotationScope/v1' && scope.continuationSha256 === attempt.continuationSha256
          && ['sessionId','credentialId','principalId','routeId'].every(key => scope[key] === attempt[key])
          && oauthConsentInteger(scope.credentialVersion) === oauthConsentInteger(attempt.credentialVersion));
      } else {
        const enrollment = setupNativeOriginal(inputs.enrollment_original,1500000), scope = setupNativeOriginal(inputs.scope_original,32768);
        setupHardwareNeed(setupNativeOriginal(enrollment.intent_original,1200000).apiVersion === 'catchplate.setupNativeEnrollmentIntent/v1'
          && !Object.prototype.hasOwnProperty.call(scope,'apiVersion') && oauthConsentInteger(scope.credentialVersion) === 1n);
      }
      const before = oauthConsentInteger(attempt.issuedAtEpochNs), expires = oauthConsentInteger(attempt.expiresAtEpochNs);
      setupHardwareNeed(before > 0n && before < expires && expires <= 9223372036854775807n && expires-before <= 300000000000n);
      if (bundle.evidenceOriginal === null) setupHardwareNeed(bundle.verifierRequestOriginal === null && row.phase === 'hardware_outcome_unknown');
      else {
        setupHardwareEvidence(bundle.evidenceOriginal,attempt);
        const request = setupNativeOriginal(bundle.verifierRequestOriginal,4*1024*1024);
        setupHardwareNeed(oauthConsentCanonical(request) === oauthConsentCanonical({...inputs,attempt_original:bundle.attemptOriginal,evidence_original:bundle.evidenceOriginal}));
      }
      const remaining = expires-BigInt(Date.now())*1000000n;
      op.current(); return {...bundle,row,attempt,expires,until:performance.now()+Number((remaining > 0n && remaining <= 300000000000n ? remaining : 0n)/1000000n),
        actor:op.actor,authScope:op.scope,session:op.session};
    }
    function setupHardwareEvidence(text,attempt) {
      const v = setupNativeOriginal(text,65536);
      setupHardwareNeed(oauthConsentClosed(v,['statement','signature','nativeKeyEvidence'])
        && oauthConsentClosed(v.statement,['apiVersion','attempt','policyOriginalSha256','routePolicyDigest','bootId','keyId',
          'controlPlaneResponseSigningKeyId','dataPlaneBinarySha256','observedAtEpochNs'])
        && oauthConsentClosed(v.nativeKeyEvidence,['apiVersion','attestationDocumentB64','responseProofPublicKey'])
        && v.nativeKeyEvidence.apiVersion === 'catchplate.nativeResponseProofKeyEvidence/v1'
        && v.statement?.apiVersion === 'catchplate.nativeSetupHardwareStatement/v1'
        && oauthConsentCanonical(v.statement.attempt) === oauthConsentCanonical(attempt)
        && typeof v.signature === 'string' && /^ed25519:[A-Za-z0-9_-]{86}$/.test(v.signature)); return v;
    }
    function setupHardwareShow(held) {
      setupHardwareButtons(); $('setup-hardware-review').textContent = oauthConsentCanonical({sessionId:held.session,phase:held.row.phase,
        attemptSha256:held.row.attemptSha256,policyHash:held.attempt.policyHash,principalId:held.attempt.principalId,routeId:held.attempt.routeId,
        expiresAtEpochNs:held.attempt.expiresAtEpochNs,nativeEvidenceRetained:held.evidenceOriginal !== null});
    }
    function setupHardwareLive(held,op) {
      op.current(); setupHardwareNeed(held && setupHardwareHeld === held && held.actor === op.actor && held.authScope === op.scope
        && held.session === op.session && held.row.phase === 'hardware_outcome_unknown' && performance.now() < held.until
        && BigInt(Date.now())*1000000n < held.expires);
    }
    async function setupHardwarePrepare() {
      const op = setupHardwareBegin(); let sent = false;
      try {
        setupHardwareNeed($('setup-hardware-prepare-confirm').checked); await setupEnrollmentCookie(op);
        const reply = setupHardwareReply(await setupHardwarePost('options',{apiVersion:setupHardwareRequest,sessionId:op.session},op),
          200,'fresh-assertion-required',['options']);
        const options = reply.options, s = options?.catchplate, k = options?.publicKey;
        setupHardwareNeed(oauthConsentClosed(options,['publicKey','catchplate']) && oauthConsentClosed(s,['schema','operation','operationId','challengeId','credentialRecordId','payloadDigest'])
          && s.schema === 'catchplate.setupNativeHardwareOptions/v1' && s.operation === 'setup.native-hardware.prepare'
          && oauthConsentDigest(s.operationId) && oauthConsentDigest(s.challengeId) && oauthConsentDigest(s.payloadDigest) && nativeSetupId(s.credentialRecordId)
          && oauthConsentClosed(k,['challenge','rpId','allowCredentials','timeout','userVerification']) && k.rpId === location.hostname
          && k.userVerification === 'required' && oauthConsentInteger(k.timeout) === 30000n && workloadIssuanceBase64(k.challenge,32).byteLength === 32
          && Array.isArray(k.allowCredentials) && k.allowCredentials.length === 1 && oauthConsentClosed(k.allowCredentials[0],['type','id']) && k.allowCredentials[0].type === 'public-key');
        workloadIssuanceBase64(k.allowCredentials[0].id,3072);
        setupHardwareMessage('Fresh hardware challenge authorization for exact server-selected arguments: ' + s.payloadDigest);
        const credential = await navigator.credentials.get({signal:op.signal,publicKey:prepareRequestOptions({publicKey:{...k,timeout:30000}})});
        op.current(); setupHardwareNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
          && credential.rawId.byteLength <= 3072 && credential.id === k.allowCredentials[0].id && bytesToB64(credential.rawId) === credential.id);
        const assertion = credentialToJson(credential);
        const v = setupHardwareReply(await setupHardwarePost('prepare',{apiVersion:setupHardwareRequest,sessionId:op.session,assertion},op,() => {
          setupHardwareNeed($('setup-hardware-prepare-confirm').checked); setupHardwareMark(op,'prepare',s.payloadDigest); sent = true;
        }),201,'independent-verification-required',['hardware','bundle']);
        setupHardwareHeld = await setupHardwareBundle(v.bundle,v.hardware,op); setupHardwareShow(setupHardwareHeld);
        setupHardwareMessage('One native challenge returned. Download exact public originals to the approved independent hardware and proxy verifiers. No final Setup or measured-host claim.');
      } catch (error) {
        setupHardwareMessage(sent ? 'Prepare/contact outcome unknown. Read retained state only; do not repeat the challenge.' : 'Preparation unavailable; no effect request was sent.'); throw error;
      } finally { setupHardwareContact = false; $('setup-hardware-prepare-confirm').checked = false; op.close(); }
    }
    async function setupHardwareFile(name,maximum,op) {
      const input = $('setup-hardware-' + name), files = input.files; setupHardwareNeed(files?.length === 1);
      const file = files[0]; setupHardwareNeed(file.size >= 2 && file.size <= maximum);
      const bytes = new Uint8Array(await file.arrayBuffer());
      try {
        op.current(); setupHardwareNeed(input.files?.[0] === file && bytes.byteLength === file.size);
        const original = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes); setupNativeOriginal(original,maximum);
        return {original,file,input};
      } finally { bytes.fill(0); }
    }
    function setupHardwareResult(text,row,held) {
      const v = setupNativeOriginal(text,8192);
      setupHardwareNeed(oauthConsentClosed(v,['apiVersion','resultScope','hostAssociationTrust','measuredHost','finalSetup','proxyReady','okForAction',
        'attemptSha256','evidenceSha256','hardwareReceiptSha256','proxyReceiptSha256']) && v.apiVersion === 'catchplate.setupNativeHardwareResult/v1'
        && v.resultScope === 'enclave-hardware-and-proxy-only' && v.hostAssociationTrust === 'trusted-host-local'
        && v.measuredHost === false && v.finalSetup === false && v.proxyReady === false && v.okForAction === false
        && v.attemptSha256 === row.attemptSha256 && v.attemptSha256 === held.row.attemptSha256);
      ['evidenceSha256','hardwareReceiptSha256','proxyReceiptSha256'].forEach(name => setupHardwareNeed(oauthConsentDigest(v[name]))); return v;
    }
    async function setupHardwareComplete() {
      const op = setupHardwareBegin(), held = setupHardwareHeld; let sent = false;
      try {
        setupHardwareLive(held,op); setupHardwareNeed($('setup-hardware-complete-confirm').checked); await setupEnrollmentCookie(op);
        const quoteFile = held.evidenceOriginal === null ? await setupHardwareFile('evidence',65536,op) : null;
        const evidence = held.evidenceOriginal ?? quoteFile.original; setupHardwareEvidence(evidence,held.attempt);
        const hardware = await setupHardwareFile('hardware',16384,op), proxy = await setupHardwareFile('proxy',16384,op);
        const evidenceSha = await workloadIssuanceHash(new TextEncoder().encode(evidence));
        for (const [file,role] of [[hardware,'hardware-verifier'],[proxy,'proxy-verifier']]) {
          const receipt = setupNativeOriginal(file.original,16384), r = receipt.payload;
          setupHardwareNeed(oauthConsentClosed(receipt,['payload','signature']) && r?.apiVersion === 'catchplate.setupNativeIndependentVerification/v1'
            && oauthConsentClosed(r,['apiVersion','purpose','resultScope','attemptSha256','evidenceSha256','runtimeSha256','enrollmentSha256','installationSha256',
              'scopeSha256','quoteSha256','releaseRecordSha256','policyHash','verifierKeyId','verifierProvider','issuedAtEpochNs','expiresAtEpochNs','measuredHost','finalSetup','proxyReady'])
            && r.purpose === role && r.resultScope === 'enclave-hardware-and-proxy-only' && r.measuredHost === false && r.finalSetup === false
            && r.proxyReady === false && r.attemptSha256 === held.row.attemptSha256 && r.evidenceSha256 === evidenceSha
            && oauthConsentDigest(r.verifierKeyId) && /^ed25519:[A-Za-z0-9_-]{86}$/.test(receipt.signature));
        }
        setupHardwareLive(held,op);
        const body = {apiVersion:setupHardwareRequest,sessionId:op.session,evidenceOriginal:evidence,hardwareReceiptOriginal:hardware.original,proxyReceiptOriginal:proxy.original};
        const digest = await workloadIssuanceHash(new TextEncoder().encode(oauthConsentCanonical(body)));
        const v = setupHardwareReply(await setupHardwarePost('complete',body,op,() => {
          setupHardwareLive(held,op); setupHardwareNeed($('setup-hardware-complete-confirm').checked && hardware.input.files?.[0] === hardware.file
            && proxy.input.files?.[0] === proxy.file && (!quoteFile || quoteFile.input.files?.[0] === quoteFile.file));
          setupHardwareMark(op,'complete',digest); sent = true;
        }),200,'hardware-proxy-verified',['hardware','resultOriginal']);
        const row = setupHardwarePublic(v.hardware), result = setupHardwareResult(v.resultOriginal,row,held);
        setupHardwareNeed(row.phase === 'hardware_proxy_verified' && row.prepareRequestDigest === held.row.prepareRequestDigest && result.evidenceSha256 === evidenceSha
          && result.hardwareReceiptSha256 === await workloadIssuanceHash(new TextEncoder().encode(hardware.original))
          && result.proxyReceiptSha256 === await workloadIssuanceHash(new TextEncoder().encode(proxy.original)));
        op.current(); setupHardwareHeld = {...held,row,evidenceOriginal:evidence}; setupHardwareShow(setupHardwareHeld);
        $('setup-hardware-result').textContent = v.resultOriginal;
        setupHardwareMessage('Independent enclave hardware/proxy evidence recorded. Trusted-host-local association is unchanged; measuredHost, finalSetup and proxyReady remain false.');
      } catch (error) {
        setupHardwareMessage(sent ? 'Completion outcome unknown. Read retained state only; do not resubmit.' : 'Originals or lifetime unavailable; no completion was sent.'); throw error;
      } finally { setupHardwareContact = false; $('setup-hardware-complete-confirm').checked = false; op.close(); }
    }
    async function setupHardwareLookup() {
      const op = setupHardwareBegin(); setupHardwareHeld = null; setupHardwareButtons();
      try {
        await setupEnrollmentCookie(op);
        const v = setupHardwareReply(await setupHardwarePost('lookup',{apiVersion:setupHardwareRequest,sessionId:op.session},op),200,'observation',['hardware','bundle','resultOriginal']);
        if (v.hardware === null) {
          setupHardwareNeed(v.bundle === null && v.resultOriginal === null); $('setup-hardware-result').textContent = 'No retained slot observed. This does not clear markers or permit retry.';
        } else {
          const held = await setupHardwareBundle(v.bundle,v.hardware,op);
          if (held.row.phase === 'hardware_proxy_verified') setupHardwareResult(v.resultOriginal,held.row,held);
          else setupHardwareNeed(v.resultOriginal === null);
          op.current(); setupHardwareHeld = held; setupHardwareShow(held);
          $('setup-hardware-result').textContent = v.resultOriginal ?? 'Unresolved original attempt; no completion claim.';
        }
        setupHardwareMessage('Historical observation only. No contact, deadline renewal, marker clearing or final authority was granted. A lost quote is not regenerated.');
      } catch (error) { setupHardwareHeld = null; setupHardwareButtons(); setupHardwareMessage('Lookup unavailable; do not infer failure or retry.'); throw error; }
      finally { op.close(); }
    }
    function setupHardwareDownload(kind) {
      const held = setupHardwareHeld;
      setupHardwareNeed(!setupEnrollmentBusy && held && setupEnrollmentAuth('requester') === held.actor && sessionActivationAuthScope() === held.authScope
        && $('setup-policy-session').value.trim() === held.session && ['request','evidence'].includes(kind));
      const text = kind === 'request' ? held.verifierRequestOriginal : held.evidenceOriginal; setupHardwareNeed(typeof text === 'string');
      const url = URL.createObjectURL(new Blob([new TextEncoder().encode(text)],{type:'application/json'}));
      const link = document.createElement('a'); link.href = url; link.download = 'setup-native-hardware-' + kind + '.json';
      try { link.click(); } finally { setTimeout(() => URL.revokeObjectURL(url),1000); }
      setupHardwareMessage('Exact public original download requested. Use only approved independent verifier channels; no key, signing or new contact permission is supplied.');
    }
    $('setup-policy-session').addEventListener('input',setupHardwareClear);
    ['evidence','hardware','proxy'].forEach(name => $('setup-hardware-' + name).addEventListener('change',() => {
      setupHardwareEpoch++; setupHardwareOperation?.abort(); $('setup-hardware-complete-confirm').checked = false;
    }));
    window.addEventListener('pagehide',setupHardwareClear);
"""
