"""Scoped native completion UI; no browser authority or automatic issuer contact."""

SETUP_NATIVE_FINAL_HTML = r"""
            <hr>
            <details id="setup-final-controls">
              <summary>Complete this scoped native Setup</summary>
              <p class="hint">The requester reserves a final challenge. An independently pinned final authority verifies the exact hardware/proxy originals. A different attestation_reviewer uses a fresh hardware passkey; audit inclusion is required before settlement. This is enclave-hardware-and-proxy-only with trusted-host-local CA readback, not measured Linux-host evidence, general production acceptance or proxy-ready permission.</p>
              <label><input id="setup-final-confirm" type="checkbox">I reviewed this exact Setup, scope, original lifetime and one-attempt operation.</label>
              <button type="button" onclick="runUiAction('Reserve scoped final challenge', () => setupFinalEffect('prepare'))">Requester passkey + prepare once</button>
              <button type="button" class="secondary" onclick="runUiAction('Read retained final state', setupFinalLookup)">Read retained state; no issuer contact</button>
              <button id="setup-final-download" type="button" class="secondary" disabled onclick="setupFinalDownload()">Download exact final-authority request</button>
              <p class="hint">Send the public original only through your approved independent issuer channel. No key is uploaded or generated. A receipt is an authorization for one protected consumption, not proof that consumption happened.</p>
              <label>Independent final-authority receipt (canonical original, at most 16 KiB)</label>
              <input id="setup-final-receipt" type="file" accept="application/json,.json" autocomplete="off">
              <button type="button" onclick="runUiAction('Consume final authorization', () => setupFinalEffect('complete'))">Different reviewer passkey + consume once</button>
              <button type="button" onclick="runUiAction('Settle audited scoped completion', () => setupFinalEffect('settle'))">Same reviewer: settle once after audit inclusion</button>
              <button type="button" class="secondary" onclick="setupFinalClear()">Clear page-held originals</button>
              <pre id="setup-final-result">No scoped completion observed.</pre>
              <p id="setup-final-status" class="hint" role="status" aria-live="polite">Unknown submissions stay fenced. Read-only recovery never renews deadlines, clears markers or authorizes another effect.</p>
            </details>
"""

SETUP_NATIVE_FINAL_SCRIPT = r"""
    const setupFinalRequest = 'serverware.setupNativeFinalRequest/v1';
    let setupFinalHeld = null, setupFinalEpoch = 0, setupFinalBusy = false, setupFinalOperation = null;
    function setupFinalNeed(v) { if (!v) throw new Error('Scoped final Setup context differs or is unavailable. Read retained state; do not retry unknown effects.'); }
    function setupFinalMessage(v) { $('setup-final-status').textContent = v; }
    function setupFinalClear() {
      setupFinalEpoch++; setupFinalOperation?.abort(); setupFinalHeld = null;
      $('setup-final-receipt').value = ''; $('setup-final-confirm').checked = false; $('setup-final-download').disabled = true;
      $('setup-final-result').textContent = 'No page-held completion observation.';
      setupFinalMessage('Originals cleared; protected attempts, tab markers and original deadlines are unchanged.');
    }
    function setupFinalAuth(phase) {
      const a = state.authStatus;
      setupFinalNeed(!adminToken() && window.isSecureContext && window.top === window && a?.authenticated === true
        && a.authMethod === 'oidc-session' && a.sessionState === 'active' && a.webauthnRequired === false
        && workloadIssuanceText(a.userId,4096) && Array.isArray(a.roles));
      if (phase === 'prepare') setupFinalNeed(['credential_owner','policy_author'].every(r => a.roles.includes(r)));
      else if (phase !== 'lookup') setupFinalNeed(a.roles.includes('attestation_reviewer'));
      return a.userId;
    }
    function setupFinalBegin(phase) {
      setupFinalNeed(!setupFinalBusy);
      const actor = setupFinalAuth(phase), scope = sessionActivationAuthScope(), epoch = setupFinalEpoch;
      const session = $('setup-policy-session').value.trim(); setupFinalNeed(nativeSetupId(session));
      const c = new AbortController(), until = performance.now()+30000, expires = Date.now()+30000;
      const timer = setTimeout(() => c.abort(),30000);
      const op = {actor,scope,session,signal:c.signal,abort(){c.abort();},
        current(){setupFinalNeed(!c.signal.aborted && epoch === setupFinalEpoch && performance.now()<until && Date.now()<expires
          && setupFinalAuth(phase) === actor && sessionActivationAuthScope() === scope && $('setup-policy-session').value.trim() === session);},
        close(){clearTimeout(timer);c.abort();setupFinalBusy=false;if(setupFinalOperation===op)setupFinalOperation=null;}};
      try {op.current();setupFinalBusy=true;setupFinalOperation=op;return op;} catch(e){clearTimeout(timer);c.abort();throw e;}
    }
    async function setupFinalPost(phase,body,op,contact=null) {
      setupFinalNeed(['options','prepare','complete','settle','lookup'].includes(phase));
      let text = oauthConsentCanonical(body); setupFinalNeed(new TextEncoder().encode(text).byteLength<=32768);
      try {
        op.current(); const response = await fetch('/api/csrf',{credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:op.signal});
        const csrf = await setupPolicyRead(response,op,4096);
        setupFinalNeed(response.ok && oauthConsentClosed(csrf,['ok','token','cookie','header']) && csrf.ok === true
          && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token' && workloadIssuanceText(csrf.token,1024));
        op.current();if(contact)contact();
        const reply = await fetch('/api/setup/native-final/'+phase,{method:'POST',credentials:'same-origin',mode:'same-origin',redirect:'error',
          cache:'no-store',signal:op.signal,headers:{'Content-Type':'application/json',[csrf.header]:csrf.token},body:text});
        return {status:reply.status,value:await setupPolicyRead(reply,op,4*1024*1024)};
      } finally {text=null;}
    }
    function setupFinalReply(reply,status,fields) {
      const v=reply.value;
      setupFinalNeed(reply.status===status && oauthConsentClosed(v,['apiVersion','status','okForAction','automaticRetryAllowed','measuredHost',
        'proxyReady','resultScope','hostAssociationTrust',...fields]) && v.apiVersion==='serverware.setupNativeFinalResponse/v1'
        && v.okForAction===false && v.automaticRetryAllowed===false && v.measuredHost===false && v.proxyReady===false
        && v.resultScope==='enclave-hardware-and-proxy-only' && v.hostAssociationTrust==='trusted-host-local');return v;
    }
    async function setupFinalRetain(v,op) {
      const row=v.final;
      setupFinalNeed(typeof v.completionAuditIncluded==='boolean');
      if(row===null){setupFinalNeed(v.bundle===null && v.scopedNativeSetupComplete===false && v.completionAuditIncluded===false);setupFinalHeld=null;return;}
      setupFinalNeed(oauthConsentClosed(row,['revision','phase','owner_id','reviewer_id','challenge_sha256','prepare_request_digest','complete_request_digest','settle_request_digest'])
        && oauthConsentDigest(row.challenge_sha256) && oauthConsentDigest(row.prepare_request_digest));
      const rev=oauthConsentInteger(row.revision);
      setupFinalNeed(rev>=0n && rev<=2n && row.phase===['final_outcome_unknown','native_completion_pending_audit','native_scoped_complete'][Number(rev)]
        && (rev===0n ? row.reviewer_id===null && row.complete_request_digest===null : workloadIssuanceText(row.reviewer_id,1024)
          && row.reviewer_id!==row.owner_id && oauthConsentDigest(row.complete_request_digest))
        && (rev<2n ? row.settle_request_digest===null : oauthConsentDigest(row.settle_request_digest)));
      const b=v.bundle;setupFinalNeed(oauthConsentClosed(b,['challengeOriginal','issuerRequestOriginal','receiptOriginal']));
      const c=setupNativeOriginal(b.challengeOriginal,8192), request=setupNativeOriginal(b.issuerRequestOriginal,4*1024*1024);
      setupFinalNeed(oauthConsentClosed(c,['apiVersion','challengeId','sessionId','ownerId','hardwareSha256','policyHash','configurationSha256','nonce',
        'issuedAtEpochNs','expiresAtEpochNs','resultScope','hostAssociationTrust']) && c.apiVersion==='serverware.setupNativeFinalChallenge/v1'
        && nativeSetupId(c.challengeId) && c.sessionId===op.session && c.ownerId===row.owner_id && c.resultScope==='enclave-hardware-and-proxy-only'
        && c.hostAssociationTrust==='trusted-host-local' && workloadIssuanceBase64(c.nonce,32).byteLength===32
        && oauthConsentDigest(c.policyHash) && oauthConsentDigest(c.configurationSha256)
        && await workloadIssuanceHash(new TextEncoder().encode(b.challengeOriginal))===row.challenge_sha256
        && oauthConsentClosed(request,['actor_id','control_plane_configuration_digest','credential_policy','maximum_final_nanos','hardware_original','challenge_original'])
        && request.challenge_original===b.challengeOriginal && request.actor_id===row.owner_id
        && request.control_plane_configuration_digest===c.configurationSha256
        && await workloadIssuanceHash(new TextEncoder().encode(request.hardware_original))===c.hardwareSha256);
      const issued=oauthConsentInteger(c.issuedAtEpochNs),expires=oauthConsentInteger(c.expiresAtEpochNs);
      setupFinalNeed(0n<issued && issued<expires && expires-issued<=300000000000n && expires<=9223372036854775807n);
      if(rev>0n) setupFinalReceipt(b.receiptOriginal,c,row); else setupFinalNeed(b.receiptOriginal===null);
      setupFinalNeed(v.scopedNativeSetupComplete === (rev===2n && v.setupPhase==='native_scoped_complete'));
      op.current();setupFinalHeld={...b,row,c,completionAuditIncluded:v.completionAuditIncluded,actor:op.actor,scope:op.scope,session:op.session,expires,
        until:performance.now()+Number((expires-BigInt(Date.now())*1000000n)/1000000n)};
    }
    function setupFinalReceipt(text,c,row) {
      const v=setupNativeOriginal(text,16384),r=v.payload;
      setupFinalNeed(oauthConsentClosed(v,['payload','signature']) && oauthConsentClosed(r,['apiVersion','purpose','resultScope','hostAssociationTrust',
        'challengeSha256','hardwareSha256','sessionId','nonceSha256','policyHash','configurationSha256','authorityKeyId','authorityProvider',
        'issuedAtEpochNs','expiresAtEpochNs','measuredHost','proxyReady']) && r.apiVersion==='serverware.setupNativeFinalReceipt/v1'
        && r.purpose==='native-setup-final-authorization' && r.resultScope===c.resultScope && r.hostAssociationTrust===c.hostAssociationTrust
        && r.challengeSha256===row.challenge_sha256 && r.hardwareSha256===c.hardwareSha256 && r.sessionId===c.sessionId
        && r.policyHash===c.policyHash && r.configurationSha256===c.configurationSha256
        && r.measuredHost===false && r.proxyReady===false && oauthConsentDigest(r.authorityKeyId) && oauthConsentDigest(r.nonceSha256)
        && workloadIssuanceText(r.authorityProvider,128) && /^ed25519:[A-Za-z0-9_-]{86}$/.test(v.signature)
        && oauthConsentInteger(c.issuedAtEpochNs)<=oauthConsentInteger(r.issuedAtEpochNs)
        && oauthConsentInteger(r.issuedAtEpochNs)<oauthConsentInteger(r.expiresAtEpochNs)
        && oauthConsentInteger(r.expiresAtEpochNs)===oauthConsentInteger(c.expiresAtEpochNs));return v;
    }
    function setupFinalLive(held,op,phase) {
      op.current();setupFinalNeed(held && setupFinalHeld===held && held.actor===op.actor && held.scope===op.scope && held.session===op.session
        && performance.now()<held.until && BigInt(Date.now())*1000000n<held.expires
        && held.row.owner_id!==op.actor && (phase==='complete' ? held.row.phase==='final_outcome_unknown'
          : held.row.phase==='native_completion_pending_audit' && held.row.reviewer_id===op.actor && held.completionAuditIncluded===true));
    }
    function setupFinalShow(v) {
      $('setup-final-result').textContent=oauthConsentCanonical({final:v.final,setupPhase:v.setupPhase,completionAuditIncluded:v.completionAuditIncluded,scopedNativeSetupComplete:v.scopedNativeSetupComplete,
        resultScope:v.resultScope,hostAssociationTrust:v.hostAssociationTrust,measuredHost:false,proxyReady:false});
      $('setup-final-download').disabled=!setupFinalHeld;
      setupFinalMessage(v.scopedNativeSetupComplete ? 'Scoped native Setup complete. This is not general production acceptance, measured-host proof or proxy-ready permission. Existing credential/policy authorization still governs every request.'
        : 'Original state retained. Only an explicit next phase is available; no automatic retry, issuer contact or renewed lifetime.');
    }
    async function setupFinalLookup() {
      const op=setupFinalBegin('lookup');setupFinalHeld=null;$('setup-final-download').disabled=true;
      try{await setupEnrollmentCookie(op);const v=setupFinalReply(await setupFinalPost('lookup',{apiVersion:setupFinalRequest,sessionId:op.session},op),200,
        ['final','bundle','setupPhase','scopedNativeSetupComplete','completionAuditIncluded']);setupFinalNeed(v.status==='observation');
        await setupFinalRetain(v,op);setupFinalShow(v);}finally{op.close();}
    }
    function setupFinalMark(op,phase,digest) {
      op.current();const key='serverware.setup-native-final:'+op.actor+':'+op.session+':'+phase;
      setupFinalNeed(oauthConsentDigest(digest) && sessionStorage.getItem(key)===null);sessionStorage.setItem(key,digest);
      setupFinalNeed(sessionStorage.getItem(key)===digest);
    }
    async function setupFinalEffect(phase) {
      setupFinalNeed(['prepare','complete','settle'].includes(phase));
      const op=setupFinalBegin(phase),held=setupFinalHeld;let sent=false,file=null,receipt=null;
      try {
        setupFinalNeed($('setup-final-confirm').checked);await setupEnrollmentCookie(op);
        if(phase!=='prepare')setupFinalLive(held,op,phase);
        if(phase==='complete'){
          const input=$('setup-final-receipt');setupFinalNeed(input.files?.length===1);file=input.files[0];setupFinalNeed(file.size>=2 && file.size<=16384);
          const bytes=new Uint8Array(await file.arrayBuffer());
          try{op.current();setupFinalNeed(input.files?.[0]===file && bytes.length===file.size);receipt=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
            setupFinalReceipt(receipt,held.c,held.row);}finally{bytes.fill(0);}
        }
        const body={apiVersion:setupFinalRequest,sessionId:op.session,...(phase==='complete'?{receiptOriginal:receipt}:{})};
        let digest,assertion;
        if(phase!=='settle'){
          const v=setupFinalReply(await setupFinalPost('options',{...body,phase},op),200,['options']);
          setupFinalNeed(v.status==='fresh-assertion-required');const options=v.options,s=options?.serverware,k=options?.publicKey;
          setupFinalNeed(oauthConsentClosed(options,['publicKey','serverware']) && oauthConsentClosed(s,['schema','operation','operationId','challengeId','credentialRecordId','payloadDigest'])
            && s.schema==='serverware.setupNativeFinalOptions/v1' && s.operation==='setup.native-final.'+phase && oauthConsentDigest(s.operationId)
            && oauthConsentDigest(s.challengeId) && oauthConsentDigest(s.payloadDigest) && nativeSetupId(s.credentialRecordId)
            && oauthConsentClosed(k,['challenge','rpId','allowCredentials','timeout','userVerification']) && k.rpId===location.hostname && k.userVerification==='required'
            && oauthConsentInteger(k.timeout)===30000n && workloadIssuanceBase64(k.challenge,32).byteLength===32 && Array.isArray(k.allowCredentials)
            && k.allowCredentials.length===1 && oauthConsentClosed(k.allowCredentials[0],['type','id']) && k.allowCredentials[0].type==='public-key');
          workloadIssuanceBase64(k.allowCredentials[0].id,3072);digest=s.payloadDigest;
          const result=await navigator.credentials.get({signal:op.signal,publicKey:prepareRequestOptions({publicKey:{...k,timeout:30000}})});
          op.current();setupFinalNeed(result?.type==='public-key' && result.rawId instanceof ArrayBuffer && result.rawId.byteLength<=3072
            && result.id===k.allowCredentials[0].id && bytesToB64(result.rawId)===result.id);assertion=credentialToJson(result);
        }else digest=held.row.challenge_sha256;
        const v=setupFinalReply(await setupFinalPost(phase,{...body,...(assertion?{assertion}:{})},op,()=>{
          setupFinalNeed($('setup-final-confirm').checked);if(phase!=='prepare')setupFinalLive(held,op,phase);
          if(file)setupFinalNeed($('setup-final-receipt').files?.[0]===file);setupFinalMark(op,phase,digest);sent=true;
        }),phase==='prepare'?201:200,['final','bundle','setupPhase','scopedNativeSetupComplete','completionAuditIncluded']);
        setupFinalNeed(v.status===({prepare:'independent-final-authorization-required',complete:'native-completion-pending-audit',settle:'scoped-native-setup-complete'})[phase]);
        await setupFinalRetain(v,op);setupFinalShow(v);
      }catch(e){setupFinalMessage(sent?'Submission outcome unknown. Read retained state only; do not repeat this phase.'
        :'No effect request was sent. Required original state, role, audit inclusion or lifetime may be unavailable.');throw e;}
      finally{receipt=null;$('setup-final-confirm').checked=false;op.close();}
    }
    function setupFinalDownload() {
      const held=setupFinalHeld;setupFinalNeed(held && held.actor===state.authStatus?.userId && held.scope===sessionActivationAuthScope()
        && $('setup-policy-session').value.trim()===held.session);
      const blob=new Blob([held.issuerRequestOriginal],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');
      try{link.href=url;link.download='native-setup-final-request.json';link.click();}finally{URL.revokeObjectURL(url);}
    }
    $('setup-policy-session').addEventListener('input',setupFinalClear);
    window.addEventListener('pagehide',setupFinalClear);
"""
