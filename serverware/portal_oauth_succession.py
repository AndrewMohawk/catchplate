"""Retired-scope ceremony UI. No assertion persistence or effect replay."""
OAUTH_SUCCESSION_HTML = r"""
          <section id="oauth-succession-controls" class="stack">
            <h3>Retired-scope succession</h3>
            <p class="hint">A separately signed family or provider-wide successor grant is required. Old fences and consumed attempts remain immutable. All affected active holders must drain; only the named target receives a new generation. Unknown provider contact remains blocking.</p>
            <button id="oauth-succession-inventory" type="button" class="secondary">Review my cold-admitted successor grants</button>
            <label>Authorization ID <input id="oauth-succession-id" maxlength="36" autocomplete="off"></label>
            <button id="oauth-succession-inspect" type="button" class="secondary">Inspect retained state only</button>
            <pre id="oauth-succession-review">No reviewed successor.</pre>
            <label><input id="oauth-succession-confirm" type="checkbox">I reviewed the exact scope, predecessor fences, complete material and lineage lists, signed roots, target application and original expiry windows.</label>
            <button id="oauth-succession-authorize" type="button">Requester hardware: authorize and capture all 28 parts once</button>
            <label>Purpose-specific approval ID <input id="oauth-succession-approval" maxlength="36" autocomplete="off"></label>
            <button id="oauth-succession-decide" type="button">Different owner hardware: approve exact scope once</button>
            <button id="oauth-succession-fence" type="button">Requester: drain, fence once and enter native succession</button>
            <button id="oauth-succession-request" type="button">Requester hardware: request fresh candidate approval</button>
            <button id="oauth-succession-approve" type="button">Different owner hardware: approve fresh candidate</button>
            <button id="oauth-succession-activate" type="button">Requester hardware: activate only the target successor</button>
            <p id="oauth-succession-status" role="status" aria-live="polite">Keep nonsecret authorization/approval IDs. A lost acknowledgement is unknown: do not repeat acquisition, drains, contact or activation. Inspection is never continuation permission.</p>
          </section>
"""

OAUTH_SUCCESSION_SCRIPT = r"""
    const successionProfile = 'serverware.oauthRetiredScopeSuccessionOptions/v1';
    let successionBusy = false, successionHeld = null;
    const successionSpent = new Set();
    const successionNames = {authorize: 'oauth.succession.authorize', decide: 'oauth.succession.decide',
      request: 'oauth.succession.activation-request', approve: 'oauth.succession.activation-decide', activate: 'oauth.succession.activate'};
    function successionMessage(text) { $('oauth-succession-status').textContent = text; }
    function successionId() { const id = $('oauth-succession-id').value.trim(); oauthConsentNeed(nativeSetupId(id)); return id; }
    function successionEncode(original) {
      const bytes = new TextEncoder().encode(original); oauthConsentNeed(bytes.length <= 8388608);
      let text = ''; for (let n = 0; n < bytes.length; n += 8192) text += String.fromCharCode(...bytes.subarray(n, n + 8192));
      return btoa(text).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
    async function successionFetch(path, body, operation, sent = null) {
      oauthConsentNeed(/^\/api\/oauth\/succession\/(?:inventory|ceremony(?:\/options)?|fence|[0-9a-f-]{36})$/.test(path));
      const headers = {}; let original = null;
      if (body !== null) {
        const csrf = await oauthConsentRequest('/api/csrf', null, operation);
        oauthConsentNeed(csrf.status === 200 && csrf.value.ok === true && csrf.value.header === 'X-Serverware-CSRF-Token');
        headers[csrf.value.header] = csrf.value.token; headers['Content-Type'] = 'application/json';
        original = oauthConsentCanonical(body); oauthConsentNeed(new TextEncoder().encode(original).length <= 3145728);
      }
      operation.current(); if (sent) sent();
      const response = await fetch(path, {method: body === null ? 'GET' : 'POST', headers, body: original,
        credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: operation.signal});
      const result = await oauthConsentRead(response, 8388608, operation);
      oauthConsentNeed(response.status === 200); return result.value;
    }
    async function successionRead(inventory = false) {
      oauthConsentNeed(!successionBusy); let operation = null;
      try {
        successionBusy = true; operation = oauthConsentBegin(); await oauthConsentCookie(operation);
        const value = await successionFetch('/api/oauth/succession/' + (inventory ? 'inventory' : successionId()), inventory ? {} : null, operation);
        oauthConsentNeed(value.apiVersion === 'serverware.oauthRetiredScopeSuccessionObservation/v1' && value.okForAction === false);
        $('oauth-succession-review').textContent = oauthConsentCanonical(value); $('oauth-succession-confirm').checked = false;
        successionHeld = null;
        if (inventory) {
          oauthConsentNeed(Array.isArray(value.authorizations) && value.authorizations.length <= 16);
          if (value.authorizations.length === 1) $('oauth-succession-id').value = value.authorizations[0].authorizationId;
        } else {
          oauthConsentNeed(value.authorization?.authorizationId === successionId() && value.continuationAllowed === false);
          successionHeld = value;
        }
        successionMessage('Read-only observation. Review it before a separate action; it never recreates a missing acknowledgement.');
      } catch (_) { successionMessage('Read unavailable or refused. No mutation or fallback was attempted.'); }
      finally { successionBusy = false; operation?.close(); }
    }
    async function successionAction(kind) {
      oauthConsentNeed(!successionBusy && successionHeld !== null && $('oauth-succession-confirm').checked);
      const id = successionId(), grant = successionHeld.authorization;
      const approvalId = ['authorize', 'request'].includes(kind) ? null : $('oauth-succession-approval').value.trim() || null;
      const key = id + ':' + kind + ':' + (approvalId || '');
      oauthConsentNeed(grant.authorizationId === id && !successionSpent.has(key));
      let operation = null, assertion = null;
      try {
        successionBusy = true; operation = oauthConsentBegin(); await oauthConsentCookie(operation);
        const provider = (state.oauthProviders || []).find(item => item.id === grant.providerId);
        oauthConsentNeed(provider?.consentProfile === successionProfile);
        const approver = ['decide', 'approve'].includes(kind);
        oauthConsentNeed(approver ? operation.actor !== grant.requesterId : operation.actor === grant.requesterId);
        const bound = ['authorize', 'decide', 'fence'].includes(kind) ? grant.admissionExpiresAtEpochNs : grant.pendingExpiresAtEpochNs;
        oauthConsentNeed(oauthConsentInteger(bound) > BigInt(Date.now()) * 1000000n);
        const status = successionHeld.status;
        if (kind === 'authorize') oauthConsentNeed(status === 'missing-association-outcome-unknown');
        else if (kind === 'decide') oauthConsentNeed(status === 'requested' && successionHeld.snapshotParts.length === 28 && nativeSetupId(approvalId));
        else if (kind === 'fence') oauthConsentNeed(status === 'approved');
        else oauthConsentNeed(Object.hasOwn(successionNames, kind) && status === 'staged' && successionHeld.review !== null
          && (kind === 'request' || nativeSetupId(approvalId)));
        oauthConsentNeed(window.confirm('Perform ' + kind + ' exactly once for the reviewed signed scope? Old fences remain immutable. A failed or lost response is not permission to repeat any effect.'));
        let value;
        const spent = () => { successionSpent.add(key); successionMessage('One irreversible handoff started. Do not resubmit if the acknowledgement is lost.'); };
        if (kind === 'fence') {
          value = await successionFetch('/api/oauth/succession/fence', {authorizationId: id}, operation, spent);
          oauthConsentNeed(oauthConsentClosed(value, ['apiVersion', 'callbackOrigin', 'portalOrigin', 'intent'])
            && value.apiVersion === 'serverware.nativeOAuthSuccessionIntentResponse/v1' && value.portalOrigin === location.origin
            && value.intent?.schema === 'serverware.nativeOAuthSuccessionIntent/v1' && value.intent.requesterId === operation.actor
            && value.intent.providerId === grant.providerId);
          const origin = nativeOAuthOrigin(value.callbackOrigin);
          oauthConsentNeed(provider.redirectUri === origin + '/oauth/callback/' + provider.id);
          const fragment = successionEncode(oauthConsentCanonical(value.intent));
          await oauthConsentCookie(operation); operation.current(); successionHeld = null;
          location.assign(origin + '/oauth/begin#original=' + fragment);
          return;
        }
        const body = {authorizationId: id, operation: successionNames[kind], approvalId};
        const options = await successionFetch('/api/oauth/succession/ceremony/options', body, operation);
        oauthConsentNeed(options.serverware?.schema === successionProfile && options.serverware.operation === body.operation);
        assertion = await nativeSetupPasskey(options, operation);
        value = await successionFetch('/api/oauth/succession/ceremony',
          {...body, mfa: {oauthRetiredScopeSuccessionProfile: successionProfile, assertion}}, operation, spent);
        assertion = null;
        oauthConsentNeed(value.apiVersion === 'serverware.oauthRetiredScopeSuccessionResult/v1' && value.ok === true && value.operation === body.operation);
        if (value.approval?.id) $('oauth-succession-approval').value = value.approval.id;
        successionHeld = null; $('oauth-succession-confirm').checked = false;
        successionMessage('Definite protected result observed. Inspect before the next separate ceremony; do not repeat this one.');
      } catch (_) { successionMessage('No definite result. Preserve the IDs and inspect only. Do not retry, reconstruct a native handoff, reset history or clear a fence.'); }
      finally { assertion = null; successionBusy = false; operation?.close(); }
    }
    $('oauth-succession-inventory').addEventListener('click', () => void successionRead(true));
    $('oauth-succession-inspect').addEventListener('click', () => void successionRead());
    for (const kind of ['authorize', 'decide', 'fence', 'request', 'approve', 'activate']) {
      $('oauth-succession-' + kind).addEventListener('click', () => void successionAction(kind));
    }
"""
