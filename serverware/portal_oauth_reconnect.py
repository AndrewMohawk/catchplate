"""Same-account family replacement UI; no assertion persistence or retries."""
OAUTH_RECONNECT_HTML = r"""
          <section id="oauth-reconnect-controls" class="stack">
            <h3>Controlled same-account reconnect</h3>
            <p class="hint">Requires a separately signed active-family replacement grant and the explicitly provisioned native reconnect origin. Every affected holder must drain. Other family lineages remain fenced; this does not revoke provider tokens or succeed a retired family.</p>
            <button id="oauth-reconnect-inventory" type="button" class="secondary">Review my cold-admitted grants</button>
            <label>Authorization / exchange ID <input id="oauth-reconnect-id" maxlength="36" autocomplete="off"></label>
            <button id="oauth-reconnect-inspect" type="button" class="secondary">Inspect retained outcome only</button>
            <pre id="oauth-reconnect-review">No reviewed replacement authorization.</pre>
            <label><input id="oauth-reconnect-confirm" type="checkbox">I reviewed the same account, requested scopes, every affected lineage and original expiries.</label>
            <button id="oauth-reconnect-authorize" type="button">Fresh passkey, drain and fence once; continue at native origin</button>
            <label>Activation approval ID <input id="oauth-reconnect-approval" maxlength="36" autocomplete="off"></label>
            <button id="oauth-reconnect-request" type="button">Requester passkey: request candidate approval once</button>
            <button id="oauth-reconnect-decide" type="button">Different owner passkey: approve candidate once</button>
            <button id="oauth-reconnect-activate" type="button">Requester passkey: activate target successor once</button>
            <p id="oauth-reconnect-status" role="status" aria-live="polite">Keep the nonsecret authorization and approval IDs. Missing acknowledgement is unknown, not permission to retry or reopen.</p>
          </section>
"""

OAUTH_RECONNECT_SCRIPT = r"""
    const reconnectProfile = 'serverware.oauthReconnectApprovalOptions/v1';
    let reconnectBusy = false, reconnectHeld = null;
    const reconnectSpent = new Set();
    function reconnectMessage(text) { $('oauth-reconnect-status').textContent = text; }
    function reconnectId() { const id = $('oauth-reconnect-id').value.trim(); oauthConsentNeed(nativeSetupId(id)); return id; }
    async function reconnectFetch(path, body, operation, sent = null) {
      oauthConsentNeed(/^\/api\/oauth\/reconnect\/(?:inventory|authorize(?:\/options)?|activation(?:\/options)?|[0-9a-f-]{36})$/.test(path));
      let original = null; const headers = {};
      if (body !== null) {
        const csrf = await oauthConsentRequest('/api/csrf', null, operation);
        oauthConsentNeed(csrf.status === 200 && csrf.value.ok === true && csrf.value.header === 'X-Serverware-CSRF-Token');
        headers[csrf.value.header] = csrf.value.token; headers['Content-Type'] = 'application/json';
        original = oauthConsentCanonical(body); oauthConsentNeed(new TextEncoder().encode(original).length <= 196608);
      }
      operation.current(); if (sent) sent();
      const response = await fetch(path, {method: body === null ? 'GET' : 'POST', headers, body: original,
        credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: operation.signal});
      const parsed = await oauthConsentRead(response, 8388608, operation);
      oauthConsentNeed(response.status === 200); return parsed.value;
    }
    async function reconnectRead(inventory = false, target = null) {
      oauthConsentNeed(!reconnectBusy); let operation = null;
      try {
        const selection = target === null ? null : oauthCredentialRecoverySelection(target, reconnectProfile);
        oauthConsentNeed(selection === null || inventory);
        const identifier = inventory ? null : reconnectId();
        reconnectHeld = null; $('oauth-reconnect-confirm').checked = false;
        if (inventory) $('oauth-reconnect-id').value = '';
        const field = $('oauth-reconnect-id').value;
        reconnectBusy = true; operation = oauthConsentBegin();
        const originalCurrent = operation.current;
        operation = {...operation, current() {
          originalCurrent(); oauthConsentNeed($('oauth-reconnect-id').value === field && (selection === null
            || oauthCredentialRecoverySelection(target, reconnectProfile).original === selection.original));
        }};
        operation.current(); await oauthConsentCookie(operation);
        const value = await reconnectFetch('/api/oauth/reconnect/' + (inventory ? 'inventory' : identifier), inventory ? {} : null, operation);
        operation.current();
        oauthConsentNeed(value.apiVersion === 'serverware.oauthReconnectObservation/v1' && value.okForAction === false);
        $('oauth-reconnect-review').textContent = oauthConsentCanonical(value); $('oauth-reconnect-confirm').checked = false;
        reconnectHeld = null;
        if (inventory) {
          oauthConsentNeed(Array.isArray(value.authorizations) && value.authorizations.length <= 16);
          const matches = selection ? value.authorizations.filter(item => item.credentialId === target && item.providerId === selection.providerId) : value.authorizations;
          if (matches.length === 1) $('oauth-reconnect-id').value = matches[0].authorizationId;
          reconnectMessage(matches.length === 1 ? 'One matching cold-admitted grant selected. Inspect its retained operation before a separate action.'
            : matches.length === 0 ? 'No matching cold-admitted grant. Nothing was selected or authorized.'
              : 'Multiple matching grants. Review and explicitly choose the exact authorization ID before inspection.');
        } else {
          oauthConsentNeed(value.authorization?.authorizationId === reconnectId() && value.continuationAllowed === false);
          reconnectHeld = value;
          reconnectMessage('Read-only status: ' + value.status + '. Inspection does not permit replay or native continuation.');
        }
        if (selection) { $('oauth-reconnect-controls').scrollIntoView({block: 'nearest'}); $('oauth-reconnect-id').focus(); }
      } catch (_) { reconnectMessage('Inspection unavailable or refused. No mutation or fallback was attempted.'); }
      finally { reconnectBusy = false; operation?.close(); }
    }
    async function reconnectAction(kind) {
      oauthConsentNeed(!reconnectBusy && $('oauth-reconnect-confirm').checked && reconnectHeld !== null);
      const identifier = reconnectId(), approvalId = $('oauth-reconnect-approval').value.trim() || null;
      oauthConsentNeed(reconnectHeld.authorization.authorizationId === identifier);
      const names = {request: 'oauth.reconnect.activation-request', decide: 'oauth.reconnect.activation-decide', activate: 'oauth.reconnect.activate'};
      const key = identifier + ':' + kind + ':' + (approvalId || '');
      oauthConsentNeed(!reconnectSpent.has(key)); let operation = null, assertion = null;
      try {
        reconnectBusy = true; operation = oauthConsentBegin(); await oauthConsentCookie(operation);
        const authorization = reconnectHeld.authorization;
        oauthConsentNeed(oauthConsentInteger(authorization.expiresAtEpochNs) > BigInt(Date.now()) * 1000000n);
        if (kind === 'authorize') {
          oauthConsentNeed(authorization.requesterId === operation.actor && reconnectHeld.status === 'no-local-association-outcome-unknown');
        } else {
          oauthConsentNeed(Object.hasOwn(names, kind) && reconnectHeld.status === 'staged' && reconnectHeld.review !== null
            && (kind === 'decide' ? authorization.requesterId !== operation.actor : authorization.requesterId === operation.actor)
            && (kind === 'request' ? approvalId === null : nativeSetupId(approvalId)));
        }
        oauthConsentNeed(window.confirm(kind === 'authorize'
          ? 'Permanently drain all listed current holders and fence this complete local family? A failure can leave it fenced; no automatic restart is authorized.'
          : 'Perform ' + kind + ' for this exact reviewed same-account candidate? Other lineages stay fenced; no provider cleanup is implied.'));
        const prefix = '/api/oauth/reconnect/' + (kind === 'authorize' ? 'authorize' : 'activation');
        const body = kind === 'authorize' ? {authorizationId: identifier} : {authorizationId: identifier, operation: names[kind], approvalId};
        const options = await reconnectFetch(prefix + '/options', body, operation);
        oauthConsentNeed(options.serverware?.schema === reconnectProfile
          && options.serverware.operation === (kind === 'authorize' ? 'oauth.reconnect.authorize' : names[kind]));
        assertion = await nativeSetupPasskey(options, operation);
        const value = await reconnectFetch(prefix, {...body, mfa: {oauthReconnectProfile: reconnectProfile, assertion}}, operation,
          () => {reconnectSpent.add(key); reconnectMessage('One irreversible handoff started. Lost response remains unknown.');});
        assertion = null;
        if (kind === 'authorize') {
          oauthConsentNeed(oauthConsentClosed(value, ['apiVersion', 'callbackOrigin', 'portalOrigin', 'intent'])
            && value.apiVersion === 'serverware.nativeOAuthReconnectIntentResponse/v1' && value.portalOrigin === location.origin
            && value.intent?.schema === 'serverware.nativeOAuthReconnectIntent/v1' && value.intent.requesterId === operation.actor
            && value.intent.providerId === authorization.providerId);
          const origin = nativeOAuthOrigin(value.callbackOrigin);
          const provider = (state.oauthProviders || []).find(item => item.id === authorization.providerId);
          oauthConsentNeed(provider?.consentProfile === reconnectProfile && provider.redirectUri === origin + '/oauth/callback/' + provider.id);
          await oauthConsentCookie(operation); operation.current(); reconnectHeld = null;
          location.assign(origin + '/oauth/begin#original=' + nativeOAuthEncode(oauthConsentCanonical(value.intent)));
        } else {
          oauthConsentNeed(value.ok === true && value.operation === names[kind] && value.idempotentReplay === false);
          if (value.approval?.id) $('oauth-reconnect-approval').value = value.approval.id;
          reconnectHeld = null; $('oauth-reconnect-confirm').checked = false;
          reconnectMessage('Definite protected result observed. Inspect again before a separate next action.');
        }
      } catch (_) { reconnectMessage('No definite result. Do not resubmit, drain again or reconstruct a native handoff. Inspect the retained ID; all unresolved fences remain in force.'); }
      finally { assertion = null; reconnectBusy = false; operation?.close(); }
    }
    $('oauth-reconnect-inventory').addEventListener('click', () => void reconnectRead(true));
    $('oauth-reconnect-inspect').addEventListener('click', () => void reconnectRead());
    for (const kind of ['authorize', 'request', 'decide', 'activate']) {
      $('oauth-reconnect-' + kind).addEventListener('click', () => void reconnectAction(kind));
    }
"""
