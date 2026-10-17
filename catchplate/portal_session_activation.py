"""Explicit browser controls for original-bound activation and recovery.

Locators and approval bindings stay page-local. Server original admission,
fresh authorization and durable one-use claims remain authoritative. No action
chain, SQL retry, profile fallback, token handling or persisted draft is added.
"""


SESSION_ACTIVATION_CSS = r"""
    .session-activation-fields { display: grid; grid-template-columns: minmax(0, 2fr) minmax(220px, 1fr); gap: 12px; }
    .session-activation-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-block: 12px; }
    .session-activation-observation { padding: 12px; border: 1px solid var(--border, #cbd5e1); border-radius: 8px; }
    #session-activation-route, #session-activation-status, #session-activation-approval, #session-activation-current { white-space: pre-wrap; overflow-wrap: anywhere; }
    @media (max-width: 620px) {
      .session-activation-fields { grid-template-columns: minmax(0, 1fr); }
      .session-activation-actions button { width: 100%; white-space: normal; }
    }
"""


SESSION_ACTIVATION_HTML = r"""
      <section id="session-activation-workspace" aria-labelledby="session-activation-heading">
        <h2 id="session-activation-heading" tabindex="-1">Activate or recover this browser session</h2>
        <p>Select one explicit action for a real retained finalization local ID. This panel uses the browser cookie, never the operator-token field. A locator is not proof of ownership, completion or permission.</p>
        <div class="session-activation-fields">
          <div><label for="session-activation-locator">Retained finalization local ID</label>
            <input id="session-activation-locator" maxlength="71" spellcheck="false" autocomplete="off" placeholder="sha256:…" aria-describedby="session-activation-boundary"></div>
          <div><label for="session-activation-action">One action</label>
            <select id="session-activation-action">
              <option value="activate">Activate pending session</option>
              <option value="recover">Recover retained token delivery</option>
              <option value="activation-complete">Reconcile activation completion</option>
              <option value="consume-complete">Reconcile consume completion</option>
              <option value="consume">Fresh consume after activation completion</option>
              <option value="release-proof">Prepare release intent and proof</option>
              <option value="release">First release · LIVE checkpoint 0</option>
              <option value="retained-release">Retained-outcome release · RECOVERY checkpoint 1</option>
            </select></div>
        </div>
        <div class="session-activation-actions">
          <button id="session-activation-copy-finalization" class="secondary" type="button">Use finalization ID from registration panel</button>
          <a href="#registration-handoff-workspace">Retained registration actions</a>
        </div>
        <p id="session-activation-description" class="hint"></p>
        <p id="session-activation-route" class="hint"></p>
        <div class="session-activation-actions">
          <button id="session-activation-submit" type="button">Fresh authorization + submit selected action</button>
          <button id="session-activation-discard" class="secondary" type="button">Discard local authorization prompt</button>
        </div>
        <p id="session-activation-status" role="status" aria-live="polite">No action submitted. Current session state is not established by this panel.</p>
        <div id="session-activation-approval-panel" hidden>
          <p id="session-activation-approval" class="hint" aria-live="polite"></p>
          <div class="session-activation-actions">
            <a href="#approval-workspace">Separate operator: review approval queue</a>
            <button id="session-activation-continue" type="button">After approval: fresh authorization + continue once</button>
          </div>
        </div>
        <div class="session-activation-observation">
          <h3>Current cookie confirmation · read only</h3>
          <p id="session-activation-current" role="status" aria-live="polite">Not checked against this retained target. Completion or proof preparation is not session activation.</p>
          <div class="session-activation-actions">
            <button id="session-activation-confirm" class="secondary" type="button">Check current browser cookie against selected target</button>
          </div>
        </div>
        <p id="session-activation-boundary" class="hint">No automatic next action, retry or profile fallback. A failed or lost action response leaves its outcome unknown. Changing selection cannot unlock an attempted action. Each permitted action needs fresh server authorization; a separately authorized recovery is not a retry of SQL. Intermediate completion/proof responses never set an active-session badge. Cookie delivery still needs a separate current-target check. All controls here are source-integrated, not runtime or production evidence.</p>
      </section>
"""


SESSION_ACTIVATION_SCRIPT = r"""
    const sessionActivationActions = Object.freeze(Object.fromEntries([
      {id: 'activate', label: 'Activate pending session', postPath: '/api/auth/session/activation', optionsPath: '/api/auth/session/activation/permission/options', description: 'One fresh pending-session activation workflow. Requires separate action and planning assertions; a lost result is not permission to repeat execution.'},
      {id: 'recover', label: 'Recover retained token delivery', postPath: '/api/auth/session/activation/recovery', optionsPath: '/api/auth/session/activation/recovery/options', description: 'Fresh authorization for an existing retained post-intent recovery target. Old-cookie possession is not current-session identity; no SQL is retried.'},
      {id: 'activation-complete', label: 'Reconcile activation completion', postPath: '/api/auth/session/activation/completion/recovery', optionsPath: '/api/auth/session/activation/completion/recovery/options', description: 'Completion-only reconciliation of the exact historical activation controls. No activation SQL retry, token delivery or session-success claim.'},
      {id: 'consume-complete', label: 'Reconcile consume completion', postPath: '/api/auth/session/activation/consume/completion/recovery', optionsPath: '/api/auth/session/activation/consume/completion/recovery/options', description: 'Completion-only reconciliation of historical consume controls. A signed acknowledgment is not token release or current-session success.'},
      {id: 'consume', label: 'Fresh consume after activation completion', postPath: '/api/auth/session/activation/completion/recovery/consume', optionsPath: '/api/auth/session/activation/completion/recovery/consume/options', description: 'A separately fresh consume purpose under independent execution authority. Uses the same durable consume slot; completion data never delivers a token or retries an unknown SQL attempt.'},
      {id: 'release-proof', label: 'Prepare release intent and proof', postPath: '/api/auth/session/activation/consume/completion/recovery/release-proof', optionsPath: '/api/auth/session/activation/consume/completion/recovery/release-proof/options', description: 'Preparation-only intent/proof authority for acknowledged consume records. This does not authorize LIVE or RECOVERY release, open a token or activate a session.'},
      {id: 'release', label: 'First release · LIVE checkpoint 0', postPath: '/api/auth/session/activation/consume/completion/recovery/release', optionsPath: '/api/auth/session/activation/consume/completion/recovery/release/options', description: 'Fresh release-purpose authorization with independently admitted LIVE authority. This action cannot retry or switch profiles after an unknown result.'},
      {id: 'retained-release', label: 'Retained-outcome release · RECOVERY checkpoint 1', postPath: '/api/auth/session/activation/consume/completion/recovery/retained-release', optionsPath: '/api/auth/session/activation/consume/completion/recovery/retained-release/options', description: 'Distinct fresh retained-release authorization with independent RECOVERY authority. Neither missing local data nor reconstructed outcome data proves private-store presence or absence.'},
    ].map(action => [action.id, Object.freeze(action)])));
    let sessionActivationEpoch = 0;
    let sessionActivationBusy = false;
    let sessionActivationContext = null;
    let sessionActivationPending = null;
    const sessionActivationAttempts = new Set();

    function openProtectedOIDCSessionWorkflow() {
      if (sessionActivationBusy || oidcSessionActivationBusy) return {uiHandled: true, blocked: true};
      const protectedMode = !oidcSessionStatusUnknown
        && state.authStatus?.sessionActivationMode === 'protected'
        && state.authStatus?.sessionState === 'pending_webauthn'
        && state.authStatus?.webauthnRequired === true;
      const message = protectedMode
        ? 'Protected session workflow selected, not readiness or activation. Use a real retained finalization ID below, or follow Retained registration actions to obtain it. Choose each authorization/action explicitly; no request or hardware prompt was started.'
        : 'Session activation mode is unavailable or not confirmed for this pending session. Refresh session status or ask the operator to complete protected configuration. No legacy fallback, request or hardware prompt was started.';
      sessionActivationMessage(message, !protectedMode);
      setStatus(message, protectedMode ? 'pending' : 'error');
      $('session-activation-workspace').scrollIntoView({block: 'start', behavior: 'auto'});
      $('session-activation-heading').focus();
      if (protectedMode) $('session-activation-locator').focus();
      // Navigation only: retain selection, attempt locks and page-local IDs.
      // In particular, do not infer/copy an ID or run the panel's next action.
      return {uiHandled: true, blocked: !protectedMode};
    }

    function sessionActivationDigest(value) {
      return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
    }

    function sessionActivationSelection() {
      const localDigest = $('session-activation-locator').value.trim();
      if (!sessionActivationDigest(localDigest)) throw new Error('Retained finalization locator required');
      return Object.freeze({localDigest});
    }

    function sessionActivationAuthScope() {
      const roles = values => Array.isArray(values) ? [...values].sort() : [];
      const credentials = (state.webauthnCredentials || []).map(item => [
        item.id, item.user_id, item.credential_id_sha256, item.active, item.revoked_at,
        item.revocation_source, item.authenticator_class, item.aaguid,
        item.attestation_root_sha256, item.attestation_trust_bundle_digest,
        item.attestation_trust_bundle_sequence, item.current_trust?.enrollment_trusted,
        item.current_trust?.currently_trusted, item.current_trust?.reason,
        item.current_trust?.effective_authenticator_class,
      ]).sort((left, right) => String(left[0]).localeCompare(String(right[0])));
      return JSON.stringify([Boolean(adminToken()), state.currentUserId, roles(state.currentUserRoles),
        state.policy_hash, state.policy_signing_key_id, state.activePolicy?.policy_hash,
        state.activePolicy?.policy_signing_key_id, state.authStatus?.authenticated,
        state.authStatus?.userId, state.authStatus?.authMethod, state.authStatus?.sessionState,
        state.authStatus?.webauthnRequired, state.authStatus?.sessionActivationMode,
        roles(state.authStatus?.roles), credentials]);
    }

    function sessionActivationMessage(message, error = false) {
      $('session-activation-status').textContent = message;
      $('session-activation-status').setAttribute('role', error ? 'alert' : 'status');
    }

    function sessionActivationInvalidate(reason = 'Selection or authorization context changed.') {
      sessionActivationEpoch += 1;
      sessionActivationPending = null;
      sessionActivationContext = sessionActivationAuthScope();
      if (!$('session-activation-workspace')) return;
      sessionActivationMessage(sessionActivationBusy
        ? 'Context changed during a request. Its outcome may be unknown; no automatic retry or stale result will be used.'
        : reason + ' Local authorization was discarded; recorded attempts remain locked on this page.');
      $('session-activation-current').textContent = 'Current cookie has not been confirmed against the present selection.';
      renderSessionActivation();
    }

    function renderSessionActivation() {
      if (!$('session-activation-workspace')) return;
      const context = sessionActivationAuthScope();
      if (sessionActivationContext !== null && context !== sessionActivationContext) {
        sessionActivationEpoch += 1;
        sessionActivationPending = null;
        sessionActivationMessage('Authentication, policy or credential trust changed. Fresh authorization is required; attempted actions remain locked.');
        $('session-activation-current').textContent = 'Earlier current-cookie observations are stale; check the selected target again.';
      }
      sessionActivationContext = context;
      const action = sessionActivationActions[$('session-activation-action').value];
      let selected = null;
      try { selected = sessionActivationSelection(); } catch (_) {}
      const blocked = sessionActivationBusy || oidcSessionActivationBusy;
      const key = selected && action ? selected.localDigest + ':' + action.id : null;
      $('session-activation-submit').disabled = blocked || !key || Boolean(sessionActivationPending)
        || sessionActivationAttempts.size >= 128 || sessionActivationAttempts.has(key);
      $('session-activation-confirm').disabled = blocked || !key;
      for (const name of ['locator', 'action', 'copy-finalization', 'discard']) $('session-activation-' + name).disabled = blocked;
      $('session-activation-description').textContent = action?.description || 'Select one fixed action.';
      $('session-activation-route').textContent = action ? 'POST ' + action.postPath : '';
      $('session-activation-approval-panel').hidden = !sessionActivationPending;
      $('session-activation-continue').disabled = blocked || !sessionActivationPending;
      $('session-activation-approval').textContent = sessionActivationPending
        ? 'Approval: ' + sessionActivationPending.approvalId
          + '\nA different authorized operator must approve this exact action. Continue makes new options and fresh assertions once; it does not reuse an assertion or retry SQL.' : '';
    }

    function sessionActivationGuard(epoch, action, selected, authScope) {
      return () => epoch === sessionActivationEpoch && action === sessionActivationActions[$('session-activation-action').value]
        && selected.localDigest === $('session-activation-locator').value.trim()
        && authScope === sessionActivationAuthScope();
    }

    async function sessionActivationSubmit(continuing = false) {
      if (sessionActivationBusy || oidcSessionActivationBusy) return;
      let selected, action, authorization = null, attempted = false;
      let stillCurrent = () => true;
      try {
        selected = sessionActivationSelection();
        action = sessionActivationActions[$('session-activation-action').value];
        if (!action || typeof continuing !== 'boolean') throw new Error('Fixed action required');
        const key = selected.localDigest + ':' + action.id;
        const authScope = sessionActivationAuthScope(), prior = sessionActivationPending;
        if (continuing) {
          if (!prior || prior.action !== action || prior.selected.localDigest !== selected.localDigest
              || prior.authScope !== authScope || !sessionActivationAttempts.has(key)) throw new Error('Continuation changed');
        } else if (prior || sessionActivationAttempts.has(key) || sessionActivationAttempts.size >= 128) {
          throw new Error('Action already attempted on this page');
        }
        if (!window.confirm(action.label + '\n' + selected.localDigest
            + '\nOne explicit action only. No automatic next action, retry or profile fallback.')) return;
        const epoch = sessionActivationEpoch;
        stillCurrent = sessionActivationGuard(epoch, action, selected, authScope);
        if (!stillCurrent()) return;
        // Consume the sole continuation association before another ceremony.
        // The original attempt key is never removed, even on cancellation.
        sessionActivationPending = null;
        sessionActivationBusy = true;
        oidcSessionActivationBusy = true;
        renderAuthStatus();
        sessionActivationMessage('Obtaining fresh action-bound authorization. The selected action has not been sent by this click.');
        authorization = await sessionActivationAuthorize(action, selected, stillCurrent,
          continuing ? prior.approvalId : null, continuing ? prior.binding : null);
        if (!stillCurrent()) return;
        if (continuing && !sessionActivationSameBinding(authorization.binding, prior.binding)) throw new Error('Fresh binding changed');
        sessionActivationAttempts.add(key);
        attempted = true;
        sessionActivationMessage(action.label + ': one explicit request in progress. Do not repeat it.');
        const response = await sessionActivationPost(action.postPath, authorization.body, stillCurrent);
        const outcome = await sessionActivationOutcome(action, response, selected, stillCurrent, authorization.binding);
        if (!stillCurrent()) return;
        if (outcome.kind === 'approval-required') {
          if (continuing) {
            sessionActivationMessage('The explicit approval continuation did not finish. This page remains locked; no further request is sent automatically.', true);
          } else {
            sessionActivationPending = Object.freeze({action, selected, authScope,
              binding: authorization.binding, approvalId: outcome.approvalId});
            sessionActivationMessage(outcome.detail);
          }
        } else {
          sessionActivationMessage(outcome.detail, outcome.kind === 'unknown');
          $('session-activation-current').textContent = outcome.kind === 'delivery-unconfirmed' && outcome.canConfirm
            ? 'Delivery was reported, but the current cookie is not yet confirmed against this target. Use the separate read-only check.'
            : 'This action does not establish a current active session. A separate read-only target check is available.';
        }
      } catch (_) {
        if (stillCurrent()) sessionActivationMessage(attempted
          ? 'The action response was lost, rejected or invalid. Its outcome is unknown. The page attempt remains locked; no retry or profile fallback occurred.'
          : 'Fresh authorization was cancelled, changed or unavailable. This click did not send the selected action. No saved assertion or automatic continuation remains.', true);
      } finally {
        // Drop references only; JavaScript does not guarantee memory erasure.
        authorization = null;
        if (sessionActivationBusy) {
          sessionActivationBusy = false;
          oidcSessionActivationBusy = false;
          renderAuthStatus();
        }
        renderSessionActivation();
      }
    }

    async function sessionActivationCheckCurrent() {
      if (sessionActivationBusy || oidcSessionActivationBusy) return;
      let stillCurrent = () => true;
      try {
        const selected = sessionActivationSelection();
        const action = sessionActivationActions[$('session-activation-action').value];
        if (!action) throw new Error('Fixed action required');
        stillCurrent = sessionActivationGuard(sessionActivationEpoch, action, selected, sessionActivationAuthScope());
        sessionActivationBusy = true;
        oidcSessionActivationBusy = true;
        renderAuthStatus();
        $('session-activation-current').textContent = 'Checking the current browser cookie against this exact retained target; no activation action is repeated.';
        const result = await sessionActivationConfirm(action, selected, stillCurrent);
        if (stillCurrent()) $('session-activation-current').textContent = result.detail;
      } catch (_) {
        if (stillCurrent()) $('session-activation-current').textContent = 'Current target session is unknown. No activation action was repeated and no earlier unknown outcome was changed.';
      } finally {
        sessionActivationBusy = false;
        oidcSessionActivationBusy = false;
        renderAuthStatus();
        renderSessionActivation();
      }
    }

    function initSessionActivation() {
      $('session-activation-locator').value = '';
      $('session-activation-locator').addEventListener('input', () => sessionActivationInvalidate('The retained target changed.'));
      $('session-activation-action').addEventListener('change', () => sessionActivationInvalidate('The selected action changed.'));
      $('session-activation-submit').addEventListener('click', () => sessionActivationSubmit(false));
      $('session-activation-continue').addEventListener('click', () => sessionActivationSubmit(true));
      $('session-activation-discard').addEventListener('click', () => sessionActivationInvalidate('Local authorization prompt discarded.'));
      $('session-activation-confirm').addEventListener('click', sessionActivationCheckCurrent);
      $('session-activation-copy-finalization').addEventListener('click', () => {
        if (sessionActivationBusy || oidcSessionActivationBusy) return;
        const digest = $('registration-handoff-finalization-locator').value.trim();
        if (!sessionActivationDigest(digest)) {
          sessionActivationMessage('Enter or obtain a real retained finalization local ID in the registration panel first. No ID was invented.', true);
          return;
        }
        $('session-activation-locator').value = digest;
        sessionActivationInvalidate('Copied only the registration panel locator; the server must still admit its originals and your fresh authority.');
      });
      window.addEventListener('pagehide', () => {
        sessionActivationEpoch += 1;
        sessionActivationPending = null;
        $('session-activation-locator').value = '';
      });
      renderSessionActivation();
    }
"""
