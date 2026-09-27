"""Explicit portal actions for retained registration evidence and recovery.

Only public locators, negotiation bindings and bounded server status are held
in this page's memory. Real server auth/replay/one-use gates remain mandatory.
No automatic action chain, request retry, secret persistence or finalization
execution is supplied by this fragment.
"""


REGISTRATION_HANDOFF_CSS = r"""
    .registration-handoff-fields { display: grid; grid-template-columns: minmax(0, 2fr) minmax(190px, 1fr); gap: 12px; }
    .registration-handoff-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-block: 14px; }
    #registration-handoff-status, #registration-handoff-negotiation { white-space: pre-wrap; overflow-wrap: anywhere; }
    #registration-finalization-locator { overflow-wrap: anywhere; }
    @media (max-width: 620px) {
      .registration-handoff-fields { grid-template-columns: minmax(0, 1fr); }
      .registration-handoff-actions button { width: 100%; white-space: normal; }
    }
"""


REGISTRATION_HANDOFF_HTML = r"""
      <section id="registration-handoff-workspace" aria-labelledby="registration-handoff-heading">
        <h2 id="registration-handoff-heading">Retained registration actions</h2>
        <p>Use the evidence grant local ID from a real retained preparation. These actions are separate: no automatic chaining or retry. A local ID is a locator, not ownership or execution permission.</p>
        <div class="registration-handoff-fields">
          <div><label for="registration-handoff-locator">Evidence grant local ID</label>
            <input id="registration-handoff-locator" maxlength="71" spellcheck="false" autocomplete="off" placeholder="sha256:…" aria-describedby="registration-handoff-boundary"></div>
          <div><label for="registration-handoff-mode">Present caller authorization</label>
            <select id="registration-handoff-mode">
              <option value="operator">Operator with credential history · fresh WebAuthn</option>
              <option value="operator-bootstrap">Operator with no credential history · fresh bootstrap</option>
              <option value="pending">Pending OIDC first enrollment · fresh bootstrap</option>
            </select></div>
        </div>
        <p class="hint">The server decides whether this branch is permitted. A historical enrollment mode does not grant present permission. Bootstrap tokens are masked and cleared, never saved by this panel.</p>
        <div class="registration-handoff-actions">
          <button id="registration-handoff-execute" type="button">Execute evidence</button>
          <button id="registration-handoff-complete" type="button">Request completion</button>
          <button id="registration-handoff-recover" type="button">Recover completion</button>
          <button id="registration-handoff-finalize" type="button">Prepare finalization</button>
        </div>
        <div class="registration-handoff-actions">
          <button id="registration-handoff-use-inspected" class="secondary" type="button">Use inspected grant local ID</button>
          <a href="#custody-workspace">Admin-only local metadata inspection</a>
        </div>
        <p id="registration-handoff-boundary" class="hint">Execute evidence is not credential finalization. Request completion uses live originals; Recover completion uses separately authorized historical recovery and never retries SQL. Prepare finalization retains a separate preparation only; the authorization-before-planning execution path is not connected, and fresh permission cannot authorize this plan retroactively. Registration is not finalized and no session is activated here.</p>
        <p id="registration-handoff-status" role="status" aria-live="polite">No action submitted. Registration not finalized.</p>
        <p id="registration-handoff-negotiation" class="hint" aria-live="polite"></p>
        <div class="registration-handoff-actions">
          <button id="registration-handoff-continue" type="button" hidden>Authorize selected action</button>
          <button id="registration-handoff-cancel" class="secondary" type="button" hidden>Discard local authorization prompt</button>
          <a id="registration-handoff-review" href="#approval-workspace" hidden>Review in the approval queue</a>
        </div>
        <p id="registration-finalization-locator" hidden></p>
      </section>
"""


REGISTRATION_HANDOFF_SCRIPT = r"""
    const registrationHandoffActions = Object.freeze({
      execute: {label: 'Execute evidence', suffix: 'execute-retained', purpose: 'execute-registration-evidence', action: 'webauthn.registration.execution.execute', schema: 'serverware.webAuthnRegistrationExecutionHandoff/v1', status: 'observed-commit', authenticated: false},
      complete: {label: 'Request completion', suffix: 'complete-retained', purpose: 'complete-registration-evidence', action: 'webauthn.registration.execution.complete', schema: 'serverware.webAuthnRegistrationCompletion/v1', status: 'completion-acknowledged', authenticated: true},
      recover: {label: 'Recover completion', suffix: 'recover-completion', purpose: 'recover-registration-evidence-completion', action: 'webauthn.registration.execution.recover', schema: 'serverware.webAuthnRegistrationCompletionRecovery/v1', status: 'completion-recovered', authenticated: true},
      finalize: {label: 'Prepare finalization', suffix: 'prepare-finalization', purpose: 'prepare-retained-registration-finalization', action: 'webauthn.registration.finalization.prepare', schema: 'serverware.webAuthnRegistrationFinalizationPreparation/v1', status: 'finalization-prepared'},
    });
    let registrationHandoffEpoch = 0;
    let registrationHandoffBusy = false;
    let registrationHandoffPending = null;
    // A page-local duplicate-click guard only; the server owns durable one-use.
    const registrationHandoffSubmitted = new Set();

    function registrationHandoffDigest(value) {
      return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
    }

    function registrationHandoffSelection() {
      const digest = $('registration-handoff-locator').value.trim();
      const mode = $('registration-handoff-mode').value;
      if (!registrationHandoffDigest(digest) || !['operator', 'operator-bootstrap', 'pending'].includes(mode)) {
        throw new Error('Enter a real retained evidence grant local ID and select the present caller flow.');
      }
      return {digest, mode};
    }

    function registrationHandoffAuthScope() {
      return JSON.stringify([Boolean(adminToken()), state.authStatus?.authenticated === true,
        state.authStatus?.userId, state.authStatus?.authMethod, state.authStatus?.sessionState,
        state.authStatus?.roles]);
    }

    function registrationHandoffMessage(message, error = false) {
      const target = $('registration-handoff-status');
      target.textContent = message;
      target.setAttribute('role', error ? 'alert' : 'status');
    }

    function renderRegistrationHandoff() {
      let selected = null;
      try { selected = registrationHandoffSelection(); } catch (_) {}
      for (const kind of Object.keys(registrationHandoffActions)) {
        $('registration-handoff-' + kind).disabled = registrationHandoffBusy || Boolean(registrationHandoffPending)
          || !selected || registrationHandoffSubmitted.size >= 128
          || registrationHandoffSubmitted.has(selected.digest + ':' + kind);
      }
      for (const name of ['locator', 'mode', 'use-inspected']) $('registration-handoff-' + name).disabled = registrationHandoffBusy;
      const pending = registrationHandoffPending;
      $('registration-handoff-continue').hidden = !pending;
      $('registration-handoff-cancel').hidden = !pending;
      $('registration-handoff-review').hidden = !pending?.approvalId;
      $('registration-handoff-continue').disabled = registrationHandoffBusy;
      $('registration-handoff-cancel').disabled = registrationHandoffBusy;
      $('registration-handoff-continue').textContent = pending?.approvalId
        ? 'After approval: fresh assertion + submit' : 'Fresh assertion + submit selected action';
      $('registration-handoff-negotiation').textContent = pending
        ? `${registrationHandoffActions[pending.kind].label}\nAction: ${pending.action}\nResource: ${pending.resourceId}\nPayload: ${pending.payloadDigest}`
          + (pending.approvalId ? `\nApproval: ${pending.approvalId}\nA different authorized operator must approve. Continuing always requires a NEW assertion; approval state is checked by the server.` : '\nThe server requires fresh WebAuthn. Nothing is automatically resubmitted.')
        : '';
    }

    function clearRegistrationHandoffPrompt() {
      registrationHandoffEpoch += 1;
      registrationHandoffPending = null;
      $('registration-finalization-locator').hidden = true;
      $('registration-finalization-locator').textContent = '';
      registrationHandoffMessage(registrationHandoffBusy
        ? 'Selection or authentication changed. Any submitted request may still have taken effect; no retry is allowed.'
        : 'Local prompt cleared; server approvals and attempts are unchanged. Registration not finalized.');
      renderRegistrationHandoff();
    }

    function registrationHandoffChallenge(detail, selected, kind, approvalId = null) {
      const action = registrationHandoffActions[kind];
      if (!detail || typeof detail !== 'object' || Array.isArray(detail) || detail.action !== action.action
          || detail.automaticRetryAllowed !== false
          || typeof detail.resourceId !== 'string' || detail.resourceId.length < 1 || detail.resourceId.length > 4096
          || !registrationHandoffDigest(detail.payloadDigest)
          || (approvalId !== null && (typeof approvalId !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(approvalId)))) {
        throw new Error('Server authorization binding is malformed; no action was repeated.');
      }
      return {...selected, kind, action: detail.action, resourceId: detail.resourceId,
        payloadDigest: detail.payloadDigest, approvalId, authScope: registrationHandoffAuthScope()};
    }

    async function registrationHandoffPost(selected, action, body, stillCurrent) {
      const pending = selected.mode === 'pending';
      const path = (pending ? '/api/auth/session/webauthn/register/' : '/api/webauthn/register/') + action.suffix;
      let options = {method: 'POST', cache: 'no-store', body: JSON.stringify(body)};
      try {
        if (!pending) {
          await ensureCsrfToken();
          if (!stillCurrent()) throw new Error('Selection changed before action submission.');
          return await api(path, options);
        }
        // sessionApi's normal helper skips CSRF when an operator token is in
        // the page. This route ALWAYS acts as the pending cookie subject.
        const response = await fetch('/api/csrf', {credentials: 'same-origin', cache: 'no-store'});
        const csrf = await response.json();
        if (!response.ok || typeof csrf.token !== 'string' || !csrf.token || csrf.token.length > 1024) {
          throw new Error('Pending-session CSRF admission failed; no action request was sent.');
        }
        if (!stillCurrent()) throw new Error('Selection changed before action submission.');
        csrfToken = csrf.token;
        options.headers = {'X-Serverware-CSRF-Token': csrf.token};
        return await sessionApi(path, options);
      } finally {
        // Drop local references; JavaScript strings are not guaranteed wiped.
        options.body = '';
        options.headers = {};
      }
    }

    function registrationHandoffAccepted(value, selected, kind) {
      const action = registrationHandoffActions[kind];
      const fields = ['schema', 'status', 'purpose', 'localDigest', 'registrationCompleted', 'currentnessEstablished', 'automaticRetryAllowed'];
      fields.push(...(kind === 'finalize' ? ['finalizationLocalDigest', 'operation', 'finalizationExecuted'] : ['observationAuthenticated']));
      if (!custodyClosed(value, fields) || value.schema !== action.schema || value.status !== action.status
          || value.purpose !== action.purpose || value.localDigest !== selected.digest
          || value.registrationCompleted !== false || value.currentnessEstablished !== false || value.automaticRetryAllowed !== false
          || (kind !== 'finalize' && value.observationAuthenticated !== action.authenticated)
          || (kind === 'finalize' && (!registrationHandoffDigest(value.finalizationLocalDigest)
            || value.operation !== 'webauthn.registration.finalize' || value.finalizationExecuted !== false))) {
        throw new Error('Unexpected server result. Remote state is unknown; do not repeat the action.');
      }
      if (kind === 'finalize') {
        $('registration-finalization-locator').textContent = `Separate finalization local ID: ${value.finalizationLocalDigest} — prepared, not executed. Evidence grant input remains unchanged.`;
        $('registration-finalization-locator').hidden = false;
      }
      return kind === 'execute'
        ? 'Server reports observed-commit for evidence admission; this is not signed completion. Registration not finalized. No automatic next action or retry.'
        : kind === 'finalize'
          ? 'Server reports finalization-prepared and retained. Finalization NOT executed; registration not finalized; session not activated.'
          : `Server reports ${action.status} with authenticated originals. This does not establish currentness, finalize registration or activate a session.`;
    }

    async function submitRegistrationHandoff(kind, continuing = false) {
      if (registrationHandoffBusy) return;
      let selected, action, body, submitted = false;
      const epoch = registrationHandoffEpoch, token = adminToken();
      const stillCurrent = () => epoch === registrationHandoffEpoch && token === adminToken();
      try {
        selected = registrationHandoffSelection();
        action = registrationHandoffActions[kind];
        if (!action || registrationHandoffSubmitted.size >= 128
            || registrationHandoffSubmitted.has(selected.digest + ':' + kind)) throw new Error('This page already submitted that action. Inspect retained state; do not repeat it.');
        const previous = registrationHandoffPending;
        if (continuing ? !previous || previous.kind !== kind || previous.digest !== selected.digest || previous.mode !== selected.mode : Boolean(previous)) {
          throw new Error('The selected authorization prompt changed. No request was sent.');
        }
        registrationHandoffBusy = true;
        renderRegistrationHandoff();
        await fetchAuthStatus();
        if (!stillCurrent()) return;
        if (selected.mode === 'pending') {
          if (state.authStatus?.sessionState !== 'pending_webauthn') throw new Error('A current pending OIDC first-enrollment session is required.');
        } else if (!hasOperatorAuth()) throw new Error('Sign in as an operator or enter an operator token.');
        if (continuing && previous.authScope !== registrationHandoffAuthScope()) {
          registrationHandoffPending = null;
          throw new Error('Authentication changed. Discarded the old authorization prompt; nothing was submitted.');
        }
        body = {purpose: action.purpose, localDigest: selected.digest};
        if (continuing) {
          // approvalId in the challenge helper selects a DIFFERENT approver's
          // challenge. The requester always obtains an ordinary fresh assertion.
          const assertion = await controlPlaneAssertion({action: previous.action,
            resourceId: previous.resourceId, payloadDigest: previous.payloadDigest, approvalId: null});
          if (!stillCurrent()) return;
          body.mfa = {assertion, ...(previous.approvalId ? {approvalId: previous.approvalId} : {})};
        } else if (selected.mode !== 'operator') {
          if ($('webauthn-bootstrap-dialog').open) throw new Error('Finish the open bootstrap dialog first.');
          body.bootstrapToken = await requestWebAuthnBootstrapToken();
          if (!body.bootstrapToken) {
            registrationHandoffMessage('Bootstrap presentation cancelled. No action submitted.');
            return;
          }
          if (!stillCurrent()) return;
        } else if (!window.confirm(`${action.label} for ${selected.digest}?\nThe server may first require fresh WebAuthn and separate approval. This never finalizes registration or activates a session.`)) return;
        if (!stillCurrent()) return;
        registrationHandoffMessage(`${action.label}: one explicit request in progress. Do not repeat it.`);
        submitted = true;
        registrationHandoffSubmitted.add(selected.digest + ':' + kind);
        const value = await registrationHandoffPost(selected, action, body, stillCurrent);
        if (!stillCurrent()) return;
        registrationHandoffPending = null;
        registrationHandoffMessage(registrationHandoffAccepted(value, selected, kind));
      } catch (error) {
        if (!stillCurrent()) return;
        const detail = error instanceof ApiError ? error.detail : null;
        if (submitted && selected.mode === 'operator' && detail
            && ((error.status === 412 && detail.error === 'control_plane_webauthn_required')
              || (error.status === 428 && detail.error === 'control_plane_approval_required'))) {
          try {
            const approval = error.status === 428 ? detail.approvalId : registrationHandoffPending?.approvalId ?? null;
            const next = registrationHandoffChallenge(detail, selected, kind, approval);
            const prior = registrationHandoffPending;
            if (prior && (prior.action !== next.action || prior.resourceId !== next.resourceId || prior.payloadDigest !== next.payloadDigest)) {
              throw new Error('Server authorization binding changed; discard this prompt and inspect the record.');
            }
            registrationHandoffPending = next;
            registrationHandoffSubmitted.delete(selected.digest + ':' + kind);
            registrationHandoffMessage(error.status === 428
              ? 'Server requires a separate approver. The previous assertion was consumed; continuation requires a new click and NEW assertion.'
              : 'Server requires fresh action-bound WebAuthn. Use the explicit authorization button; no request was automatically repeated.');
          } catch (_) {
            registrationHandoffPending = null;
            registrationHandoffSubmitted.add(selected.digest + ':' + kind);
            registrationHandoffMessage('Invalid or changed authorization binding. No automatic retry; inspect retained state.', true);
          }
        } else {
          if (submitted) {
            registrationHandoffSubmitted.add(selected.digest + ':' + kind);
            registrationHandoffPending = null;
          }
          registrationHandoffMessage(submitted
            ? (error instanceof ApiError && error.status < 500
              ? `Server denied the explicit request (HTTP ${error.status}). No automatic retry; registration not finalized.`
              : 'Response unavailable or unrecognized. Remote state is UNKNOWN; the action may have taken effect. Do not retry SQL. Use separate recovery only with fresh server authorization.')
            : 'Authorization cancelled, changed or unavailable before action submission. No action request was sent by this click.', true);
        }
      } finally {
        if (body) { delete body.bootstrapToken; delete body.mfa; }
        registrationHandoffBusy = false;
        renderRegistrationHandoff();
      }
    }

    function initRegistrationHandoff() {
      for (const kind of Object.keys(registrationHandoffActions)) {
        $('registration-handoff-' + kind).addEventListener('click', () => submitRegistrationHandoff(kind));
      }
      $('registration-handoff-continue').addEventListener('click', () => {
        if (registrationHandoffPending) submitRegistrationHandoff(registrationHandoffPending.kind, true);
      });
      $('registration-handoff-cancel').addEventListener('click', clearRegistrationHandoffPrompt);
      $('registration-handoff-locator').addEventListener('input', clearRegistrationHandoffPrompt);
      $('registration-handoff-mode').addEventListener('change', clearRegistrationHandoffPrompt);
      $('admin-token').addEventListener('input', clearRegistrationHandoffPrompt);
      $('operator-sign-out').addEventListener('click', clearRegistrationHandoffPrompt);
      $('registration-handoff-use-inspected').addEventListener('click', () => {
        if (registrationHandoffBusy) return;
        const record = custodyView.detail?.record;
        if (!record || record.family !== 'registration-execution' || record.selector !== 'webauthn.registration.evidence.admit'
            || !registrationHandoffDigest(record.localDigest) || !custodyCanRequest()) {
          registrationHandoffMessage('First inspect an actual registration-execution grant in the admin-only custody inventory, or paste its real preparation local ID. No ID was invented.', true);
          return;
        }
        $('registration-handoff-locator').value = record.localDigest;
        clearRegistrationHandoffPrompt();
        registrationHandoffMessage('Copied an inspected local locator only. Metadata does not establish ownership, association completeness or action readiness.');
      });
      window.addEventListener('pagehide', () => {
        registrationHandoffEpoch += 1;
        registrationHandoffPending = null;
        $('webauthn-bootstrap-token').value = '';
      });
      renderRegistrationHandoff();
    }
"""
