"""Static rotation navigation and the development-only plaintext editor.

Browser state is neither authorization nor durable custody. A pending secret is
held only in this page's memory until explicit continuation or discard. Network
uncertainty never authorizes a retry, and clearing references is not zeroization.
"""


STATIC_CREDENTIAL_REPLACEMENT_HTML = r"""
  <dialog id="credential-replacement-dialog" aria-labelledby="credential-replacement-heading">
    <form id="credential-replacement-form">
      <h2 id="credential-replacement-heading">Replace static credential secret</h2>
      <p id="credential-replacement-target"></p>
      <p class="hint">The current secret is never retrieved. The existing credential identity, kind, metadata and policy assignments stay unchanged. OAuth accounts must use their provider reconnect flow.</p>
      <label for="credential-replacement-secret">New secret (preserved exactly, including whitespace)</label>
      <textarea id="credential-replacement-secret" autocomplete="off" autocapitalize="off" spellcheck="false" required></textarea>
      <p class="hint">If another operator's approval is required, this page retains the new secret only in memory. Keep this tab open and continue explicitly after approval. Reloading, signing out, changing authentication or discarding loses that continuation; no secret is saved to browser storage.</p>
      <div class="toolbar">
        <button id="credential-replacement-submit" type="submit">Replace secret</button>
        <button id="credential-replacement-continue" type="button" hidden>Continue approved replacement</button>
        <button id="credential-replacement-discard" class="secondary" type="button">Discard local secret</button>
      </div>
      <p id="credential-replacement-status" class="hint" role="status" aria-live="polite"></p>
    </form>
  </dialog>
"""


STATIC_CREDENTIAL_REPLACEMENT_SCRIPT = r"""
    const credentialReplacementKind = 'credential-secret-replace';
    let credentialReplacementEpoch = 0, credentialReplacement = null;

    function credentialReplacementEligible(item) {
      return protectedStaticCredentials === false && protectedStaticRotation === false
        && item && typeof item.id === 'string' && item.id.length > 0
        && typeof item.kind === 'string' && item.kind !== 'oauth2'
        && item.metadata?.oauth !== true && (item.lifecycle_status || 'active') === 'active';
    }
    function credentialReplacementButton(item) {
      if (protectedStaticRotation === true) {
        const eligible = item && typeof item.id === 'string'
          && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.id)
          && ['bearer', 'basic', 'header', 'query', 'cookie'].includes(item.kind)
          && item.metadata?.oauth !== true && item.lifecycle_status === 'active';
        // Navigation only: the destination reads the actual predecessor after
        // explicit prerequisite checks. Never open the plaintext editor here.
        return eligible ? `<a href="/credentials/static/rotation#credential=${item.id}">Review secret rotation</a> ` : '';
      }
      if (protectedStaticCredentials !== false)
        return '<span class="muted">Protected rotation is not selected for this deployment; no plaintext editor.</span>';
      return credentialReplacementEligible(item)
        ? `<button type="button" data-credential-replacement="${esc(item.id)}">Replace secret</button>` : '';
    }
    function credentialReplacementScope() {
      // These client observations constrain only this editor. The server still
      // authenticates each request and binds every approval to its real actor.
      return JSON.stringify([adminToken(), oidcSessionStatusUnknown, state.currentUserId,
        state.currentUserRoles, state.authStatus?.authenticated, state.authStatus?.userId,
        state.authStatus?.authMethod, state.authStatus?.sessionState, state.authStatus?.roles]);
    }
    function credentialReplacementNeed(value) {
      if (!value) throw new Error('Replacement context changed or is unavailable. No automatic retry.');
    }
    function credentialReplacementMessage(message) {
      $('credential-replacement-status').textContent = message;
    }
    function credentialReplacementForget(owner) {
      for (const mutation of owner.mutations) {
        if (mutation.body) { delete mutation.body.secret; delete mutation.body.mfa; }
      }
      owner.mutations.clear(); owner.original = null; owner.pending = null;
    }
    function discardCredentialReplacement(message = 'Local replacement discarded. An already sent request may still have taken effect; inspect before any new action.') {
      const owner = credentialReplacement;
      credentialReplacement = null; credentialReplacementEpoch += 1;
      if (owner) {
        owner.controller.abort();
        if (pendingMutation && owner.mutations.has(pendingMutation)) {
          pendingMutation = null; persistPendingMutation(); renderPendingMutation();
        }
        credentialReplacementForget(owner);
        owner.scope = null;
      }
      $('credential-replacement-secret').value = '';
      if ($('credential-replacement-dialog').open) $('credential-replacement-dialog').close();
      credentialReplacementMessage(message);
    }
    function credentialReplacementAuthChanged() {
      const owner = credentialReplacement;
      if (!owner) return;
      try { owner.check(); } catch (_) {
        discardCredentialReplacement('Authentication, credential or approval changed. Local secret discarded; inspect any sent request before a new action.');
      }
    }
    function openCredentialReplacement(id) {
      credentialReplacementNeed(!credentialReplacement && !pendingMutation && hasOperatorAuth()
        && typeof state.currentUserId === 'string' && state.currentUserId.length > 0);
      const item = (state.credentials || []).find(row => row.id === id);
      credentialReplacementNeed(credentialReplacementEligible(item));
      const owner = {
        id, actor: state.currentUserId, scope: credentialReplacementScope(), epoch: credentialReplacementEpoch,
        controller: new AbortController(), mutations: new Set(), original: null, pending: null,
        busy: false, digest: null, expires: null, assertions: 0,
        check() {
          credentialReplacementNeed(credentialReplacement === owner && owner.epoch === credentialReplacementEpoch
            && !owner.controller.signal.aborted && owner.scope === credentialReplacementScope()
            && hasOperatorAuth() && credentialReplacementEligible((state.credentials || []).find(row => row.id === id))
            && (owner.expires === null || Date.now() < owner.expires)
            && (!owner.pending || pendingMutation === owner.pending));
          const approval = owner.pending && (state.controlPlaneApprovals || []).find(row => row.id === owner.pending.approvalId);
          credentialReplacementNeed(!approval || ['pending', 'approved'].includes(approval.status));
        },
        retain(mutation) { owner.check(); owner.mutations.add(mutation); },
        assertion() { owner.check(); credentialReplacementNeed(owner.assertions === 0); owner.assertions += 1; },
        challenge(detail) {
          owner.check();
          credentialReplacementNeed(detail.action === 'credential.update' && detail.resourceId === id
            && typeof detail.payloadDigest === 'string' && /^sha256:[0-9a-f]{64}$/.test(detail.payloadDigest)
            && (owner.digest === null || owner.digest === detail.payloadDigest));
          owner.digest = detail.payloadDigest;
        },
        pause(mutation, detail) {
          owner.challenge(detail);
          credentialReplacementNeed(typeof detail.approvalId === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(detail.approvalId)
            && typeof detail.expiresAt === 'string' && Number.isFinite(Date.parse(detail.expiresAt)));
          owner.expires = Date.parse(detail.expiresAt); owner.pending = mutation;
          pendingMutation = mutation; owner.check();
        }
      };
      credentialReplacement = owner;
      $('credential-replacement-target').textContent = `Credential: ${item.name || id} (${id})`;
      $('credential-replacement-secret').value = '';
      credentialReplacementMessage('Enter a new secret. Submission uses the existing MFA and approval policy.');
      renderCredentialReplacement();
      $('credential-replacement-dialog').showModal();
      $('credential-replacement-secret').focus();
    }
    function credentialReplacementGuard(mutation) {
      if (mutation?.kind !== credentialReplacementKind) return null;
      const owner = credentialReplacement;
      credentialReplacementNeed(owner && owner.busy
        && (mutation === owner.original || mutation === owner.pending)
        && mutation.persist === false && mutation.method === 'PUT'
        && mutation.path === `/api/credentials/${encodeURIComponent(owner.id)}`);
      owner.check(); return owner;
    }
    function credentialReplacementApiGuard(owner) {
      if (owner === undefined || owner === null) return null;
      credentialReplacementNeed(owner === credentialReplacement && owner.busy);
      owner.check(); return owner;
    }
    function renderCredentialReplacement() {
      const owner = credentialReplacement;
      if (!owner) return;
      $('credential-replacement-secret').disabled = owner.busy || owner.pending !== null;
      $('credential-replacement-secret').required = owner.pending === null;
      $('credential-replacement-submit').disabled = owner.busy || owner.pending !== null;
      $('credential-replacement-continue').hidden = owner.pending === null;
      const approval = owner.pending && (state.controlPlaneApprovals || []).find(row => row.id === owner.pending.approvalId);
      $('credential-replacement-continue').disabled = owner.busy || approval?.status !== 'approved';
    }
    async function executeCredentialReplacement(owner, continuation) {
      // Set busy before any await, including the refresh preceding continuation.
      owner.check(); credentialReplacementNeed(!owner.busy); owner.busy = true; owner.assertions = 0;
      renderCredentialReplacement();
      try {
        if (continuation) {
          await refresh(); owner.check();
          const approval = (state.controlPlaneApprovals || []).find(row => row.id === owner.pending?.approvalId);
          credentialReplacementNeed(approval && ['pending', 'approved'].includes(approval.status)
            && approval.action === 'credential.update' && approval.resource_id === owner.id
            && approval.payload_digest === owner.digest && approval.requester_id === owner.actor);
          if (approval.status === 'pending') {
            credentialReplacementMessage('Still awaiting the existing approval. No replacement was sent.');
            return {pending: true};
          }
        }
        owner.check();
        const completed = await runControlPlaneMutation(continuation ? owner.pending : owner.original);
        owner.check();
        if (completed.pending) {
          credentialReplacementMessage('Approval required. Secret held only in this page memory. Continue explicitly after another operator approves, or discard.');
          return {pending: true};
        }
        credentialReplacementForget(owner);
        await finishMutation(completed.mutation, completed.result); owner.check();
        discardCredentialReplacement('Replacement accepted and credential list refreshed.');
        setStatus('Static credential replacement accepted; credential list refreshed.', 'success');
        return {uiHandled: true};
      } catch (_) {
        // Do not surface arbitrary server/error text alongside a secret input.
        // A response lost after PUT is uncertain, not permission to replay it.
        if (credentialReplacement === owner) {
          discardCredentialReplacement('Replacement not confirmed. Local secret discarded. Inspect current state before any new submission.');
          setStatus('Replacement not confirmed. Local secret discarded; no automatic retry.', 'error');
        }
        return {uiHandled: true, blocked: true};
      } finally {
        owner.busy = false;
        if (credentialReplacement === owner) renderCredentialReplacement();
      }
    }
    async function submitCredentialReplacement() {
      const owner = credentialReplacement;
      if (owner?.busy) return {uiHandled: true, blocked: true};
      credentialReplacementNeed(owner && !owner.busy && !owner.original && !owner.pending);
      owner.check();
      let secret = $('credential-replacement-secret').value;
      const valid = typeof secret === 'string' && secret.length > 0
        && !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(secret)
        && new TextEncoder().encode(secret).byteLength <= 1048576;
      if (!valid) {
        secret = null; discardCredentialReplacement('Invalid replacement input discarded. Enter a nonempty UTF-8 secret of at most 1 MiB.');
        return {uiHandled: true, blocked: true};
      }
      owner.original = {kind: credentialReplacementKind, label: 'Replace static credential secret',
        persist: false, path: `/api/credentials/${encodeURIComponent(owner.id)}`,
        method: 'PUT', body: {secret}};
      owner.mutations.add(owner.original); secret = null;
      $('credential-replacement-secret').value = '';
      return executeCredentialReplacement(owner, false);
    }
    async function continueCredentialReplacement() {
      const owner = credentialReplacement;
      if (owner?.busy) return {uiHandled: true, blocked: true};
      credentialReplacementNeed(owner && !owner.busy && owner.pending && pendingMutation === owner.pending);
      return executeCredentialReplacement(owner, true);
    }
    function initCredentialReplacement() {
      $('credentials').addEventListener('click', event => {
        const button = event.target.closest('button[data-credential-replacement]');
        if (!button || !$('credentials').contains(button)) return;
        runUiAction('Replace static credential secret', () => openCredentialReplacement(button.dataset.credentialReplacement));
      });
      $('credential-replacement-form').addEventListener('submit', event => {
        event.preventDefault(); runUiAction('Replace static credential secret', submitCredentialReplacement);
      });
      $('credential-replacement-continue').addEventListener('click', () =>
        runUiAction('Continue static credential replacement', continueCredentialReplacement));
      $('credential-replacement-discard').addEventListener('click', () => discardCredentialReplacement());
      $('credential-replacement-dialog').addEventListener('cancel', event => {
        event.preventDefault(); discardCredentialReplacement();
      });
      window.addEventListener('pagehide', () => discardCredentialReplacement());
    }
"""
