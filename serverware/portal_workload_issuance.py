"""Explicit, page-local orchestration of the existing workload issuance API.

Only independently supplied public originals are selected. No key input, browser
storage, capability log, automatic effect retry or enrollment/TLS claim is added.
"""


WORKLOAD_ISSUANCE_HTML = r"""
        <section id="workload-issuance-workspace" aria-labelledby="workload-issuance-heading">
          <h2 id="workload-issuance-heading">Issue a workload certificate</h2>
          <p class="hint">Use an active OIDC operator cookie. A policy author requests; a different approver approves with a fresh passkey. An entered bearer token is not used. Both ceremonies are additional to the independent signed issuance grant.</p>
          <p class="hint">Select only the public originals below. Keep the workload private key on its host. The packet can contain a CA-install capability: it is sent only to this control plane, never copied to browser storage, logs or the approval queue.</p>
          <label for="workload-issuance-grant">Independently signed issuance grant (JSON, at most 32 KiB)</label>
          <input id="workload-issuance-grant" type="file" accept="application/json,.json" autocomplete="off">
          <label for="workload-issuance-packet">Original enrollment packet (JSON, at most 8 MiB)</label>
          <input id="workload-issuance-packet" type="file" accept="application/json,.json" autocomplete="off">
          <label for="workload-issuance-request">Locally prepared signed CSR request (JSON, at most 64 KiB)</label>
          <input id="workload-issuance-request" type="file" accept="application/json,.json" autocomplete="off">
          <p class="hint">The portal limits the encoded request to 3 MiB; the server's cold-context and 64 MiB aggregate bounds can be tighter. These file ceilings cannot all be combined. No private-key or replacement-CSR field is accepted.</p>
          <div class="toolbar">
            <button id="workload-issuance-start" type="button">Fresh passkey + request issuance approval</button>
            <button id="workload-issuance-clear" class="secondary" type="button">Clear local files and result</button>
          </div>
          <div id="workload-issuance-pending" hidden>
            <p id="workload-issuance-binding" class="hint" style="overflow-wrap:anywhere"></p>
            <a href="#approval-workspace">Different operator: review the approval queue</a>
            <button id="workload-issuance-continue" type="button">After approval: new passkey + continue once</button>
          </div>
          <p id="workload-issuance-status" class="hint" role="status" aria-live="polite">No issuance requested. Select the three public originals; never select a private key.</p>
          <button id="workload-issuance-download" class="secondary" type="button" disabled>Download public certificate for local admission</button>
          <p class="hint">A certificate response is not completed enrollment or an authenticated proxy connection. Admit the downloaded leaf locally against your retained request/private key and independently pinned issuer. Trust distribution, rotation/revocation, service channels and sidecar setup remain separate.</p>
          <fieldset>
            <legend>Separate CLI handoff: create an assertion file</legend>
            <p class="hint">Import the options receipt from your explicit CLI options request. This lane only reads current cookie status and performs a passkey ceremony: it never requests options, submits issuance or approves a request. Compare the displayed action/resource/payload binding with your local request before continuing.</p>
            <label for="workload-issuance-options-receipt">Same-origin options receipt (JSON, at most 192 KiB; options body at most 32 KiB)</label>
            <input id="workload-issuance-options-receipt" type="file" accept="application/json,.json" autocomplete="off">
            <div class="toolbar">
              <button id="workload-issuance-import-options" class="secondary" type="button">Import and inspect options receipt</button>
              <button id="workload-issuance-create-assertion" type="button" disabled>Fresh passkey + create assertion file</button>
              <button id="workload-issuance-download-assertion" class="secondary" type="button" disabled>Download one-use assertion file</button>
            </div>
            <p id="workload-issuance-assertion-status" class="hint" role="status" aria-live="polite" style="overflow-wrap:anywhere">No options receipt imported.</p>
            <p class="hint">The browser checks the active OIDC user and this page's current context, not an exact session ID. The server enforces the original challenge lifetime and actual cookie at submission; import, ceremony and download cannot renew that lifetime. No expiry is invented or exported.</p>
            <p class="hint">The downloaded assertion is a sensitive, one-use authorization file, not a cookie or private key. Protect it with mode 0600, pin its displayed SHA-256 locally, and submit only through your explicit CLI command. No approval ID is included. Clear this page's local files after use; no issuance result is implied.</p>
          </fieldset>
        </section>
"""


WORKLOAD_ISSUANCE_SCRIPT = r"""
    const workloadIssuanceAction = 'workload.identity.issue';
    const workloadIssuancePath = '/api/agents/workload-identity/issue';
    const workloadIssuanceSchema = 'serverware.workloadIdentityIssuanceResponse/v1';
    const workloadIssuanceFileIds = ['workload-issuance-grant', 'workload-issuance-packet', 'workload-issuance-request'];
    const workloadIssuanceLimits = [32 * 1024, 8 * 1024 * 1024, 64 * 1024];
    const workloadIssuanceAttempts = new Set();
    const workloadIssuanceApprovalAttempts = new Set();
    const workloadIssuanceAssertionAttempts = new Set();
    let workloadIssuanceEpoch = 0, workloadIssuanceBusy = false, workloadIssuancePending = null;
    let workloadIssuanceCertificate = null, workloadIssuanceController = null, workloadIssuanceContext = null;
    let workloadIssuanceUncertain = false, workloadIssuanceApprovalUnknown = false, workloadIssuanceContact = false;
    let workloadIssuanceReceipt = null, workloadIssuanceAssertionFile = null;

    function workloadIssuanceClosed(value, fields) {
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
    }
    function workloadIssuanceText(value, maximum = 512) {
      return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(value);
    }
    function workloadIssuanceDigest(value) { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
    function workloadIssuanceId(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value); }
    function workloadIssuanceNeed(ok) { if (!ok) throw new Error('Workload issuance data or current context is unavailable. No automatic retry is permitted.'); }
    function workloadIssuanceMessage(message, failed = false) {
      const target = $('workload-issuance-status');
      if (!target) return;
      target.textContent = (workloadIssuanceUncertain ? 'A prior issuance outcome remains unknown. ' : '')
        + (workloadIssuanceApprovalUnknown ? 'A submitted approval outcome remains unknown. ' : '') + message;
      target.setAttribute('role', failed ? 'alert' : 'status');
    }
    function workloadIssuanceScope() {
      // Existing public auth/policy/credential facts invalidate UI state only;
      // the server independently authenticates the real cookie and originals.
      return sessionActivationAuthScope();
    }
    function workloadIssuanceAuth(role) {
      const value = state.authStatus;
      workloadIssuanceNeed(!adminToken() && value?.authenticated === true
        && value.authMethod === 'oidc-session' && value.sessionState === 'active'
        && workloadIssuanceText(value.userId, 4096) && Array.isArray(value.roles)
        && (value.roles.includes(role) || value.roles.includes('admin')));
      return value.userId;
    }
    function workloadIssuanceInvalidate(reason = 'Authentication or original selection changed.', clearFiles = true) {
      workloadIssuanceEpoch += 1;
      if (workloadIssuanceContact) workloadIssuanceUncertain = true;
      workloadIssuanceController?.abort();
      workloadIssuancePending = null;
      workloadIssuanceCertificate = null;
      workloadIssuanceReceipt = null;
      if (workloadIssuanceAssertionFile) workloadIssuanceAssertionFile.bytes.fill(0);
      workloadIssuanceAssertionFile = null;
      if (clearFiles) [...workloadIssuanceFileIds, 'workload-issuance-options-receipt'].forEach(id => { if ($(id)) $(id).value = ''; });
      workloadIssuanceAssertionMessage('Local receipt and assertion were discarded. Original server challenge expiry and page attempt locks are unchanged.');
      workloadIssuanceContext = workloadIssuanceScope();
      workloadIssuanceMessage(reason + ' Pending authorization and downloadable bytes were discarded; page attempt locks remain.', workloadIssuanceUncertain);
      renderWorkloadIssuance();
    }
    function renderWorkloadIssuance() {
      if (!$('workload-issuance-workspace')) return;
      const observed = workloadIssuanceScope();
      if (workloadIssuanceContext !== null && observed !== workloadIssuanceContext) {
        workloadIssuanceInvalidate('Operator, policy or credential trust changed.');
        return;
      }
      workloadIssuanceContext = observed;
      let allowed = false;
      try { workloadIssuanceAuth('policy_author'); allowed = true; } catch (_) {}
      $('workload-issuance-start').disabled = workloadIssuanceBusy || workloadIssuanceUncertain || !allowed || workloadIssuancePending !== null;
      $('workload-issuance-continue').disabled = workloadIssuanceBusy || workloadIssuanceUncertain || !allowed || workloadIssuancePending === null;
      $('workload-issuance-pending').hidden = workloadIssuancePending === null;
      $('workload-issuance-binding').textContent = workloadIssuancePending
        ? 'Approval ' + workloadIssuancePending.approvalId + ' · resource ' + workloadIssuancePending.resourceId
          + ' · action digest ' + workloadIssuancePending.payloadDigest : '';
      $('workload-issuance-download').disabled = workloadIssuanceBusy || workloadIssuanceCertificate === null || !allowed;
      const handoffBlocked = workloadIssuanceBusy || workloadIssuanceUncertain || !allowed || workloadIssuancePending !== null;
      $('workload-issuance-import-options').disabled = handoffBlocked;
      $('workload-issuance-create-assertion').disabled = handoffBlocked || workloadIssuanceReceipt === null
        || workloadIssuanceAssertionAttempts.has(workloadIssuanceReceipt.challengeDigest);
      $('workload-issuance-download-assertion').disabled = handoffBlocked || workloadIssuanceAssertionFile === null;
    }

    // Bounded duplicate-rejecting JSON scan before the single graph parse.
    // File numbers are never authority inputs or reserialized; response numbers
    // must be safe integers. Exact original file bytes are always transmitted.
    function workloadIssuanceJson(text, file = false) {
      let offset = 0, nodes = 0;
      const white = () => { while (/[\x20\t\r\n]/.test(text[offset] || '\0')) offset += 1; };
      function string() {
        const start = offset++;
        workloadIssuanceNeed(text[start] === '"');
        let escaped = false;
        while (offset < text.length) {
          const ch = text[offset++];
          if (!escaped && ch === '"') return JSON.parse(text.slice(start, offset));
          if (!escaped && ch === '\\') escaped = true; else escaped = false;
        }
        workloadIssuanceNeed(false);
      }
      function value(depth) {
        workloadIssuanceNeed(depth <= 20 && ++nodes <= (file ? 16384 : 4096));
        white();
        if (text[offset] === '"') { string(); return; }
        const opening = text[offset];
        if (opening === '{' || opening === '[') {
          offset += 1; white();
          const end = opening === '{' ? '}' : ']', keys = new Set();
          if (text[offset] === end) { offset += 1; return; }
          for (;;) {
            if (opening === '{') {
              const key = string();
              workloadIssuanceNeed(!keys.has(key) && key !== '__proto__' && keys.size < 256);
              keys.add(key); white(); workloadIssuanceNeed(text[offset++] === ':');
            }
            value(depth + 1); white();
            if (text[offset] === end) { offset += 1; return; }
            workloadIssuanceNeed(text[offset++] === ','); white();
          }
        }
        const start = offset;
        while (offset < text.length && !/[\x20\t\r\n,\]}]/.test(text[offset])) offset += 1;
        workloadIssuanceNeed(offset > start);
        const atom = JSON.parse(text.slice(start, offset));
        workloadIssuanceNeed(atom === null || typeof atom === 'boolean'
          || typeof atom === 'number' && Number.isFinite(atom) && (file || Number.isSafeInteger(atom)));
      }
      value(0); white(); workloadIssuanceNeed(offset === text.length);
      return JSON.parse(text);
    }
    async function workloadIssuanceRead(response, maximum, current) {
      current();
      workloadIssuanceNeed(response instanceof Response && response.body
        && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const declared = response.headers.get('Content-Length');
      workloadIssuanceNeed(declared === null || /^[0-9]+$/.test(declared) && Number(declared) <= maximum);
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let text = '', size = 0, complete = false;
      try {
        for (;;) {
          current(); const chunk = await reader.read(); current();
          if (chunk.done) { complete = true; break; }
          size += chunk.value.byteLength; workloadIssuanceNeed(size <= maximum);
          text += decoder.decode(chunk.value, {stream: true});
        }
        text += decoder.decode();
        return workloadIssuanceJson(text);
      } finally {
        if (!complete) { try { await reader.cancel(); } catch (_) {} }
        reader.releaseLock(); text = '';
      }
    }
    async function workloadIssuancePost(path, body, current, signal, contact = null) {
      workloadIssuanceNeed([workloadIssuancePath, workloadIssuancePath + '/options',
        '/api/control-plane/mutations/webauthn/options'].includes(path)
        || /^\/api\/control-plane\/approvals\/[A-Za-z0-9_-]{1,64}\/approve$/.test(path));
      let original = JSON.stringify(body), token = null;
      workloadIssuanceNeed(new TextEncoder().encode(original).byteLength <= 3 * 1024 * 1024);
      const timeout = new AbortController(), abort = () => timeout.abort();
      const timer = setTimeout(abort, 30000);
      signal.addEventListener('abort', abort, {once: true});
      try {
        current();
        const response = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin',
          cache: 'no-store', redirect: 'error', signal: timeout.signal});
        const csrf = await workloadIssuanceRead(response, 4096, current);
        workloadIssuanceNeed(response.ok && workloadIssuanceClosed(csrf, ['ok', 'token', 'cookie', 'header'])
          && csrf.ok === true && workloadIssuanceText(csrf.token, 1024)
          && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token');
        token = csrf.token; current();
        if (contact) contact();
        const result = await fetch(path, {method: 'POST', mode: 'same-origin', credentials: 'same-origin',
          cache: 'no-store', redirect: 'error', signal: timeout.signal,
          headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': token}, body: original});
        const payload = await workloadIssuanceRead(result, 128 * 1024, current);
        return {status: result.status, payload};
      } finally {
        clearTimeout(timer); signal.removeEventListener('abort', abort); original = ''; token = null;
      }
    }
    function workloadIssuanceCanonical(value) {
      if (Array.isArray(value)) return '[' + value.map(workloadIssuanceCanonical).join(',') + ']';
      if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key =>
        workloadIssuanceCanonical(key) + ':' + workloadIssuanceCanonical(value[key])).join(',') + '}';
      return JSON.stringify(value).replace(/[\u007f-\uffff]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
    }
    async function workloadIssuanceHash(bytes) {
      return 'sha256:' + Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
        byte => byte.toString(16).padStart(2, '0')).join('');
    }
    async function workloadIssuanceObjectHash(value) {
      return workloadIssuanceHash(new TextEncoder().encode(workloadIssuanceCanonical(value)));
    }
    function workloadIssuanceBase64(value, maximum) {
      workloadIssuanceNeed(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value)
        && value.length <= Math.ceil(maximum * 4 / 3) && value.length % 4 !== 1);
      const bytes = b64ToBytes(value);
      workloadIssuanceNeed(bytes.byteLength <= maximum && bytesToB64(bytes) === value);
      return bytes;
    }
    function workloadIssuanceFiles() {
      return workloadIssuanceFileIds.map((id, index) => {
        const list = $(id).files;
        workloadIssuanceNeed(list && list.length === 1 && list[0].size >= 2 && list[0].size <= workloadIssuanceLimits[index]);
        return list[0];
      });
    }
    async function workloadIssuanceOriginals(files, current) {
      workloadIssuanceNeed(files.reduce((total, file) => total + Math.ceil(file.size * 4 / 3), 0)
        + 40 * 1024 <= 3 * 1024 * 1024);
      const wrappers = [], parsed = [];
      for (let index = 0; index < files.length; index += 1) {
        current(); let bytes = new Uint8Array(await files[index].arrayBuffer()); current();
        workloadIssuanceNeed(bytes.byteLength === files[index].size);
        let text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
        workloadIssuanceNeed(!/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text));
        const value = workloadIssuanceJson(text, true);
        if (index === 1) workloadIssuanceNeed(value?.apiVersion === 'serverware.agentEnrollment/v1');
        else workloadIssuanceNeed(workloadIssuanceClosed(value, ['schema', 'payload', 'signature'])
          && value.schema === (index === 0 ? 'serverware.signedWorkloadIdentityIssuanceAuthorization/v1'
            : 'serverware.signedWorkloadIdentityRequest/v1'));
        wrappers.push(Object.freeze({base64Url: bytesToB64(bytes), byteCount: bytes.byteLength,
          bytesDigest: await workloadIssuanceHash(bytes)}));
        // Retain only the grant's public scalar binding, never packet/capability graphs.
        if (index === 0) parsed.push(value.payload);
        bytes = null; text = ''; current();
      }
      const grant = parsed[0];
      workloadIssuanceNeed(grant && typeof grant === 'object' && grant.packetSha256 === wrappers[1].bytesDigest
        && grant.requestSha256 === wrappers[2].bytesDigest && workloadIssuanceText(grant.principalId)
        && workloadIssuanceText(grant.nonce) && workloadIssuanceText(grant.grantId)
        && ['bootstrapDigest', 'configurationDigest', 'issuerCertificateSha256'].every(key => workloadIssuanceDigest(grant[key]))
        && typeof grant.serialNumber === 'string' && /^[1-9a-f][0-9a-f]{0,39}$/.test(grant.serialNumber));
      const binding = Object.freeze({action: workloadIssuanceAction, authorizationDigest: wrappers[0].bytesDigest,
        packetDigest: wrappers[1].bytesDigest, requestDigest: wrappers[2].bytesDigest,
        principalId: grant.principalId, nonce: grant.nonce, bootstrapDigest: grant.bootstrapDigest,
        configurationDigest: grant.configurationDigest, issuerCertificateDigest: grant.issuerCertificateSha256, grantId: grant.grantId});
      return {body: {schema: 'serverware.workloadIdentityIssuanceRequest/v1',
        authorization: wrappers[0], packet: wrappers[1], request: wrappers[2]}, binding,
        resourceId: await workloadIssuanceObjectHash({principalId: grant.principalId, nonce: grant.nonce}),
        payloadDigest: await workloadIssuanceObjectHash(binding), serialNumber: grant.serialNumber};
    }
    async function workloadIssuanceOptions(options, binding, userId, current, approval = null) {
      workloadIssuanceNeed(workloadIssuanceClosed(options, ['publicKey', 'serverware'])
        && workloadIssuanceClosed(options.serverware, ['challenge_id', 'payload', 'payload_digest'])
        && workloadIssuanceText(options.serverware.challenge_id, 128));
      const payload = options.serverware.payload, key = options.publicKey;
      const fields = ['v', 'type', 'user_id', 'action', 'resource_id', 'payload_digest', 'nonce'];
      if (approval) fields.push('control_plane_approval_id', 'approval_requester_id', 'approval_expires_at', 'decision');
      workloadIssuanceNeed(workloadIssuanceClosed(payload, fields) && payload.v === (approval ? 2 : 1)
        && payload.type === 'serverware.control_plane_mutation' && payload.user_id === userId
        && payload.action === workloadIssuanceAction && payload.resource_id === binding.resourceId
        && payload.payload_digest === binding.payloadDigest && workloadIssuanceText(payload.nonce, 128));
      if (approval) workloadIssuanceNeed(payload.control_plane_approval_id === approval.id
        && payload.approval_requester_id === approval.requester_id
        && payload.approval_expires_at === approval.expires_at && payload.decision === 'approve');
      workloadIssuanceNeed(workloadIssuanceClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
        && key.userVerification === 'required' && workloadIssuanceText(key.rpId, 253)
        && Number.isSafeInteger(key.timeout) && key.timeout > 0 && key.timeout <= 120000
        && Array.isArray(key.allowCredentials) && key.allowCredentials.length > 0 && key.allowCredentials.length <= 64);
      const digest = await workloadIssuanceObjectHash(payload); current();
      workloadIssuanceBase64(key.challenge, 32);
      workloadIssuanceNeed(digest === options.serverware.payload_digest
        && bytesToB64(new Uint8Array(digest.slice(7).match(/../g).map(part => parseInt(part, 16)))) === key.challenge);
      const ids = key.allowCredentials.map(item => {
        const fields = ['type', 'id'];
        if (item && Object.hasOwn(item, 'transports')) fields.push('transports');
        workloadIssuanceNeed(workloadIssuanceClosed(item, fields) && item.type === 'public-key'
          && (!Object.hasOwn(item, 'transports') || Array.isArray(item.transports) && item.transports.length <= 8
            && item.transports.every(value => ['usb', 'nfc', 'ble', 'internal', 'hybrid'].includes(value))));
        workloadIssuanceBase64(item.id, 3072); return item.id;
      });
      workloadIssuanceNeed(new Set(ids).size === ids.length && window.PublicKeyCredential && navigator.credentials);
      return {key, ids};
    }
    async function workloadIssuanceCeremony(options, binding, userId, current, signal, approval = null) {
      const {key, ids} = await workloadIssuanceOptions(options, binding, userId, current, approval);
      current();
      const credential = await navigator.credentials.get({signal, publicKey: prepareRequestOptions({publicKey:
        {...key, allowCredentials: key.allowCredentials.map(item => ({...item, transports: [...(item.transports || [])]}))}})});
      current();
      workloadIssuanceNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
        && credential.rawId.byteLength <= 3072 && ids.includes(credential.id)
        && bytesToB64(credential.rawId) === credential.id && credential.response);
      let size = 0;
      for (const name of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']) {
        const value = credential.response[name];
        if (value == null && name === 'userHandle') continue;
        workloadIssuanceNeed(value instanceof ArrayBuffer && value.byteLength <= 16 * 1024);
        size += value.byteLength;
      }
      workloadIssuanceNeed(size <= 16 * 1024);
      const assertion = credentialToJson(credential);
      workloadIssuanceNeed(new TextEncoder().encode(JSON.stringify({assertion, approvalId: 'x'.repeat(64)})).byteLength <= 32 * 1024);
      return assertion;
    }
    function workloadIssuanceAssertionMessage(message, failed = false) {
      const target = $('workload-issuance-assertion-status');
      if (!target) return;
      target.textContent = message; target.setAttribute('role', failed ? 'alert' : 'status');
    }
    async function workloadIssuanceCurrentCookie(userId, current, signal) {
      const controller = new AbortController(), abort = () => controller.abort();
      const timer = setTimeout(abort, 10000);
      signal.addEventListener('abort', abort, {once: true});
      try {
        current(); workloadIssuanceNeed(!signal.aborted);
        const response = await fetch('/api/auth/status', {credentials: 'same-origin', mode: 'same-origin',
          cache: 'no-store', redirect: 'error', signal: controller.signal});
        const value = await workloadIssuanceRead(response, 32 * 1024, current);
        workloadIssuanceNeed(response.status === 200 && workloadIssuanceClosed(value, ['authenticated', 'userId',
          'roles', 'authMethod', 'sessionState', 'webauthnRequired', 'oidcBrowserLoginConfigured'])
          && value.authenticated === true && value.userId === userId && value.authMethod === 'oidc-session'
          && value.sessionState === 'active' && value.webauthnRequired === false
          && typeof value.oidcBrowserLoginConfigured === 'boolean' && Array.isArray(value.roles)
          && value.roles.length <= 64 && value.roles.every(role => workloadIssuanceText(role, 128))
          && new Set(value.roles).size === value.roles.length
          && JSON.stringify([...value.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
        current();
      } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
    }
    async function workloadIssuanceReceiptOriginal(file, userId, current) {
      current(); workloadIssuanceNeed(window.isSecureContext && window.location.protocol === 'https:'
        && window.top === window && file instanceof File && file.size >= 2 && file.size <= 192 * 1024);
      const raw = new Uint8Array(await file.arrayBuffer()); current();
      workloadIssuanceNeed(raw.byteLength === file.size);
      const value = workloadIssuanceJson(new TextDecoder('utf-8', {fatal: true}).decode(raw));
      workloadIssuanceNeed(workloadIssuanceClosed(value, ['schema', 'origin', 'path', 'httpStatus', 'body'])
        && value.schema === 'serverware.workloadIdentitySubmissionReceipt/v1'
        && value.origin === window.location.origin && value.path === workloadIssuancePath + '/options'
        && value.httpStatus === 200 && workloadIssuanceClosed(value.body, ['base64Url', 'byteCount', 'bytesDigest'])
        && Number.isSafeInteger(value.body.byteCount) && value.body.byteCount >= 2 && value.body.byteCount <= 32 * 1024
        && workloadIssuanceDigest(value.body.bytesDigest));
      const bodyBytes = workloadIssuanceBase64(value.body.base64Url, 32 * 1024);
      workloadIssuanceNeed(bodyBytes.byteLength === value.body.byteCount
        && await workloadIssuanceHash(bodyBytes) === value.body.bytesDigest); current();
      const body = workloadIssuanceJson(new TextDecoder('utf-8', {fatal: true}).decode(bodyBytes));
      workloadIssuanceNeed(workloadIssuanceClosed(body, ['schema', 'status', 'action', 'resourceId', 'payloadDigest',
        'options', 'automaticRetryAllowed']) && body.schema === workloadIssuanceSchema
        && body.status === 'fresh-assertion-required' && body.action === workloadIssuanceAction
        && workloadIssuanceDigest(body.resourceId) && workloadIssuanceDigest(body.payloadDigest)
        && body.automaticRetryAllowed === false);
      await workloadIssuanceOptions(body.options, body, userId, current); current();
      const receiptDigest = await workloadIssuanceHash(raw); current();
      return {body, receiptDigest};
    }
    function workloadIssuanceAssertionOriginal(assertion, options) {
      workloadIssuanceNeed(workloadIssuanceClosed(assertion, ['id', 'rawId', 'type', 'response'])
        && assertion.type === 'public-key' && assertion.id === assertion.rawId
        && options.publicKey.allowCredentials.some(item => item.id === assertion.id));
      workloadIssuanceBase64(assertion.rawId, 3072);
      const response = assertion.response, fields = ['clientDataJSON', 'authenticatorData', 'signature'];
      if (response && Object.hasOwn(response, 'userHandle')) fields.push('userHandle');
      workloadIssuanceNeed(workloadIssuanceClosed(response, fields));
      const client = workloadIssuanceJson(new TextDecoder('utf-8', {fatal: true}).decode(
        workloadIssuanceBase64(response.clientDataJSON, 8192)));
      const clientFields = ['type', 'challenge', 'origin'];
      if (client && Object.hasOwn(client, 'crossOrigin')) clientFields.push('crossOrigin');
      workloadIssuanceNeed(workloadIssuanceClosed(client, clientFields) && client.type === 'webauthn.get'
        && client.challenge === options.publicKey.challenge && client.origin === window.location.origin
        && (!Object.hasOwn(client, 'crossOrigin') || client.crossOrigin === false));
      workloadIssuanceBase64(response.authenticatorData, 8192);
      workloadIssuanceBase64(response.signature, 8192);
      if (response.userHandle != null) workloadIssuanceBase64(response.userHandle, 1024);
      const bytes = new TextEncoder().encode(JSON.stringify(assertion));
      workloadIssuanceNeed(bytes.byteLength >= 2 && bytes.byteLength <= 32 * 1024);
      return bytes;
    }
    async function workloadIssuanceImportOptions() {
      if (workloadIssuanceBusy || workloadIssuanceUncertain || workloadIssuancePending !== null) return;
      try {
        const userId = workloadIssuanceAuth('policy_author'), files = $('workload-issuance-options-receipt').files;
        workloadIssuanceNeed(files && files.length === 1);
        const file = files[0], epoch = workloadIssuanceEpoch, context = workloadIssuanceScope();
        const current = () => { workloadIssuanceNeed(epoch === workloadIssuanceEpoch
          && context === workloadIssuanceScope() && userId === workloadIssuanceAuth('policy_author')
          && $('workload-issuance-options-receipt').files?.[0] === file); };
        workloadIssuanceBusy = true; workloadIssuanceController = new AbortController();
        workloadIssuanceReceipt = null;
        if (workloadIssuanceAssertionFile) workloadIssuanceAssertionFile.bytes.fill(0);
        workloadIssuanceAssertionFile = null; renderWorkloadIssuance();
        const {body, receiptDigest} = await workloadIssuanceReceiptOriginal(file, userId, current);
        await workloadIssuanceCurrentCookie(userId, current, workloadIssuanceController.signal); current();
        workloadIssuanceNeed(!workloadIssuanceAssertionAttempts.has(body.options.serverware.payload_digest));
        workloadIssuanceReceipt = Object.freeze({file, epoch, context, userId, receiptDigest,
          resourceId: body.resourceId, payloadDigest: body.payloadDigest, challengeDigest: body.options.serverware.payload_digest});
        workloadIssuanceAssertionMessage('Imported for ' + userId + ' · action ' + workloadIssuanceAction
          + ' · resource ' + body.resourceId + ' · payload ' + body.payloadDigest
          + '. Compare these with your local request, then explicitly create the assertion. No issuance contact occurred.');
      } catch (_) {
        workloadIssuanceReceipt = null;
        workloadIssuanceAssertionMessage('No current matching options receipt was imported. Refresh cookie status if it changed; nothing was submitted or retried.', true);
      } finally { workloadIssuanceBusy = false; workloadIssuanceController = null; renderWorkloadIssuance(); }
    }
    async function workloadIssuanceCreateAssertion() {
      if (workloadIssuanceBusy || workloadIssuanceUncertain || workloadIssuancePending !== null) return;
      const held = workloadIssuanceReceipt;
      let bytes = null;
      try {
        workloadIssuanceNeed(held !== null && !workloadIssuanceAssertionAttempts.has(held.challengeDigest));
        const current = () => { workloadIssuanceNeed(workloadIssuanceReceipt === held
          && held.epoch === workloadIssuanceEpoch && held.context === workloadIssuanceScope()
          && held.userId === workloadIssuanceAuth('policy_author')
          && $('workload-issuance-options-receipt').files?.[0] === held.file); };
        current(); workloadIssuanceBusy = true; workloadIssuanceController = new AbortController(); renderWorkloadIssuance();
        const {body, receiptDigest} = await workloadIssuanceReceiptOriginal(held.file, held.userId, current);
        workloadIssuanceNeed(receiptDigest === held.receiptDigest && body.resourceId === held.resourceId
          && body.payloadDigest === held.payloadDigest && body.options.serverware.payload_digest === held.challengeDigest);
        await workloadIssuanceCurrentCookie(held.userId, current, workloadIssuanceController.signal); current();
        // The same imported challenge gets only one ceremony attempt on this page.
        workloadIssuanceAssertionAttempts.add(held.challengeDigest);
        const assertion = await workloadIssuanceCeremony(body.options, body, held.userId, current, workloadIssuanceController.signal);
        bytes = workloadIssuanceAssertionOriginal(assertion, body.options);
        await workloadIssuanceCurrentCookie(held.userId, current, workloadIssuanceController.signal); current();
        const digest = await workloadIssuanceHash(bytes); current();
        workloadIssuanceAssertionFile = Object.freeze({bytes, digest, receipt: held}); bytes = null;
        workloadIssuanceAssertionMessage('One-use assertion ready for explicit download. Pin ' + digest
          + ' locally and protect the file with mode 0600. No issuance was submitted; the original server challenge lifetime is unchanged.');
      } catch (_) {
        if (bytes) bytes.fill(0);
        workloadIssuanceAssertionMessage('No assertion file is available from this attempt. No automatic ceremony retry or issuance submission occurred; original server expiry is unchanged.', true);
      } finally { workloadIssuanceBusy = false; workloadIssuanceController = null; renderWorkloadIssuance(); }
    }
    async function workloadIssuanceDownloadAssertion() {
      if (workloadIssuanceBusy || workloadIssuanceUncertain || workloadIssuancePending !== null) return;
      const held = workloadIssuanceAssertionFile;
      try {
        workloadIssuanceNeed(held !== null);
        const receipt = held.receipt;
        const current = () => { workloadIssuanceNeed(workloadIssuanceAssertionFile === held
          && workloadIssuanceReceipt === receipt && receipt.epoch === workloadIssuanceEpoch
          && receipt.context === workloadIssuanceScope() && receipt.userId === workloadIssuanceAuth('policy_author')
          && $('workload-issuance-options-receipt').files?.[0] === receipt.file); };
        current(); workloadIssuanceBusy = true; workloadIssuanceController = new AbortController(); renderWorkloadIssuance();
        await workloadIssuanceCurrentCookie(receipt.userId, current, workloadIssuanceController.signal); current();
        const url = URL.createObjectURL(new Blob([held.bytes], {type: 'application/json'}));
        const link = document.createElement('a'); link.href = url; link.download = 'workload-identity-assertion.json';
        workloadIssuanceAssertionFile = null; held.bytes.fill(0);
        try { link.click(); } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
        workloadIssuanceAssertionMessage('Assertion download requested once: ' + held.digest
          + '. Protect mode 0600 and pin the file locally. Browser download completion is not verified; no issuance was submitted and no lifetime was renewed.');
      } catch (_) {
        if (held) held.bytes.fill(0);
        workloadIssuanceAssertionFile = null;
        workloadIssuanceAssertionMessage('Assertion download did not finish in the current context. Local assertion bytes were discarded; no automatic retry or issuance contact occurred.', true);
      } finally { workloadIssuanceBusy = false; workloadIssuanceController = null; renderWorkloadIssuance(); }
    }
    async function workloadIssuanceOutcome(reply, originals, current, continuing) {
      const value = reply.payload;
      if (reply.status === 428 && workloadIssuanceClosed(value, ['schema', 'status', 'action', 'resourceId',
          'payloadDigest', 'approvalId', 'freshAuthorizationRequired', 'automaticRetryAllowed'])
          && value.schema === workloadIssuanceSchema && value.status === 'approval-required'
          && value.action === workloadIssuanceAction && value.resourceId === originals.resourceId
          && value.payloadDigest === originals.payloadDigest && workloadIssuanceId(value.approvalId)
          && value.freshAuthorizationRequired === true && value.automaticRetryAllowed === false && !continuing) {
        return {pending: Object.freeze({approvalId: value.approvalId, resourceId: value.resourceId, payloadDigest: value.payloadDigest})};
      }
      if (reply.status !== 200) return {unknown: true};
      workloadIssuanceNeed(workloadIssuanceClosed(value, ['schema', 'status', 'association', 'certificate',
        'proxyAuthenticated', 'enrollmentComplete', 'automaticRetryAllowed'])
        && value.schema === workloadIssuanceSchema && value.status === 'certificate-issued'
        && value.proxyAuthenticated === false && value.enrollmentComplete === false && value.automaticRetryAllowed === false);
      const association = value.association, wrapper = value.certificate;
      workloadIssuanceNeed(workloadIssuanceClosed(association, ['schema', 'authorizationDigest', 'requestDigest',
        'issuerCertificateDigest', 'certificateSha256', 'serialNumber'])
        && association.schema === 'serverware.workloadIdentityIssuerResponse/v1'
        && association.authorizationDigest === originals.binding.authorizationDigest
        && association.requestDigest === originals.binding.requestDigest
        && association.issuerCertificateDigest === originals.binding.issuerCertificateDigest
        && association.serialNumber === originals.serialNumber
        && workloadIssuanceClosed(wrapper, ['base64Url', 'byteCount', 'bytesDigest'])
        && Number.isSafeInteger(wrapper.byteCount) && wrapper.byteCount >= 2 && wrapper.byteCount <= 64 * 1024
        && wrapper.bytesDigest === association.certificateSha256);
      const bytes = workloadIssuanceBase64(wrapper.base64Url, 64 * 1024);
      workloadIssuanceNeed(bytes.byteLength === wrapper.byteCount && await workloadIssuanceHash(bytes) === wrapper.bytesDigest);
      current(); return {certificate: bytes};
    }
    async function workloadIssuanceSubmit(continuing = false) {
      if (workloadIssuanceBusy || workloadIssuanceUncertain) return;
      let originals = null;
      const prior = workloadIssuancePending, epoch = workloadIssuanceEpoch, context = workloadIssuanceScope();
      try {
        const userId = workloadIssuanceAuth('policy_author'), files = workloadIssuanceFiles();
        workloadIssuanceNeed(continuing ? prior !== null : prior === null);
        const current = () => { workloadIssuanceNeed(epoch === workloadIssuanceEpoch
          && context === workloadIssuanceScope() && userId === workloadIssuanceAuth('policy_author')
          && files.every((file, index) => $(workloadIssuanceFileIds[index]).files?.[0] === file)); };
        workloadIssuanceBusy = true; workloadIssuanceContact = false;
        workloadIssuanceController = new AbortController();
        // Consume the explicit continuation locally before any new options.
        if (continuing) workloadIssuancePending = null;
        renderWorkloadIssuance();
        originals = await workloadIssuanceOriginals(files, current); current();
        const attempt = originals.payloadDigest;
        if (continuing) workloadIssuanceNeed(prior.payloadDigest === attempt && prior.resourceId === originals.resourceId);
        else { workloadIssuanceNeed(!workloadIssuanceAttempts.has(attempt)); workloadIssuanceAttempts.add(attempt); }
        const options = await workloadIssuancePost(workloadIssuancePath + '/options', originals.body,
          current, workloadIssuanceController.signal);
        const data = options.payload;
        workloadIssuanceNeed(options.status === 200 && workloadIssuanceClosed(data,
          ['schema', 'status', 'action', 'resourceId', 'payloadDigest', 'options', 'automaticRetryAllowed'])
          && data.schema === workloadIssuanceSchema && data.status === 'fresh-assertion-required'
          && data.action === workloadIssuanceAction && data.resourceId === originals.resourceId
          && data.payloadDigest === originals.payloadDigest && data.automaticRetryAllowed === false);
        const assertion = await workloadIssuanceCeremony(data.options, originals, userId, current, workloadIssuanceController.signal);
        const mfa = continuing ? {assertion, approvalId: prior.approvalId} : {assertion};
        const reply = await workloadIssuancePost(workloadIssuancePath, {...originals.body, mfa}, current,
          workloadIssuanceController.signal, () => { workloadIssuanceContact = true; });
        const outcome = await workloadIssuanceOutcome(reply, originals, current, continuing); current();
        if (outcome.pending) {
          workloadIssuanceContact = false; workloadIssuancePending = outcome.pending;
          workloadIssuanceMessage('Approval is required. A different operator must review the exact binding. After approval, explicitly continue with a new passkey; nothing is resubmitted automatically.');
        } else if (outcome.certificate) {
          workloadIssuanceContact = false; workloadIssuanceCertificate = outcome.certificate;
          workloadIssuanceMessage('Server returned a matching public certificate. Download it for genuine local admission; enrollment and proxy authentication remain unconfirmed.');
        } else { workloadIssuanceUncertain = true; workloadIssuanceMessage('No certificate result was admitted. Do not retry an uncertain issuance.', true); }
      } catch (_) {
        if (workloadIssuanceContact) workloadIssuanceUncertain = true;
        workloadIssuanceMessage('The explicit operation did not finish. No automatic retry, approval continuation or certificate admission occurred.', true);
      } finally {
        originals = null; workloadIssuanceContact = false; workloadIssuanceBusy = false;
        workloadIssuanceController = null; renderWorkloadIssuance();
      }
    }
    async function workloadIssuanceApprove(id, note) {
      workloadIssuanceNeed(!workloadIssuanceBusy && workloadIssuanceId(id) && !workloadIssuanceApprovalAttempts.has(id));
      const item = (state.controlPlaneApprovals || []).find(value => value.id === id);
      const userId = workloadIssuanceAuth('approver');
      workloadIssuanceNeed(item?.action === workloadIssuanceAction && item.status === 'pending'
        && item.can_approve === true && workloadIssuanceText(item.requester_id, 4096) && item.requester_id !== userId
        && workloadIssuanceDigest(item.resource_id) && workloadIssuanceDigest(item.payload_digest)
        && workloadIssuanceText(item.expires_at, 128) && (note === null || workloadIssuanceText(note, 500)));
      const held = Object.freeze({id, requester_id: item.requester_id, expires_at: item.expires_at,
        resourceId: item.resource_id, payloadDigest: item.payload_digest});
      const epoch = workloadIssuanceEpoch, context = workloadIssuanceScope();
      const current = () => { workloadIssuanceNeed(epoch === workloadIssuanceEpoch
        && context === workloadIssuanceScope() && userId === workloadIssuanceAuth('approver')); };
      workloadIssuanceApprovalAttempts.add(id); workloadIssuanceBusy = true;
      workloadIssuanceController = new AbortController(); renderWorkloadIssuance();
      let submitted = false;
      try {
        const options = await workloadIssuancePost('/api/control-plane/mutations/webauthn/options',
          {action: workloadIssuanceAction, resourceId: held.resourceId, payloadDigest: held.payloadDigest, approvalId: id},
          current, workloadIssuanceController.signal);
        workloadIssuanceNeed(options.status === 200);
        const assertion = await workloadIssuanceCeremony(options.payload, held, userId, current,
          workloadIssuanceController.signal, held);
        const result = await workloadIssuancePost('/api/control-plane/approvals/' + id + '/approve',
          {note, mfa: {assertion}}, current, workloadIssuanceController.signal, () => { submitted = true; });
        const approved = result.payload;
        workloadIssuanceNeed(result.status === 200 && workloadIssuanceClosed(approved, ['id', 'action', 'resource_id',
          'payload_digest', 'status', 'requester_id', 'requested_at', 'expires_at', 'approved_by', 'approved_at',
          'consumed_by', 'consumed_at', 'decision_note', 'approver_webauthn_credential_id', 'request'])
          && approved.id === id && approved.action === workloadIssuanceAction && approved.status === 'approved'
          && approved.requester_id === held.requester_id && approved.approved_by === userId
          && approved.resource_id === held.resourceId && approved.payload_digest === held.payloadDigest
          && approved.expires_at === held.expires_at);
        workloadIssuanceMessage('Approval recorded for the exact request. The requester must explicitly continue with a new passkey; no certificate was issued by this approval action.');
        return {pending: true};
      } catch (_) {
        if (submitted) workloadIssuanceApprovalUnknown = true;
        workloadIssuanceMessage(submitted ? 'Approval outcome is unknown. Review the queue; no automatic resubmission is permitted.'
          : 'Fresh approval did not finish. No automatic retry is permitted.', true);
        return {blocked: true};
      } finally { workloadIssuanceBusy = false; workloadIssuanceController = null; renderWorkloadIssuance(); }
    }
    function workloadIssuanceReview(value) {
      const fields = ['action', 'authorizationDigest', 'packetDigest', 'requestDigest', 'principalId', 'nonce',
        'bootstrapDigest', 'configurationDigest', 'issuerCertificateDigest', 'grantId'];
      if (!workloadIssuanceClosed(value, fields) || value.action !== workloadIssuanceAction
          || !fields.filter(key => key.endsWith('Digest')).every(key => workloadIssuanceDigest(value[key]))
          || !['principalId', 'nonce', 'grantId'].every(key => workloadIssuanceText(value[key]))) return {};
      return Object.fromEntries(fields.map(key => [key, value[key]]));
    }
    function initWorkloadIssuance() {
      workloadIssuanceFileIds.forEach(id => $(id).addEventListener('change', () => workloadIssuanceInvalidate('Original file selection changed.', false)));
      $('workload-issuance-options-receipt').addEventListener('change', () => workloadIssuanceInvalidate('Options receipt selection changed.', false));
      $('workload-issuance-import-options').addEventListener('click', workloadIssuanceImportOptions);
      $('workload-issuance-create-assertion').addEventListener('click', workloadIssuanceCreateAssertion);
      $('workload-issuance-download-assertion').addEventListener('click', workloadIssuanceDownloadAssertion);
      $('workload-issuance-start').addEventListener('click', () => workloadIssuanceSubmit(false));
      $('workload-issuance-continue').addEventListener('click', () => workloadIssuanceSubmit(true));
      $('workload-issuance-clear').addEventListener('click', () => workloadIssuanceInvalidate('Local files cleared.'));
      $('workload-issuance-download').addEventListener('click', () => {
        try {
          workloadIssuanceAuth('policy_author');
          workloadIssuanceNeed(!workloadIssuanceBusy && workloadIssuanceContext === workloadIssuanceScope()
            && workloadIssuanceCertificate instanceof Uint8Array);
          const url = URL.createObjectURL(new Blob([workloadIssuanceCertificate], {type: 'application/x-pem-file'}));
          const link = document.createElement('a'); link.href = url; link.download = 'workload-identity-certificate.pem';
          link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (_) { workloadIssuanceMessage('No current matching certificate is available for download.', true); }
      });
      window.addEventListener('pagehide', () => workloadIssuanceInvalidate('Page closed.'));
      renderWorkloadIssuance();
    }
"""
