"""Cookie-only static rotation; new plaintext stays on the native TLS page.

Original candidates and assertions remain page-local. Browser checks constrain
this continuation only; the authority independently verifies every original.
No polling, storage, automatic approval, effect retry or implicit Setup binding.
"""

STATIC_CREDENTIAL_ROTATION_SCRIPT = r"""
const staticRotationSchema = 'serverware.staticCredentialRotationPortalRequest/v1';
const staticRotationReview = 'serverware.staticCredentialRotationReview/v1';
const staticRotationPrefix = '/api/credentials/static/rotation';
const staticRotationDecisionAttempts = new Set();
const staticRotationOriginals = new WeakMap();
function staticRotationNeed(ok) {
  if (!ok) throw new Error('Static credential context is unavailable or changed. Do not retry an uncertain action.');
}
function staticRotationClosed(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}
function staticRotationText(value, limit = 4 * 1024 * 1024) {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= limit;
}
function staticRotationJson(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
}
function staticRotationNumberView(original) {
  // Display/comparison only: retain integer spelling, including int64 versions.
  // Never send this projection or rebuild an Original from parsed JSON.
  staticRotationNeed(staticRotationText(original));
  return JSON.parse(original.replace(/"(?:\\[\s\S]|[^"\\])*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/g,
    token => token.startsWith('"') ? token : JSON.stringify(token)));
}
function staticRotationVersions(original) {
  const request = staticRotationNumberView(original).request;
  const previous = request?.previousCredentialVersion, next = request?.credentialVersion;
  staticRotationNeed(typeof previous === 'string' && typeof next === 'string'
    && /^[1-9][0-9]{0,18}$/.test(previous) && /^[1-9][0-9]{0,18}$/.test(next)
    && BigInt(previous) < 9223372036854775807n && BigInt(next) === BigInt(previous) + 1n);
  return {previous, next};
}
function staticRotationFailure(error, identity) {
  const details = error?.uncertainty;
  let message = 'Outcome uncertain or refused. No retry is allowed from this continuation.';
  if (details?.code === 'static_rotation_drain_uncertain') {
    message = 'The predecessor drain may have started. Do not reset, retry or renew it.';
    identity += '\nServer credential: ' + details.credentialId + '\nServer candidate: ' + details.candidateSha256;
  } else if (details?.code === 'static_rotation_commit_uncertain') {
    message = 'The protected operation may have committed. Inspect its original identity; do not retry it.';
    identity += '\nServer operation: ' + details.operation + '\nServer request: ' + details.requestDigest;
  }
  return message + '\n' + identity;
}
function staticRotationExpiry(value) {
  staticRotationNeed(typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value));
  const milliseconds = BigInt(value) / 1000000n;
  staticRotationNeed(milliseconds <= BigInt(Number.MAX_SAFE_INTEGER));
  return Number(milliseconds);
}
function staticRotationOperation(checkContext, auth = null) {
  const controller = new AbortController();
  let wall = Date.now(), mono = performance.now(), expires = wall + 30000, deadline = mono + 30000;
  const timer = setTimeout(() => controller.abort(), 30000);
  return {controller, auth,
    check() {
      const nextWall = Date.now(), nextMono = performance.now();
      staticRotationNeed(!controller.signal.aborted && nextWall >= wall && nextMono >= mono
        && nextWall < expires && nextMono < deadline);
      wall = nextWall; mono = nextMono; checkContext();
    },
    clip(epoch) {
      this.check(); expires = Math.min(expires, staticRotationExpiry(epoch));
      deadline = Math.min(deadline, performance.now() + expires - Date.now()); this.check();
    },
    close() { clearTimeout(timer); controller.abort(); }
  };
}
async function staticRotationRead(response, operation, maximum = 4 * 1024 * 1024) {
  operation.check();
  staticRotationNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
  let original = '', size = 0, complete = false;
  try {
    for (;;) {
      const item = await reader.read(); operation.check();
      if (item.done) { complete = true; break; }
      size += item.value.byteLength; staticRotationNeed(size <= maximum);
      original += decoder.decode(item.value, {stream: true});
    }
    original += decoder.decode(); operation.check();
    const value = JSON.parse(original);
    if (!response.ok) {
      const drain = response.status === 409 && staticRotationClosed(value,
        ['ok', 'code', 'retryAllowed', 'credentialId', 'candidateSha256'])
        && value.code === 'static_rotation_drain_uncertain'
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.credentialId)
        && /^sha256:[0-9a-f]{64}$/.test(value.candidateSha256);
      const commit = response.status === 409 && staticRotationClosed(value,
        ['ok', 'code', 'retryAllowed', 'operation', 'requestDigest'])
        && value.code === 'static_rotation_commit_uncertain'
        && ['credential.static.rotate', 'credential.static.rotation-approval-request',
          'credential.static.rotation-approval-decide'].includes(value.operation)
        && /^sha256:[0-9a-f]{64}$/.test(value.requestDigest);
      const error = new Error('Static rotation request was not confirmed. Do not retry an uncertain action.');
      if ((drain || commit) && value.ok === false && value.retryAllowed === false) error.uncertainty = Object.freeze(value);
      throw error;
    }
    staticRotationNeed(value && typeof value === 'object' && !Array.isArray(value));
    staticRotationOriginals.set(value, original);
    return value;
  } finally {
    if (!complete) { try { await reader.cancel(); } catch (_) {} }
    reader.releaseLock();
  }
}
async function staticRotationCookie(operation) {
  operation.check();
  const reply = await fetch('/api/auth/status', {credentials: 'same-origin', mode: 'same-origin',
    redirect: 'error', cache: 'no-store', signal: operation.controller.signal});
  const value = await staticRotationRead(reply, operation, 32768);
  staticRotationNeed(staticRotationClosed(value, ['authenticated', 'userId', 'roles', 'authMethod', 'sessionState',
    'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode']) && value.authenticated === true
    && value.authMethod === 'oidc-session' && value.sessionState === 'active' && value.webauthnRequired === false
    && staticRotationText(value.userId, 512) && Array.isArray(value.roles) && value.roles.length <= 64
    && value.roles.every(role => staticRotationText(role, 128)) && new Set(value.roles).size === value.roles.length
    && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
    && typeof value.oidcBrowserLoginConfigured === 'boolean');
  const scope = staticRotationJson({...value, roles: [...value.roles].sort()});
  staticRotationNeed(operation.auth === null || operation.auth === scope); operation.auth = scope;
  operation.check(); return value;
}
async function staticRotationRequest(route, body, operation) {
  staticRotationNeed(/^(assignment|readiness|predecessor|intent|candidate|approval\/status|(approval\/(request|decide)|rotate)\/(draft|options|execute))$/.test(route));
  await staticRotationCookie(operation); operation.check();
  const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin',
    redirect: 'error', cache: 'no-store', signal: operation.controller.signal});
  const csrf = await staticRotationRead(csrfResponse, operation, 4096);
  staticRotationNeed(staticRotationClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
    && staticRotationText(csrf.token, 1024) && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token');
  const original = staticRotationJson({apiVersion: staticRotationSchema, ...body});
  staticRotationNeed(new TextEncoder().encode(original).length <= 4 * 1024 * 1024); operation.check();
  const response = await fetch(staticRotationPrefix + '/' + route, {method: 'POST', credentials: 'same-origin',
    mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.controller.signal,
    headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: original});
  operation.check(); return staticRotationRead(response, operation);
}
function staticRotationDraft(value, expected, operation) {
  staticRotationNeed(staticRotationClosed(value, ['apiVersion', 'okForAction', 'operation', 'argumentsOriginal',
    'requestDigest', 'expiresAtEpochNs']) && value.apiVersion === staticRotationSchema && value.okForAction === false
    && value.operation === expected && staticRotationText(value.argumentsOriginal)
    && /^sha256:[0-9a-f]{64}$/.test(value.requestDigest));
  operation.clip(value.expiresAtEpochNs); return value;
}
function staticRotationBytes(value) {
  staticRotationNeed(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && value.length <= 32768);
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
}
function staticRotationB64(value) {
  staticRotationNeed(value instanceof ArrayBuffer && value.byteLength <= 16384);
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function staticRotationMfa(route, draft, operation) {
  const options = await staticRotationRequest(route + '/options', {argumentsOriginal: draft.argumentsOriginal}, operation);
  const rotate = route === 'rotate', schema = rotate ? 'serverware.staticCredentialRotationOptions/v1' : 'serverware.staticCredentialRotationApprovalOptions/v1';
  staticRotationNeed(staticRotationClosed(options, ['publicKey', 'serverware'])
    && staticRotationClosed(options.serverware, ['schema', 'operation', 'requestDigest', 'challengeId', 'credentialRecordId', 'expiresAt'])
    && options.serverware.schema === schema && options.serverware.operation === draft.operation
    && options.serverware.requestDigest === draft.requestDigest && options.publicKey?.userVerification === 'required'
    && Array.isArray(options.publicKey.allowCredentials) && options.publicKey.allowCredentials.length === 1);
  const expiry = Date.parse(options.serverware.expiresAt);
  staticRotationNeed(Number.isSafeInteger(expiry) && expiry > Date.now()); operation.clip(String(BigInt(expiry) * 1000000n));
  const publicKey = {...options.publicKey, challenge: staticRotationBytes(options.publicKey.challenge),
    allowCredentials: options.publicKey.allowCredentials.map(value => ({...value, id: staticRotationBytes(value.id)}))};
  operation.check();
  const credential = await navigator.credentials.get({publicKey, signal: operation.controller.signal}); operation.check();
  staticRotationNeed(credential?.type === 'public-key' && credential.id === options.publicKey.allowCredentials[0].id
    && staticRotationB64(credential.rawId) === credential.id);
  const assertion = {id: credential.id, rawId: staticRotationB64(credential.rawId), type: credential.type,
    response: {clientDataJSON: staticRotationB64(credential.response.clientDataJSON),
      authenticatorData: staticRotationB64(credential.response.authenticatorData), signature: staticRotationB64(credential.response.signature),
      userHandle: credential.response.userHandle === null ? null : staticRotationB64(credential.response.userHandle)}};
  const mfa = {[rotate ? 'staticCredentialRotationProfile' : 'staticCredentialRotationApprovalProfile']: schema, assertion};
  staticRotationNeed(staticRotationJson(mfa).length <= 16384); return mfa;
}
async function staticRotationDecide(id, decision) {
  const item = (state.controlPlaneApprovals || []).find(value => value.id === id);
  staticRotationNeed(item?.request?.apiVersion === staticRotationReview && item.status === 'pending'
    && ['approve', 'deny'].includes(decision) && !adminToken() && !staticRotationDecisionAttempts.has(id)
    && ($('control-plane-note-' + id)?.value ?? '') === '');
  const scope = policyAuthoringScope(), original = staticRotationJson(item);
  const operation = staticRotationOperation(() => staticRotationNeed(scope === policyAuthoringScope()
    && !adminToken() && original === staticRotationJson((state.controlPlaneApprovals || []).find(value => value.id === id))));
  staticRotationDecisionAttempts.add(id);
  let requestDigest = '(draft not returned)';
  try {
    const draft = staticRotationDraft(await staticRotationRequest('approval/decide/draft', {approvalId: id, decision}, operation),
      'credential.static.rotation-approval-decide', operation);
    requestDigest = draft.requestDigest;
    const held = JSON.parse(JSON.parse(draft.argumentsOriginal).request.approvalOriginal);
    // The server retained its full row. Compare the actually displayed compact
    // review; never recreate the signed original from rounded browser numbers.
    staticRotationNeed(held.id === id && held.payload_digest === item.payload_digest
      && staticRotationJson(JSON.parse(held.request_json)) === staticRotationJson(item.request));
    const reviewed = JSON.parse(held.request_json);
    const versions = staticRotationVersions('{"request":' + held.request_json + '}');
    staticRotationNeed(window.confirm((decision === 'approve' ? 'Approve' : 'Deny') + ' this exact rotation review?'
      + '\nCredential: ' + reviewed.credentialId + '\nVersion: ' + versions.previous + ' → ' + versions.next
      + '\nCandidate: ' + held.payload_digest + '\nApproval: ' + id
      + '\nThis decision does not rotate the credential.'));
    const mfa = await staticRotationMfa('approval/decide', draft, operation);
    const result = await staticRotationRequest('approval/decide/execute', {argumentsOriginal: draft.argumentsOriginal, mfa}, operation);
    staticRotationNeed(result.ok === true && result.operation === draft.operation && result.requestDigest === draft.requestDigest
      && result.approval?.id === id && result.approval.status === (decision === 'approve' ? 'approved' : 'denied')
      && result.candidateSha256 === item.payload_digest && result.auditState === 'controlled_pending');
    setStatus('Static rotation decision recorded. Audit publication is pending; no credential was rotated.');
  } catch (error) {
    setStatus(staticRotationFailure(error, 'Approval: ' + id
      + '\nOperation: credential.static.rotation-approval-decide\nRequest: ' + requestDigest));
    return;
  } finally { operation.close(); }
  await refresh();
}
"""

STATIC_CREDENTIAL_ROTATION_PAGE_SCRIPT = r"""
let rotationFlow = null;
const sr = id => document.getElementById(id);
function rotationPageMessage(value) { sr('rotation-status').textContent = value; }
let rotationAssignmentBusy = false;
let rotationPrerequisitesObserved = false;
function rotationPagePrefill() {
  const fragment = window.location.hash;
  if (!fragment) return;
  try {
    // Public editable navigation only, never an authority or retained version.
    // Remove it before parsing or any network work; no query/storage fallback.
    window.history.replaceState(null, '', '/credentials/static/rotation');
    const match = fragment.length === 48
      && /^#credential=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(fragment);
    if (!match) throw new Error('Invalid rotation shortcut');
    sr('rotation-credential-id').value = match[1];
    rotationPageMessage('Credential ID copied from the inventory. Review it and check intake prerequisites. No predecessor read, intake or drain has started.');
  } catch (_) {
    rotationPageMessage('The rotation shortcut could not be used. Enter the existing credential ID manually. No request or drain was started.');
  }
}
rotationPagePrefill();
function rotationPagePrerequisiteControls() {
  sr('rotation-assignment-admit').disabled = sr('rotation-readiness-check').disabled = rotationAssignmentBusy || Boolean(rotationFlow);
  sr('rotation-start').disabled = rotationAssignmentBusy || Boolean(rotationFlow) || !rotationPrerequisitesObserved;
}
async function rotationPageObservePrerequisites(operation) {
  rotationPrerequisitesObserved = false;
  const result = await staticRotationRequest('readiness', {}, operation);
  staticRotationNeed(staticRotationClosed(result, ['apiVersion', 'okForAction', 'nativeAssignmentState',
    'currentnessAssignmentState', 'intakePrerequisitesMet', 'observedAtEpochNs', 'expiresAtEpochNs'])
    && result.apiVersion === staticRotationSchema && result.okForAction === false
    && ['missing', 'retained', 'expired'].includes(result.nativeAssignmentState)
    && ['missing', 'retained', 'unavailable'].includes(result.currentnessAssignmentState)
    && result.intakePrerequisitesMet === (result.nativeAssignmentState === 'retained' && result.currentnessAssignmentState === 'retained')
    && staticRotationExpiry(result.observedAtEpochNs) < staticRotationExpiry(result.expiresAtEpochNs));
  operation.clip(result.expiresAtEpochNs);
  rotationPrerequisitesObserved = result.intakePrerequisitesMet;
  sr('rotation-readiness-status').textContent = rotationPrerequisitesObserved
    ? 'Both required assignments observed. Intake rechecks before starting. This is not native serving readiness or permission to drain or rotate.'
    : 'Native assignment: ' + result.nativeAssignmentState + '; currentness startup assignment: ' + result.currentnessAssignmentState
      + '. The deployment operator must resolve missing or unavailable originals. This page cannot provision or renew them. No intake or drain started.';
  return rotationPrerequisitesObserved;
}
sr('rotation-readiness-check').addEventListener('click', () => {
  if (rotationAssignmentBusy || rotationFlow) return;
  rotationAssignmentBusy = true; rotationPrerequisitesObserved = false; rotationPagePrerequisiteControls();
  const operation = staticRotationOperation(() => staticRotationNeed(!rotationFlow));
  void (async () => {
    try { await rotationPageObservePrerequisites(operation); }
    catch (_) { sr('rotation-readiness-status').textContent = 'Prerequisites were not confirmed. No intake or drain started. Check again explicitly after the operator resolves them.'; }
    finally { operation.close(); rotationAssignmentBusy = false; rotationPagePrerequisiteControls(); }
  })();
});
sr('rotation-assignment-admit').addEventListener('click', () => {
  if (rotationAssignmentBusy || rotationFlow) return;
  const original = sr('rotation-assignment-original').value;
  const operation = staticRotationOperation(() => staticRotationNeed(!rotationFlow
    && sr('rotation-assignment-original').value === original));
  rotationAssignmentBusy = true; rotationPrerequisitesObserved = false; rotationPagePrerequisiteControls();
  void (async () => {
    try {
      staticRotationNeed(staticRotationText(original, 65536));
      const result = await staticRotationRequest('assignment', {assignmentOriginal: original}, operation);
      staticRotationNeed(staticRotationClosed(result, ['apiVersion', 'okForAction', 'assignmentSha256', 'holderId', 'expiresAtEpochNs'])
        && result.apiVersion === staticRotationSchema && result.okForAction === false
        && /^sha256:[0-9a-f]{64}$/.test(result.assignmentSha256) && /^sha256:[0-9a-f]{64}$/.test(result.holderId));
      operation.clip(result.expiresAtEpochNs);
      sr('rotation-assignment-status').textContent = 'Independent assignment retained: ' + result.assignmentSha256
        + '. Each rotation still requires fresh native proof and your passkey. No credential was changed.';
      await rotationPageObservePrerequisites(operation);
    } catch (_) {
      sr('rotation-assignment-status').textContent = 'Assignment admission was not confirmed. The same signed original may be inspected again; a different assignment cannot replace it. No credential action was sent.';
    } finally {
      operation.close(); rotationAssignmentBusy = false;
      rotationPagePrerequisiteControls();
    }
  })();
});
function rotationPageCheck(flow) {
  staticRotationNeed(rotationFlow === flow && !flow.failed && flow.popup && !flow.popup.closed
    && Date.now() >= flow.lastWall && performance.now() >= flow.lastMono
    && Date.now() < flow.expires && performance.now() < flow.deadline);
  flow.lastWall = Date.now(); flow.lastMono = performance.now();
}
function rotationPageFail(flow, error = null) {
  if (!flow) { rotationPageMessage('No retained rotation continuation is available.'); return; }
  flow.failed = true; sr('rotation-request').disabled = sr('rotation-rotate').disabled = sr('rotation-approval-status').disabled = true;
  if (flow.waiter) { flow.waiter.reject(new Error('Native preparation outcome is uncertain.')); flow.waiter = null; }
  rotationPageMessage(staticRotationFailure(error, 'Credential: ' + (flow.id || flow.requestedId)
    + '\nCandidate: ' + (flow.digest || '(not returned)') + '\nApproval: ' + (flow.approvalId || '(none)')
    + '\nOperation: ' + (flow.activeOperation || '(intake only)')
    + '\nRequest: ' + (flow.requestDigest || '(draft not returned)'))
    + '\nReloading or opening another tab does not resolve uncertainty.');
}
window.addEventListener('message', event => {
  const flow = rotationFlow;
  if (!flow || flow.failed || event.source !== flow.popup || event.origin !== flow.origin) return;
  const value = event.data;
  try {
    rotationPageCheck(flow);
    if (value?.apiVersion === 'serverware.nativeStaticCredentialRotationReadyMessage/v1') {
      if (flow.ready) return;
      staticRotationNeed(staticRotationClosed(value, ['apiVersion'])); flow.ready = true;
      staticRotationNeed(!flow.intentSent && staticRotationText(flow.intentOriginal)); flow.intentSent = true;
      flow.popup.postMessage({apiVersion: 'serverware.nativeStaticCredentialRotationIntentMessage/v1', intentOriginal: flow.intentOriginal}, flow.origin);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialRotationCandidateMessage/v1') {
      staticRotationNeed(staticRotationClosed(value, ['apiVersion', 'candidateOriginal']) && flow.intentSent
        && !flow.candidateReceived && staticRotationText(value.candidateOriginal));
      flow.candidateReceived = true; void rotationPageCandidate(flow, value.candidateOriginal);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialRotationPreparedMessage/v1') {
      staticRotationNeed(staticRotationClosed(value, ['apiVersion', 'preparationOriginal']) && flow.waiter
        && staticRotationText(value.preparationOriginal));
      const reply = JSON.parse(value.preparationOriginal);
      staticRotationNeed(reply.apiVersion === 'serverware.nativeStaticCredentialRotationPreparationResponse/v1'
        && reply.argumentsOriginal === flow.waiter.argumentsOriginal);
      const waiter = flow.waiter; flow.waiter = null; waiter.resolve(value.preparationOriginal);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialRotationPrepareFailedMessage/v1') {
      staticRotationNeed(staticRotationClosed(value, ['apiVersion', 'credentialId', 'argumentsOriginal', 'outcome'])
        && flow.waiter && value.credentialId === flow.id && value.argumentsOriginal === flow.waiter.argumentsOriginal
        && value.outcome === 'uncertain'); rotationPageFail(flow);
    }
  } catch (_) { rotationPageFail(flow); }
});
async function rotationPageCandidate(flow, original) {
  const operation = staticRotationOperation(() => rotationPageCheck(flow), flow.auth);
  try {
    const native = JSON.parse(original);
    staticRotationNeed(native.apiVersion === 'serverware.nativeStaticCredentialRotationCandidateResponse/v1'
      && native.candidate?.credentialId === flow.id && native.candidate.intentOriginal === flow.intentOriginal);
    const result = await staticRotationRequest('candidate', {candidateOriginal: original}, operation);
    staticRotationNeed(result.apiVersion === staticRotationSchema && result.okForAction === false
      && staticRotationText(result.candidateArgumentsOriginal) && /^sha256:[0-9a-f]{64}$/.test(result.candidateSha256)
      && result.credentialId === flow.id && result.portalOrigin === location.origin
      && result.intakeOrigin === flow.origin && result.twoPersonRequired === flow.twoPerson);
    const candidate = JSON.parse(result.candidateArgumentsOriginal);
    const versions = staticRotationVersions(result.candidateArgumentsOriginal);
    staticRotationNeed(candidate.request?.credentialId === flow.id && candidate.approval_id === null
      && candidate.request.nativeGenerationOriginal === native.candidate.nativeGenerationOriginal
      && candidate.request.previousProvenanceOriginal === flow.provenance
      && candidate.request.predecessorBarrierSha256 === null && candidate.request.predecessorCurrentnessRootSha256 === null
      && versions.previous === flow.previousVersion && versions.next === flow.nextVersion);
    flow.candidate = result.candidateArgumentsOriginal; flow.digest = result.candidateSha256;
    flow.expires = Math.min(flow.expires, staticRotationExpiry(result.expiresAtEpochNs));
    flow.deadline = Math.min(flow.deadline, performance.now() + flow.expires - Date.now()); rotationPageCheck(flow);
    sr('rotation-request').disabled = !flow.twoPerson; sr('rotation-rotate').disabled = flow.twoPerson;
    rotationPageMessage('Candidate sealed, not saved. ' + (flow.twoPerson ? 'Request a distinct operator’s approval, explicitly check its status, then Rotate.' : 'Explicitly Rotate with a fresh passkey.'));
  } catch (error) { rotationPageFail(flow, error); } finally { operation.close(); }
}
sr('rotation-form').addEventListener('submit', event => {
  event.preventDefault();
  if (rotationFlow || rotationAssignmentBusy || !rotationPrerequisitesObserved) return;
  const form = new FormData(event.target), requestedId = String(form.get('credentialId'));
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(requestedId)) {
    rotationPageMessage('Correct the existing credential ID to its exact UUID. No request, intake or drain was started.'); return;
  }
  // Open synchronously inside the user gesture. Never noopener: the two fixed
  // origins deliberately retain this exact WindowProxy, not a named window.
  const popup = window.open('about:blank', '_blank');
  if (!popup) { rotationPageMessage('Allow this page’s native intake popup, then start explicitly.'); return; }
  let flow = null;
  rotationAssignmentBusy = true; rotationPrerequisitesObserved = false; rotationPagePrerequisiteControls();
  for (const field of event.target.elements) field.disabled = true;
  void (async () => {
    const operation = staticRotationOperation(() => flow ? rotationPageCheck(flow)
      : staticRotationNeed(!rotationFlow && rotationAssignmentBusy && !popup.closed));
    try {
      if (!await rotationPageObservePrerequisites(operation)) return;
      // No flow or drain attempt exists until the read-only prerequisites pass.
      flow = {popup, origin: null, auth: null, ready: false, intentSent: false, candidateReceived: false,
        failed: false, busy: true, lastWall: Date.now(), lastMono: performance.now(),
        expires: Date.now() + 30000, deadline: performance.now() + 30000, requestAttempted: false, rotateAttempted: false,
        requestedId, provenance: null};
      rotationFlow = flow;
      rotationPageMessage('Reading the current generation and its retained public provenance. No drain or rotation has started.');
      const previous = await staticRotationRequest('predecessor', {credentialId: flow.requestedId}, operation);
      staticRotationNeed(staticRotationClosed(previous, ['apiVersion', 'okForAction', 'credentialId', 'credentialVersion',
        'originRequestDigest', 'provenanceOriginal', 'provenanceSha256'])
        && previous.apiVersion === 'serverware.staticCredentialProvenanceObservation/v1' && previous.okForAction === false
        && previous.credentialId === flow.requestedId && staticRotationText(previous.provenanceOriginal, 40960)
        && /^sha256:[0-9a-f]{64}$/.test(previous.originRequestDigest)
        && /^sha256:[0-9a-f]{64}$/.test(previous.provenanceSha256));
      const previousVersion = staticRotationNumberView(staticRotationOriginals.get(previous)).credentialVersion;
      staticRotationNeed(typeof previousVersion === 'string' && /^[1-9][0-9]{0,18}$/.test(previousVersion)
        && BigInt(previousVersion) < 9223372036854775807n);
      flow.provenance = previous.provenanceOriginal;
      const result = await staticRotationRequest('intent', {credentialId: flow.requestedId,
        previousProvenanceOriginal: flow.provenance, ttlSeconds: Number(form.get('ttlSeconds'))}, operation);
      staticRotationNeed(staticRotationClosed(result, ['apiVersion', 'okForAction', 'intentOriginal', 'credentialId',
        'expiresAtEpochNs', 'intakeOrigin', 'portalOrigin', 'twoPersonRequired'])
        && result.apiVersion === staticRotationSchema && result.okForAction === false && result.credentialId === flow.requestedId
        && result.portalOrigin === location.origin && staticRotationText(result.intentOriginal)
        && typeof result.twoPersonRequired === 'boolean');
      const intent = JSON.parse(result.intentOriginal), versions = staticRotationVersions(result.intentOriginal);
      staticRotationNeed(intent.apiVersion === 'serverware.staticCredentialRotationIntent/v1'
        && intent.operation === 'credential.static.rotate' && intent.request?.credentialId === flow.requestedId
        && intent.request.previousProvenanceOriginal === flow.provenance
        && intent.request.previousCurrentnessOriginRequestDigest === previous.originRequestDigest
        && versions.previous === previousVersion
        && typeof intent.request.name === 'string' && typeof intent.request.kind === 'string');
      const origin = new URL(result.intakeOrigin);
      staticRotationNeed(origin.protocol === 'https:' && origin.origin === result.intakeOrigin
        && origin.username === '' && origin.password === '' && origin.origin !== location.origin);
      flow.origin = origin.origin; flow.auth = operation.auth; flow.id = result.credentialId;
      flow.intentOriginal = result.intentOriginal; flow.twoPerson = result.twoPersonRequired;
      flow.previousVersion = versions.previous; flow.nextVersion = versions.next;
      sr('rotation-selection').textContent = 'Credential: ' + flow.id + '\nVersion: ' + versions.previous + ' → ' + versions.next
        + '\nName: ' + intent.request.name + '\nKind: ' + intent.request.kind
        + '\nExisting public metadata: ' + JSON.stringify(intent.request.metadata);
      flow.expires = staticRotationExpiry(result.expiresAtEpochNs);
      flow.deadline = performance.now() + flow.expires - Date.now(); rotationPageCheck(flow);
      popup.location.replace(flow.origin + '/credentials/static/rotate');
      rotationPageMessage('Current predecessor and unchanged labels were read. Enter the NEW secret only in the native rotation window. No drain or rotation has started.');
    } catch (error) {
      if (flow) rotationPageFail(flow, error);
      else { rotationPrerequisitesObserved = false; sr('rotation-readiness-status').textContent = 'Prerequisites were not confirmed. No intake or drain started. Check again explicitly.'; }
    } finally {
      operation.close(); rotationAssignmentBusy = false;
      if (flow) flow.busy = false;
      else { popup.close(); for (const field of event.target.elements) field.disabled = false; }
      rotationPagePrerequisiteControls();
    }
  })();
});
function rotationPageApprovalReady(flow) {
  const status = flow.approvalStatus;
  return !flow.twoPerson || Boolean(status && status.approvalId === flow.approvalId
    && status.credentialId === flow.id && status.candidateSha256 === flow.digest
    && status.status === 'approved' && status.consumed === false
    && staticRotationExpiry(status.observedAtEpochNs) < staticRotationExpiry(status.expiresAtEpochNs)
    && Date.now() < staticRotationExpiry(status.expiresAtEpochNs));
}
async function rotationPageApprovalStatus() {
  const flow = rotationFlow;
  rotationPageCheck(flow);
  staticRotationNeed(!flow.busy && flow.twoPerson && flow.candidate && flow.approvalId && !flow.rotateAttempted);
  const candidate = flow.candidate, approvalId = flow.approvalId, digest = flow.digest;
  const operation = staticRotationOperation(() => {
    rotationPageCheck(flow);
    staticRotationNeed(flow.candidate === candidate && flow.approvalId === approvalId && flow.digest === digest
      && !flow.rotateAttempted);
  }, flow.auth);
  flow.busy = true; flow.approvalStatus = null;
  sr('rotation-approval-status').disabled = sr('rotation-rotate').disabled = true;
  try {
    const result = await staticRotationRequest('approval/status', {candidateArgumentsOriginal: candidate, approvalId}, operation);
    operation.check();
    staticRotationNeed(staticRotationClosed(result, ['apiVersion', 'okForAction', 'approvalId', 'credentialId',
      'candidateSha256', 'status', 'consumed', 'expiresAtEpochNs', 'observedAtEpochNs'])
      && result.apiVersion === 'serverware.staticCredentialRotationApprovalStatus/v1' && result.okForAction === false
      && result.approvalId === approvalId && result.credentialId === flow.id && result.candidateSha256 === digest
      && ['pending', 'approved', 'denied', 'consumed', 'invalidated'].includes(result.status)
      && typeof result.consumed === 'boolean');
    const expires = staticRotationExpiry(result.expiresAtEpochNs), observed = staticRotationExpiry(result.observedAtEpochNs);
    staticRotationNeed(expires <= flow.expires);
    flow.approvalStatus = Object.freeze(result);
    const ready = rotationPageApprovalReady(flow);
    sr('rotation-rotate').disabled = !ready;
    rotationPageMessage(ready ? 'Approval observed. Explicitly Rotate once with your passkey; current approval and authority will be checked again.'
      : result.status === 'pending' && !result.consumed && observed < expires && Date.now() < expires
        ? 'Approval is still pending. Keep both pages open and check again explicitly after the other operator decides. No rotation was attempted.'
        : 'Approval is ' + result.status + (result.consumed ? ' and consumed' : '')
          + (observed >= expires || Date.now() >= expires ? ' or expired' : '') + '. Rotation remains unavailable. No rotation was attempted.');
  } catch (_) {
    // A read has no ambiguous write to retry. Preserve the original candidate,
    // but never keep a prior readiness observation after a failed status read.
    flow.approvalStatus = null;
    rotationPageMessage('Approval status was not confirmed. No rotation was attempted. Check explicitly again only with the original session and candidate.');
  } finally {
    flow.busy = false; operation.close();
    if (rotationFlow === flow && !flow.failed && !flow.rotateAttempted) {
      try { rotationPageCheck(flow); sr('rotation-approval-status').disabled = false; } catch (_) { /* Original lifetime stays closed. */ }
    }
  }
}
async function rotationPageAction(rotate) {
  const flow = rotationFlow;
  rotationPageCheck(flow); staticRotationNeed(!flow.busy && flow.candidate
    && !(rotate ? flow.rotateAttempted : flow.requestAttempted) && (rotate || flow.twoPerson));
  if (rotate && !rotationPageApprovalReady(flow)) {
    sr('rotation-rotate').disabled = true;
    rotationPageMessage('Check this candidate’s approval status before Rotate. No rotation was attempted.'); return;
  }
  flow.busy = true;
  // Unlike creation, the rotation draft performs a real irreversible drain.
  // Spend this attempt before the first request, including a missing response.
  if (rotate) flow.rotateAttempted = true;
  else flow.requestAttempted = true;
  flow.activeOperation = rotate ? 'credential.static.rotate' : 'credential.static.rotation-approval-request';
  flow.requestDigest = null;
  sr('rotation-request').disabled = sr('rotation-rotate').disabled = sr('rotation-approval-status').disabled = true;
  const operation = staticRotationOperation(() => rotationPageCheck(flow), flow.auth);
  try {
    const route = rotate ? 'rotate' : 'approval/request', expected = rotate ? 'credential.static.rotate' : 'credential.static.rotation-approval-request';
    const draft = staticRotationDraft(await staticRotationRequest(route + '/draft', {candidateArgumentsOriginal: flow.candidate,
      ...(rotate ? {approvalId: flow.approvalId || null} : {ttlSeconds: 3600})}, operation), expected, operation);
    flow.requestDigest = draft.requestDigest;
    if (rotate) {
      const selected = JSON.parse(draft.argumentsOriginal), versions = staticRotationVersions(draft.argumentsOriginal);
      staticRotationNeed(selected.request?.credentialId === flow.id && versions.previous === flow.previousVersion
        && versions.next === flow.nextVersion && selected.approval_id === (flow.approvalId || null)
        && selected.request.previousProvenanceOriginal === flow.provenance
        && selected.request.nativeGenerationOriginal === JSON.parse(flow.candidate).request.nativeGenerationOriginal
        && /^sha256:[0-9a-f]{64}$/.test(selected.request.predecessorBarrierSha256)
        && /^sha256:[0-9a-f]{64}$/.test(selected.request.predecessorCurrentnessRootSha256));
      rotationPageMessage('Predecessor drained. Complete the passkey and native proof within this original interval. Request: ' + draft.requestDigest);
    }
    const mfa = await staticRotationMfa(route, draft, operation);
    let preparationOriginal;
    if (rotate) {
      await staticRotationCookie(operation); operation.check();
      preparationOriginal = await new Promise((resolve, reject) => {
        flow.waiter = {resolve, reject, argumentsOriginal: draft.argumentsOriginal};
        operation.controller.signal.addEventListener('abort', () => {
          if (flow.waiter) { flow.waiter = null; reject(new Error('Original preparation interval expired.')); }
        }, {once: true});
        flow.popup.postMessage({apiVersion: 'serverware.nativeStaticCredentialRotationPrepareMessage/v1',
          credentialId: flow.id, argumentsOriginal: draft.argumentsOriginal}, flow.origin);
      });
      operation.check();
    }
    const result = await staticRotationRequest(route + '/execute', {argumentsOriginal: draft.argumentsOriginal, mfa,
      ...(rotate ? {preparationOriginal} : {})}, operation);
    staticRotationNeed(result.ok === true && result.operation === expected && result.requestDigest === draft.requestDigest
      && result.candidateSha256 === flow.digest && result.idempotentReplay === false && result.auditState === 'controlled_pending');
    if (rotate) {
      const exact = staticRotationNumberView(staticRotationOriginals.get(result));
      staticRotationNeed(result.credential?.id === flow.id && exact.credential?.credential_version === flow.nextVersion
        && result.credential.lifecycle_status === 'active' && result.approvalId === (flow.approvalId || null));
      rotationPageMessage('Credential rotated: ' + flow.id + '\nVersion: ' + flow.previousVersion + ' → ' + flow.nextVersion
        + '\nRequest: ' + draft.requestDigest + '\nAudit publication is pending. Existing identity and public fields are unchanged; no policy is staged or activated.');
    } else {
      staticRotationNeed(result.approval?.status === 'pending' && result.approval.resource_id === flow.id
        && result.approval.payload_digest === flow.digest && staticRotationText(result.approval.id, 64));
      flow.approvalId = result.approval.id;
      flow.approvalStatus = null;
      rotationPageMessage('Approval requested: ' + flow.approvalId + '. A different operator must review it in the approval queue. Explicitly check approval status before Rotate. Nothing is saved yet.');
      sr('rotation-approval-status').disabled = false;
    }
  } catch (error) {
    rotationPageFail(flow, error);
  } finally { flow.busy = false; operation.close(); }
}
sr('rotation-request').addEventListener('click', () => void rotationPageAction(false).catch(() => rotationPageFail(rotationFlow)));
sr('rotation-rotate').addEventListener('click', () => void rotationPageAction(true).catch(() => rotationPageFail(rotationFlow)));
sr('rotation-approval-status').addEventListener('click', () => void rotationPageApprovalStatus().catch(() => {
  sr('rotation-rotate').disabled = true; rotationPageMessage('The original approval continuation is unavailable. No rotation was attempted.');
}));
"""

STATIC_CREDENTIAL_ROTATION_PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Rotate protected static credential</title>
<style>body{font:16px system-ui;max-width:48rem;margin:3rem auto;padding:0 1rem}label{display:block;margin-top:1rem}input,select,textarea{box-sizing:border-box;width:100%;padding:.5rem}button{margin:.8rem .5rem .8rem 0;padding:.6rem}pre,p{overflow-wrap:anywhere}</style>
<h1>Rotate protected static credential</h1>
<p>Use your active OIDC operator session. Select an existing static credential. Its current version, public provenance, identity, kind and metadata are read from protected state, not edited here. Enter the new secret exclusively in the authenticated native window. No secret, candidate or assertion is saved to browser storage.</p>
<details><summary>Deployment operator: admit the native assignment</summary>
<p>After the enclave boots, the independent assignment service signs its actual public identity and immutable configuration. Admit that unchanged public original once for this server process. This does not authorize rotation or replace fresh native proof. Never paste private keys or credentials here.</p>
<label>Signed public assignment original<textarea id="rotation-assignment-original" autocomplete="off" spellcheck="false"></textarea></label>
<button id="rotation-assignment-admit" type="button">Admit signed assignment</button>
<p id="rotation-assignment-status" role="status" aria-live="polite">No assignment submitted from this page.</p></details>
<button id="rotation-readiness-check" type="button">Check intake prerequisites</button>
<p id="rotation-readiness-status" role="status" aria-live="polite">Check both retained assignments before opening intake. This does not check native serving liveness or authorize a drain or rotation.</p>
<form id="rotation-form"><label>Existing credential ID<input id="rotation-credential-id" name="credentialId" required autocomplete="off" spellcheck="false"></label>
<p>The server retrieves and verifies the previous generation's retained public evidence. If its original evidence or completed audit is unavailable, rotation stays unavailable; this page never guesses or renews it.</p>
<label>Candidate lifetime (seconds, maximum 3600)<input name="ttlSeconds" type="number" min="1" max="3600" value="900" required></label>
<button id="rotation-start" type="submit" disabled>Open native secret intake</button></form>
<pre id="rotation-selection" aria-label="Actual selected predecessor"></pre>
<button id="rotation-request" type="button" disabled>Passkey + request approval</button>
<button id="rotation-approval-status" type="button" disabled>Check approval status</button>
<p>Rotate first irreversibly drains the current generation, then requests your passkey and fresh native evidence. An expired, failed or uncertain drain cannot be reset or retried here. Wait for any required approval before clicking.</p>
<button id="rotation-rotate" type="button" disabled>Drain + passkey + Rotate once</button>
<p id="rotation-status" role="status" aria-live="polite">No intake or rotation has started.</p>
<p><a href="/approvals" target="_blank" rel="noopener">Approval queue</a> · <a href="/">Return to Setup</a></p>
<script>""" + STATIC_CREDENTIAL_ROTATION_SCRIPT + STATIC_CREDENTIAL_ROTATION_PAGE_SCRIPT + "</script></html>"
