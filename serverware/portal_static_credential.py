"""Cookie-only static onboarding; plaintext remains on the native TLS page.

Original candidates and assertions remain page-local. Browser checks constrain
this continuation only; the authority independently verifies every original.
No polling, storage, automatic approval, effect retry or implicit Setup binding.
"""

STATIC_CREDENTIAL_SCRIPT = r"""
const staticPortalSchema = 'serverware.staticCredentialPortalRequest/v1';
const staticPortalReview = 'serverware.staticCredentialCreationApprovalRequest/v1';
const staticPortalPrefix = '/api/credentials/static';
const staticPortalDecisionAttempts = new Set();
function staticPortalNeed(ok) {
  if (!ok) throw new Error('Static credential context is unavailable or changed. Do not retry an uncertain action.');
}
function staticPortalClosed(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}
function staticPortalText(value, limit = 4 * 1024 * 1024) {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= limit;
}
function staticPortalJson(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
}
function staticPortalExpiry(value) {
  staticPortalNeed(typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value));
  const milliseconds = BigInt(value) / 1000000n;
  staticPortalNeed(milliseconds <= BigInt(Number.MAX_SAFE_INTEGER));
  return Number(milliseconds);
}
function staticPortalOperation(checkContext, auth = null) {
  const controller = new AbortController();
  let wall = Date.now(), mono = performance.now(), expires = wall + 30000, deadline = mono + 30000;
  const timer = setTimeout(() => controller.abort(), 30000);
  return {controller, auth,
    check() {
      const nextWall = Date.now(), nextMono = performance.now();
      staticPortalNeed(!controller.signal.aborted && nextWall >= wall && nextMono >= mono
        && nextWall < expires && nextMono < deadline);
      wall = nextWall; mono = nextMono; checkContext();
    },
    clip(epoch) {
      this.check(); expires = Math.min(expires, staticPortalExpiry(epoch));
      deadline = Math.min(deadline, performance.now() + expires - Date.now()); this.check();
    },
    close() { clearTimeout(timer); controller.abort(); }
  };
}
async function staticPortalRead(response, operation, maximum = 4 * 1024 * 1024) {
  operation.check();
  staticPortalNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
  let original = '', size = 0, complete = false;
  try {
    for (;;) {
      const item = await reader.read(); operation.check();
      if (item.done) { complete = true; break; }
      size += item.value.byteLength; staticPortalNeed(size <= maximum);
      original += decoder.decode(item.value, {stream: true});
    }
    original += decoder.decode(); operation.check();
    staticPortalNeed(response.ok);
    return JSON.parse(original);
  } finally {
    if (!complete) { try { await reader.cancel(); } catch (_) {} }
    reader.releaseLock();
  }
}
async function staticPortalCookie(operation) {
  operation.check();
  const reply = await fetch('/api/auth/status', {credentials: 'same-origin', mode: 'same-origin',
    redirect: 'error', cache: 'no-store', signal: operation.controller.signal});
  const value = await staticPortalRead(reply, operation, 32768);
  staticPortalNeed(staticPortalClosed(value, ['authenticated', 'userId', 'roles', 'authMethod', 'sessionState',
    'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode']) && value.authenticated === true
    && value.authMethod === 'oidc-session' && value.sessionState === 'active' && value.webauthnRequired === false
    && staticPortalText(value.userId, 512) && Array.isArray(value.roles) && value.roles.length <= 64
    && value.roles.every(role => staticPortalText(role, 128)) && new Set(value.roles).size === value.roles.length
    && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
    && typeof value.oidcBrowserLoginConfigured === 'boolean');
  const scope = staticPortalJson({...value, roles: [...value.roles].sort()});
  staticPortalNeed(operation.auth === null || operation.auth === scope); operation.auth = scope;
  operation.check(); return value;
}
async function staticPortalRequest(route, body, operation) {
  staticPortalNeed(/^(assignment|intent|candidate|(approval\/(request|decide)|create)\/(draft|options|execute))$/.test(route));
  await staticPortalCookie(operation); operation.check();
  const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin',
    redirect: 'error', cache: 'no-store', signal: operation.controller.signal});
  const csrf = await staticPortalRead(csrfResponse, operation, 4096);
  staticPortalNeed(staticPortalClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
    && staticPortalText(csrf.token, 1024) && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token');
  const original = staticPortalJson({apiVersion: staticPortalSchema, ...body});
  staticPortalNeed(new TextEncoder().encode(original).length <= 4 * 1024 * 1024); operation.check();
  const response = await fetch(staticPortalPrefix + '/' + route, {method: 'POST', credentials: 'same-origin',
    mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: operation.controller.signal,
    headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: original});
  operation.check(); return staticPortalRead(response, operation);
}
function staticPortalDraft(value, expected, operation) {
  staticPortalNeed(staticPortalClosed(value, ['apiVersion', 'okForAction', 'operation', 'argumentsOriginal',
    'requestDigest', 'expiresAtEpochNs']) && value.apiVersion === staticPortalSchema && value.okForAction === false
    && value.operation === expected && staticPortalText(value.argumentsOriginal)
    && /^sha256:[0-9a-f]{64}$/.test(value.requestDigest));
  operation.clip(value.expiresAtEpochNs); return value;
}
function staticPortalBytes(value) {
  staticPortalNeed(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && value.length <= 32768);
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
}
function staticPortalB64(value) {
  staticPortalNeed(value instanceof ArrayBuffer && value.byteLength <= 16384);
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function staticPortalMfa(route, draft, operation) {
  const options = await staticPortalRequest(route + '/options', {argumentsOriginal: draft.argumentsOriginal}, operation);
  const create = route === 'create', schema = create ? 'serverware.staticCredentialCreationOptions/v1' : 'serverware.staticCredentialApprovalOptions/v1';
  staticPortalNeed(staticPortalClosed(options, ['publicKey', 'serverware'])
    && staticPortalClosed(options.serverware, ['schema', 'operation', 'requestDigest', 'challengeId', 'credentialRecordId', 'expiresAt'])
    && options.serverware.schema === schema && options.serverware.operation === draft.operation
    && options.serverware.requestDigest === draft.requestDigest && options.publicKey?.userVerification === 'required'
    && Array.isArray(options.publicKey.allowCredentials) && options.publicKey.allowCredentials.length === 1);
  const expiry = Date.parse(options.serverware.expiresAt);
  staticPortalNeed(Number.isSafeInteger(expiry) && expiry > Date.now()); operation.clip(String(BigInt(expiry) * 1000000n));
  const publicKey = {...options.publicKey, challenge: staticPortalBytes(options.publicKey.challenge),
    allowCredentials: options.publicKey.allowCredentials.map(value => ({...value, id: staticPortalBytes(value.id)}))};
  operation.check();
  const credential = await navigator.credentials.get({publicKey, signal: operation.controller.signal}); operation.check();
  staticPortalNeed(credential?.type === 'public-key' && credential.id === options.publicKey.allowCredentials[0].id
    && staticPortalB64(credential.rawId) === credential.id);
  const assertion = {id: credential.id, rawId: staticPortalB64(credential.rawId), type: credential.type,
    response: {clientDataJSON: staticPortalB64(credential.response.clientDataJSON),
      authenticatorData: staticPortalB64(credential.response.authenticatorData), signature: staticPortalB64(credential.response.signature),
      userHandle: credential.response.userHandle === null ? null : staticPortalB64(credential.response.userHandle)}};
  const mfa = {[create ? 'staticCredentialCreationProfile' : 'staticCredentialApprovalProfile']: schema, assertion};
  staticPortalNeed(staticPortalJson(mfa).length <= 16384); return mfa;
}
async function staticPortalDecide(id, decision) {
  const item = (state.controlPlaneApprovals || []).find(value => value.id === id);
  staticPortalNeed(item?.request?.apiVersion === staticPortalReview && item.status === 'pending'
    && ['approve', 'deny'].includes(decision) && !adminToken() && !staticPortalDecisionAttempts.has(id)
    && ($('control-plane-note-' + id)?.value ?? '') === '');
  const scope = policyAuthoringScope(), original = staticPortalJson(item);
  const operation = staticPortalOperation(() => staticPortalNeed(scope === policyAuthoringScope()
    && !adminToken() && original === staticPortalJson((state.controlPlaneApprovals || []).find(value => value.id === id))));
  staticPortalDecisionAttempts.add(id);
  try {
    const draft = staticPortalDraft(await staticPortalRequest('approval/decide/draft', {approvalId: id, decision}, operation),
      'credential.static.approval-decide', operation);
    const held = JSON.parse(JSON.parse(draft.argumentsOriginal).request.approvalOriginal);
    // The server retained its full row. Compare the actually displayed compact
    // review; never recreate the signed original from rounded browser numbers.
    staticPortalNeed(held.id === id && held.payload_digest === item.payload_digest
      && staticPortalJson(JSON.parse(held.request_json)) === staticPortalJson(item.request));
    const mfa = await staticPortalMfa('approval/decide', draft, operation);
    const result = await staticPortalRequest('approval/decide/execute', {argumentsOriginal: draft.argumentsOriginal, mfa}, operation);
    staticPortalNeed(result.ok === true && result.operation === draft.operation && result.requestDigest === draft.requestDigest
      && result.approval?.id === id && result.approval.status === (decision === 'approve' ? 'approved' : 'denied')
      && result.candidateSha256 === item.payload_digest && result.auditState === 'controlled_pending');
    setStatus('Static credential decision recorded. Audit publication is pending; no credential was created.');
  } finally { operation.close(); }
  await refresh();
}
"""

STATIC_CREDENTIAL_PAGE_SCRIPT = r"""
let staticFlow = null;
const sc = id => document.getElementById(id);
function staticPageMessage(value) { sc('static-status').textContent = value; }
let staticAssignmentBusy = false;
sc('static-assignment-admit').addEventListener('click', () => {
  if (staticAssignmentBusy || staticFlow) return;
  const original = sc('static-assignment-original').value;
  const operation = staticPortalOperation(() => staticPortalNeed(!staticFlow
    && sc('static-assignment-original').value === original));
  staticAssignmentBusy = true;
  sc('static-assignment-admit').disabled = sc('static-start').disabled = true;
  void (async () => {
    try {
      staticPortalNeed(staticPortalText(original, 65536));
      const result = await staticPortalRequest('assignment', {assignmentOriginal: original}, operation);
      staticPortalNeed(staticPortalClosed(result, ['apiVersion', 'okForAction', 'assignmentSha256', 'holderId', 'expiresAtEpochNs'])
        && result.apiVersion === staticPortalSchema && result.okForAction === false
        && /^sha256:[0-9a-f]{64}$/.test(result.assignmentSha256) && /^sha256:[0-9a-f]{64}$/.test(result.holderId));
      operation.clip(result.expiresAtEpochNs);
      sc('static-assignment-status').textContent = 'Independent assignment retained: ' + result.assignmentSha256
        + '. Each creation still requires fresh native proof and your passkey. No credential was created.';
    } catch (_) {
      sc('static-assignment-status').textContent = 'Assignment admission was not confirmed. The same signed original may be inspected again; a different assignment cannot replace it. No credential action was sent.';
    } finally {
      operation.close(); staticAssignmentBusy = false;
      sc('static-assignment-admit').disabled = sc('static-start').disabled = false;
    }
  })();
});
function staticPageCheck(flow) {
  staticPortalNeed(staticFlow === flow && !flow.failed && flow.popup && !flow.popup.closed
    && Date.now() >= flow.lastWall && performance.now() >= flow.lastMono
    && Date.now() < flow.expires && performance.now() < flow.deadline);
  flow.lastWall = Date.now(); flow.lastMono = performance.now();
}
function staticPageFail(flow) {
  flow.failed = true; sc('static-request').disabled = sc('static-create').disabled = true;
  if (flow.waiter) { flow.waiter.reject(new Error('Native preparation outcome is uncertain.')); flow.waiter = null; }
  staticPageMessage('This continuation stopped. Any sent action may have taken effect. Inspect the original credential/approval; do not retry it. Reloading does not resolve uncertainty.');
}
window.addEventListener('message', event => {
  const flow = staticFlow;
  if (!flow || flow.failed || event.source !== flow.popup || event.origin !== flow.origin) return;
  const value = event.data;
  try {
    staticPageCheck(flow);
    if (value?.apiVersion === 'serverware.nativeStaticCredentialReadyMessage/v1') {
      if (flow.ready) return;
      staticPortalNeed(staticPortalClosed(value, ['apiVersion'])); flow.ready = true;
      staticPortalNeed(!flow.intentSent && staticPortalText(flow.intentOriginal)); flow.intentSent = true;
      flow.popup.postMessage({apiVersion: 'serverware.nativeStaticCredentialIntentMessage/v1', intentOriginal: flow.intentOriginal}, flow.origin);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialCandidateMessage/v1') {
      staticPortalNeed(staticPortalClosed(value, ['apiVersion', 'candidateOriginal']) && flow.intentSent
        && !flow.candidateReceived && staticPortalText(value.candidateOriginal));
      flow.candidateReceived = true; void staticPageCandidate(flow, value.candidateOriginal);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialPreparedMessage/v1') {
      staticPortalNeed(staticPortalClosed(value, ['apiVersion', 'preparationOriginal']) && flow.waiter
        && staticPortalText(value.preparationOriginal));
      const reply = JSON.parse(value.preparationOriginal);
      staticPortalNeed(reply.apiVersion === 'serverware.nativeStaticCredentialPreparationResponse/v1'
        && reply.argumentsOriginal === flow.waiter.argumentsOriginal);
      const waiter = flow.waiter; flow.waiter = null; waiter.resolve(value.preparationOriginal);
    } else if (value?.apiVersion === 'serverware.nativeStaticCredentialPrepareFailedMessage/v1') {
      staticPortalNeed(staticPortalClosed(value, ['apiVersion', 'credentialId', 'argumentsOriginal', 'outcome'])
        && flow.waiter && value.credentialId === flow.id && value.argumentsOriginal === flow.waiter.argumentsOriginal
        && value.outcome === 'uncertain'); staticPageFail(flow);
    }
  } catch (_) { staticPageFail(flow); }
});
async function staticPageCandidate(flow, original) {
  const operation = staticPortalOperation(() => staticPageCheck(flow), flow.auth);
  try {
    const native = JSON.parse(original);
    staticPortalNeed(native.apiVersion === 'serverware.nativeStaticCredentialCandidateResponse/v1'
      && native.candidate?.credentialId === flow.id && native.candidate.intentOriginal === flow.intentOriginal);
    const result = await staticPortalRequest('candidate', {candidateOriginal: original}, operation);
    staticPortalNeed(result.apiVersion === staticPortalSchema && result.okForAction === false
      && staticPortalText(result.candidateArgumentsOriginal) && /^sha256:[0-9a-f]{64}$/.test(result.candidateSha256)
      && result.credentialId === flow.id && result.portalOrigin === location.origin
      && result.intakeOrigin === flow.origin && result.twoPersonRequired === flow.twoPerson);
    const candidate = JSON.parse(result.candidateArgumentsOriginal);
    staticPortalNeed(candidate.request?.credentialId === flow.id && candidate.approval_id === null
      && candidate.request.nativeGenerationOriginal === native.candidate.nativeGenerationOriginal);
    flow.candidate = result.candidateArgumentsOriginal; flow.digest = result.candidateSha256;
    flow.expires = Math.min(flow.expires, staticPortalExpiry(result.expiresAtEpochNs));
    flow.deadline = Math.min(flow.deadline, performance.now() + flow.expires - Date.now()); staticPageCheck(flow);
    sc('static-request').disabled = !flow.twoPerson; sc('static-create').disabled = flow.twoPerson;
    staticPageMessage('Candidate sealed, not saved. ' + (flow.twoPerson ? 'Request a distinct operator’s approval, then explicitly Create.' : 'Explicitly Create with a fresh passkey.'));
  } catch (_) { staticPageFail(flow); } finally { operation.close(); }
}
sc('static-form').addEventListener('submit', event => {
  event.preventDefault();
  if (staticFlow || staticAssignmentBusy) return;
  // Open synchronously inside the user gesture. Never noopener: the two fixed
  // origins deliberately retain this exact WindowProxy, not a named window.
  const popup = window.open('about:blank', '_blank');
  if (!popup) { staticPageMessage('Allow this page’s native intake popup, then start explicitly.'); return; }
  const flow = {popup, origin: null, auth: null, ready: false, intentSent: false, candidateReceived: false,
    failed: false, busy: true, lastWall: Date.now(), lastMono: performance.now(),
    expires: Date.now() + 30000, deadline: performance.now() + 30000, requestAttempted: false, createAttempted: false};
  staticFlow = flow; sc('static-start').disabled = true;
  const form = new FormData(event.target);
  for (const field of event.target.elements) field.disabled = true;
  void (async () => {
    const operation = staticPortalOperation(() => staticPageCheck(flow));
    try {
      const metadata = JSON.parse(form.get('metadata') || '{}');
      staticPortalNeed(metadata && typeof metadata === 'object' && !Array.isArray(metadata) && metadata.oauth !== true);
      const result = await staticPortalRequest('intent', {name: String(form.get('name')), kind: String(form.get('kind')),
        metadata, ttlSeconds: Number(form.get('ttlSeconds'))}, operation);
      staticPortalNeed(result.apiVersion === staticPortalSchema && result.okForAction === false
        && result.portalOrigin === location.origin && staticPortalText(result.intentOriginal)
        && typeof result.twoPersonRequired === 'boolean');
      const origin = new URL(result.intakeOrigin);
      staticPortalNeed(origin.protocol === 'https:' && origin.origin === result.intakeOrigin
        && origin.username === '' && origin.password === '' && origin.origin !== location.origin);
      flow.origin = origin.origin; flow.auth = operation.auth; flow.id = result.credentialId;
      flow.intentOriginal = result.intentOriginal; flow.twoPerson = result.twoPersonRequired;
      flow.expires = staticPortalExpiry(result.expiresAtEpochNs);
      flow.deadline = performance.now() + flow.expires - Date.now(); staticPageCheck(flow);
      popup.location.replace(flow.origin + '/credentials/static');
      staticPageMessage('Enter the secret only in the native intake window. Keep both pages open. Nothing is saved yet.');
    } catch (_) { staticPageFail(flow); } finally { flow.busy = false; operation.close(); }
  })();
});
async function staticPageAction(create) {
  const flow = staticFlow;
  staticPageCheck(flow); staticPortalNeed(!flow.busy && flow.candidate
    && !(create ? flow.createAttempted : flow.requestAttempted) && (create || flow.twoPerson));
  flow.busy = true;
  if (create) flow.createAttempted = true; else flow.requestAttempted = true;
  sc('static-request').disabled = sc('static-create').disabled = true;
  const operation = staticPortalOperation(() => staticPageCheck(flow), flow.auth);
  try {
    const route = create ? 'create' : 'approval/request', expected = create ? 'credential.static.create' : 'credential.static.approval-request';
    const draft = staticPortalDraft(await staticPortalRequest(route + '/draft', {candidateArgumentsOriginal: flow.candidate,
      ...(create ? {approvalId: flow.approvalId || null} : {ttlSeconds: 3600})}, operation), expected, operation);
    const mfa = await staticPortalMfa(route, draft, operation);
    let preparationOriginal;
    if (create) {
      await staticPortalCookie(operation); operation.check();
      preparationOriginal = await new Promise((resolve, reject) => {
        flow.waiter = {resolve, reject, argumentsOriginal: draft.argumentsOriginal};
        operation.controller.signal.addEventListener('abort', () => {
          if (flow.waiter) { flow.waiter = null; reject(new Error('Original preparation interval expired.')); }
        }, {once: true});
        flow.popup.postMessage({apiVersion: 'serverware.nativeStaticCredentialPrepareMessage/v1',
          credentialId: flow.id, argumentsOriginal: draft.argumentsOriginal}, flow.origin);
      });
      operation.check();
    }
    const result = await staticPortalRequest(route + '/execute', {argumentsOriginal: draft.argumentsOriginal, mfa,
      ...(create ? {preparationOriginal} : {})}, operation);
    staticPortalNeed(result.ok === true && result.operation === expected && result.requestDigest === draft.requestDigest
      && result.candidateSha256 === flow.digest && result.idempotentReplay === false && result.auditState === 'controlled_pending');
    if (create) {
      staticPortalNeed(result.credential?.id === flow.id && result.credential.credential_version === 1
        && result.credential.lifecycle_status === 'active' && result.approvalId === (flow.approvalId || null));
      staticPageMessage('Credential created: ' + flow.id + '. Audit publication is pending. Return to Setup and explicitly bind this exact credential; policy is not staged or activated.');
    } else {
      staticPortalNeed(result.approval?.status === 'pending' && result.approval.resource_id === flow.id
        && result.approval.payload_digest === flow.digest && staticPortalText(result.approval.id, 64));
      flow.approvalId = result.approval.id;
      staticPageMessage('Approval requested: ' + flow.approvalId + '. A different operator must review it in the portal approval queue. After approval, click Create once. Nothing is saved yet.');
      sc('static-create').disabled = false;
    }
  } catch (_) { staticPageFail(flow); } finally { flow.busy = false; operation.close(); }
}
sc('static-request').addEventListener('click', () => void staticPageAction(false).catch(() => staticPageFail(staticFlow)));
sc('static-create').addEventListener('click', () => void staticPageAction(true).catch(() => staticPageFail(staticFlow)));
"""

STATIC_CREDENTIAL_PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Create protected static credential</title>
<style>body{font:16px system-ui;max-width:48rem;margin:3rem auto;padding:0 1rem}label{display:block;margin-top:1rem}input,select,textarea{box-sizing:border-box;width:100%;padding:.5rem}button{margin:.8rem .5rem .8rem 0;padding:.6rem}pre,p{overflow-wrap:anywhere}</style>
<h1>Create protected static credential</h1>
<p>Use your active OIDC operator session. This page accepts public labels only. Enter the secret exclusively in the separately authenticated native intake window. Keep both tabs open; no candidate or assertion is saved to browser storage.</p>
<details><summary>Deployment operator: admit the native assignment</summary>
<p>After the enclave boots, the independent assignment service signs its actual public identity and immutable configuration. Admit that unchanged public original once for this server process. This does not authorize creation or replace fresh native proof. Never paste private keys or credentials here.</p>
<label>Signed public assignment original<textarea id="static-assignment-original" autocomplete="off" spellcheck="false"></textarea></label>
<button id="static-assignment-admit" type="button">Admit signed assignment</button>
<p id="static-assignment-status" role="status" aria-live="polite">No assignment submitted from this page.</p></details>
<form id="static-form"><label>Name<input name="name" required autocomplete="off"></label>
<label>Kind<select name="kind"><option>bearer</option><option>basic</option><option>header</option><option>query</option><option>cookie</option></select></label>
<label>Public metadata JSON<textarea name="metadata" required autocomplete="off">{}</textarea></label>
<p>Supply the provider, provider_subject and secret_class required by your policy, plus username for basic or injection_name for header/query/cookie. Never put a secret in metadata. Provider labels do not verify account ownership.</p>
<label>Candidate lifetime (seconds, maximum 3600)<input name="ttlSeconds" type="number" min="1" max="3600" value="900" required></label>
<button id="static-start" type="submit">Open native secret intake</button></form>
<button id="static-request" type="button" disabled>Passkey + request approval</button>
<button id="static-create" type="button" disabled>Passkey + Create once</button>
<p id="static-status" role="status" aria-live="polite">No intake or creation has started.</p>
<p><a href="/approvals" target="_blank" rel="noopener">Approval queue</a> · <a href="/">Return to Setup</a></p>
<script>""" + STATIC_CREDENTIAL_SCRIPT + STATIC_CREDENTIAL_PAGE_SCRIPT + "</script></html>"
