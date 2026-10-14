"""Public-only portal coordinator. Private review bytes stay on native TLS.

Browser checks constrain a single gesture; they are not signature admission or
evidence that a human read the review. The authority and native owner recheck
their own currentness, exact originals and one-use disclosure requirements.
"""
from __future__ import annotations

import json


NATIVE_JIT_REVIEW_SCRIPT = r"""
function nativeReviewNeed(ok) {
  if (!ok) throw new Error('Protected review is unavailable or changed. No uncertain step will be retried.');
}
function nativeReviewClosed(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}
function nativeReviewText(value, maximum) {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= maximum;
}
function nativeReviewUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
}
function nativeReviewOriginal(original, kind) {
  const native = kind === 'Challenge' || kind === 'Preparation';
  nativeReviewNeed(nativeReviewText(original, (native ? 128 : 64) * 1024));
  const envelope = JSON.parse(original);
  nativeReviewNeed(nativeReviewClosed(envelope, native
    ? ['statement', 'signature', 'nativeKeyEvidence', 'assignmentOriginal']
    : ['schema', 'payload', 'signatureBase64Url']));
  const value = native ? envelope.statement : envelope.payload;
  nativeReviewNeed(value && typeof value === 'object' && !Array.isArray(value)
    && value.schema === 'serverware.nativeJitReviewOpening' + kind + '/v1');
  if (!native) nativeReviewNeed(envelope.schema === 'serverware.signedNativeJitReviewOpening' + kind + '/v1');
  // These rounded numbers are ONLY conservative UI cutoffs. Forward the exact
  // original string, never stringify a signed object or derive authority here.
  nativeReviewNeed(Number.isFinite(value.expiresAtEpochNs) && value.expiresAtEpochNs > 0);
  return value;
}
function nativeReviewConsumeApproval() {
  const fragment = window.location.hash, query = window.location.search;
  window.history.replaceState(null, '', window.location.pathname);
  nativeReviewNeed(window.location.protocol === 'https:' && window.location.pathname === '/approvals/review/native'
    && !query && fragment.startsWith('#approval=')
    && nativeReviewUuid(fragment.slice(10)));
  return fragment.slice(10);
}
function createNativeReviewController({nativeOrigin, maximumRequestBytes}) {
  const start = document.getElementById('native-review-open');
  const status = document.getElementById('native-review-status');
  const target = new URL(nativeOrigin);
  nativeReviewNeed(Number.isSafeInteger(maximumRequestBytes) && maximumRequestBytes > 0
    && target.protocol === 'https:' && target.origin === nativeOrigin
    && target.pathname === '/' && !target.search && !target.hash && !target.username && !target.password
    && nativeOrigin !== window.location.origin);
  let approvalId = null, flow = null, used = false, disposed = false;
  const message = value => { status.textContent = value; };
  const holdKey = id => 'serverware.nativeJitReviewUncertain.' + id;
  try {
    approvalId = nativeReviewConsumeApproval();
    nativeReviewNeed(sessionStorage.getItem(holdKey(approvalId)) === null
      && sessionStorage.getItem('serverware.approvalDecisionUncertain.' + approvalId) === null);
    message('Open the protected native review. This records disclosure only; it does not approve or deny the request.');
  } catch (_) {
    used = true; start.disabled = true;
    message('This review link is invalid or an earlier opening has an uncertain outcome. Return to Pending actions; nothing was retried.');
  }
  function check(current) {
    const wall = Date.now(), mono = performance.now();
    nativeReviewNeed(!disposed && flow === current && !current.closed && !current.controller.signal.aborted
      && current.popup && !current.popup.closed && window.location.protocol === 'https:'
      && window.location.pathname === '/approvals/review/native' && !window.location.search && !window.location.hash
      && window.location.origin === current.portalOrigin && wall >= current.wall && mono >= current.mono
      && wall < current.expires && mono < current.deadline);
    current.wall = wall; current.mono = mono;
  }
  function clip(current, value) {
    check(current);
    const expiry = Math.floor(value.expiresAtEpochNs / 1000000) - 1;
    nativeReviewNeed(Number.isSafeInteger(expiry));
    current.expires = Math.min(current.expires, expiry);
    current.deadline = Math.min(current.deadline, performance.now() + current.expires - Date.now());
    check(current);
  }
  function close(current) {
    if (!current || current.closed) return;
    current.closed = true; clearTimeout(current.timer); current.controller.abort();
    current.challenge = current.authorization = current.preparation = null;
  }
  function fail(current) {
    close(current); start.disabled = true;
    message('Protected review did not complete here. Its outcome may be uncertain; no step was retried. Return to Pending actions.');
  }
  async function read(response, current, maximum) {
    check(current);
    nativeReviewNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
    const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
    let text = '', length = 0, complete = false;
    try {
      for (;;) {
        const part = await reader.read(); check(current);
        if (part.done) { complete = true; break; }
        length += part.value.byteLength; nativeReviewNeed(length <= maximum);
        text += decoder.decode(part.value, {stream: true});
      }
      text += decoder.decode(); check(current); nativeReviewNeed(response.ok);
      return JSON.parse(text);
    } finally {
      if (!complete) { try { await reader.cancel(); } catch (_) {} }
      reader.releaseLock();
    }
  }
  async function cookie(current) {
    check(current);
    const response = await fetch('/api/auth/status', {credentials: 'same-origin', mode: 'same-origin',
      redirect: 'error', cache: 'no-store', signal: current.controller.signal});
    const value = await read(response, current, 32768);
    nativeReviewNeed(nativeReviewClosed(value, ['authenticated', 'userId', 'roles', 'authMethod', 'sessionState',
      'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode']) && value.authenticated === true
      && value.authMethod === 'oidc-session' && value.sessionState === 'active' && value.webauthnRequired === false
      && nativeReviewText(value.userId, 1024) && Array.isArray(value.roles) && value.roles.length <= 64
      && value.roles.every(role => nativeReviewText(role, 128)) && new Set(value.roles).size === value.roles.length
      && typeof value.oidcBrowserLoginConfigured === 'boolean'
      && ['legacy', 'protected', 'unavailable'].includes(value.sessionActivationMode)
      && value.roles.some(role => role === 'approver' || role === 'admin'));
    const scope = JSON.stringify({...value, roles: [...value.roles].sort()});
    nativeReviewNeed(current.auth === null || current.auth === scope); current.auth = scope;
    return value;
  }
  async function request(phase, body, current) {
    nativeReviewNeed(phase === 'authorize' || phase === 'receipt');
    await cookie(current); check(current);
    const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', mode: 'same-origin',
      redirect: 'error', cache: 'no-store', signal: current.controller.signal});
    const csrf = await read(csrfResponse, current, 4096);
    nativeReviewNeed(nativeReviewClosed(csrf, ['ok', 'token', 'cookie', 'header']) && csrf.ok === true
      && nativeReviewText(csrf.token, 1024) && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token');
    const original = JSON.stringify(body); nativeReviewNeed(new TextEncoder().encode(original).length <= maximumRequestBytes);
    check(current);
    const response = await fetch('/api/approvals/review/native/' + phase, {method: 'POST', credentials: 'same-origin',
      mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: current.controller.signal,
      headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: original});
    return read(response, current, 5 * 1024 * 1024);
  }
  function scope(value, current) {
    nativeReviewNeed(value && typeof value === 'object' && value.reviewId === current.reviewId
      && value.approvalRequestId === approvalId && value.reviewerId === current.userId
      && value.browserNonceCommitment === current.challengeValue.browserNonceCommitment
      && value.recipientPublicKey === current.challengeValue.recipientPublicKey);
  }
  function send(current, value) { check(current); current.popup.postMessage(value, nativeOrigin); }
  async function receive(event) {
    const current = flow;
    if (!current || current.closed || event.source !== current.popup || event.origin !== nativeOrigin) return;
    try {
      check(current); const value = event.data;
      if (current.phase === 'ready' && nativeReviewClosed(value, ['type'])
          && value.type === 'serverware.native-jit-review.ready') {
        current.phase = 'challenge';
        // Persist only the selected public UUID before the first native effect.
        sessionStorage.setItem(holdKey(approvalId), approvalId);
        nativeReviewNeed(sessionStorage.getItem(holdKey(approvalId)) === approvalId);
        send(current, {type: 'serverware.native-jit-review.start', approvalRequestId: approvalId});
      } else if (current.phase === 'challenge' && nativeReviewClosed(value, ['type', 'challengeOriginal'])
          && value.type === 'serverware.native-jit-review.challenge') {
        current.phase = 'authorizing';
        const challenge = nativeReviewOriginal(value.challengeOriginal, 'Challenge');
        nativeReviewNeed(nativeReviewText(challenge.reviewId, 128) && challenge.approvalRequestId === approvalId
          && challenge.nativeOrigin === nativeOrigin && challenge.portalOrigin === current.portalOrigin);
        current.reviewId = challenge.reviewId; current.challengeValue = challenge; current.challenge = value.challengeOriginal;
        clip(current, challenge);
        const result = await request('authorize', {challengeOriginal: current.challenge}, current); check(current);
        nativeReviewNeed(nativeReviewClosed(result, ['authorizationOriginal', 'parentOriginal', 'childOriginal', 'pairOriginal', 'evidenceOriginal'])
          && nativeReviewText(result.parentOriginal, 512 * 1024) && nativeReviewText(result.childOriginal, 512 * 1024)
          && nativeReviewText(result.pairOriginal, 1024 * 1024) && nativeReviewText(result.evidenceOriginal, 128 * 1024));
        const authorization = nativeReviewOriginal(result.authorizationOriginal, 'Authorization');
        scope(authorization.scope, current); clip(current, authorization);
        current.authorization = result.authorizationOriginal; current.scope = JSON.stringify(authorization.scope);
        current.phase = 'prepared';
        send(current, {type: 'serverware.native-jit-review.authorized', authorizationOriginal: result.authorizationOriginal,
          parentOriginal: result.parentOriginal, childOriginal: result.childOriginal, pairOriginal: result.pairOriginal,
          proofOriginal: result.evidenceOriginal});
      } else if (current.phase === 'prepared' && nativeReviewClosed(value, ['type', 'preparationOriginal'])
          && value.type === 'serverware.native-jit-review.prepared') {
        current.phase = 'committing';
        const prepared = nativeReviewOriginal(value.preparationOriginal, 'Preparation');
        scope(prepared.scope, current); nativeReviewNeed(JSON.stringify(prepared.scope) === current.scope);
        clip(current, prepared); current.preparation = value.preparationOriginal;
        const result = await request('receipt', {challengeOriginal: current.challenge,
          authorizationOriginal: current.authorization, preparationOriginal: current.preparation}, current); check(current);
        nativeReviewNeed(nativeReviewClosed(result, ['acknowledgmentOriginal']));
        const ack = nativeReviewOriginal(result.acknowledgmentOriginal, 'CommitAcknowledgment');
        scope(ack.scope, current); nativeReviewNeed(JSON.stringify(ack.scope) === current.scope && ack.reviewDigest === prepared.reviewDigest);
        clip(current, ack); current.phase = 'disclosed';
        send(current, {type: 'serverware.native-jit-review.committed', commitAckOriginal: result.acknowledgmentOriginal});
      } else if (current.phase === 'disclosed' && nativeReviewClosed(value, ['type', 'reviewId'])
          && value.type === 'serverware.native-jit-review.disclosed' && value.reviewId === current.reviewId) {
        nativeReviewNeed(sessionStorage.getItem(holdKey(approvalId)) === approvalId);
        sessionStorage.removeItem(holdKey(approvalId)); close(current);
        message('Protected review is open in the native window. No approval or denial was submitted.');
      } else { throw new Error('Unexpected native review phase'); }
    } catch (_) { fail(current); }
  }
  async function begin() {
    if (used || disposed) return;
    used = true; start.disabled = true;
    // This call must remain synchronous in the one explicit user gesture.
    const popup = window.open('about:blank', '_blank');
    const wall = Date.now(), mono = performance.now();
    const current = {popup, portalOrigin: window.location.origin, wall, mono, expires: wall + 30000,
      deadline: mono + 30000, controller: new AbortController(), closed: false, auth: null, phase: 'starting'};
    flow = current; current.timer = setTimeout(() => fail(current), 30000);
    try {
      check(current); const identity = await cookie(current); check(current); current.userId = identity.userId;
      current.phase = 'ready'; popup.location.replace(nativeOrigin + '/reviews/jit');
      message('Opening the protected native review. Keep both windows open; no approval or denial is being submitted.');
    } catch (_) { fail(current); }
  }
  window.addEventListener('message', receive);
  start.addEventListener('click', begin);
  return {start: begin, dispose() {
    disposed = true; close(flow); window.removeEventListener('message', receive); start.removeEventListener('click', begin);
  }};
}
"""


def render_native_review_page(native_origin: str) -> str:
    from serverware import authority_native_jit_review_open_contract as wire
    from serverware.authority_native_jit_review_open_custody import origin

    selected = json.dumps(origin(native_origin)).replace("<", "\\u003c")
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Open protected review · Serverware</title>
<style>body{font:1rem system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
button{font:inherit;padding:.65rem 1rem}p{max-width:65ch}</style>
<main><h1>Open protected review</h1>
<p>Private request details open in a separate native window. This page coordinates access but never receives those details.</p>
<button id="native-review-open" type="button">Open review</button>
<p id="native-review-status" role="status" aria-live="polite"></p>
<p><a href="/#pending-actions">Return to Pending actions</a></p></main><script>""" + NATIVE_JIT_REVIEW_SCRIPT + "\ncreateNativeReviewController({nativeOrigin:" + selected + ",maximumRequestBytes:" + str(wire.MAX_HTTP_REQUEST) + "});</script></html>"
