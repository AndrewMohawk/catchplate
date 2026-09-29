"""Cold-owner-bound genesis review and a dedicated, non-authoritative portal.

Only the maintenance gate dispatches these routes. Preview never reserves,
approves, writes, retries, or extends the signed maintenance window.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from serverware import authority_policy_file_approval as approval

PREFIX = "/api/policy/genesis-maintenance"
POSTS = frozenset({PREFIX + "/context", PREFIX + "/review"})
SCHEMA = "serverware.policyGenesisMaintenancePortal"
MAX_BODY = 24 * 1024 * 1024
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}


def _owner(owner):
    from serverware import control_plane_policy_genesis_maintenance as maintenance
    approval.require(type(owner) is maintenance.MaintenanceOwner and owner is maintenance._OWNER)
    owner.check()


def _actor(ceremony):
    identity = ceremony.identity
    approval.require(type(identity.user_id) is str and identity.user_id.startswith("oidc:")
        and len(identity.user_id.encode("utf-8")) <= 512
        and identity.auth_method == "oidc-session"
        and len(identity.roles) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in identity.roles))
    return {"userId": identity.user_id, "authMethod": identity.auth_method, "roles": sorted(identity.roles)}


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _row_bounds(row):
    import re
    approval.require(type(row["id"]) is str and re.fullmatch(r"[0-9a-f-]{36}", row["id"]) is not None
        and type(row["requester_id"]) is str and row["requester_id"].startswith("oidc:")
        and len(row["requester_id"].encode("utf-8")) <= 512
        and type(row["status"]) is str and 1 <= len(row["status"]) <= 64
        and type(row["expires_at"]) is str and 1 <= len(row["expires_at"]) <= 128
        and row["action"] in {"policy.file.genesis.materialize", "policy.file.resolve"}
        and (row.get("approved_by") is None or type(row["approved_by"]) is str and len(row["approved_by"].encode("utf-8")) <= 512))
    approval.digest(row["payload_digest"])


def _review(owner, request, body, deadline, expires):
    from serverware import control_plane_publication_authorization as ceremonies
    from serverware import control_plane_policy_file_publication as files
    _owner(owner)
    ceremony = ceremonies._Ceremony(request, purpose="policy-file", deadline_ns=deadline, expires_epoch_ns=expires)
    approval.require(type(body) is dict)
    if request.url.path == PREFIX + "/context":
        approval.require(body == {"schema": SCHEMA + "ContextRequest/v1"})
        from serverware import db
        rows = []
        # Bounded navigation, not complete absence proof. An exact ID can still
        # be reviewed directly if it is outside the newest 64 returned rows.
        for row in db.list_control_plane_approvals(limit=64):
            ceremony.check()
            try:
                owner.require_approval(row["id"])
            except (ValueError, KeyError, OSError):
                continue
            _row_bounds(row)
            rows.append({"approvalId": row["id"], "requesterId": row["requester_id"],
                "status": row["status"], "action": row["action"], "payloadDigest": row["payload_digest"],
                "expiresAt": row["expires_at"]})
        value = {"schema": SCHEMA + "Context/v1", "actor": _actor(ceremony),
            "targetOriginal": approval.canonical(owner.material_binding).decode("ascii"),
            "maintenanceExpiresAtEpochNs": str(owner.expires), "approvals": rows,
            "maxPolicyOriginalBytes": files.bundles.MAX_POLICY_BUNDLE_BYTES,
            "hardwareRequired": True, "distinctApproverRequired": True,
            "automaticRetryAllowed": False, "restartRequired": True}
    else:
        approval.require(body.get("schema") == SCHEMA + "ReviewRequest/v1"
            and body.get("kind") in {"bundle", "approval", "resolution"})
        fields = {"schema", "kind", "policyOriginalBase64url"}
        fields |= ({"approvalId"} if body["kind"] == "approval" else
            {"publicationId", "reason"} if body["kind"] == "bundle" else
            {"publicationId", "reason", "intentSha256", "outcome"})
        approval.require(set(body) == fields)
        raw = files._original(body["policyOriginalBase64url"])
        _, _, signed = files._signed(raw)
        ceremony.check()
        row_view = None
        if body["kind"] == "approval":
            row = ceremonies._approval(body["approvalId"], "policy-file")
            _row_bounds(row)
            owner.require_approval(body["approvalId"])
            bound = approval.request_binding(json.loads(row["request_json"]))
            approval.require(approval.canonical(bound).decode("ascii") == row["request_json"]
                and row["action"] == approval.action(bound) and row["resource_id"] == approval.RESOURCE
                and row["payload_digest"] == _digest(approval.canonical(bound)))
            row_view = {"approvalId": row["id"], "requesterId": row["requester_id"],
                "status": row["status"], "expiresAt": row["expires_at"], "approvedBy": row.get("approved_by"),
                "action": row["action"], "payloadDigest": row["payload_digest"]}
        elif body["kind"] == "bundle":
            bound = {"kind": "genesis-materialize", "publicationId": body["publicationId"],
                "reason": body["reason"], **signed, "expectedFileSha256": None,
                "genesisPreparationDigest": owner.scope["genesisPreparationDigest"],
                "genesisFinalizationDigest": owner.scope["genesisFinalizationDigest"]}
        else:
            bound = {key: body[key] for key in ("publicationId", "intentSha256", "outcome", "reason")}
            bound["kind"] = "resolve"
        bound = approval.request_binding(bound)
        owner.matches(bound)
        if bound["kind"] == "resolve":
            observed = files.inspect_publication()
            matches = [item for item in observed["attempts"] if item["publicationId"] == bound["publicationId"]
                and item["intentSha256"] == bound["intentSha256"]]
            approval.require(len(matches) == 1)
            material = matches[0]["binding"]
        else:
            material = bound
        approval.require(all(material[key] == value for key, value in signed.items()))
        owner.matches(material)
        value = {"schema": SCHEMA + "Review/v1", "actor": _actor(ceremony),
            "requestOriginal": approval.canonical(bound).decode("ascii"),
            "materialOriginal": approval.canonical(material).decode("ascii"),
            "payloadDigest": _digest(approval.canonical(bound)), "approval": row_view,
            "policyOriginalBytes": len(raw), "maintenanceExpiresAtEpochNs": str(owner.expires),
            "automaticRetryAllowed": False}
    ceremony.check()
    _owner(owner)
    approval.require(len(approval.canonical(value)) <= 128 * 1024)
    return value


def _object(pairs):
    value = {}
    for key, item in pairs:
        approval.require(key not in value)
        value[key] = item
    return value


async def dispatch(owner, scope, receive, send):
    """Fixed routes only, reached after the genuine outer maintenance gate."""
    _owner(owner)
    if scope["method"] == "GET" and scope["path"] == "/":
        digest = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
        headers = {**HEADERS, "Content-Security-Policy": "default-src 'none'; script-src 'sha256-" + digest
            + "'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}
        await HTMLResponse(HTML.replace("__SCRIPT__", SCRIPT), headers=headers)(scope, receive, send)
        return
    request = Request(scope, receive)
    try:
        until = min(time.monotonic_ns() + 30_000_000_000, owner.outer_deadline)
        expires = min(time.time_ns() + 30_000_000_000, owner.expires)
        approval.require(request.method == "POST" and request.url.path in POSTS and not request.url.query
            and not request.headers.get("authorization") and not request.headers.get("x-serverware-admin-token")
            and not request.headers.get("content-encoding")
            and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json")
        # Authenticate and check cookie CSRF before accepting a large upload.
        from serverware.control_plane_publication_authorization import _identity
        identity = await run_in_threadpool(_identity, request, "policy-file")
        approval.require(identity.auth_method == "oidc-session")
        approval.require(time.monotonic_ns() < until and time.time_ns() < expires)
        raw = bytearray()
        chunks = 0
        async with asyncio.timeout(max(0, until - time.monotonic_ns()) / 1_000_000_000):
            async for chunk in request.stream():
                _owner(owner)
                chunks += 1
                approval.require(time.monotonic_ns() < until and chunks <= 4096
                    and len(raw) + len(chunk) <= (1024 if request.url.path.endswith("/context") else MAX_BODY))
                raw.extend(chunk)
        value = json.loads(raw, object_pairs_hook=_object)
        approval.require(time.monotonic_ns() < until)
        result = await run_in_threadpool(_review, owner, request, value, until, expires)
        approval.require(time.monotonic_ns() < until)
        response = JSONResponse(result, headers=HEADERS)
    except HTTPException as exc:
        response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=HEADERS)
    except Exception:
        response = JSONResponse({"detail": "Exact genesis review unavailable; no effect authorized or retried"},
            status_code=409, headers=HEADERS)
    await response(scope, receive, send)


HTML = r"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Serverware · Genesis maintenance</title><style>
body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f7f9fc}
section{background:white;border:1px solid #bcc9db;border-radius:8px;padding:1rem;margin:1rem 0}
label{display:block;margin-top:1rem}input,textarea,select{box-sizing:border-box;width:100%;padding:.55rem;font:inherit}
button,a{margin:.5rem .5rem .5rem 0}button{padding:.65rem;border:1px solid #234f7e;border-radius:4px;background:#edf5ff;cursor:pointer}
button:disabled{opacity:.45;cursor:not-allowed}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:28rem;overflow:auto}
.warning{border-left:5px solid #b45400;padding-left:1rem}h1{font-size:1.7rem}[role=alert]{color:#8b2500}
</style><h1>Genesis maintenance · not the normal dashboard</h1>
<p class="warning">Only the independently admitted finalized genesis may be published here. Runtime, provider, release and business routes are disabled. A successful publication does not start services: stop this process and perform a fresh normal startup.</p>
<section><h2>1 · Authenticated operator</h2><a href="/api/auth/oidc/start?return_to=/">Sign in with OIDC</a>
<button id="status">Read current session</button><button id="session">Bind pending session with existing passkey once</button>
<button id="logout">Sign out</button><pre id="auth">No current session checked.</pre>
<p>Use independently enrolled operators. This page does not enroll, recover or replace a key. If a session action is uncertain, read current status; do not repeat its assertion.</p></section>
<section><h2>2 · Exact signed target and bundle</h2><button id="context">Read cold target and approval queue</button><pre id="target">Not inspected.</pre>
<label for="bundle">Original signed policy file (maximum 16 MiB; kept only in memory)</label><input id="bundle" type="file">
<label for="reason">Exact requester reason (optional)</label><textarea id="reason" maxlength="500"></textarea>
<button id="review">Verify original and review new genesis request</button>
<pre id="reviewed">No reviewed request. Review is not permission.</pre>
<details><summary>Exact selected signed file (read all policy rules before authorizing)</summary><pre id="file-original">No verified file selected.</pre></details>
<label><input id="confirmed" type="checkbox">I reviewed the exact signed file, target, reason and selected action shown above.</label></section>
<section><h2>3 · Distinct operators and explicit one-shot actions</h2><pre id="queue">No approvals inspected.</pre>
<label for="approval">Exact approval ID (also accepts an ID outside the bounded queue)</label><input id="approval" maxlength="36" autocomplete="off">
<button id="select">Review this approval against selected original</button>
<p>The requester and different approver both review the same original file. Each action requires a NEW hardware ceremony. An approved request is not a completed filesystem effect.</p>
<button id="request" disabled>Fresh requester passkey · request approval once</button>
<button id="decide" disabled>Different operator · approve once</button>
<button id="execute" disabled>Fresh requester passkey · materialize or resolve once</button>
<p id="message" role="status" aria-live="polite">No action submitted.</p></section>
<section><h2>4 · Inspect interruption; explicitly resolve retained intent</h2><button id="inspect">Read exact file/journal observation</button><pre id="observation">Not inspected.</pre>
<label for="attempt">Retained publication ID</label><input id="attempt" maxlength="32" autocomplete="off">
<label for="intent">Retained intent SHA-256</label><input id="intent" maxlength="71" autocomplete="off">
<label for="outcome">Explicit resolution (no rename or retry)</label><select id="outcome"><option value="finalize-installed">Finalize installed exact original</option><option value="abandon-uninstalled">Abandon definitely uninstalled exact original</option></select>
<button id="resolve">Review selected resolution against signed file</button>
<p>A missing response or missing association is UNKNOWN, not noncommit. Resolution requires its own new requester/different-approver ceremonies and exact protected readback. Malformed, orphaned or superseded history is refused.</p>
<h3>Nonsecret recovery hints</h3><pre id="hints">No local hints.</pre><button id="copy">Copy displayed recovery hints</button>
<p>Hints persist only in this tab, never assertions, policy bytes, keys, tokens or DSNs. They are navigation data, not evidence or authority. Inspection never unlocks a sent action.</p></section>
<script>__SCRIPT__</script></html>"""


SCRIPT = r"""
'use strict';
const $ = id => document.getElementById(id), prefix = '/api/policy/genesis-maintenance';
const schema = 'serverware.policyGenesisMaintenancePortal', optionsSchema = 'serverware.policyFileApprovalOptions/v1';
const storeKey = 'serverware.genesisMaintenanceHints.v1';
let busy = false, csrf = null, context = null, review = null, original = null, observation = null;
let history = [], storageOK = true, sessionAttempted = false, terminal = false;
const need = (value, message = 'Exact data or current authority unavailable; no automatic retry.') => {if (!value) throw new Error(message);};
const closed = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const id = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const aid = value => typeof value === 'string' && /^[0-9a-f-]{36}$/.test(value);
const bytes = value => new TextEncoder().encode(value);
function say(message, error = false) {$('message').textContent = message; $('message').setAttribute('role', error ? 'alert' : 'status');}
function hintOK(h) {return closed(h, ['phase','kind','publicationId','payloadDigest','approvalId','actorId','status'])
  && ['request','decide','execute','session'].includes(h.phase) && (h.publicationId === null || id(h.publicationId))
  && ['genesis-materialize','resolve',null].includes(h.kind)
  && (h.payloadDigest === null || digest(h.payloadDigest)) && (h.approvalId === null || aid(h.approvalId))
  && typeof h.actorId === 'string' && bytes(h.actorId).length <= 512
  && ['handoff-attempted','approval-observed','completion-observed'].includes(h.status);}
try {const raw = sessionStorage.getItem(storeKey); need(raw === null || bytes(raw).length <= 65536);
  history = raw === null ? [] : JSON.parse(raw); need(Array.isArray(history) && history.length <= 32 && history.every(hintOK));
  sessionAttempted = history.some(h => h.phase === 'session');
  terminal = history.some(h => h.phase === 'execute' && h.status === 'completion-observed');
} catch (_) {storageOK = false; history = [];}
function save() {need(storageOK && history.length <= 32 && history.every(hintOK)); const raw = JSON.stringify(history);
  need(bytes(raw).length <= 65536); try {sessionStorage.setItem(storeKey, raw); need(sessionStorage.getItem(storeKey) === raw);}
  catch (_) {storageOK = false; throw new Error('Recovery hints could not be retained; no effect will be sent.');}
  $('hints').textContent = JSON.stringify(history, null, 2);}
function blocked(phase) {if (!review) return true; const b = JSON.parse(review.requestOriginal);
  return history.some(h => h.phase === phase && (phase === 'decide' ? h.approvalId === review.approval?.approvalId
    : h.kind === b.kind && (b.kind === 'genesis-materialize' || h.publicationId === b.publicationId)));}
function render() {
  for (const element of document.querySelectorAll('button,input,textarea,select')) element.disabled = busy;
  const row = review?.approval, actor = review?.actor.userId;
  $('request').disabled = busy || terminal || !storageOK || !$('confirmed').checked || !review || row !== null || blocked('request');
  $('decide').disabled = busy || terminal || !storageOK || !$('confirmed').checked || !row || row.status !== 'pending' || row.requesterId === actor || blocked('decide');
  $('execute').disabled = busy || terminal || !storageOK || !$('confirmed').checked || !row || row.status !== 'approved'
    || row.requesterId !== actor || typeof row.approvedBy !== 'string' || row.approvedBy === actor || blocked('execute');
  $('session').disabled = busy || !storageOK || sessionAttempted;
  $('hints').textContent = storageOK ? JSON.stringify(history, null, 2) : 'Local hints unavailable. All effects blocked.';
}
function operation() {need(!busy && window.isSecureContext && window.top === window); busy = true;
  const controller = new AbortController(), deadline = performance.now() + 30000;
  const timer = setTimeout(() => controller.abort(), 30000); render();
  return {signal: controller.signal, deadline, current() {need(!controller.signal.aborted && performance.now() < deadline,
    'Original browser operation expired. Any dispatched result is unknown.');}, close() {clearTimeout(timer); busy = false; render();}};}
async function jsonReply(op, response) {op.current(); need(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true}); let raw = '', size = 0, chunks = 0;
  try {for (;;) {const part = await reader.read(); op.current(); if (part.done) break;
    size += part.value.length; need(size <= 256 * 1024 && ++chunks <= 1024); raw += decoder.decode(part.value, {stream: true});}
    raw += decoder.decode();} finally {await reader.cancel().catch(() => {});}
  const value = JSON.parse(raw); op.current(); return {status: response.status, ok: response.ok, value};}
async function call(op, path, body = undefined) {op.current();
  need(path === '/api/auth/status' || path === '/api/csrf' || path === '/api/policy/file-publication'
    || ['/api/auth/session/webauthn/options','/api/auth/session/webauthn/verify','/api/auth/logout',prefix+'/context',prefix+'/review',
      '/api/policy/file-publication/webauthn/options','/api/policy/file-publication/genesis-materialize','/api/policy/file-publication/resolve'].includes(path)
    || /^\/api\/control-plane\/approvals\/[0-9a-f-]{36}\/approve$/.test(path));
  if (body !== undefined && !csrf) {const got = await call(op, '/api/csrf'); need(got.ok && got.value.ok === true
    && got.value.header === 'X-Serverware-CSRF-Token' && typeof got.value.token === 'string' && got.value.token.length <= 512); csrf = got.value.token;}
  const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  need(raw === undefined || bytes(raw).length <= 24 * 1024 * 1024); op.current();
  return jsonReply(op, await fetch(path, {method: raw === undefined ? 'GET' : 'POST', credentials:'same-origin', cache:'no-store', redirect:'error',
    signal:op.signal, headers:raw === undefined ? {} : {'Content-Type':'application/json','X-Serverware-CSRF-Token':csrf}, body:raw}));}
async function good(op,path,body) {const reply = await call(op,path,body); need(reply.ok, 'Server refused this action or observation. No automatic retry.'); return reply.value;}
async function sha(raw) {return 'sha256:' + [...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(v=>v.toString(16).padStart(2,'0')).join('');}
function encode(raw) {let s=''; for(let i=0;i<raw.length;i+=8192)s+=String.fromCharCode(...raw.subarray(i,i+8192)); return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');}
function decode(value) {need(typeof value==='string' && /^[A-Za-z0-9_-]+$/.test(value) && value.length<=32768); const s=atob(value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4));
  const raw=Uint8Array.from(s,c=>c.charCodeAt(0)); need(encode(raw)===value); return raw;}
async function assertion(op, publicKey) {op.current(); need(publicKey && publicKey.userVerification==='required' && Array.isArray(publicKey.allowCredentials)
    && publicKey.allowCredentials.length>=1 && publicKey.allowCredentials.length<=64 && typeof publicKey.rpId==='string'
    && (location.hostname===publicKey.rpId || location.hostname.endsWith('.'+publicKey.rpId)));
  const credential=await navigator.credentials.get({signal:op.signal,publicKey:{...publicKey,challenge:decode(publicKey.challenge),
    allowCredentials:publicKey.allowCredentials.map(c=>({type:'public-key',id:decode(c.id)})),timeout:Math.min(30000,op.deadline-performance.now())}});
  op.current(); need(credential?.type==='public-key' && publicKey.allowCredentials.some(c=>c.id===credential.id)
    && encode(new Uint8Array(credential.rawId))===credential.id); const r=credential.response;
  const client=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(r.clientDataJSON));
  need(client.type==='webauthn.get' && client.challenge===publicKey.challenge && client.origin===location.origin && client.crossOrigin!==true);
  const result={id:credential.id,rawId:encode(new Uint8Array(credential.rawId)),type:'public-key',response:{
    authenticatorData:encode(new Uint8Array(r.authenticatorData)),clientDataJSON:encode(new Uint8Array(r.clientDataJSON)),
    signature:encode(new Uint8Array(r.signature)),userHandle:r.userHandle===null?null:encode(new Uint8Array(r.userHandle))}};
  need(bytes(JSON.stringify(result)).length<=14000); return result;}
async function loadFile(op) {const f=$('bundle').files[0]; need(f && f.size>0 && f.size<=16*1024*1024);
  const raw=new Uint8Array(await f.arrayBuffer()); op.current(); need(raw.length===f.size); return {raw,encoded:encode(raw),sha:await sha(raw)};}
async function readContext(op) {const value=await good(op,prefix+'/context',{schema:schema+'ContextRequest/v1'});
  need(closed(value,['schema','actor','targetOriginal','maintenanceExpiresAtEpochNs','approvals','maxPolicyOriginalBytes','hardwareRequired','distinctApproverRequired','automaticRetryAllowed','restartRequired'])
    && value.schema===schema+'Context/v1' && value.hardwareRequired===true && value.distinctApproverRequired===true
    && value.automaticRetryAllowed===false && value.restartRequired===true && value.maxPolicyOriginalBytes===16*1024*1024
    && typeof value.targetOriginal==='string' && bytes(value.targetOriginal).length<=8192 && Array.isArray(value.approvals) && value.approvals.length<=64);
  context=value; $('target').textContent=value.targetOriginal+'\nOriginal maintenance expiry (epoch ns): '+value.maintenanceExpiresAtEpochNs;
  $('queue').textContent=JSON.stringify(value.approvals,null,2); $('auth').textContent=JSON.stringify(value.actor,null,2); return value;}
async function acceptReview(op,value,file,keepConfirmation=false) {need(closed(value,['schema','actor','requestOriginal','materialOriginal','payloadDigest','approval','policyOriginalBytes','maintenanceExpiresAtEpochNs','automaticRetryAllowed'])
    && value.schema===schema+'Review/v1' && value.automaticRetryAllowed===false && value.policyOriginalBytes===file.raw.length
    && typeof value.requestOriginal==='string' && bytes(value.requestOriginal).length<=8192
    && typeof value.materialOriginal==='string' && bytes(value.materialOriginal).length<=8192
    && digest(value.payloadDigest) && await sha(bytes(value.requestOriginal))===value.payloadDigest);
  const material=JSON.parse(value.materialOriginal),bound=JSON.parse(value.requestOriginal);
  need(material.kind==='genesis-materialize' && material.expectedFileSha256===null && material.policyOriginalSha256===file.sha
    && id(bound.publicationId) && ['genesis-materialize','resolve'].includes(bound.kind));
  if(value.approval!==null)need(closed(value.approval,['approvalId','requesterId','status','expiresAt','approvedBy','action','payloadDigest'])
    && aid(value.approval.approvalId) && value.approval.payloadDigest===value.payloadDigest);
  op.current(); review=value; original=file; $('reviewed').textContent='Exact reviewed request (ASCII original; integer precision preserved):\n'+value.requestOriginal
    +'\nExact underlying material:\n'+value.materialOriginal+'\nPayload: '+value.payloadDigest+'\nActor: '+value.actor.userId;
  $('file-original').textContent=new TextDecoder('utf-8',{fatal:true}).decode(file.raw);
  if(!keepConfirmation)$('confirmed').checked=false;
  $('attempt').value=bound.publicationId; if(bound.kind==='resolve')$('intent').value=bound.intentSha256;
  if(value.approval)$('approval').value=value.approval.approvalId; say('Review only. Select one explicit fresh ceremony.');}
function burn(phase) {need(review && storageOK && !blocked(phase) && history.length<32); const b=JSON.parse(review.requestOriginal);
  const h={phase,kind:b.kind,publicationId:b.publicationId,payloadDigest:review.payloadDigest,approvalId:review.approval?.approvalId||null,
    actorId:review.actor.userId,status:'handoff-attempted'}; history.push(h); save(); return h;}
async function ceremony(op, phase) {need(review && original && !terminal); const row=review.approval, bound=JSON.parse(review.requestOriginal);
  const current=await readContext(op);need(current.actor.userId===review.actor.userId
    && current.actor.authMethod===review.actor.authMethod && current.maintenanceExpiresAtEpochNs===review.maintenanceExpiresAtEpochNs);
  const action=bound.kind==='resolve'?'policy.file.resolve':'policy.file.genesis.materialize';
  // Embed the exact ASCII binding, rather than round-tripping i64 through JS numbers.
  let raw='{"apiVersion":'+JSON.stringify(optionsSchema)+',"action":'+JSON.stringify(action)+',"resourceId":"active-policy-file","payloadDigest":'
    +JSON.stringify(review.payloadDigest)+',"request":'+review.requestOriginal;
  if(row)raw+=',"approvalId":'+JSON.stringify(row.approvalId); raw+='}';
  const options=await good(op,'/api/policy/file-publication/webauthn/options',raw), proof=options.serverware;
  need(closed(options,['publicKey','serverware']) && closed(proof,['schema','operation','operationId','challengeId','credentialRecordId','payloadDigest','expiresAt'])
    && proof.schema===optionsSchema && proof.operation==='policy-file-approval.'+phase
    && proof.payloadDigest===review.payloadDigest && digest(proof.operationId) && digest(proof.challengeId)
    && Number.isFinite(Date.parse(proof.expiresAt)) && Date.parse(proof.expiresAt)>Date.now());
  return assertion(op,options.publicKey);}
async function effect(op,phase) {need(review && original && $('confirmed').checked && !blocked(phase));
  if(review.approval){const previous=review.requestOriginal,actor=review.actor.userId;
    const checked=await good(op,prefix+'/review',{schema:schema+'ReviewRequest/v1',kind:'approval',approvalId:review.approval.approvalId,policyOriginalBase64url:original.encoded});
    need(checked.requestOriginal===previous && checked.actor.userId===actor); await acceptReview(op,checked,original,true);}
  const row=review.approval,b=JSON.parse(review.requestOriginal),actor=review.actor.userId;
  need(phase==='request'?row===null:row && Date.parse(row.expiresAt)>Date.now() && (phase==='decide'
    ?row.status==='pending' && row.requesterId!==actor:row.status==='approved' && row.requesterId===actor && row.approvedBy && row.approvedBy!==actor));
  let signed=await ceremony(op,phase==='execute'?'consume':phase);
  try {const mfa={publicationProfile:optionsSchema,assertion:signed}; if(phase==='execute')mfa.approvalId=row.approvalId;
    let path,body;
    if(phase==='decide'){path='/api/control-plane/approvals/'+row.approvalId+'/approve';body={note:null,mfa};}
    else if(b.kind==='resolve'){path='/api/policy/file-publication/resolve';body={publicationId:b.publicationId,intentSha256:b.intentSha256,outcome:b.outcome,reason:b.reason,mfa};}
    else {path='/api/policy/file-publication/genesis-materialize';body={publicationId:b.publicationId,policyOriginalBase64url:original.encoded,
      genesisPreparationDigest:b.genesisPreparationDigest,genesisFinalizationDigest:b.genesisFinalizationDigest,expectedFileSha256:null,reason:b.reason,mfa};}
    const hint=burn(phase); say('Handoff attempted. A lost response stays unknown; do not resend.');
    const reply=await call(op,path,body);
    if(phase==='request'){const d=reply.value.detail;need(reply.status===428 && d?.error==='control_plane_approval_required' && aid(d.approvalId)
      && d.status==='pending' && d.payloadDigest===review.payloadDigest && d.action===(b.kind==='resolve'?'policy.file.resolve':'policy.file.genesis.materialize') && d.resourceId==='active-policy-file');
      hint.approvalId=d.approvalId;hint.status='approval-observed';save();$('approval').value=d.approvalId;
      say('Pending approval '+d.approvalId+'. A different operator must review and approve. No filesystem effect reported.');}
    else if(phase==='decide'){need(reply.ok && reply.value.id===row.approvalId && reply.value.status==='approved'
      && reply.value.approved_by===actor && reply.value.requester_id===row.requesterId && reply.value.payload_digest===review.payloadDigest);
      hint.status='approval-observed';save();say('Distinct-person approval observed. Requester must explicitly review it and provide a NEW consume assertion.');}
    else {need(reply.ok && closed(reply.value,['schema','ok','publicationId','completionSha256','outcome','automaticRetryAllowed'])
      && reply.value.schema==='serverware.policyFilePublicationResult/v1' && reply.value.ok===true && reply.value.publicationId===b.publicationId
      && digest(reply.value.completionSha256) && reply.value.outcome===(b.kind==='resolve'?b.outcome:'materialized') && reply.value.automaticRetryAllowed===false);
      hint.status='completion-observed';save();terminal=true; original=null;
      say('Terminal publication/resolution observed. RESTART REQUIRED: stop maintenance and use a fresh normal startup. Abandonment does not provision a policy or authorize another genesis attempt.');}
  } finally {signed=null;}}
async function run(fn) {let op;try {op=operation();await fn(op);}catch(error){say(error.message+' Any dispatched effect remains locked; inspect explicitly.',true);}finally{op?.close();}}
$('status').onclick=()=>run(async op=>{$('auth').textContent=JSON.stringify(await good(op,'/api/auth/status'),null,2);});
$('session').onclick=()=>run(async op=>{need(!sessionAttempted && storageOK && history.length<32);const options=await good(op,'/api/auth/session/webauthn/options',{});
  need(closed(options,['publicKey','serverware']) && closed(options.serverware,['challenge_id','payload_digest']) && digest(options.serverware.payload_digest));
  let signed=await assertion(op,options.publicKey);try {sessionAttempted=true;history.push({phase:'session',kind:null,publicationId:null,payloadDigest:null,approvalId:null,actorId:'pending-cookie',status:'handoff-attempted'});save();
    const reply=await good(op,'/api/auth/session/webauthn/verify',{response:signed});need(reply.ok===true && reply.authenticated===true);
    csrf=null;say('Session endpoint acknowledged. Read current session before publication; no fallback or retry.');}finally{signed=null;}});
$('logout').onclick=()=>run(async op=>{await good(op,'/api/auth/logout',{});csrf=null;context=null;review=null;original=null;say('Signed out. Recovery hints remain observations only.');});
$('context').onclick=()=>run(readContext);
$('review').onclick=()=>run(async op=>{review=null;await readContext(op);const file=await loadFile(op);
  // Hex is the actual backend ID contract; no timestamp or inferred slot.
  const publicationId=[...crypto.getRandomValues(new Uint8Array(16))].map(x=>x.toString(16).padStart(2,'0')).join('');
  const value=await good(op,prefix+'/review',{schema:schema+'ReviewRequest/v1',kind:'bundle',publicationId,reason:$('reason').value||null,policyOriginalBase64url:file.encoded});
  await acceptReview(op,value,file);});
$('select').onclick=()=>run(async op=>{review=null;const file=await loadFile(op);need(aid($('approval').value));const value=await good(op,prefix+'/review',
  {schema:schema+'ReviewRequest/v1',kind:'approval',approvalId:$('approval').value,policyOriginalBase64url:file.encoded});await acceptReview(op,value,file);});
$('resolve').onclick=()=>run(async op=>{review=null;const file=await loadFile(op);need(id($('attempt').value)&&digest($('intent').value));
  const value=await good(op,prefix+'/review',{schema:schema+'ReviewRequest/v1',kind:'resolution',publicationId:$('attempt').value,intentSha256:$('intent').value,
    outcome:$('outcome').value,reason:$('reason').value||null,policyOriginalBase64url:file.encoded});await acceptReview(op,value,file);});
for(const phase of ['request','decide','execute'])$(phase).onclick=()=>run(op=>effect(op,phase));
$('inspect').onclick=()=>run(async op=>{observation=await good(op,'/api/policy/file-publication');need(observation.schema==='serverware.policyFilePublicationObservation/v1'
  && observation.automaticRetryAllowed===false && Array.isArray(observation.attempts)&&observation.attempts.length<=16);
  $('observation').textContent=JSON.stringify(observation,null,2);if(observation.terminalSha256 && observation.terminalMatches && observation.incompletePublicationId===null){
    terminal=true;say('Settled terminal observation. RESTART REQUIRED; no automatic promotion or new genesis attempt.');}
  else say('Read-only observation only. Missing/incomplete association remains unknown; no sent action was unlocked.');});
$('copy').onclick=()=>run(async op=>{await navigator.clipboard.writeText($('hints').textContent);op.current();say('Nonsecret recovery hints copied.');});
for(const field of ['bundle','reason','approval','attempt','intent','outcome'])$(field).addEventListener('change',()=>{review=null;original=null;$('confirmed').checked=false;$('file-original').textContent='Selection changed; review again.';render();});
$('confirmed').addEventListener('change',render);
render();
"""
