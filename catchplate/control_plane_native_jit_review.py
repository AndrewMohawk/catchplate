"""Cookie-bound, public-only HTTP handoff to the native review authority.

The original Request is admitted before reading any body. The same finite
frame guards streaming, worker dispatch and actual response send. This module
never opens a retained pair and cannot select an authority from a flag or DTO.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
import hashlib
import hmac
import json
import os
import re
import threading
import time

from fastapi import Request
from starlette.responses import HTMLResponse, JSONResponse

from catchplate import authority_native_jit_review_open_contract as wire

PAGE = "/approvals/review/native"
PREFIX = "/api/approvals/review/native"
POST_PATHS = frozenset({PREFIX + "/authorize", PREFIX + "/receipt"})
PATHS = POST_PATHS | {PAGE}
_SCOPE_KEY = "catchplate.native_jit_review_open_frame"
_SLOTS = asyncio.BoundedSemaphore(2)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class ReviewUnavailable(ValueError):
    pass


def _need(value):
    if not value:
        raise ReviewUnavailable("Protected review is unavailable or changed")


def _error(status=503):
    return JSONResponse({"detail": "Protected review is unavailable or changed; no uncertain step was retried"},
        status_code=status, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _epoch(value):
    _need(type(value) is str)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _need(parsed.tzinfo is not None)
    return int(parsed.timestamp() * 1_000_000_000)


def _identity(request, owner, *, mutation):
    """Uncached local admission; the authority separately proves current rows."""
    from catchplate import auth, db, webauthn
    from catchplate.control_plane_approval_verification import _request_pin

    _request_pin(request)
    _need(auth.OIDC_ENABLED is True and auth.OIDC_BROWSER_LOGIN_ENABLED is True
        and owner.portal_origin == webauthn.WEBAUTHN_ORIGIN
        and type(request) is Request and request.scope.get("type") == "http"
        and request.scope.get("scheme") == "https" and request.url.scheme == "https"
        and not request.scope.get("root_path") and not request.scope.get("query_string")
        and request.scope.get("raw_path") == request.url.path.encode("ascii")
        and str(request.url).split("/", 3)[:3] == owner.portal_origin.split("/")
        and len(request.headers.getlist("host")) == 1
        and not request.headers.getlist("authorization")
        and not request.headers.getlist("x-catchplate-admin-token")
        and len(request.headers.getlist("cookie")) == 1)
    pieces = request.headers["cookie"].split(";")
    _need(all("=" in item and item.strip() for item in pieces))
    names = [item.strip().split("=", 1)[0] for item in pieces]
    _need(len(names) == len(set(names)) and "catchplate_admin" not in names)
    token = request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME)
    _need(auth.oidc_session_token_is_well_formed(token))
    if mutation:
        _need(request.method == "POST" and request.url.path in POST_PATHS
            and request.headers.getlist("origin") == [owner.portal_origin]
            and request.headers.getlist("content-type") == ["application/json"]
            and request.headers.getlist("sec-fetch-site") in ([], ["same-origin"]))
        csrf = request.cookies.get(auth.CSRF_COOKIE_NAME)
        headers = request.headers.getlist(auth.CSRF_HEADER_NAME)
        _need(type(csrf) is str and 0 < len(csrf) <= 1024 and len(headers) == 1
            and 0 < len(headers[0]) <= 1024 and hmac.compare_digest(csrf, headers[0]))
    else:
        _need(request.method in {"GET", "HEAD"}
            and request.url.path in {PAGE, "/api/approvals/capabilities"}
            and request.headers.getlist("origin") in ([], [owner.portal_origin])
            and request.headers.getlist("content-length") in ([], ["0"])
            and not request.headers.getlist("transfer-encoding"))
    session = db.get_active_oidc_browser_session(auth.oidc_session_token_digest(token))
    _need(type(session) is dict and session.get("status") == "active" and session.get("revoked_at") is None
        and type(session.get("id")) is str and _UUID.fullmatch(session["id"])
        and session.get("token_digest") == auth.oidc_session_token_digest(token)
        and bool(session.get("bound_webauthn_credential_id")))
    credential = session.get("_bound_credential")
    _need(type(credential) is dict and credential.get("id") == session["bound_webauthn_credential_id"]
        and credential.get("user_id") == session.get("user_id") and credential.get("revoked_at") is None
        and not credential.get("dev_private_key_pem"))
    identity = auth.oidc_identity_from_browser_session(session)
    _need(type(identity) is auth.AdminIdentity and identity.auth_method == "oidc-session"
        and identity.user_id.startswith("oidc:") and identity.has_any_role({"approver"}))
    trust = webauthn.credential_trust_status(credential)
    _need(trust.get("currently_trusted") is True
        and session.get("activation_trust_bundle_digest") == trust.get("current_trust_bundle_digest")
        and session.get("activation_trust_bundle_sequence") == trust.get("current_trust_bundle_sequence")
        and session.get("activation_authenticator_class") == trust.get("effective_authenticator_class"))
    expiry = min(_epoch(session["expires_at"]), _epoch(session["provider_expires_at"]))
    _need(time.time_ns() < expiry)
    pin = (identity, session["id"], session["token_digest"], expiry, credential["id"],
        credential.get("credential_id"), credential.get("public_key_cose"),
        trust.get("current_trust_bundle_digest"), trust.get("current_trust_bundle_sequence"),
        trust.get("effective_authenticator_class"))
    return pin, token.encode("ascii"), session["id"], expiry


class _Frame:
    def __init__(self, request):
        from catchplate import native_jit_review_open_service as service
        from catchplate.control_plane_approval_verification import _request_pin

        self.started_epoch, self.started_mono = time.time_ns(), time.monotonic_ns()
        self.expires = self.started_epoch + wire.MAX_INTERVAL_NS
        self.deadline_ns = self.started_mono + wire.MAX_INTERVAL_NS
        self.last_epoch, self.last_mono = self.started_epoch, self.started_mono
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.lock = os.getpid(), threading.RLock()
        self.closed = self.dispatched = False
        self.response = None
        self.owner = service.selected()
        _need(self.owner is not None)
        self.owner.check()
        self.mutation = request.url.path in POST_PATHS
        self.identity, token, self.session_id, expiry = _identity(request, self.owner, mutation=self.mutation)
        self.original_token = bytearray(token)
        self.expires = min(self.expires, expiry)
        self.deadline_ns = min(self.deadline_ns, self.started_mono + self.expires - self.started_epoch)
        self.check()

    def check(self):
        from catchplate import native_jit_review_open_service as service
        from catchplate.control_plane_approval_verification import _request_pin

        with self.lock:
            epoch, mono = time.time_ns(), time.monotonic_ns()
            _need(not self.closed and self.pid == os.getpid() and self.request.scope is self.scope
                and _request_pin(self.request) == self.pin and service.selected() is self.owner
                and self.last_epoch <= epoch < self.expires and self.last_mono <= mono < self.deadline_ns)
            self.owner.check()
            identity, token, session_id, expiry = _identity(self.request, self.owner, mutation=self.mutation)
            _need(identity == self.identity and token == self.original_token and session_id == self.session_id
                and self.expires <= expiry)
            end_epoch, end_mono = time.time_ns(), time.monotonic_ns()
            _need(epoch <= end_epoch < self.expires and mono <= end_mono < self.deadline_ns)
            self.last_epoch, self.last_mono = end_epoch, end_mono

    def clip(self, expiry):
        with self.lock:
            _need(type(expiry) is int)
            self.expires = min(self.expires, expiry)
            self.deadline_ns = min(self.deadline_ns, self.started_mono + self.expires - self.started_epoch)
            self.check()

    def stage(self, response):
        self.check()
        _need(self.response is None and len(response.body) <= wire.MAX_HTTP_RESPONSE)
        self.response = (response.status_code, response.body)
        return response

    def close(self):
        with self.lock:
            self.closed = True
            self.original_token[:] = bytes(len(self.original_token))
            self.response = None


def available(request):
    """Observe an already admitted owner; this read never initializes one."""
    frame = None
    try:
        frame = _Frame(request)
        return True
    except Exception:
        return False
    finally:
        if frame is not None:
            frame.close()


def page_response(request):
    from catchplate.portal_native_jit_review import render_native_review_page

    try:
        _need(request.url.path == PAGE and _SCOPE_KEY not in request.scope)
        frame = _Frame(request)
        request.scope[_SCOPE_KEY] = frame
        return frame.stage(HTMLResponse(render_native_review_page(frame.owner.native_origin),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"}))
    except Exception:
        return _error()


def _document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ReviewUnavailable()))


def _sha(original):
    return "sha256:" + hashlib.sha256(original.encode("ascii")).hexdigest()


def _scope(frame, scope, challenge, challenge_original):
    _need(scope["reviewId"] == challenge["reviewId"] and scope["approvalRequestId"] == challenge["approvalRequestId"]
        and scope["reviewerId"] == frame.identity[0].user_id and scope["sessionId"] == frame.session_id
        and scope["credentialRecordId"] == frame.identity[4] and scope["challengeSha256"] == _sha(challenge_original)
        and scope["browserNonceCommitment"] == challenge["browserNonceCommitment"]
        and scope["recipientPublicKey"] == challenge["recipientPublicKey"]
        and all(scope[name] == challenge[name] for name in ("sourceContractDigest",
            "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest")))


def _dispatch(frame, value):
    frame.check()
    challenge = wire.validate_challenge_original(value["challengeOriginal"])["statement"]
    _need(challenge["portalOrigin"] == frame.owner.portal_origin and challenge["nativeOrigin"] == frame.owner.native_origin
        and _UUID.fullmatch(challenge["approvalRequestId"]))
    frame.clip(challenge["expiresAtEpochNs"])
    if frame.request.url.path.endswith("/authorize"):
        _need(set(value) == {"challengeOriginal"})
        frame.dispatched = True
        result = frame.owner.authorize(challenge_original=value["challengeOriginal"],
            original_token=bytes(frame.original_token), session_id=frame.session_id,
            deadline_ns=frame.deadline_ns, check=frame.check)
        _need(type(result) is dict and set(result) == {"authorizationOriginal", "parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal"})
        authorization = wire.validate_authorization_original(result["authorizationOriginal"])["payload"]
        frame.clip(authorization["expiresAtEpochNs"])
        for name, maximum in (("parentOriginal", 512 * 1024), ("childOriginal", 512 * 1024),
                ("pairOriginal", 1024 * 1024), ("evidenceOriginal", 128 * 1024)):
            _need(type(result[name]) is str and 0 < len(result[name].encode("ascii")) <= maximum)
        scope = authorization["scope"]
        _need(all(scope[digest] == _sha(result[name]) for digest, name in (
            ("parentOriginalSha256", "parentOriginal"), ("childOriginalSha256", "childOriginal"),
            ("pairSha256", "pairOriginal"), ("sealProofSha256", "evidenceOriginal"))))
    else:
        _need(set(value) == {"challengeOriginal", "authorizationOriginal", "preparationOriginal"})
        authorization = wire.validate_authorization_original(value["authorizationOriginal"])["payload"]
        preparation = wire.validate_preparation_original(value["preparationOriginal"])["statement"]
        _need(preparation["scope"] == authorization["scope"]
            and preparation["authorizationSha256"] == _sha(value["authorizationOriginal"]))
        _scope(frame, authorization["scope"], challenge, value["challengeOriginal"])
        frame.clip(min(authorization["expiresAtEpochNs"], preparation["expiresAtEpochNs"]))
        frame.dispatched = True
        result = frame.owner.receipt(challenge_original=value["challengeOriginal"],
            authorization_original=value["authorizationOriginal"], preparation_original=value["preparationOriginal"],
            original_token=bytes(frame.original_token), session_id=frame.session_id,
            deadline_ns=frame.deadline_ns, check=frame.check)
        _need(type(result) is dict and set(result) == {"acknowledgmentOriginal"})
        ack = wire.validate_acknowledgment_original(result["acknowledgmentOriginal"])["payload"]
        _need(ack["scope"] == preparation["scope"] and ack["reviewDigest"] == preparation["reviewDigest"]
            and ack["authorizationSha256"] == _sha(value["authorizationOriginal"])
            and ack["preparationSha256"] == _sha(value["preparationOriginal"]))
        frame.clip(ack["expiresAtEpochNs"])
        scope = ack["scope"]
    _scope(frame, scope, challenge, value["challengeOriginal"])
    frame.check()
    return frame.stage(JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}))


async def handle_request(request):
    frame = None
    body = bytearray()
    try:
        _need(request.url.path in POST_PATHS and _SCOPE_KEY not in request.scope)
        # No request body is read before real cookie/current credential admission.
        frame = _Frame(request)
        request.scope[_SCOPE_KEY] = frame
        lengths = request.headers.getlist("content-length")
        _need(len(lengths) == 1 and re.fullmatch(r"[1-9][0-9]{0,6}", lengths[0])
            and not request.headers.getlist("transfer-encoding") and not request.headers.getlist("content-encoding"))
        size = int(lengths[0]); _need(2 <= size <= wire.MAX_HTTP_REQUEST)
        stream = request.stream().__aiter__()
        body_deadline = min(frame.deadline_ns, frame.started_mono + 5_000_000_000)
        while True:
            frame.check()
            remaining = (body_deadline - time.monotonic_ns()) / 1_000_000_000
            _need(remaining > 0)
            try:
                chunk = await asyncio.wait_for(anext(stream), timeout=remaining)
            except StopAsyncIteration:
                break
            frame.check(); _need(type(chunk) is bytes and len(body) + len(chunk) <= size)
            body.extend(chunk)
        _need(len(body) == size)
        value = _document(body.decode("utf-8")); body.clear()
        _need(type(value) is dict)
        fields = {"challengeOriginal"} if request.url.path.endswith("/authorize") else {
            "challengeOriginal", "authorizationOriginal", "preparationOriginal"}
        _need(set(value) == fields)
        frame.check()
        await asyncio.wait_for(_SLOTS.acquire(), timeout=(frame.deadline_ns - time.monotonic_ns()) / 1_000_000_000)
        try:
            worker = asyncio.create_task(asyncio.to_thread(_dispatch, frame, value))
        except BaseException:
            _SLOTS.release()
            raise
        def done(task):
            _SLOTS.release()
            if not task.cancelled():
                task.exception()
        worker.add_done_callback(done)
        return await asyncio.wait_for(asyncio.shield(worker),
            timeout=(frame.deadline_ns - time.monotonic_ns()) / 1_000_000_000)
    except asyncio.CancelledError:
        if frame is not None:
            frame.close()
        raise
    except Exception:
        if frame is not None:
            frame.close()
        return _error()
    finally:
        body.clear()


async def _send_response(scope, receive, send, response, *, before_dispatch=False, downstream_failed=False):
    frame = scope.get(_SCOPE_KEY)
    expected = ((response.status_code, frame.response[1]) if type(frame) is _Frame
        and frame.response is not None and scope.get("method") == "HEAD" and response.body == b""
        else (response.status_code, response.body))
    if (before_dispatch or downstream_failed or type(frame) is not _Frame or frame.closed
            or frame.response != expected):
        await _error()(scope, receive, send)
        return
    started = False
    async def guarded(message):
        nonlocal started
        frame.check()
        _need(scope is frame.scope and not any(name.lower() == b"set-cookie" for name, _ in response.raw_headers))
        if message.get("type") == "http.response.start":
            started = True
        await asyncio.wait_for(send(message), timeout=(frame.deadline_ns - time.monotonic_ns()) / 1_000_000_000)
    try:
        await response(scope, receive, guarded)
    except Exception:
        if started:
            raise RuntimeError("native review response lost its send guard") from None
        await _error()(scope, receive, send)


def _discard_scope(scope):
    frame = scope.pop(_SCOPE_KEY, None)
    if type(frame) is _Frame:
        frame.close()
