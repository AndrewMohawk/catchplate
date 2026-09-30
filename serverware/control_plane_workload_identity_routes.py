"""Cookie-only, fresh two-person issuance of independently granted originals.

The pre-parser owns one cold request scope through the actual signed HTTP send.
Neither a CA-install session, successful options call nor HTTP approval mints an
issuance grant. No original packet, assertion, cookie or key is logged/stored.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from serverware import auth, webauthn
from serverware import control_plane_workload_identity_client as client
from serverware import control_plane_workload_identity_startup as startup
from serverware import workload_identity_issuer_transport as transport
from serverware.setup_receipts import JsonLimits, parse_strict_json_object


router = APIRouter()
ACTION = "workload.identity.issue"
POST_PATH = "/api/agents/workload-identity/issue"
OPTIONS_PATH = POST_PATH + "/options"
PATHS = frozenset({POST_PATH, OPTIONS_PATH})
from serverware import control_plane_setup_native_enrollment as native_setup
PATHS = PATHS | native_setup.PATHS
REQUEST_SCHEMA = "serverware.workloadIdentityIssuanceRequest/v1"
RESPONSE_SCHEMA = "serverware.workloadIdentityIssuanceResponse/v1"
MAX_REQUEST_BYTES = 12 * 1024 * 1024
_SCOPE_KEY = "serverware.workload-identity-issuance.original-request"
_CONSTRUCTION = object()
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_LIMITS = JsonLimits(max_bytes=MAX_REQUEST_BYTES, max_depth=8, max_object_keys=16,
    max_total_keys=128, max_array_items=16, max_total_nodes=512,
    max_string_bytes=MAX_REQUEST_BYTES)
_SMALL_LIMITS = JsonLimits(max_bytes=32 * 1024, max_depth=6, max_object_keys=16,
    max_total_keys=96, max_array_items=16, max_total_nodes=256, max_string_bytes=16 * 1024)


def _fail(status=403):
    raise HTTPException(status_code=status, detail="workload issuance request refused")


def error(status_code=503, *, unknown=False):
    code = status_code if type(status_code) is int and status_code in (
        400, 401, 403, 405, 409, 412, 413, 415, 428, 503) else 503
    return JSONResponse(status_code=code, headers=_HEADERS, content={
        "schema": RESPONSE_SCHEMA, "status": "issuance-outcome-unknown" if unknown else "refused",
        "automaticRetryAllowed": False, "proxyAuthenticated": False, "enrollmentComplete": False})


async def _blocking(operation):
    from serverware import app as application

    # Cancellation must not close the source scope while its sequential worker
    # still owns the same ledger. Wait only for that already bounded operation.
    task = asyncio.create_task(application._run_bounded_blocking(
        application._SIGNED_RESPONSE_WORKER_SLOTS, operation))
    cancelled = None
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError as exc:
            cancelled = exc
            if task.done():
                raise
        except BaseException:
            if cancelled is not None:
                raise cancelled
            raise
    if cancelled is not None:
        raise cancelled
    return result


def _cookie_identity(request, *, approver=False):
    """No header auth and no cached Request OIDC identity, including final send."""
    from serverware import app as application

    if (request.headers.getlist("authorization") or request.headers.getlist("x-serverware-admin-token")
            or request.headers.getlist("origin") != [webauthn.WEBAUTHN_ORIGIN]
            or not webauthn.WEBAUTHN_ORIGIN or webauthn.WEBAUTHN_ORIGIN == "null"
            or len(request.headers.getlist("cookie")) != 1):
        _fail()
    application._require_registration_execution_session_csrf(request)
    # Starlette's cookie dictionary otherwise hides duplicate auth cookies.
    names = [part.strip().split("=", 1)[0] for part in request.headers["cookie"].split(";")]
    if any(names.count(name) > 1 for name in (
            "serverware_admin", auth.OIDC_SESSION_COOKIE_NAME, auth.CSRF_COOKIE_NAME)):
        _fail()
    admin = request.cookies.get("serverware_admin")
    oidc = request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME)
    if bool(admin) == bool(oidc):
        _fail(401)
    try:
        if admin:
            if len(admin) > 4096 or not auth.check_admin_token(admin):
                _fail(401)
            identity = auth.AdminIdentity(auth.ADMIN_USER_ID, frozenset(auth.ADMIN_ROLES), "admin-cookie")
        else:
            identity = auth.oidc_identity_from_session_token(oidc)
    except Exception:
        _fail(401)
    if (type(identity) is not auth.AdminIdentity or type(identity.user_id) is not str
            or not 1 <= len(identity.user_id) <= 4096 or len(identity.roles) > 64
            or not identity.has_any_role({"approver" if approver else "policy_author"})):
        _fail()
    return identity


def _fresh_assertion(*, identity, resource_id, payload_digest, mfa, approval_context=None):
    from serverware import app as application

    if (type(mfa) is not dict or not {"assertion"} <= set(mfa) <= {"assertion", "approvalId"}
            or type(mfa["assertion"]) is not dict):
        _fail(412)
    approval_id = mfa.get("approvalId")
    if approval_id is not None and (type(approval_id) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", approval_id) is None):
        _fail(400)
    try:
        # Deliberately never use the optional-MFA/authority-DTO generic helper.
        return application.verify_control_plane_mutation_assertion(
            user_id=identity.user_id, action=ACTION, resource_id=resource_id,
            payload_digest=payload_digest, authn_policy=application._control_plane_mutation_authn_policy(),
            assertion=mfa["assertion"], approval_context=approval_context)
    except Exception:
        _fail()


def _approve_assertion(request, approval, mfa):
    from serverware import control_plane_workload_identity_approval as approval_source

    try:
        return approval_source._verify_on_request(request, approval=approval, mfa=mfa)
    except Exception:
        _fail()


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class _Frame:
    def __init__(self, construction, scope, manager, context, size):
        if construction is not _CONSTRUCTION:
            _fail()
        self.scope, self.manager, self.context, self.size = scope, manager, context, size
        self.path, self.headers = scope["path"], tuple(scope["headers"])
        self.original, self.request, self.identity, self.policy = None, None, None, None
        self.credential, self.result, self.response = None, None, None
        self.started, self.dispatched, self.closed = False, False, False
        self.approver = False

    def base(self):
        self.context.work.charge(input_bytes=2 * sum(len(k) + len(v) for k, v in self.headers))
        if (self.closed or self.scope.get(_SCOPE_KEY) is not self
                or self.scope.get("path") != self.path or self.scope.get("method") != "POST"
                or self.scope.get("query_string", b"") != b""
                or tuple(self.scope["headers"]) != self.headers):
            _fail()
        return self.context.base_current()

    def native(self, operation):
        self.context.current()
        self.context.work.charge(input_bytes=64 * 1024, json_nodes=512)
        value = transport._native(operation, work=self.context.work,
            current=self.base, deadline_ns=self.context.deadline_ns)
        self.context.current()
        return value

    def auth_current(self):
        from serverware import app as application

        self.base()
        self.context.work.charge(input_bytes=64 * 1024, json_nodes=512)
        identity = transport._native(lambda: _cookie_identity(self.request, approver=self.approver),
            work=self.context.work, current=self.base, deadline_ns=self.context.deadline_ns)
        if (identity != self.identity
                or application._control_plane_mutation_authn_policy() != self.policy):
            _fail()
        if self.credential is not None:
            record_id, key, user_id = self.credential

            def credential_current():
                credential = application.db.get_webauthn_credential_by_record_id(record_id)
                if (type(credential) is not dict or credential.get("revoked_at") is not None
                        or credential.get("public_key_cose") != key or credential.get("user_id") != user_id):
                    _fail()
                webauthn._allowed_authenticator(credential, self.policy)

            transport._native(credential_current, work=self.context.work,
                current=self.base, deadline_ns=self.context.deadline_ns)
        return self.base()

    def bind(self, request, *, approver=False):
        from serverware import app as application

        self.base()
        if self.request is not None or request.scope is not self.scope or type(self.original) is not bytes:
            _fail()
        self.request = request
        if approver and self.path not in native_setup.PATHS:
            _fail()
        self.approver = approver
        self.identity = self.native(lambda: _cookie_identity(request, approver=approver))
        self.policy = application._control_plane_mutation_authn_policy()
        self.context._retain_current(self.auth_current, self.context.window, self.context.deadline_ns)

    def stage(self, response):
        self.context.current()
        self.context.work.charge(input_bytes=2 * len(response.body))
        maximum = native_setup.MAX_RESPONSE if self.path in native_setup.PATHS else 128 * 1024
        if self.response is not None or len(response.body) > maximum:
            _fail()
        self.response = (response.status_code, response.body)
        return response

    def before_send(self, response):
        startup._require_context(self.context)
        if self.result is not None:
            client._require_result(self.result, context=self.context)
        self.context.work.charge(input_bytes=2 * len(response.body))
        if (self.response is None or self.response != (response.status_code, response.body)
                or any(name.lower() == b"set-cookie" for name, _ in response.raw_headers)):
            _fail()
        self.context.current()


def _open_frame(request, size):
    owner = startup.require_started()
    if owner is None or owner.enabled is not True or _SCOPE_KEY in request.scope:
        _fail(503)
    manager = startup._request_on_owner(owner, _additional_original_bytes=8 * size + 64 * 1024)
    context = manager.__enter__()
    try:
        frame = _Frame(_CONSTRUCTION, request.scope, manager, context, size)
        request.scope[_SCOPE_KEY] = frame
    except BaseException as exc:
        manager.__exit__(type(exc), exc, exc.__traceback__)
        raise
    if (context.original_reservation_bytes + 8 * size + client.EXCHANGE_RESERVATION_BYTES
            > transport.MAX_ORIGINAL_BYTES):
        _fail(413)
    frame.base()
    return frame


async def _frame_request(request):
    refusal = native_setup.error if request.scope.get("path") in native_setup.PATHS else error
    if request.scope.get("path") not in PATHS or request.method != "POST":
        return refusal(405)
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1 or re.fullmatch(r"[1-9][0-9]{0,7}", lengths[0]) is None
            or request.headers.getlist("transfer-encoding") or request.headers.getlist("content-encoding")
            or request.scope.get("query_string", b"") != b""
            or sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8 * 1024):
        return refusal(400)
    if request.headers.getlist("content-type") != ["application/json"]:
        return refusal(415)
    size = int(lengths[0])
    maximum = native_setup.MAX_HTTP if request.scope.get("path") in native_setup.PATHS else MAX_REQUEST_BYTES
    if not 2 <= size <= maximum:
        return refusal(413)
    body = bytearray()
    try:
        frame = await _blocking(lambda: _open_frame(request, size))
        stream = request.stream().__aiter__()
        while True:
            await _blocking(frame.context.current)
            remaining = (frame.context.deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                _fail(503)
            try:
                chunk = await asyncio.wait_for(stream.__anext__(), timeout=remaining)
            except StopAsyncIteration:
                break
            if type(chunk) is not bytes or len(chunk) > size - len(body):
                _fail(400)
            frame.context.work.charge(input_bytes=2 * len(chunk))
            body.extend(chunk)
        if len(body) != size:
            _fail(400)
        frame.context.work.charge(input_bytes=size)
        frame.original = bytes(body)
        body.clear()
        request._body, request._stream_consumed = frame.original, False
        frame.context.current()
        return None
    except HTTPException as exc:
        return refusal(exc.status_code)
    except Exception:
        return refusal()


def _original(value, maximum, work):
    if type(value) is not dict or set(value) != {"base64Url", "byteCount", "bytesDigest"}:
        _fail(400)
    encoded, size, digest = value["base64Url"], value["byteCount"], value["bytesDigest"]
    if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
            or len(encoded) != (size * 8 + 5) // 6
            or type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None):
        _fail(400)
    work.charge(input_bytes=4 * len(encoded) + 3 * size)
    if re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        _fail(400)
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if (len(raw) != size or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded
            or _digest(raw, work) != digest):
        _fail(400)
    return raw


def _payload(frame, *, issue):
    frame.context.current()
    work = frame.context.work
    work.charge(input_bytes=4 * len(frame.original), json_nodes=512)
    payload = parse_strict_json_object(frame.original, limits=_LIMITS)
    fields = {"schema", "authorization", "packet", "request"} | ({"mfa"} if issue else set())
    if set(payload) != fields or payload["schema"] != REQUEST_SCHEMA:
        _fail(400)
    raw = tuple(_original(payload[name], limit, work) for name, limit in zip(
        ("authorization", "packet", "request"), transport.REQUEST_LIMITS))
    mfa = payload.get("mfa")
    if issue:
        # Bound the assertion independently of the large enrollment original.
        mfa_bytes = work.wire(mfa)
        if len(mfa_bytes) > 32 * 1024:
            _fail(413)
        parse_strict_json_object(mfa_bytes, limits=_SMALL_LIMITS)
    return raw, mfa


def _binding(admitted, work):
    binding = {"action": ACTION, "authorizationDigest": admitted.authorization_digest,
        "packetDigest": admitted.packet_digest, "requestDigest": admitted.request_digest,
        "principalId": admitted.principal_id, "nonce": admitted.nonce,
        "bootstrapDigest": admitted.bootstrap_digest, "configurationDigest": admitted.configuration_digest,
        "issuerCertificateDigest": admitted.issuer_certificate_digest, "grantId": admitted.grant_id}
    resource = _digest(work.wire({"principalId": admitted.principal_id, "nonce": admitted.nonce}), work)
    return binding, resource, _digest(work.wire(binding), work)


def _response(frame, content, status_code=200):
    # Measure/charge the actual public JSON before constructing its HTTP body.
    body = frame.context.work.wire(content)
    return frame.stage(Response(content=body, status_code=status_code,
        headers=_HEADERS, media_type="application/json"))


def _run(request, *, issue):
    from serverware import app as application
    from serverware.control_plane_oidc_session_activation_approval import _ApprovalRequired

    frame = request.scope.get(_SCOPE_KEY)
    if type(frame) is not _Frame:
        return error(400)
    try:
        frame.bind(request)
        raw, mfa = _payload(frame, issue=issue)
        admitted = client._admit_on_context(frame.context, originals=raw)
        binding, resource, digest = _binding(admitted, frame.context.work)
        if not issue:
            options = frame.native(lambda: application.control_plane_mutation_options(
                user_id=frame.identity.user_id, action=ACTION, resource_id=resource,
                payload_digest=digest, authn_policy=frame.policy))
            return _response(frame, {
                "schema": RESPONSE_SCHEMA, "status": "fresh-assertion-required", "action": ACTION,
                "resourceId": resource, "payloadDigest": digest, "options": options,
                "automaticRetryAllowed": False})
        evidence = frame.native(lambda: _fresh_assertion(identity=frame.identity,
            resource_id=resource, payload_digest=digest, mfa=mfa))
        credential = frame.native(lambda: application.db.get_webauthn_credential_by_record_id(
            evidence["credential_record_id"]))
        if type(credential) is not dict:
            _fail()
        frame.credential = (credential["id"], credential["public_key_cose"], frame.identity.user_id)
        try:
            frame.native(lambda: application._require_control_plane_two_person(
                action=ACTION, resource_id=resource, payload_digest=digest, mfa=mfa,
                identity=frame.identity, request=binding))
        except _ApprovalRequired as exc:
            approval_id = exc.detail.get("approvalId") if type(exc.detail) is dict else None
            if type(approval_id) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", approval_id) is None:
                _fail()
            return _response(frame, {
                "schema": RESPONSE_SCHEMA, "status": "approval-required", "action": ACTION,
                "resourceId": resource, "payloadDigest": digest, "approvalId": approval_id,
                "freshAuthorizationRequired": True, "automaticRetryAllowed": False}, 428)
        frame.context.current()
        # This flag is deliberately conservative: any failure after entering the
        # one-shot exchange is unknown, even when no response original arrives.
        frame.dispatched = True
        result = client._issue_on_context(frame.context, authorization_bytes=raw[0],
            packet_bytes=raw[1], request_bytes=raw[2])
        frame.result = client._require_result(result, context=frame.context)
        work = frame.context.work
        work.charge(input_bytes=4 * len(result.association_bytes), json_nodes=64)
        association = parse_strict_json_object(result.association_bytes, limits=_SMALL_LIMITS)
        certificate = result.certificate_bytes
        work.charge(input_bytes=4 * len(certificate))
        wrapper = {"base64Url": base64.urlsafe_b64encode(certificate).decode("ascii").rstrip("="),
            "byteCount": len(certificate), "bytesDigest": _digest(certificate, work)}
        result.current()
        return _response(frame, {
            "schema": RESPONSE_SCHEMA, "status": "certificate-issued", "association": association,
            "certificate": wrapper, "proxyAuthenticated": False, "enrollmentComplete": False,
            "automaticRetryAllowed": False})
    except HTTPException as exc:
        return error(503 if frame.dispatched else exc.status_code, unknown=frame.dispatched)
    except Exception:
        return error(unknown=frame.dispatched)


@router.post(OPTIONS_PATH)
def options(request: Request):
    return _run(request, issue=False)


@router.post(POST_PATH)
def issue(request: Request):
    return _run(request, issue=True)


@router.post(native_setup.PREFIX + "/draft")
@router.post(native_setup.PREFIX + "/options")
@router.post(native_setup.PREFIX + "/request")
@router.post(native_setup.PREFIX + "/decide")
@router.post(native_setup.PREFIX + "/issue")
def setup_enrollment(request: Request):
    frame = request.scope.get(_SCOPE_KEY)
    if type(frame) is not _Frame:
        return native_setup.error(400)
    response = native_setup.run(frame, request)
    if frame.response is None:
        return frame.stage(response)
    return response


async def _send_response(scope, receive, send, response, *, before_dispatch=False, downstream_failed=False):
    frame = scope.get(_SCOPE_KEY)
    refusal = native_setup.error if scope.get("path") in native_setup.PATHS else error
    if (before_dispatch or downstream_failed or type(frame) is not _Frame
            or frame.response is None):
        # Never propagate generic exception text or an unstaged success. Failure
        # bodies contain no original request, token or issuance authority.
        safe = refusal(503 if downstream_failed else min(response.status_code, 503),
            unknown=type(frame) is _Frame and frame.dispatched)
        await safe(scope, receive, send)
        return
    started = False

    async def guarded(message):
        nonlocal started
        if message.get("type") in ("http.response.start", "http.response.body"):
            await _blocking(lambda: frame.before_send(response))
        if message.get("type") == "http.response.start":
            started = True
        remaining = (frame.context.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            _fail(503)
        await asyncio.wait_for(send(message), timeout=remaining)

    try:
        await response(scope, receive, guarded)
    except Exception:
        if started:
            raise RuntimeError("workload issuance response lost its current send guard") from None
        await refusal(unknown=frame.dispatched)(scope, receive, send)


def _discard_scope(scope):
    frame = scope.pop(_SCOPE_KEY, None)
    if type(frame) is not _Frame or frame.closed:
        return
    frame.closed = True
    frame.original, frame.request, frame.credential, frame.result, frame.response = None, None, None, None, None
    # Exit as an aborted/finished scope: never run a child after invalidation.
    frame.manager.__exit__(RuntimeError, RuntimeError("workload HTTP scope closed"), None)
