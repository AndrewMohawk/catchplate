#!/usr/bin/env python3
"""Actual portal route/middleware/frame controls with synthetic read seams.

The actual OIDC identity projection, wire parsers, request frame, bounded body
reader, worker dispatch and final send guard run unchanged. Only authoritative
row/trust observations and the selected authority service are doubles. Public
proof signatures below are inert shape fixtures, NOT native admission, signing,
receipt persistence, private disclosure or hardware/runtime acceptance.
"""
from __future__ import annotations

import ast
import asyncio
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import Depends, HTTPException, Request, Response
from starlette.responses import HTMLResponse, JSONResponse

ROOT = Path(__file__).resolve().parents[1]
DATA = tempfile.TemporaryDirectory(prefix="native-review-portal-test-")
os.environ["CATCHPLATE_DATA_DIR"] = DATA.name
os.environ["CATCHPLATE_PROCESS_MODE"] = "catchplate-control-plane"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"

from catchplate import auth, db, webauthn
from catchplate import control_plane_native_jit_review as http
from catchplate import authority_native_jit_review_open_contract as wire
from catchplate import portal_native_jit_review as portal

PORTAL = "https://portal.example.test"
NATIVE = "https://native.example.test"
APPROVAL = "11111111-1111-4111-8111-111111111111"
SESSION = "22222222-2222-4222-8222-222222222222"
REVIEW = "33333333-3333-4333-8333-333333333333"
RECEIPT = "44444444-4444-4444-8444-444444444444"
USER = "oidc:synthetic-reviewer"
TOKEN = "T" * 64
CSRF = "synthetic-csrf-token"
NOW = 1_893_456_000_000_000_000
SECOND = 1_000_000_000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def date(epoch):
    return datetime.fromtimestamp(epoch / SECOND, timezone.utc).isoformat()


class PublicOriginals:
    """Independent complete literal wire shapes; no signature is admitted."""

    def __init__(self):
        identity = {name: digest(name) for name in (
            "holderId", "keyId", "controlPlaneResponseSigningKeyId", "releaseRecordSha256",
            "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256",
            "expectedBinaryDigest", "browserCertificateSha256", "browserPublicKeySpkiSha256")}
        identity["bootId"] = b64(b"b" * 32)
        common = {name: digest(name) for name in ("sourceContractDigest",
            "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest",
            "browserNonceCommitment")}
        challenge = {"schema": "catchplate.nativeJitReviewOpeningChallenge/v1",
            "reviewId": REVIEW, "approvalRequestId": APPROVAL, **common, "identity": identity,
            "nativeOrigin": NATIVE, "portalOrigin": PORTAL, "recipientPublicKey": b64(b"r" * 32),
            "challenge": b64(b"c" * 32), "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 20 * SECOND}
        self.challenge = self.native(challenge)
        self.grant = {name: canonical({"syntheticPublicOriginal": name}) for name in (
            "parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal")}
        scope = {"reviewId": REVIEW, "approvalRequestId": APPROVAL, "reviewerId": USER,
            "sessionId": SESSION, "credentialRecordId": "synthetic-credential-record",
            "challengeSha256": digest(self.challenge), **common,
            "recipientPublicKey": challenge["recipientPublicKey"],
            "sealedSourceContractDigest": digest("sealed source contract"),
            **{key: NOW + 25 * SECOND for key in ("documentExpiresAtEpochNs", "approvalExpiresAtEpochNs",
                "sessionExpiresAtEpochNs", "assignmentExpiresAtEpochNs")},
            **{key: digest(self.grant[name]) for key, name in (
                ("parentOriginalSha256", "parentOriginal"), ("childOriginalSha256", "childOriginal"),
                ("pairSha256", "pairOriginal"), ("sealProofSha256", "evidenceOriginal"))}}
        authorization = {"schema": "catchplate.nativeJitReviewOpeningAuthorization/v1",
            "operation": "jit.review-open.authorize", "requestDigest": digest("authorize request"),
            "scope": scope, "currentRootVectorDigest": digest("current root vector"),
            "currentRootHeadDigest": digest("current head"), "currentRootSequence": 7,
            "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 18 * SECOND}
        self.authorization = self.authority(authorization)
        self.grant["authorizationOriginal"] = self.authorization
        preparation = {"schema": "catchplate.nativeJitReviewOpeningPreparation/v1",
            "operation": "nativeJitReviewOpen.prepare/v1", "authorizationSha256": digest(self.authorization),
            "scope": scope, "identity": identity, "reviewDigest": digest("synthetic private review digest"),
            "reviewFormat": "catchplate.nativeJitImmutableReview/v1", "preparedAtEpochNs": NOW,
            "expiresAtEpochNs": NOW + 16 * SECOND}
        self.preparation = self.native(preparation)
        acknowledgment = {"schema": "catchplate.nativeJitReviewOpeningCommitAcknowledgment/v1",
            "operation": "jit.review-open.receipt.issue", "requestDigest": digest("receipt request"),
            "authorizationSha256": digest(self.authorization), "preparationSha256": digest(self.preparation),
            "scope": scope, "reviewDigest": preparation["reviewDigest"], "receiptId": RECEIPT,
            "receiptExpiresAtEpochNs": NOW + 15 * SECOND, "commitMarkerSha256": digest("commit marker"),
            "completionReceiptSha256": digest("completion receipt"), "afterRootVectorDigest": digest("after root"),
            "committedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 14 * SECOND}
        self.ack = self.authority(acknowledgment)

    @staticmethod
    def native(statement):
        return canonical({"statement": statement, "signature": "ed25519:" + b64(b"s" * 64),
            "nativeKeyEvidence": {"apiVersion": "catchplate.nativeResponseProofKeyEvidence/v1",
                "responseProofPublicKey": b64(b"k" * 32), "attestationDocumentB64": b64(b"synthetic-not-attestation")},
            "assignmentOriginal": canonical({"synthetic": "not an admitted assignment"})})

    @staticmethod
    def authority(payload):
        return canonical({"schema": payload["schema"].replace("catchplate.native", "catchplate.signedNative", 1),
            "payload": payload, "signatureBase64Url": b64(b"a" * 64)})

    def body(self, phase):
        return {"challengeOriginal": self.challenge, **({"authorizationOriginal": self.authorization,
            "preparationOriginal": self.preparation} if phase == "receipt" else {})}


class SyntheticService:
    """Routing boundary only: this object is not a selectable native authority."""
    portal_origin, native_origin = PORTAL, NATIVE

    def __init__(self, fixture):
        self.fixture, self.calls, self.checks = fixture, [], 0
        self.effect = None

    def check(self):
        self.checks += 1

    def invoke(self, phase, arguments):
        self.calls.append((phase, arguments.copy()))
        arguments["check"]()
        if self.effect:
            self.effect(phase, arguments)
        return copy.deepcopy(self.fixture.grant if phase == "authorize" else {"acknowledgmentOriginal": self.fixture.ack})

    def authorize(self, **arguments):
        return self.invoke("authorize", arguments)

    def receipt(self, **arguments):
        return self.invoke("receipt", arguments)


APP_SOURCE = ast.parse((ROOT / "catchplate/app.py").read_text())
SELECTED = {"csrf_middleware", "bounded_control_plane_request_middleware", "native_approval_review_page",
    "native_approval_review_handoff", "approval_capabilities", "_control_plane_security_headers"}


def actual_routes():
    # Select complete actual middleware/route bodies. Local helpers remain real
    # imports; no stale hand-copied authentication/parser helper substitutes.
    nodes = [copy.deepcopy(node) for node in APP_SOURCE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in SELECTED]
    assert {node.name for node in nodes} == SELECTED
    for node in nodes:
        node.decorator_list = []
    namespace = {"Request": Request, "Response": Response, "HTMLResponse": HTMLResponse,
        "JSONResponse": JSONResponse, "HTTPException": HTTPException, "AdminIdentity": auth.AdminIdentity,
        "Depends": Depends, "require_admin": lambda: None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<actual-native-review-http-source>", "exec"), namespace)
    return namespace


class NativeReviewPortalHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from catchplate import native_jit_review_open_service as service
        from catchplate import development_sandbox, operator_demo
        self.service = service
        self.unconfigured_selected = service.selected
        self.values, self.clock = PublicOriginals(), [NOW, 100 * SECOND]
        self.owner = SyntheticService(self.values)
        self.trust = {"currently_trusted": True, "current_trust_bundle_digest": digest("trust"),
            "current_trust_bundle_sequence": 9, "effective_authenticator_class": "security-key"}
        self.session = {"id": SESSION, "user_id": USER, "status": "active", "revoked_at": None,
            "token_digest": auth.oidc_session_token_digest(TOKEN), "roles": ["approver"],
            "bound_webauthn_credential_id": "synthetic-credential-record",
            "activation_trust_bundle_digest": self.trust["current_trust_bundle_digest"],
            "activation_trust_bundle_sequence": 9, "activation_authenticator_class": "security-key",
            "expires_at": date(NOW + 120 * SECOND), "provider_expires_at": date(NOW + 90 * SECOND),
            "_bound_credential": {"id": "synthetic-credential-record", "user_id": USER,
                "credential_id": "synthetic-credential-id", "public_key_cose": "synthetic-cose",
                "revoked_at": None}}
        self.reads, self.sent, self.events, self.last_frame = [], [], [], None
        self.routes = actual_routes()
        for target, name, value in ((auth, "OIDC_ENABLED", True), (auth, "OIDC_BROWSER_LOGIN_ENABLED", True),
                (auth, "OIDC_SESSION_WEBAUTHN_REQUIRED", True),
                (auth, "CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", ("security-key",)),
                (webauthn, "WEBAUTHN_ORIGIN", PORTAL), (http, "_SLOTS", asyncio.BoundedSemaphore(2))):
            self.enterContext(patch.object(target, name, value))
        self.selection = self.enterContext(patch.object(service, "selected", return_value=self.owner))
        self.enterContext(patch.object(db, "get_active_oidc_browser_session", side_effect=self.get_session))
        self.enterContext(patch.object(db, "get_rbac_role_binding", return_value={"status": "active", "roles": ["approver"]}))
        self.enterContext(patch.object(webauthn, "credential_trust_status", side_effect=lambda _: self.trust.copy()))
        self.enterContext(patch.object(http.time, "time_ns", side_effect=lambda: self.clock[0]))
        self.enterContext(patch.object(http.time, "monotonic_ns", side_effect=lambda: self.clock[1]))
        self.enterContext(patch.object(development_sandbox, "active", return_value=False))
        self.enterContext(patch.object(operator_demo, "active", return_value=False))

    def get_session(self, token_digest):
        self.events.append("session")
        return copy.deepcopy(self.session) if token_digest == auth.oidc_session_token_digest(TOKEN) else None

    async def request(self, *, phase="authorize", method="POST", raw=None, change=None, before_read=None,
            before_send=None, send_effect=None, response_effect=None, capability=False):
        path = "/api/approvals/capabilities" if capability else http.PAGE if method in {"GET", "HEAD"} else http.PREFIX + "/" + phase
        raw = canonical(self.values.body(phase)).encode() if raw is None and method == "POST" else raw or b""
        fields = [(b"host", b"portal.example.test"),
            (b"cookie", ("catchplate_oidc_session=" + TOKEN + "; catchplate_csrf=" + CSRF).encode())]
        if method == "POST":
            fields += [(b"origin", PORTAL.encode()), (b"content-type", b"application/json"),
                (b"x-catchplate-csrf-token", CSRF.encode()), (b"content-length", str(len(raw)).encode())]
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
            "scheme": "https", "path": path, "raw_path": path.encode(), "root_path": "", "query_string": b"",
            "headers": fields, "server": ("portal.example.test", 443), "client": ("127.0.0.1", 12345)}
        if change:
            change(scope)
        self.reads, self.sent = [], []

        async def receive():
            self.reads.append(True); self.events.append("body")
            if before_read:
                before_read(scope)
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(message):
            if send_effect:
                send_effect(message)
            self.sent.append(copy.deepcopy(message))

        request = Request(scope, receive)
        try:
            if capability:
                response = self.routes["approval_capabilities"](request, auth.AdminIdentity(USER, frozenset({"approver"}), "oidc-session"))
                await response(scope, receive, send)
            elif method in {"GET", "HEAD"}:
                response = self.routes["native_approval_review_page"](request)
                if method == "HEAD":
                    response.body = b""
            else:
                async def route(value):
                    return await self.routes["native_approval_review_handoff"](value)
                async def csrf(value):
                    return await self.routes["csrf_middleware"](value, route)
                response = await self.routes["bounded_control_plane_request_middleware"](request, csrf)
            self.last_frame = scope.get(http._SCOPE_KEY)
            if not capability:
                if response_effect:
                    response_effect(response)
                if before_send:
                    before_send(scope)
                await http._send_response(scope, receive, send, response)
        finally:
            http._discard_scope(scope)
        starts = [m for m in self.sent if m["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        body = b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")
        self.assertNotIn(TOKEN.encode(), body)
        self.assertNotIn(b"private-plaintext-canary", body)
        self.assertFalse(any(name.lower() == b"set-cookie" for name, _ in starts[0]["headers"]))
        if self.last_frame:
            self.assertTrue(self.last_frame.closed)
            self.assertEqual(set(self.last_frame.original_token), {0})
        return starts[0]["status"], body

    async def test_actual_middleware_authorize_exact_public_relay_and_cleanup(self):
        code, body = await self.request()
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), self.values.grant)
        self.assertEqual(len(self.reads), 1)
        self.assertLess(self.events.index("session"), self.events.index("body"))
        phase, arguments = self.owner.calls[0]
        self.assertEqual(phase, "authorize")
        self.assertEqual(arguments["challenge_original"], self.values.challenge)
        self.assertEqual(arguments["original_token"], TOKEN.encode())
        self.assertEqual(arguments["session_id"], SESSION)
        self.assertEqual(arguments["deadline_ns"], 120 * SECOND)

    async def test_receipt_exact_originals_and_acknowledgment_only(self):
        code, body = await self.request(phase="receipt")
        self.assertEqual((code, json.loads(body)), (200, {"acknowledgmentOriginal": self.values.ack}))
        self.assertEqual(len(self.owner.calls), 1)
        phase, arguments = self.owner.calls[0]
        self.assertEqual(phase, "receipt")
        self.assertEqual(arguments["authorization_original"], self.values.authorization)
        self.assertEqual(arguments["preparation_original"], self.values.preparation)
        self.assertEqual(arguments["deadline_ns"], 116 * SECOND)

    async def test_https_origin_raw_route_query_and_header_aliases_refuse_before_body(self):
        mutations = [lambda s: s.update(scheme="http"), lambda s: s.update(query_string=b"native=1"),
            lambda s: s.update(root_path="/proxy"), lambda s: s.update(raw_path=s["raw_path"].replace(b"authorize", b"%61uthorize")),
            lambda s: s["headers"].append((b"authorization", b"Bearer private-plaintext-canary")),
            lambda s: s["headers"].append((b"x-catchplate-admin-token", b"private-plaintext-canary")),
            lambda s: s["headers"].append((b"host", b"portal.example.test")),
            lambda s: s["headers"].append((b"origin", PORTAL.encode())),
            lambda s: s["headers"].append((b"cookie", b"catchplate_csrf=other")),
            lambda s: s["headers"].append((b"sec-fetch-site", b"cross-site")),
            lambda s: s["headers"].append((b"x-catchplate-csrf-token", CSRF.encode())),
            lambda s: s["headers"].__setitem__(2, (b"origin", b"https://wrong.example.test")),
            lambda s: s["headers"].__setitem__(4, (b"x-catchplate-csrf-token", b"wrong")),
            lambda s: s["headers"].__delitem__(4),
            lambda s: s["headers"].__setitem__(1, (b"cookie", ("catchplate_oidc_session=" + TOKEN + "; catchplate_csrf=x; catchplate_csrf=y").encode())),
            lambda s: s["headers"].__setitem__(1, (b"cookie", b"catchplate_admin=private-plaintext-canary"))]
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.assertEqual((await self.request(change=mutation))[0], 503)
                self.assertEqual(self.reads, [])
        self.assertEqual(self.owner.calls, [])

    async def test_current_oidc_webauthn_session_and_trust_required_before_body(self):
        original = copy.deepcopy(self.session)
        mutations = [lambda: self.session.update(status="pending"), lambda: self.session.update(revoked_at=date(NOW)),
            lambda: self.session.update(token_digest=digest("other token")),
            lambda: self.session.update(bound_webauthn_credential_id=None),
            lambda: self.session["_bound_credential"].update(user_id="oidc:other"),
            lambda: self.session["_bound_credential"].update(revoked_at=date(NOW)),
            lambda: self.session["_bound_credential"].update(dev_private_key_pem="private-plaintext-canary"),
            lambda: self.session.update(activation_trust_bundle_sequence=8),
            lambda: self.session.update(activation_authenticator_class="platform"),
            lambda: self.session.update(provider_expires_at=date(NOW)),
            lambda: self.session.update(expires_at=date(NOW)),
            lambda: self.trust.update(currently_trusted=False)]
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.session = copy.deepcopy(original); self.trust["currently_trusted"] = True; mutation()
                self.assertEqual((await self.request())[0], 503)
                self.assertEqual(self.reads, [])
        self.assertEqual(self.owner.calls, [])

    async def test_framing_duplicate_keys_and_extra_private_body_fields_are_refused(self):
        for headers in ([(b"content-length", b"4")], [(b"transfer-encoding", b"chunked")],
                [(b"content-encoding", b"gzip")], [(b"content-type", b"application/json")]):
            self.assertEqual((await self.request(change=lambda s: s["headers"].extend(headers)))[0], 503)
            self.assertEqual(self.reads, [])
        for raw in (b'{"challengeOriginal":"a","challengeOriginal":"b"}', b'{"challengeOriginal":NaN}',
                canonical({**self.values.body("authorize"), "originalToken": "private-plaintext-canary"}).encode()):
            self.assertEqual((await self.request(raw=raw))[0], 503)
        self.assertEqual(self.owner.calls, [])

    async def test_slow_body_keeps_original_deadline_and_never_dispatches(self):
        def slow(_):
            self.clock[0] += 6 * SECOND; self.clock[1] += 6 * SECOND
        self.assertEqual((await self.request(before_read=slow))[0], 503)
        self.assertEqual(len(self.reads), 1)
        self.assertEqual(self.owner.calls, [])

    async def test_current_scope_rechecked_after_body_before_dispatch(self):
        self.assertEqual((await self.request(before_read=lambda _: self.session.update(revoked_at=date(NOW))))[0], 503)
        self.assertEqual(len(self.reads), 1)
        self.assertEqual(self.owner.calls, [])

    async def test_owner_timeout_and_lost_result_are_not_retried(self):
        def expired(_phase, _arguments):
            self.clock[0] += 31 * SECOND; self.clock[1] += 31 * SECOND
        self.owner.effect = expired
        self.assertEqual((await self.request())[0], 503)
        self.assertEqual(len(self.owner.calls), 1)
        self.clock[:] = [NOW, 100 * SECOND]
        def lost(_phase, _arguments):
            raise OSError("private-plaintext-canary")
        self.owner.effect = lost
        self.assertEqual((await self.request())[0], 503)
        self.assertEqual(len(self.owner.calls), 2)

    async def test_wrong_native_challenge_scope_refused_without_authority_dispatch(self):
        for field, value in (("portalOrigin", "https://wrong.example.test"),
                ("nativeOrigin", "https://wrong.example.test"), ("approvalRequestId", "not-a-uuid")):
            challenge = json.loads(self.values.challenge); challenge["statement"][field] = value
            self.assertEqual((await self.request(raw=canonical({"challengeOriginal": canonical(challenge)}).encode()))[0], 503)
        self.assertEqual(self.owner.calls, [])

    async def test_authorization_output_identity_original_hash_and_closed_fields(self):
        saved = copy.deepcopy(self.values.grant)
        for field in ("reviewerId", "sessionId", "credentialRecordId", "challengeSha256", "parentOriginalSha256"):
            self.values.grant = copy.deepcopy(saved)
            value = json.loads(self.values.authorization)
            value["payload"]["scope"][field] = digest("wrong") if field.endswith("Sha256") else "wrong"
            self.values.grant["authorizationOriginal"] = canonical(value)
            self.assertEqual((await self.request())[0], 503)
        self.values.grant = {**saved, "privateReview": "private-plaintext-canary"}
        self.assertEqual((await self.request())[0], 503)
        self.assertEqual(len(self.owner.calls), 6)

    async def test_receipt_preparation_mismatch_refused_before_dispatch(self):
        value = json.loads(self.values.preparation)
        value["statement"]["authorizationSha256"] = digest("wrong authorization")
        body = {**self.values.body("receipt"), "preparationOriginal": canonical(value)}
        self.assertEqual((await self.request(phase="receipt", raw=canonical(body).encode()))[0], 503)
        self.assertEqual(self.owner.calls, [])

    async def test_final_send_rechecks_expiry_scope_and_staged_bytes(self):
        def expired(_):
            self.clock[0] += 21 * SECOND; self.clock[1] += 21 * SECOND
        self.assertEqual((await self.request(before_send=expired))[0], 503)
        self.clock[:] = [NOW, 100 * SECOND]
        self.assertEqual((await self.request(before_send=lambda s: s["headers"].append((b"x-changed", b"1"))))[0], 503)
        self.assertEqual((await self.request(response_effect=lambda r: setattr(r, "body", b"private-plaintext-canary")))[0], 503)
        self.assertEqual(len(self.owner.calls), 3)

    async def test_send_loss_after_headers_does_not_replay_or_emit_success_body(self):
        def lost(message):
            if message["type"] == "http.response.body":
                raise OSError("synthetic lost transport")
        with self.assertRaisesRegex(RuntimeError, "lost its send guard"):
            await self.request(send_effect=lost)
        self.assertEqual(len(self.owner.calls), 1)
        self.assertEqual([m["type"] for m in self.sent], ["http.response.start"])

    async def test_default_unavailable_and_admin_identity_cannot_admit_opening(self):
        # Exercise the actual cold selector, not a fixture-provided success or
        # fake None-returning replacement. No configure/activate API is called.
        self.selection.side_effect = self.unconfigured_selected
        self.assertEqual((await self.request())[0], 503)
        self.assertEqual(self.reads, [])
        code, body = await self.request(method="GET", capability=True)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"schema": "catchplate.approvalCapabilities/v1", "can_list": True,
            "can_open_native_review": False, "can_decide": False, "reason": "protected_review_unavailable"})
        self.selection.side_effect = None
        self.selection.return_value = self.owner
        with patch.object(db, "get_rbac_role_binding", return_value={"status": "active", "roles": ["auditor"]}):
            self.assertEqual((await self.request())[0], 503)
            self.assertEqual(self.reads, [])
        self.assertEqual(self.owner.calls, [])

    async def test_page_and_head_remain_public_only_with_purpose_specific_popup_header(self):
        for method in ("GET", "HEAD"):
            code, body = await self.request(method=method)
            self.assertEqual(code, 200)
            self.assertEqual(self.reads, [])
            if method == "HEAD":
                self.assertEqual(body, b"")
            else:
                self.assertIn(b"Open protected review", body)
                self.assertNotIn(self.values.challenge.encode(), body)
                self.assertIn((",maximumRequestBytes:" + str(wire.MAX_HTTP_REQUEST)
                    + "});</script>").encode("ascii"), body)
        headers = self.routes["_control_plane_security_headers"]
        common = dict(request_is_https=True, request_method="GET", request_path=http.PAGE,
            response_status_code=200, response_is_html=True)
        self.assertEqual(headers(**common)["Cross-Origin-Opener-Policy"], "same-origin-allow-popups")
        for delta in ({"request_query": "x=1"}, {"request_is_https": False}, {"response_status_code": 503},
                {"request_method": "POST"}, {"request_path": "/"}, {"response_is_html": False}):
            self.assertEqual(headers(**(common | delta))["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(self.owner.calls, [])

    def test_actual_outer_wrapper_uses_purpose_send_guard_and_cleanup(self):
        outer = next(node for node in APP_SOURCE.body if isinstance(node, ast.ClassDef) and node.name == "_SignedControlPlaneASGI")
        calls = {ast.unparse(node.func) for node in ast.walk(outer) if isinstance(node, ast.Call)}
        self.assertIn("delivery._send_response", calls)
        self.assertIn("native_review._discard_scope", calls)
        choices = [node for node in ast.walk(outer) if isinstance(node, ast.IfExp)
            and isinstance(node.body, ast.Name) and node.body.id == "native_review"]
        self.assertEqual(len(choices), 1)
        self.assertEqual(ast.unparse(choices[0].test), "scope.get('path') in native_review.PATHS")
        nodes = [node for node in APP_SOURCE.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {"native_approval_review_page", "native_approval_review_handoff"}]
        self.assertEqual({ast.literal_eval(decorator.args[0]) for node in nodes for decorator in node.decorator_list}, http.PATHS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
