#!/usr/bin/env python3
"""Offline API/owner controls, not connected storage or signed-proxy acceptance.

Actual wire validation, extracted unchanged app models/auth/parser/endpoint and
quota orchestration run here. SQL/publication/provider owners are explicit
inert doubles; separate durable-store and joined proxy tests establish them.
"""
from __future__ import annotations

import ast
import asyncio
import base64
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
from types import ModuleType, SimpleNamespace
from typing import Any, Literal
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import serverware
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError, model_validator
from serverware import credential_lease_profiles as profiles, operator_x_quota_api as api
from serverware.response_identity import validate_response_nonce


def offline(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"} or event.startswith("sqlite3.") or event == "subprocess.Popen":
        raise AssertionError("quota API controls forbid external effects")


sys.addaudithook(offline)
H = "sha256:" + "1" * 64
ID = "12345678-1234-4234-8234-123456789abc"
RID = "87654321-1234-4234-8234-123456789abc"
TOKEN = "inert-lease-auth-canary"
NOW = 1_800_000_000_000
NONCE = base64.urlsafe_b64encode(b"N" * 32).rstrip(b"=").decode()


def wire():
    value = {"apiVersion": api.REQUEST_VERSION, "purpose": "dispatchSecret", "principalId": "agent:app",
        "routeId": "operator.route", "credentialId": ID, "expectedCredentialVersion": 3,
        "expectedMetadataSha256": H, "recipientPublicKey": "A" * 43, "recipientKeyId": H,
        "recipientNonce": NONCE, "policyHash": H, "dataPlaneBinaryDigest": H, "maxTtlSeconds": 5}
    original = {"v": 2, "principal": value["principalId"], "client_ip": "127.0.0.1",
        "route_id": value["routeId"], "credential_ref": ID, "credential_version": "3", "policy_hash": H,
        "request": {"method": "POST", "scheme": "https", "authority": "api.x.com", "path": "/2/tweets",
            "query": [], "headers": {"content-type": "application/json"}, "body_sha256": H,
            "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "tweets.write", "providerAccount": H}}
    value["operatorXQuota"] = {"canonicalRequest": original, "requestDigest": api.digest(original),
        "operationDigest": api.digest({k: v for k, v in original.items() if k not in {"v", "client_ip"}}),
        "attemptNonce": "sha256:" + "2" * 64, "expiresAtEpochMs": NOW + 4000}
    return value


def actual_app():
    tree = ast.parse((ROOT / "serverware/app.py").read_text())
    names = {"CredentialLeaseReleaseQuotaClaim", "CredentialLeaseDurablePolicyClaim", "CredentialLeaseReleaseAuthorization",
        "CredentialLeaseRequestAuthority", "CredentialLeaseRequest", "CredentialCurrentnessDispatchPin",
        "NativeCurrentCredentialLeaseRequest", "CredentialLeaseWireRequest", "OperatorXQuotaClaimRequest",
        "_bounded_exact_data_plane_model", "_bounded_operator_x_quota_claim", "_original_data_plane_request",
        "_require_currentness_response_context", "_request_signature_inputs", "_require_data_plane_token",
        "_credential_lease_request_binding_sha256", "data_plane_operator_x_quota_claim"}
    names.add("bounded_control_plane_request_middleware")
    nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    assert len(nodes) == len(names)
    module = ModuleType("serverware.app")
    module.__dict__.update({"__builtins__": __builtins__, "Any": Any, "Literal": Literal,
        "BaseModel": BaseModel, "ConfigDict": ConfigDict, "Field": Field, "RootModel": RootModel,
        "ValidationError": ValidationError, "model_validator": model_validator, "lease_profiles": profiles,
        "Depends": Depends, "HTTPException": HTTPException, "Request": Request, "Response": Response,
        "JSONResponse": JSONResponse,
        "asyncio": asyncio, "uuid": uuid, "json": json, "time": time, "hmac": hmac, "hashlib": hashlib,
        "validate_response_nonce": validate_response_nonce, "app": FastAPI(),
        "DATA_PLANE_CREDENTIAL_LEASE_TOKEN": TOKEN, "DATA_PLANE_INSTANCE_ID": "inert-gate",
        "_RECIPIENT_ATTESTATION_MAX_BYTES": 65536, "_canonical_json": lambda v: api.canonical(v).decode(),
        "_CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY": "inert-original", "SECRET_LEASE_TTL_SECONDS": 5.0})
    selected = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    with modules(app=module):
        exec(compile(ast.fix_missing_locations(selected), str(ROOT / "serverware/app.py"), "exec"), module.__dict__)
        for value in tuple(module.__dict__.values()):
            if isinstance(value, type) and issubclass(value, BaseModel) and value is not BaseModel:
                value.model_rebuild(_types_namespace=module.__dict__)
    return module


@contextmanager
def modules(**values):
    with ExitStack() as stack:
        for name, value in values.items():
            stack.enter_context(patch.dict(sys.modules, {"serverware." + name: value}))
            stack.enter_context(patch.object(serverware, name, value, create=True))
        yield


def request(body=b"", *, authenticated=True, nonce=NONCE, query=b"", duplicate_nonce=False):
    reads = []
    async def receive():
        reads.append(True)
        return {"type": "http.request", "body": body, "more_body": False}
    headers = [(b"content-type", b"application/json")]
    if authenticated:
        headers.append((b"x-serverware-data-plane-token", TOKEN.encode()))
    if nonce is not None:
        headers.append((b"x-serverware-response-nonce", nonce.encode()))
    if duplicate_nonce:
        headers.append((b"x-serverware-response-nonce", ("C" * 43).encode()))
    return Request({"type": "http", "method": "POST", "scheme": "https", "path": api.CLAIM_PATH,
        "query_string": query, "headers": headers}, receive), reads


class QuotaApiControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = actual_app()

    def test_closed_original_and_canonical_digests(self):
        value = wire()
        self.assertEqual(api.validate_wire(value), value)
        for change in ({"extra": H}, {"recipientAttestation": None}, {"requestAuthority": None},
                {"releaseAuthorization": None}, {"expectedCredentialVersion": True}, {"maxTtlSeconds": 6}):
            with self.subTest(change=next(iter(change))), self.assertRaises(ValueError):
                api.validate_wire({**value, **change})
        for mutate in (lambda q: q.update(subject="123"), lambda q: q.update(expiresAtEpochMs=True),
                lambda q: q["canonicalRequest"].update(credential_version="4"),
                lambda q: q["canonicalRequest"]["request"].update(path="/2/users/me"),
                lambda q: q.update(operationDigest=H)):
            altered = deepcopy(value)
            mutate(altered["operatorXQuota"])
            with self.assertRaises(ValueError):
                api.validate_wire(altered)

    def test_twelve_field_binding_includes_recipient_and_original(self):
        value = wire()
        bound = api.binding(value)
        self.assertEqual(set(bound), {"principal_id", "route_id", "credential_id", "credential_version",
            "credential_metadata_digest", "policy_hash", "request_digest", "operation_digest", "attempt_nonce",
            "recipient_digest", "request_binding_digest", "expires_at_epoch_ms"})
        self.assertEqual(bound["request_binding_digest"], api.digest(value))
        self.assertEqual(bound["recipient_digest"], api.digest({k: value[k] for k in ("recipientKeyId", "recipientNonce")}))
        other = {**value, "recipientNonce": "D" * 43}
        self.assertNotEqual(api.binding(other)["request_binding_digest"], bound["request_binding_digest"])
        self.assertEqual(api.binding(other)["request_digest"], bound["request_digest"])

    def test_actual_models_separate_native_and_legacy_profiles(self):
        model = self.app.CredentialLeaseRequest.model_validate(wire())
        self.assertEqual(self.app._credential_lease_request_binding_sha256(model), api.digest(wire()))
        legacy = {**wire(), "apiVersion": "serverware.credentialLeaseRequest/v3"}
        with self.assertRaises(ValidationError):
            self.app.CredentialLeaseRequest.model_validate(legacy)
        del legacy["operatorXQuota"]
        self.assertEqual(self.app.CredentialLeaseRequest.model_validate(legacy).api_version, legacy["apiVersion"])
        for version in ("serverware.credentialLeaseRequest/v4", profiles.NATIVE_REQUEST_V1,
                profiles.POLICY_AWARE_REQUEST_V1, profiles.BROKER_REQUEST_V1):
            with self.assertRaises(ValidationError):
                self.app.CredentialLeaseRequest.model_validate({**wire(), "apiVersion": version})
        claim = {"apiVersion": api.CLAIM_REQUEST_VERSION, "leaseRequest": legacy, "reservationId": RID}
        with self.assertRaises(ValidationError):
            self.app.OperatorXQuotaClaimRequest.model_validate(claim)

    def test_actual_parser_authenticates_before_body_and_rejects_duplicates(self):
        req, reads = request(b"never-read", authenticated=False)
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(self.app._bounded_operator_x_quota_claim(req))
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(reads, [])
        for body in (b'{"apiVersion":"a","apiVersion":"b"}', b'{"x":NaN}', b"x" * 34000):
            req, _ = request(body)
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(self.app._bounded_operator_x_quota_claim(req))
            self.assertIn(caught.exception.status_code, (413, 422))

    def test_actual_outer_middleware_admits_exact_machine_post_before_parser(self):
        tree = ast.parse((ROOT / "serverware/operator_demo.py").read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "request_allowed")
        ordinary = ModuleType("serverware.operator_demo")
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / "serverware/operator_demo.py"), "exec"), ordinary.__dict__)
        ordinary.active = lambda: True
        with modules(operator_demo=ordinary, development_sandbox=SimpleNamespace(active=lambda: False),
                operator_catalog_oauth_profile=SimpleNamespace(selected=lambda: False)):
            self.assertTrue(ordinary.request_allowed("POST", api.CLAIM_PATH))
            for method in ("GET", "PUT", "DELETE"):
                self.assertFalse(ordinary.request_allowed(method, api.CLAIM_PATH))
            self.assertFalse(ordinary.request_allowed("POST", api.CLAIM_PATH + "/unknown"))
            req, reads = request(b"never-read", authenticated=False)
            async def endpoint(incoming):
                return await self.app._bounded_operator_x_quota_claim(incoming)
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(self.app.bounded_control_plane_request_middleware(req, endpoint))
            self.assertEqual(caught.exception.status_code, 401)
            self.assertEqual(reads, [])
            req.scope["path"] = api.CLAIM_PATH + "/unknown"
            # Request.url caches the old path, so construct a fresh Request.
            refused = Request(dict(req.scope), req.receive)
            response = asyncio.run(self.app.bounded_control_plane_request_middleware(refused, endpoint))
            self.assertEqual(response.status_code, 403)
            self.assertEqual(reads, [])

    def test_actual_claim_endpoint_requires_nonce_context_and_original(self):
        value = {"apiVersion": api.CLAIM_REQUEST_VERSION, "leaseRequest": wire(), "reservationId": RID}
        for options in ({"nonce": None}, {"duplicate_nonce": True}, {"query": b"retry=1"}):
            req, _ = request(api.canonical(value), **options)
            model = asyncio.run(self.app._bounded_operator_x_quota_claim(req))
            with patch.object(api, "claim") as call, self.assertRaises(HTTPException):
                self.app.data_plane_operator_x_quota_claim(req, model)
            call.assert_not_called()
        req, _ = request(api.canonical(value))
        model = asyncio.run(self.app._bounded_operator_x_quota_claim(req))
        receipt = {"apiVersion": api.CLAIM_RESPONSE_VERSION, "requestBindingSha256": api.digest(wire()), "claim": {}}
        with patch.object(api, "claim", return_value=receipt) as call:
            response = self.app.data_plane_operator_x_quota_claim(req, model)
        self.assertEqual(json.loads(response.body), receipt)
        self.assertEqual(response.headers["cache-control"], "no-store")
        call.assert_called_once_with(value)

    def test_opening_is_single_reservation_and_never_renews_deadline(self):
        value = wire()
        payload = self.app.CredentialLeaseRequest.model_validate(value)
        req, _ = request()
        req.scope["path"] = "/api/data-plane/credential-leases"
        req.scope[self.app._CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY] = (payload, value)
        reservation = {"expires_at_epoch_ms": NOW + 4000}
        calls = []
        def tx(original, operation, **kwargs):
            calls.append((deepcopy(original), operation, kwargs))
            return reservation if operation == "reserve" else None
        with modules(app=self.app), patch.object(api, "_transaction", side_effect=tx), \
                patch.object(api.time, "time_ns", return_value=NOW * 1000000), \
                patch.object(api.time, "monotonic", return_value=100.0):
            opening = api.Opening(req, payload, original_deadline=102.0)
            self.assertEqual(opening.deadline, 102.0)
            opening.reserve()
            with self.assertRaises(ValueError):
                opening.reserve()
            self.assertEqual(opening.wrap({"expiresAtEpochMs": NOW + 4000})["requestBindingSha256"], api.digest(value))
            with self.assertRaises(ValueError):
                opening.wrap({"expiresAtEpochMs": NOW + 4001})
            opening.check()
        self.assertEqual([v[1] for v in calls], ["check", "reserve", "check"])
        self.assertTrue(all(v[2]["deadline"] == 102.0 for v in calls))

    def test_claim_repeats_original_without_lease_reissuance(self):
        value = {"apiVersion": api.CLAIM_REQUEST_VERSION, "leaseRequest": wire(), "reservationId": RID}
        with patch.object(api.time, "time_ns", return_value=NOW * 1000000), \
                patch.object(api.time, "monotonic", return_value=100.0), \
                patch.object(api, "_transaction", return_value={"claimed_at_epoch_ms": NOW}) as tx:
            response = api.claim(value)
        tx.assert_called_once_with(wire(), "claim", reservation_id=RID, deadline=104.0)
        self.assertEqual(response["requestBindingSha256"], api.digest(wire()))
        self.assertEqual(set(response), {"apiVersion", "requestBindingSha256", "claim"})

    def test_committed_claim_survives_lost_ack_deadline(self):
        events = []
        class Unavailable(Exception): pass
        class Exceeded(Unavailable): pass
        class Conflict(Unavailable): pass
        connection = SimpleNamespace(execute=lambda sql: events.append(sql), commit=lambda: events.append("committed"))
        @contextmanager
        def context():
            yield connection
        storage = SimpleNamespace(QuotaExceeded=Exceeded, QuotaConflict=Conflict,
            validate_current=lambda *_: events.append("validated"),
            claim=lambda *_: events.append("charged") or {"schema": "claim"})
        publication = SimpleNamespace(assert_not_held=lambda: None, exclusive=context)
        admission = SimpleNamespace(require_runtime=lambda: "admitted", check_connection=lambda *_: None)
        # Clock advances only after actual mocked commit. The real API owner
        # must refuse output without performing a second claim or compensation.
        with modules(db=SimpleNamespace(metadata_connection=context), operator_publication=publication,
                operator_x_admission=admission, operator_x_quota=storage), \
                patch.object(api, "_current", side_effect=lambda *_: events.append("current")), \
                patch.object(api.time, "monotonic", side_effect=[1, 1, 1, 1, 6]):
            with self.assertRaises(HTTPException) as caught:
                api._transaction(wire(), "claim", reservation_id=RID, deadline=5.0)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(events.count("charged"), 1)
        self.assertEqual(events[-1], "committed")

    def test_metadata_refresh_exclusions_are_inert(self):
        for version, purpose, adapter, constraints in (
                ("serverware.credentialLeaseRequest/v3", "dispatchSecret", "x.post.v1", [{"type": "rateLimit"}]),
                (profiles.NATIVE_REQUEST_V1, "generationMetadata", "x.post.v1", [{"type": "rateLimit"}]),
                ("serverware.credentialLeaseRequest/v3", "generationMetadata", "x.post.v1", []),
                ("serverware.credentialLeaseRequest/v3", "generationMetadata", "generic.rest", [{"type": "rateLimit"}])):
            with modules(db=ModuleType("db"), operator_x_refresh=ModuleType("refresh")):
                api.prepare_metadata(SimpleNamespace(api_version=version, purpose=purpose),
                    SimpleNamespace(adapter_type=adapter, constraints=constraints), original_deadline=1.0)

    def test_metadata_refresh_uses_current_generation_and_original_unlocked_budget(self):
        events, held = [], [False]
        core = {"id": ID, "credential_version": 4, "metadata": {"operator_x_account": {}}}
        class Connection:
            def execute(self, sql, *_):
                return SimpleNamespace(fetchone=lambda: (H,) if "SELECT policy_hash" in sql else core)
        @contextmanager
        def exclusive():
            held[0] = True
            try:
                yield
            finally:
                held[0] = False
        @contextmanager
        def connection():
            yield Connection()
        def outside():
            self.assertFalse(held[0])
        def refresh(credential, version, **kwargs):
            outside()
            self.assertEqual((credential, version), (ID, 4))
            self.assertEqual(kwargs, {"principal_id": "app", "route_id": "route", "policy_hash": H, "deadline": 105.0})
            events.append("refresh")
        publication = SimpleNamespace(exclusive=exclusive, assert_not_held=outside)
        storage = SimpleNamespace(require_ready=lambda _: events.append("ready"))
        with modules(db=SimpleNamespace(get_credential=lambda *a, **k: core, metadata_connection=connection,
                row_to_credential=lambda row: row), operator_publication=publication,
                operator_x_refresh=SimpleNamespace(selected=lambda _: True, prepare_for_lease=refresh),
                operator_x_admission=SimpleNamespace(require_runtime=lambda: "dir", check_connection=lambda *a: None),
                operator_x_quota=storage, operator_catalog_x_oauth=SimpleNamespace(require_lease_binding=lambda *a, **k: None)), \
                patch.object(api, "require_route", return_value=api.UNCONTROLLED), \
                patch.object(api.time, "monotonic", return_value=100.0):
            payload = SimpleNamespace(api_version="serverware.credentialLeaseRequest/v3", purpose="generationMetadata",
                credential_id=ID, principal_id="app", route_id="route", policy_hash=H)
            route = SimpleNamespace(adapter_type="x.post.v1", constraints=[{"type": "rateLimit"}])
            api.prepare_metadata(payload, route, original_deadline=105.0)
            self.assertEqual(events, ["ready", "refresh"])
            events.clear()
            with patch.object(storage, "require_ready", side_effect=ValueError("unavailable")), self.assertRaises(ValueError):
                api.prepare_metadata(payload, route, original_deadline=105.0)
            self.assertEqual(events, [])

    def test_unmanaged_limited_metadata_does_not_enter_ordinary_quota_owner(self):
        with modules(db=SimpleNamespace(get_credential=lambda *a, **k: {"metadata": {}}),
                operator_x_refresh=SimpleNamespace(selected=lambda _: False)):
            api.prepare_metadata(SimpleNamespace(api_version="serverware.credentialLeaseRequest/v3", purpose="generationMetadata",
                credential_id=ID), SimpleNamespace(adapter_type="x.post.v1", constraints=[{"type": "rateLimit"}]),
                original_deadline=1.0)

    def test_actual_lease_source_reserves_before_secret_and_checks_after_audit(self):
        tree = ast.parse((ROOT / "serverware/app.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "data_plane_credential_leases")
        source = ast.get_source_segment((ROOT / "serverware/app.py").read_text(), function)
        self.assertLess(source.index("quota_opening.reserve()"), source.index("with credential_snapshot("))
        self.assertLess(source.index('"issued",'), source.index("quota_opening.check()"))
        self.assertIn("db.get_credential(payload.credential_id, include_secret=False)\n                if quota_opening is not None", source)
        self.assertLess(source.index("operator_x_quota_api.prepare_metadata("), source.index("with credential_snapshot("))
        self.assertIn('detail="credential generation or metadata changed before secret release"', source)


if __name__ == "__main__":
    unittest.main()
