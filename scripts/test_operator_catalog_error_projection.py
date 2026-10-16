#!/usr/bin/env python3
"""Offline catalog ASGI framing and fixed exception-projection regressions.

Runs the actual router, administrator/role/Origin admission and strict parser.
Process activation and the bounded service worker result are synthetic: this
does not claim storage, provider, full-app middleware or proxy acceptance.
The real-loopback workspace suite separately covers normal full-app GETs.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_effects(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen"} or event.startswith("sqlite3."):
        raise AssertionError("catalog projection controls forbid external effects")


sys.addaudithook(no_effects)

from fastapi import FastAPI  # noqa: E402
from serverware import auth, operator_catalog_api as api  # noqa: E402
from serverware import operator_catalog_mutations as mutations  # noqa: E402
from serverware.operator_github_app import GitHubAppUnavailable  # noqa: E402

ADMIN = "synthetic-catalog-projection-admin-private-canary"
SECRET = "synthetic-catalog-projection-secret-private-canary"
ACTOR = "catalog-projection-test"
ORIGIN = "https://console.example.com"
CATALOG = "/api/operator-demo/catalog"
POST = "/api/operator-demo/credentials"


class CatalogProjectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(api.operator_demo, "active", return_value=True))
        self.stack.enter_context(patch.object(api.config, "PUBLIC_URL", ORIGIN))
        self.stack.enter_context(patch.multiple(auth, ADMIN_TOKEN=ADMIN, ADMIN_USER_ID=ACTOR,
            ADMIN_ROLES=("admin",), OIDC_ENABLED=False, OIDC_BROWSER_LOGIN_ENABLED=False))
        self.worker = self.stack.enter_context(patch.object(api, "_blocking", new_callable=AsyncMock))
        self.worker.return_value = {"synthetic_catalog_observation": True}
        self.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.app.include_router(api.router)
        self.reads = 0

    async def request(self, *, method="GET", headers=(), chunks=(b"",), authenticate=True,
            stalled=False, disconnected=False, failure=None, payload=None):
        path = CATALOG if method == "GET" else POST
        fields = [(b"host", b"console.example.com"), *headers]
        if authenticate:
            fields.append((b"x-serverware-admin-token", ADMIN.encode()))
        if method == "POST":
            raw = json.dumps(payload if payload is not None else {
                "expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
                "name": "Projection control", "auth_type": "bearer", "secret": SECRET}).encode()
            fields.extend(((b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode())))
            chunks = (raw,)
        pending = list(chunks)
        messages = []

        async def receive():
            self.reads += 1
            if stalled:
                await asyncio.Event().wait()
            if failure is not None:
                raise failure
            if disconnected or not pending:
                return {"type": "http.disconnect"}
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}

        async def send(message):
            messages.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "https", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": fields, "root_path": "",
            "client": ("127.0.0.1", 10000), "server": ("console.example.com", 443)}
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            await asyncio.wait_for(self.app(scope, receive, send), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        starts = [item for item in messages if item["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
        response_headers = dict(starts[0]["headers"])
        self.response_headers = response_headers
        for canary in (ADMIN, SECRET):
            self.assertNotIn(canary.encode(), body + repr(response_headers).encode())
        self.assertEqual(response_headers.get(b"cache-control"), b"no-store")
        self.assertEqual(response_headers.get(b"pragma"), b"no-cache")
        self.assertEqual(response_headers.get(b"x-content-type-options"), b"nosniff")
        return starts[0]["status"], json.loads(body)

    async def test_normal_empty_stream_with_absent_or_zero_length_completes(self):
        for headers in ((), ((b"content-length", b"0"),)):
            self.worker.reset_mock()
            self.assertEqual(await self.request(headers=headers),
                (200, {"synthetic_catalog_observation": True}))
            self.worker.assert_awaited_once_with(mutations.catalog_status)
        self.assertEqual(self.reads, 2)

    async def test_nonempty_stream_refuses_without_declared_body_or_with_zero_length(self):
        for headers in ((), ((b"content-length", b"0"),)):
            for chunks in ((SECRET.encode(),), (b"", SECRET.encode())):
                self.assertEqual(await self.request(headers=headers, chunks=chunks),
                    (400, {"detail": "operator catalog status accepts no body"}))
        self.worker.assert_not_awaited()

    async def test_declared_or_encoded_body_refuses_before_receiving(self):
        for headers in (((b"content-length", b"1"),), ((b"transfer-encoding", b"chunked"),),
                ((b"content-encoding", b"gzip"),), ((b"content-length", b"0"), (b"content-length", b"0"))):
            self.assertEqual(await self.request(headers=headers, stalled=True),
                (400, {"detail": "operator catalog status accepts no body"}))
        self.assertEqual(self.reads, 0)
        self.worker.assert_not_awaited()

    async def test_stalled_stream_has_one_total_deadline_and_no_catalog_call(self):
        actual_timeout = asyncio.timeout
        # Accelerate only the existing deadline; cancellation still comes from
        # the real asyncio timeout context and the actual blocked ASGI receive.
        with patch.object(api.asyncio, "timeout", side_effect=lambda seconds: actual_timeout(0.01)) as deadline:
            self.assertEqual(await self.request(stalled=True),
                (408, {"detail": "operator catalog status body timed out"}))
        deadline.assert_called_once_with(30)
        self.assertEqual(self.reads, 1)
        self.worker.assert_not_awaited()

    async def test_disconnect_and_receive_failure_have_fixed_safe_refusals(self):
        for options in ({"disconnected": True}, {"failure": RuntimeError(SECRET)}):
            self.assertEqual(await self.request(**options),
                (400, {"detail": "operator catalog status body unavailable"}))
        self.worker.assert_not_awaited()

    async def test_authentication_and_role_precede_stream_or_service_access(self):
        self.assertEqual(await self.request(authenticate=False, stalled=True),
            (401, {"detail": "administrator authentication required"}))
        with patch.object(auth, "ADMIN_ROLES", ("auditor",)):
            self.assertEqual(await self.request(stalled=True),
                (403, {"detail": "administrator access required"}))
        self.assertEqual(self.reads, 0)
        self.worker.assert_not_awaited()

    async def test_github_app_unavailable_uses_imported_exception_and_fixed_503(self):
        self.worker.side_effect = GitHubAppUnavailable(SECRET)
        self.assertEqual(await self.request(method="POST"), (503, {"detail":
            "GitHub App verification failed; check app, installation and repository permissions"}))
        self.worker.assert_awaited_once()
        function, payload, actor = self.worker.await_args.args
        self.assertIs(function, mutations.create_credential)
        self.assertEqual(actor, ACTOR)
        self.assertEqual(payload.secret, SECRET)

    async def test_value_error_is_not_masked_by_an_unbound_prior_exception_clause(self):
        self.worker.side_effect = ValueError(SECRET)
        self.assertEqual(await self.request(method="POST"),
            (422, {"detail": "invalid operator catalog input or unsupported policy"}))
        self.worker.assert_awaited_once()

    async def test_invalid_input_names_only_known_top_level_fields_without_worker(self):
        payload = {"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
            "name": SECRET + "\n", "auth_type": "bearer", "secret": "", SECRET: SECRET}
        self.assertEqual(await self.request(method="POST", payload=payload),
            (422, {"detail": "invalid operator catalog input"}))
        self.assertEqual(self.response_headers[b"x-serverware-error-code"], b"invalid_input")
        self.assertEqual(self.response_headers[b"x-serverware-error-fields"], b"name,secret")
        self.worker.assert_not_awaited()
        self.assertEqual(await self.request(method="POST", payload=payload, authenticate=False),
            (401, {"detail": "administrator authentication required"}))
        self.assertNotIn(b"x-serverware-error-code", self.response_headers)
        self.worker.assert_not_awaited()

    async def test_closed_codes_keep_old_status_body_and_unknown_outcome(self):
        conflicts = (
            (mutations.CredentialInUse, "credential_in_use"),
            (mutations.ProviderDisconnectRequired, "provider_disconnect_required"),
            (mutations.ApprovalRequired, "approval_required"),
            (mutations.CatalogSettingUnchanged, "already_configured"),
            (mutations.CatalogConflict, "catalog_changed"),
        )
        for exception, code in conflicts:
            with self.subTest(code=code):
                self.worker.side_effect = exception(SECRET)
                self.assertEqual(await self.request(method="POST"),
                    (409, {"detail": "operator catalog or policy changed; refresh before trying again"}))
                self.assertEqual(self.response_headers[b"x-serverware-error-code"], code.encode())
                self.assertNotIn(b"x-serverware-error-fields", self.response_headers)
        for error, status, code in (
                (ValueError(SECRET), 422, "unsupported_policy"),
                (mutations.CatalogNotFound(SECRET), 404, "resource_not_found"),
                (mutations.CatalogLimitReached(SECRET, SECRET), 409, "capacity_reached"),
                (GitHubAppUnavailable(SECRET), 503, "github_app_verification_failed"),
                (RuntimeError(SECRET), 503, "mutation_outcome_unknown")):
            with self.subTest(code=code):
                self.worker.side_effect = error
                self.assertEqual((await self.request(method="POST"))[0], status)
                self.assertEqual(self.response_headers[b"x-serverware-error-code"], code.encode())
        self.worker.side_effect = None
        self.worker.return_value = {"not_serializable": object()}
        self.assertEqual(await self.request(method="POST"),
            (503, {"detail": "operator catalog result unavailable; inspect saved status before retrying"}))
        self.assertEqual(self.response_headers[b"x-serverware-error-code"], b"mutation_outcome_unknown")

    def test_error_header_allowlist_status_and_field_bounds(self):
        from fastapi import HTTPException
        from pydantic import ValidationError
        from serverware.operator_catalog_inputs import CommonAppRuleInput

        error = ValidationError.from_exception_data("Synthetic", [
            {"type": "string_type", "loc": ("scope", SECRET), "input": SECRET},
            {"type": "string_type", "loc": (SECRET,), "input": SECRET},
            # Known elsewhere but not a field of this input model must not leak.
            {"type": "string_type", "loc": ("session_token",), "input": SECRET},
        ])
        self.assertEqual(api._validation_fields(error, CommonAppRuleInput), ("scope",))
        with self.assertRaises(HTTPException) as caught:
            api._reject(422, "fixed", code="invalid_input", fields=(*api._ERROR_FIELDS, SECRET))
        names = caught.exception.headers["X-Serverware-Error-Fields"].split(",")
        self.assertEqual(names, sorted(api._ERROR_FIELDS)[:8])
        for status, code in ((422, SECRET), (503, "invalid_input")):
            with self.assertRaises(HTTPException) as caught:
                api._reject(status, "fixed", code=code, fields=(SECRET, "name"))
            self.assertNotIn("X-Serverware-Error-Code", caught.exception.headers)
            self.assertNotIn("X-Serverware-Error-Fields", caught.exception.headers)

    def test_typed_refusals_originate_at_real_pre_write_guards(self):
        identifier = "fixture-resource"
        payload = SimpleNamespace(id=identifier, proxy_authentication="bearer", approval_mode="automatic")
        record = {"id": identifier, "status": "active", "auth_type": "bearer"}
        catalog = {"credentials": [record], "applications": [record], "access_rules": []}

        def inspect_change(_payload, _actor, _collection, _event, change):
            return change(None, None, catalog)

        with patch.object(mutations, "_mutate", side_effect=inspect_change), \
                patch.object(mutations.schema, "save_resource") as save:
            record["auth_type"] = "google_oauth"
            with self.assertRaises(mutations.ProviderDisconnectRequired):
                mutations.revoke_credential(payload, ACTOR)
            record["auth_type"] = "bearer"
            catalog["access_rules"] = [{"status": "active", "credential_id": identifier}]
            with self.assertRaises(mutations.CredentialInUse):
                mutations.revoke_credential(payload, ACTOR)
            with self.assertRaises(mutations.CatalogSettingUnchanged):
                mutations.set_application_proxy_authentication(payload, ACTOR)
            catalog["access_rules"] = [{**record, "operation_bundle": "aws_ecr_publish_v1"}]
            with self.assertRaises(mutations.ApprovalRequired):
                mutations.set_rule_approval(payload, ACTOR)
            catalog["access_rules"] = [record]
            with self.assertRaises(mutations.CatalogSettingUnchanged):
                mutations.set_rule_approval(payload, ACTOR)
            save.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
