#!/usr/bin/env python3
"""Offline App-secret refusal controls, not provider or native admission tests.

Actual production functions are source-selected to isolate their dependencies:
DB reads, claims and cache observations are explicitly synthetic. Broker tests
use actual AESGCM envelopes and the actual open method, but a synthetic retained
owner/channel, not provisioned native custody. No successful verifier is mocked.
The dedicated catalog suite owns real database/transaction lifecycle acceptance.
"""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from serverware import aws_credential_boundary, github_app_boundary as boundary

ROOT = Path(__file__).resolve().parents[1]
SECRET = '{"schema":"serverware.githubAppCredential/v1","private_key_pem":"synthetic-private-canary"}'
ORDINARY = {"id": "synthetic-id", "credential_version": 3, "kind": "bearer", "metadata": {}}
MARKERS = ({"connection_type": "github_app_v1"}, {"github_app": {}}, {"github_app": None},
    {"connection_type": "other", "github_app": "malformed"})


def functions(relative, names, namespace):
    """Execute unchanged function ASTs; dependency seams remain explicit below."""
    tree = ast.parse((ROOT / relative).read_text())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != set(names):
        raise AssertionError("production function roster changed")
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        *selected], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(ROOT / relative), "exec"), namespace)
    return namespace


def runtime(public, private=None):
    def read(_id, include_secret=False):
        return deepcopy(private if include_secret else public)
    namespace = {"github_app_boundary": boundary, "aws_credential_boundary": aws_credential_boundary,
        "db": SimpleNamespace(get_credential=Mock(side_effect=read)), "copy": __import__("copy"),
        "json": json, "time": time, "_credential_cache": {}, "_credential_lock": threading.Lock(),
        "SECRET_LEASE_TTL_SECONDS": 30, "start_runtime_workers": Mock(), "_inc": Mock(),
        "_claim_release_controlled_credential": Mock(), "ReleaseAuthorizationClientError": RuntimeError}
    return functions("serverware/runtime.py", {"get_credential", "get_control_plane_credential",
        "_project_credential_for_data_plane", "invalidate_secret_leases"}, namespace)


class StoreRefused(RuntimeError):
    pass


def database_functions():
    return functions("serverware/db.py", {"_refuse_generic_aws_credential", "_refuse_generic_github_app_credential",
        "_refuse_retained_operator_aws_identity", "create_credential", "upsert_credential_with_id",
        "update_credential", "update_credential_secret_if_version", "delete_credential"}, {
        "MetadataStoreError": StoreRefused, "metadata_uses_postgres": lambda: False,
        "loads": lambda value, default: json.loads(value) if value else default})


def broker_command(secret, *, public=None, storage=None):
    """Genuine local envelope cryptography; all owner and policy identities synthetic."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from serverware import native_secret_broker_helper as native
    credential, version = "synthetic-github-app", 3
    kek, dek, nonce, wrap_nonce = AESGCM.generate_key(256), AESGCM.generate_key(256), b"a" * 12, b"b" * 12
    key = AESGCM(kek)
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    row = {"credentialId": credential, "credentialVersion": version,
        "secretKekId": "synthetic-app-kek", "secretUpdatedAt": "2026-01-01T00:00:00Z",
        "encryptedDek": "v1:" + encode(wrap_nonce) + ":" + encode(key.encrypt(wrap_nonce, dek,
            f"serverware:dek:{credential}:v{version}".encode())),
        "secretNonce": "v1:" + encode(nonce), "secretCiphertext": "v1:" + encode(AESGCM(dek).encrypt(
            nonce, secret.encode(), f"serverware:secret:{credential}:v{version}".encode()))}
    public = {} if public is None else public
    storage = {} if storage is None else storage
    now = time.time_ns() // 1_000_000
    deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
    binding = {"requestBindingSha256": "sha256:" + "1" * 64, "policyHash": "sha256:" + "2" * 64,
        "dataPlaneBinaryDigest": "sha256:" + "3" * 64, "principalId": "synthetic-principal",
        "routeId": "synthetic-route", "credentialId": credential, "credentialVersion": version,
        "metadataSha256": native._sha(native._canonical(public)), "issuedAtEpochMs": now - 1000,
        "expiresAtEpochMs": now + 30000, "requestAuthoritySha256": None, "releaseAuthorizationSha256": None}
    command = {"apiVersion": native._WORK, "operationId": "synthetic-app-open",
        "gateRecipientPublicKey": native._encoded(b"1" * 32), "gateRecipientNonce": native._encoded(b"2" * 32),
        "deadlineBoottimeNs": deadline, "leaseBinding": binding, "encryptedCredential": row,
        "metadata": public, "storageMetadata": json.dumps(storage)}
    owner = native._Broker.__new__(native._Broker)
    owner.kek, owner.rsa, owner.operations = key, None, set()
    owner.key_id, owner.channel = row["secretKekId"], SimpleNamespace(check=Mock(), send=Mock())
    return native, owner, command


class GitHubAppSecretBoundaryTests(unittest.TestCase):
    def test_reserved_metadata_and_escaped_duplicate_plaintext_are_refused(self):
        for marker in MARKERS:
            self.assertTrue(boundary.selected("bearer", marker))
        self.assertTrue(boundary.selected("github_app_v1", {}))
        escaped = "".join("\\u%04x" % ord(char) for char in boundary.SECRET_SCHEMA)
        values = [SECRET, '{"schema":"' + escaped + '"}',
            '{"schema":"' + escaped + '","schema":"ordinary"}',
            '{"schema":"' + escaped + '",broken',
            '{"private_key_pem":"-----BEGIN RSA PRIVATE KEY-----\\nsynthetic"}',  # gitleaks:allow - incomplete synthetic marker, no key bytes
            '-----BEGIN PRIVATE KEY-----\nsynthetic',
            '{"key":"\\u002d----BEGIN PRIVATE KEY-----"}']  # gitleaks:allow - escaped incomplete marker, no key bytes
        for value in values:
            self.assertTrue(boundary.secret_selected(value), "reserved text escaped refusal")
            self.assertTrue(boundary.secret_selected(value.encode()), "reserved bytes escaped refusal")
        for value in (None, "ordinary-pat", '{"access_token":"ordinary","refresh_token":"normal"}',
                '{"arbitrary":"legacy JSON bearer"}', '{"certificate":"-----BEGIN PUBLIC KEY-----"}'):
            self.assertFalse(boundary.secret_selected(value), "ordinary bearer was overblocked")

    def test_marked_runtime_reads_stop_before_decryption_claim_cache_and_workers(self):
        for marker in MARKERS:
            for controlled in (False, True):
                state = runtime({**ORDINARY, "metadata": marker}, {**ORDINARY, "secret": SECRET})
                state["_credential_cache"][(ORDINARY["id"], 3)] = (time.monotonic() + 30, deepcopy(ORDINARY))
                state["_credential_cache"][("other-id", 1)] = (time.monotonic() + 30, deepcopy(ORDINARY))
                kwargs = {"request_authority": {}, "expected_release_identity": object()} if controlled else {}
                self.assertIsNone(state["get_credential"](ORDINARY["id"], **kwargs))
                self.assertIsNone(state["get_control_plane_credential"](ORDINARY["id"]))
                self.assertEqual(set(state["_credential_cache"]), {("other-id", 1)})
                self.assertFalse(any(call.kwargs.get("include_secret") for call in state["db"].get_credential.call_args_list))
                state["_claim_release_controlled_credential"].assert_not_called()
                state["start_runtime_workers"].assert_not_called()

    def test_stripped_metadata_and_poisoned_cache_cannot_release_private_json(self):
        for private in (SECRET, '{"key":"-----BEGIN PRIVATE KEY-----\\nsynthetic"}'):
            state = runtime(ORDINARY, {**ORDINARY, "secret": private})
            self.assertIsNone(state["get_credential"](ORDINARY["id"]))
            self.assertIsNone(state["get_control_plane_credential"](ORDINARY["id"]))
            self.assertEqual(state["_credential_cache"], {})
            state["_credential_cache"][(ORDINARY["id"], 3)] = (time.monotonic() + 30,
                {**ORDINARY, "secret": private})
            state["db"].get_credential.reset_mock()
            self.assertIsNone(state["get_credential"](ORDINARY["id"]))
            state["db"].get_credential.assert_called_once_with(ORDINARY["id"])
            self.assertEqual(state["_credential_cache"], {})

    def test_ordinary_pat_json_and_oauth_projection_remain_usable(self):
        for secret in ("ordinary-pat", '{"token":"ordinary-json-bearer"}'):
            value = {**ORDINARY, "secret": secret}
            state = runtime(ORDINARY, value)
            self.assertEqual(state["get_credential"](ORDINARY["id"]), value)
            self.assertEqual(state["get_credential"](ORDINARY["id"]), value)
            self.assertEqual(sum(bool(call.kwargs.get("include_secret")) for call in
                state["db"].get_credential.call_args_list), 1)
        value = {**ORDINARY, "kind": "oauth2", "secret": '{"access_token":"ordinary-access","refresh_token":"private-refresh"}'}
        result = runtime(value)["_project_credential_for_data_plane"](value)
        self.assertEqual(json.loads(result["secret"]), {"access_token": "ordinary-access"})
        self.assertIn("refresh_token", value["secret"])

    def test_both_direct_injection_sinks_refuse_before_header_or_field_projection(self):
        for marked in (True, False):
            value = {**ORDINARY, "metadata": MARKERS[0] if marked else {}, "secret": SECRET}
            public = {key: item for key, item in value.items() if key != "secret"}
            get = Mock(side_effect=lambda _id, include_secret=False: value if include_secret else public)
            ns = functions("serverware/policies.py", {"inject_credential", "_secret_for_injection"}, {
                "db": SimpleNamespace(get_credential=get), "github_app_boundary": boundary, "json": json,
                "SECRET_FIELD_PATH_RE": re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")})
            flow = SimpleNamespace(request=SimpleNamespace(headers={}, query={}))
            result = ns["inject_credential"](flow, {"credential_id": ORDINARY["id"],
                "injection": {"type": "bearer", "field": "private_key_pem"}})
            self.assertEqual(result, "GitHub App credentials require the dedicated lease owner")
            self.assertEqual(flow.request.headers, {})
            self.assertEqual(get.call_count, 1 if marked else 2)
            engine = functions("serverware/policy_engine.py", {"_inject_credential"}, {
                "github_app_boundary": boundary, "aws_credential_boundary": aws_credential_boundary})
            with self.assertRaisesRegex(ValueError, "^GitHub App credentials cannot use generic secret injection$"):
                engine["_inject_credential"](flow, object(), value)
            self.assertEqual(flow.request.headers, {})
        # Actual unchanged legacy bearer injection remains reachable.
        get.return_value, get.side_effect = {**ORDINARY, "secret": "ordinary-pat"}, None
        self.assertEqual(ns["inject_credential"](flow, {"credential_id": ORDINARY["id"]}),
            "injected bearer into Authorization")
        self.assertEqual(flow.request.headers, {"Authorization": "Bearer ordinary-pat"})

    def test_generic_database_writers_refuse_before_any_storage_or_crypto(self):
        ns = database_functions()
        for marker, secret in [(item, "ordinary-pat") for item in MARKERS] + [({}, SECRET)]:
            actions = [lambda: ns["create_credential"]("name", "bearer", secret, marker),
                lambda: ns["upsert_credential_with_id"]("id", "name", "bearer", secret, marker),
                lambda: ns["update_credential"]("id", {"secret": secret, "metadata": marker}),
                lambda: ns["update_credential_secret_if_version"]("id", expected_version=1,
                    secret=secret, metadata=marker)]
            for action in actions:
                with self.assertRaisesRegex(StoreRefused, "^GitHub App credentials require the operator catalog lifecycle$"):
                    action()  # No storage/crypto functions exist in this namespace.
        with sqlite3.connect(":memory:") as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("CREATE TABLE operator_catalog_credentials(id TEXT PRIMARY KEY,data_json TEXT)")
            conn.execute("INSERT INTO operator_catalog_credentials VALUES (?,?)", ("id",
                json.dumps({"auth_type": "bearer", "connection_type": "github_app_v1"})))
            with self.assertRaises(StoreRefused):
                ns["_refuse_retained_operator_aws_identity"](conn, "id")
            ns["_refuse_retained_operator_aws_identity"](conn, "different-id")
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        # Wiring coverage: all generic retained-row mutation paths consult the real roster guard.
        for name in ("upsert_credential_with_id", "update_credential", "update_credential_secret_if_version", "delete_credential"):
            node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertTrue(any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == "_refuse_retained_operator_aws_identity" for call in ast.walk(node)))

    def test_broker_metadata_refusal_precedes_real_envelope_unwrap(self):
        for marker in MARKERS:
            for which in ("public", "storage"):
                native, owner, command = broker_command("ordinary-pat", **{which: marker})
                decrypt = Mock(side_effect=AssertionError("private unwrap reached"))
                owner.kek = SimpleNamespace(decrypt=decrypt)
                with self.assertRaisesRegex(ValueError, "^native broker owner unavailable$"):
                    owner.open_credential(command)
                decrypt.assert_not_called()
                owner.channel.send.assert_not_called()

    def test_broker_actual_decrypt_refuses_stripped_private_schema_and_preserves_pat(self):
        for secret in (SECRET, '{"key":"-----BEGIN PRIVATE KEY-----\\nsynthetic"}', "ordinary-pat"):
            native, owner, command = broker_command(secret)
            # Tripwire after real KEK+DEK decrypt, before gate ciphertext construction.
            reached = RuntimeError("synthetic final ciphertext boundary reached")
            with patch.object(native, "_gate_ciphertext", side_effect=reached) as output:
                if secret == "ordinary-pat":
                    with self.assertRaises(RuntimeError) as caught:
                        owner.open_credential(command)
                    self.assertIs(caught.exception, reached)
                    output.assert_called_once()
                    self.assertTrue(output.call_args.args[1] == b"ordinary-pat")
                else:
                    with self.assertRaisesRegex(ValueError, "^native broker owner unavailable$"):
                        owner.open_credential(command)
                    output.assert_not_called()
            owner.channel.send.assert_not_called()

    def test_dedicated_revoke_never_opens_private_key_and_package_keeps_leaf_only(self):
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "delete_operator_github_app_credential")
        calls = {ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)}
        self.assertIn("_operator_github_app_transaction", calls)
        self.assertIn("operator_github_app.validate_credential", calls)
        self.assertFalse(calls & {"decrypt_secret_envelope", "row_to_credential", "operator_github_app.validate_stored"})
        source = (ROOT / "scripts/package_native_broker_runtime.py").read_text()
        self.assertIn('"github_app_boundary.py"', source)
        leaf = ast.parse((ROOT / "serverware/github_app_boundary.py").read_text())
        imports = {node.module for node in leaf.body if isinstance(node, ast.ImportFrom)}
        imports.update(alias.name for node in leaf.body if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(imports, {"__future__", "json", "re"})


if __name__ == "__main__":
    unittest.main()
