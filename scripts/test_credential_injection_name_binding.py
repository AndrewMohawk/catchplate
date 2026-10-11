#!/usr/bin/env python3
"""Offline header-name binding regression, not proxy or provider acceptance.

Catalog/legacy creation uses actual private SQLite, encrypted custody, policy
signing and compilation. The exact app and engine binding functions are AST-
extracted to avoid booting the application or importing an unused HTTP proxy.
No binding guard is replaced. Legacy setup suppresses only catalog activation,
as in the existing migration fixture. Run with backend dependencies and TMPDIR.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def require_assertions(environment):
    if sys.flags.optimize != 0 or environment.get("PYTHONOPTIMIZE", "") not in {"", "0"}:
        raise RuntimeError("header binding tests require enabled Python assertions")


# Refuse optimized parent and worker interpreters before backend fixture imports.
require_assertions(os.environ)

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
SECRET = "Synthetic-Header-Token-AbC123"
NAMES = ("X-Operator-Public-Probe", "x-operator-public-probe")


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("header binding fixture attempted network contact")


def binding_functions(bundles):
    from fastapi import HTTPException
    from serverware.policies import PolicyDecision

    namespace = {"HTTPException": HTTPException, "PolicyDecision": PolicyDecision,
        "normalized_credential_provider": bundles.normalized_credential_provider,
        "hmac": hmac}
    for filename, names in (
        ("app.py", ("_assert_credential_injection_binding", "_credential_secret_for_lease")),
        ("policy_engine.py", ("_credential_metadata_scopes", "_consistent_metadata_alias",
            "_credential_policy_binding_decision")),
    ):
        source = ROOT / "serverware" / filename
        definitions = {node.name: node for node in ast.parse(source.read_text()).body
            if isinstance(node, ast.FunctionDef)}
        module = ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")], level=0)]
            + [definitions[name] for name in names], type_ignores=[])
        exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    return namespace


def check_binding(functions, route, policy, credential, *, allowed):
    before = deepcopy(credential)
    try:
        functions["_assert_credential_injection_binding"](credential, policy)
    except functions["HTTPException"] as error:
        assert not allowed and error.status_code == 409
    else:
        assert allowed, "app admitted a different or absent binding"
    decision = functions["_credential_policy_binding_decision"](
        route, policy, credential, "fixture.read")
    if allowed:
        assert decision is None
        assert functions["_credential_secret_for_lease"](credential, policy) == SECRET
    else:
        assert decision is not None and not decision.allowed and decision.status_code == 409
        assert decision.payload["error"] == "credential_policy_binding_mismatch"
    assert credential == before, "binding check changed stored metadata or token bytes"


def check_created(bundles, config, db, identifiers):
    signed = json.loads(config.POLICY_BUNDLE_PATH.read_bytes())
    snapshot = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    functions = binding_functions(bundles)
    for identifier, name in identifiers:
        credential = db.get_credential(identifier, include_secret=True)
        assert credential is not None and credential["secret"] == SECRET
        assert credential["metadata"]["injection_name"] == name
        policy = snapshot.credentials[identifier]
        route = next(item for item in snapshot.routes if item.credential_ref == identifier)
        assert policy.injection["name"] == name
        check_binding(functions, route, policy, credential, allowed=True)
        for variant in (name.lower(), name.upper()):
            selected = deepcopy(credential)
            selected["metadata"]["injection_name"] = variant
            check_binding(functions, route, policy, selected, allowed=True)
        for variant in (None, "X-Different-Header", "x_operator_public_probe", " X-Operator-Public-Probe",
                "X-Operator-Public-Probe\n", 7):
            selected = deepcopy(credential)
            if variant is None:
                del selected["metadata"]["injection_name"]
            else:
                selected["metadata"]["injection_name"] = variant
            check_binding(functions, route, policy, selected, allowed=False)
    return {"created_headers": len(identifiers), "both_bindings_verified": True}


def catalog_creation():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    identifiers = []
    for name in NAMES:
        created = mutations.create_credential(inputs.CredentialInput(
            **workspace.review(db, store, schema), name="Header binding fixture",
            auth_type="header", header_name=name, secret=SECRET), workspace.common._ACTOR)
        identifier = created["credential"]["id"]
        application = workspace.create_application(db, store, schema, inputs, mutations)
        workspace.create_rule(db, store, schema, inputs, mutations,
            application["application"]["id"], identifier)
        identifiers.append((identifier, name))
    workspace.verify_signed(config, db, store, bundles)
    return check_created(bundles, config, db, identifiers)


def legacy_creation():
    from serverware import operator_catalog_schema as schema
    with patch.object(schema, "initialize", return_value=None):
        config, db, store, bundles = workspace.common.backend()
    assert not schema.active()
    identifiers = []
    for name in NAMES:
        record, _token, _digest = store.create_connection(store.ConnectionInput(
            name="Legacy header binding fixture", upstream_url="https://api.example.com/v1/items",
            methods=["GET"], auth_type="header", header_name=name, secret=SECRET,
            response_fields=["status"]), workspace.common._ACTOR)
        identifiers.append((record["credential_id"], name))
    return check_created(bundles, config, db, identifiers)


def comparison_controls():
    _config, _db, _store, bundles = workspace.common.backend()
    functions = binding_functions(bundles)
    route = SimpleNamespace(adapter_config={"credentialBinding": {
        "credentialType": "static", "provider": "fixture", "subjects": ["subject"],
        "secretClass": "syntheticClass"}})
    policy = bundles.CredentialPolicy(id="synthetic", kind="static", provider="fixture",
        provider_subject="subject", scopes=(), injection={"type": "header", "name": "X-Key"})
    credential = {"kind": "header", "secret": SECRET, "metadata": {
        "provider_id": "fixture", "provider_subject": "subject",
        "secret_class": "syntheticClass", "injection_name": "x-key"}}
    check_binding(functions, route, policy, credential, allowed=True)
    selected = deepcopy(credential)
    selected["metadata"]["injection_name"] = "x-\u212aey"
    check_binding(functions, route, policy, selected, allowed=False)
    for kind in ("query", "cookie"):
        selected = deepcopy(credential)
        selected["kind"] = kind
        selected["metadata"]["injection_name"] = "Token"
        current = replace(policy, injection={"type": kind, "name": "Token"})
        check_binding(functions, route, current, selected, allowed=True)
        selected["metadata"]["injection_name"] = "token"
        check_binding(functions, route, current, selected, allowed=False)
    for kind, field, value in (("header", "field", "Token"), ("header", "prefix", "Api "),
            ("basic", "username", "CaseUser"), ("bearer", "prefix", "Bearer ")):
        selected = deepcopy(credential)
        selected["kind"] = kind
        metadata_key = "username" if field == "username" else "injection_" + field
        selected["metadata"][metadata_key] = value
        injection = {"type": kind, field: value}
        if kind == "header":
            injection["name"] = "X-Key"
        current = replace(policy, injection=injection)
        check_binding(functions, route, current, selected, allowed=True)
        selected["metadata"][metadata_key] = value.lower()
        check_binding(functions, route, current, selected, allowed=False)
    return {"non_header_comparisons_exact": True, "token_bytes_preserved": True}


class CredentialInjectionNameBindingTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        require_assertions(self.environment)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_optimized_child_environment_and_interpreter_refuse_before_backend(self):
        self.environment["PYTHONOPTIMIZE"] = "1"
        with patch.object(subprocess, "run") as launch:
            with self.assertRaisesRegex(RuntimeError, "require enabled Python assertions"):
                self.run_worker("comparisons")
            launch.assert_not_called()
        environment = dict(self.environment)
        environment.pop("PYTHONOPTIMIZE")
        result = subprocess.run([sys.executable, "-O", "-B", str(Path(__file__).resolve()),
            "--worker", "comparisons"], cwd=ROOT, env=environment,
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("require enabled Python assertions", result.stderr)
        self.assertFalse(self.directory.exists(), "optimized worker reached backend setup")

    def test_catalog_mixed_and_lowercase_headers_reach_both_binding_guards(self):
        self.assertEqual(self.run_worker("catalog")["created_headers"], 2)

    def test_legacy_mixed_and_lowercase_headers_reach_both_binding_guards(self):
        self.assertEqual(self.run_worker("legacy")["created_headers"], 2)

    def test_only_ascii_header_names_are_case_insensitive(self):
        self.assertTrue(self.run_worker("comparisons")["non_header_comparisons_exact"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        worker = {"catalog": catalog_creation, "legacy": legacy_creation,
            "comparisons": comparison_controls}[sys.argv[2]]
        print(json.dumps(worker(), sort_keys=True))
    else:
        unittest.main(verbosity=2)
