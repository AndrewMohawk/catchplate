"""Real projection/connector code with explicit component doubles, not admission.

The measured class's fields and role() are extracted from source, excluding its
root/launch loader. Synthetic process and driver fixtures prove handoff behavior
only; they do not claim real configuration admission, TLS or PostgreSQL success.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, dataclass
import hashlib
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import serverware
from serverware import authority_database_configuration as config


ROOT = Path(__file__).resolve().parents[1]


def digest(number):
    return "sha256:" + f"{number:064x}"


def functions(path, names, namespace):
    tree = ast.parse((ROOT / path).read_bytes())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != set(names) or len(selected) != len(names):
        raise AssertionError("source function roster changed")
    exec(compile(ast.Module(body=selected, type_ignores=[]), path, "exec"), namespace)
    return namespace


def fixture():
    tree = ast.parse((ROOT / "serverware/authority_service.py").read_bytes())
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MeasuredConfiguration")
    original.body = [node for node in original.body if isinstance(node, ast.AnnAssign)
        or isinstance(node, ast.FunctionDef) and node.name == "role"]
    namespace = dict(dataclass=dataclass, Any=Any, Ed25519PublicKey=Ed25519PublicKey,
        AuthorityServiceError=ValueError)
    exec(compile(ast.Module(body=[original], type_ignores=[]), "actual-measured-fields-and-role", "exec"), namespace)
    roles, runtime_roles = {}, {}
    for index, name in enumerate(("executor", "verifier", "issuer"), 1):
        roles[name] = dict(databaseRole=config.ISSUER_ROLE if name == "issuer" else "pilot_" + name,
            tlsClientDn="/CN=" + name, tlsClientSerial=str(index), tlsIssuerDn="/CN=component-ca",
            databaseConnectTimeoutSeconds=5.75, measurementDigest=digest(index + 10),
            responseSigningSpkiDigest=digest(index + 20))
        runtime_roles[name] = dict(measurementDigest=roles[name]["measurementDigest"],
            responseSigningSpkiDigest=roles[name]["responseSigningSpkiDigest"],
            attestationReceiptDigest=digest(index + 30))
    raw = b"Z" * 32
    roles["verifier"].update(signingPublicKeyBase64Url=base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        signingSpkiDigest="sha256:" + hashlib.sha256(Ed25519PublicKey.from_public_bytes(raw).public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest())
    payload = dict(schema="serverware.policyAuthorityServiceConfiguration/v6", roles=roles,
        generationSequence=7, generationBindingDigest=digest(40), verifierCredentialIssuanceDigest=digest(41),
        issuerCredentialIssuanceDigest=digest(42), replayWitness=dict(identityDigest=digest(43)),
        policyGenesis=dict(auditStoreIdentityDigest=digest(44), auditSignerPublicKeyDigest=digest(45)))
    runtime = dict(schema="serverware.policyAuthorityRuntimeRoleIdentities/v1", configurationDigest=digest(1),
        generationSequence=7, generationDigest=digest(46), roles=runtime_roles)
    measured = namespace["MeasuredConfiguration"](payload=payload, digest=digest(1), root_key=None,
        runtime_role_identities=runtime)
    service = ModuleType("serverware.authority_service")
    service.MeasuredConfiguration = namespace["MeasuredConfiguration"]
    launch = ModuleType("serverware.authority_launch_guard")
    launch.generation = lambda: dict(sequence=7, digest=digest(46), configurationBindingDigest=digest(40))
    return measured, {service.__name__: service, launch.__name__: launch}


@contextmanager
def component_modules(modules):
    with patch.dict(sys.modules, modules), patch.object(serverware, "authority_launch_guard",
            modules["serverware.authority_launch_guard"], create=True):
        yield


def captured():
    measured, modules = fixture()
    with component_modules(modules):
        return config.from_measured_configuration(measured)


class SessionDouble:
    def __init__(self, selected, **changes):
        self.role = dict(current_role=selected.executor_pins[0], exact_session=True,
            transaction_isolation="serializable", read_only="off", deferrable="off",
            rolsuper=False, rolcreaterole=False, rolcreatedb=False, rolreplication=False,
            rolbypassrls=False, schema_create=False, database_temporary=False)
        self.tls = dict(ssl=True, client_dn=selected.executor_pins[1],
            client_serial=selected.executor_pins[2], issuer_dn=selected.executor_pins[3])
        self.role.update({key: value for key, value in changes.items() if key in self.role})
        self.tls.update({key: value for key, value in changes.items() if key in self.tls})
        self.sql, self.closes, self.result = [], 0, None
        self.disallowed = changes.get("disallowed")
        self.recorded = changes.get("recorded", [{"componentContract": "same"}])

    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def close(self): self.closes += 1
    def fetchone(self): return self.result
    def fetchall(self): return self.result

    def execute(self, sql, parameters=None):
        self.sql.append(sql)
        self.result = None
        if sql.startswith("SELECT pg_catalog.to_regnamespace"): self.result = {"present": True}
        elif sql.startswith("SELECT current_user AS current_role"): self.result = self.role
        elif sql.startswith("SELECT ssl,"): self.result = self.tls
        elif sql.startswith("SELECT 1 FROM pg_catalog.pg_class AS relation"): self.result = self.disallowed
        elif "policy_authority_owner_contracts " in sql: self.result = self.recorded
        return self


def connector(selected, session):
    calls = []
    def connect(dsn, **kwargs):
        calls.append((dsn, kwargs))
        return session
    def owner(cur, *, database_configuration):
        if cur is not session or database_configuration is not selected:
            raise AssertionError("owner contract lost exact selected context")
        return {"componentContract": "same"}
    def descriptor(name):
        calls.append(name)
        return "component-only-dsn"
    namespace = dict(re=re, Any=Any, MetadataStoreError=ValueError,
        os=SimpleNamespace(environ={"SERVERWARE_PROCESS_MODE": "policy-authority-executor",
            "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_TLS_CLIENT_DN": "wrong-ambient"}),
        _POLICY_AUTHORITY_EXECUTOR_PROCESS_MODE="policy-authority-executor",
        _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME="serverware_metadata",
        _POLICY_AUTHORITY_OWNER_CONTRACT_ID="component-contract", _POLICY_AUTHORITY_CONTROLLED_WRITER_TABLES={"component"},
        _policy_authority_dsn_from_descriptor=descriptor,
        _metadata_psycopg=lambda: (SimpleNamespace(connect=connect), "dict-row"),
        _postgres_bootstrap_options=lambda *args, **kwargs: "options",
        _validate_policy_authority_owner_apply_function=owner)
    functions("serverware/db.py", {"_authority_database_pins", "_policy_authority_executor_pg_connect_raw"}, namespace)
    return namespace["_policy_authority_executor_pg_connect_raw"], calls


class ExecutorDatabaseConfigurationTests(unittest.TestCase):
    def test_actual_projection_uses_runtime_receipts_and_remains_immutable(self):
        measured, modules = fixture()
        with component_modules(modules):
            selected = config.from_measured_configuration(measured)
        self.assertEqual(selected.verifier_attestation_receipt_digest, digest(32))
        self.assertEqual(selected.verifier_credential_issuance_digest, digest(41))
        self.assertNotEqual(selected.verifier_attestation_receipt_digest, selected.verifier_credential_issuance_digest)
        measured.payload["roles"]["executor"]["databaseRole"] = "changed"
        self.assertEqual(selected.executor_pins[0], "pilot_executor")
        with self.assertRaises(FrozenInstanceError): selected.executor_pins = ()

    def test_missing_signed_or_runtime_inputs_cannot_use_ambient_replacements(self):
        for mutation in (lambda value: value.payload.pop("verifierCredentialIssuanceDigest"),
                lambda value: value.runtime_role_identities["roles"]["verifier"].update(measurementDigest=digest(999)),
                lambda value: value.runtime_role_identities.update(generationDigest=digest(999)),
                lambda value: value.payload["roles"]["verifier"].update(signingSpkiDigest=digest(999)),
                lambda value: value.payload.pop("policyGenesis")):
            measured, modules = fixture()
            mutation(measured)
            with component_modules(modules), self.assertRaises(config.AuthorityDatabaseConfigurationError):
                config.from_measured_configuration(measured)

    def test_actual_connector_sets_original_transaction_before_reads_and_checks_session(self):
        selected = captured()
        session = SessionDouble(selected)
        connect, calls = connector(selected, session)
        self.assertIs(connect(database_configuration=selected), session)
        self.assertEqual(session.sql[0], "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
        self.assertEqual(calls[1][1], dict(connect_timeout=5, row_factory="dict-row", options="options", autocommit=False))
        self.assertEqual(session.closes, 0)
        for changes in ({"client_dn": "wrong"}, {"current_role": "wrong"}, {"ssl": False},
                {"transaction_isolation": "read committed"}, {"read_only": "on"}, {"deferrable": "on"},
                {"schema_create": True}, {"disallowed": {"relname": "extra"}}, {"recorded": []}):
            with self.subTest(fields=tuple(changes)):
                session = SessionDouble(selected, **changes)
                connect, _ = connector(selected, session)
                with self.assertRaises(ValueError): connect(database_configuration=selected)
                self.assertEqual(session.closes, 1)
        connect, calls = connector(selected, SessionDouble(selected))
        with self.assertRaises(config.AuthorityDatabaseConfigurationError): connect(database_configuration=None)
        self.assertEqual(calls, [])

    def test_actual_executor_role_guard_uses_explicit_role_and_keeps_serializable_check(self):
        raw, events = object(), []
        namespace = dict(Any=Any, _require_postgres_connection=lambda connection: raw,
            _require_serializable=lambda connection: events.append(("serializable", connection)),
            _require_database_role=lambda connection, role: events.append((role, connection)),
            _db_value=lambda name: (_ for _ in ()).throw(AssertionError("ambient role used")))
        functions("serverware/authority_store/executor_v9.py", {"_require_executor"}, namespace)
        self.assertIs(namespace["_require_executor"](object(), expected_role="pilot_executor"), raw)
        self.assertEqual(events, [("serializable", raw), ("pilot_executor", raw)])


if __name__ == "__main__":
    unittest.main()
