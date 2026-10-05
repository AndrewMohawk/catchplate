"""Focused raw-head/resource-profile controls, not native dispatch acceptance.

The synthetic vector is genuinely computed from the complete source inventory;
its enrollment and nonce-bound head are real Ed25519 originals. No successful
permission, planner, pending row, database, worker or SQL DTO is fabricated.
Actual owner composition and wrong-owner guards are source checked only.
"""
from __future__ import annotations

import ast
import base64
from dataclasses import fields
import json
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
from serverware import control_plane_oidc_session_activation_request_dispatch as source
from serverware.authority_query_read_work import QueryReadValidationLimits, QueryReadWorkError, _ValidationWork

HEAD, AUTH = source.head, source.head.authorization
VECTOR = AUTH.vector
PIN = "sha256:" + "1" * 64
OTHER = "sha256:" + "2" * 64
NOW, AGE = 1_800_000_000_000_000_000, 1_000_000_000


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def head_fixture():
    meter = work()
    bindings, profiles = VECTOR._source_on_work(meter)
    empty = VECTOR.roots._primary_empty_root(meter)
    vector = dict(bindings, primaryRoots=[dict(table=table, rootRevision=0,
        rootDigest=empty, leafCount=0) for table in VECTOR.PRIMARY_TABLES], countedRoots=[
            dict(indexId=name, table=profiles[name].table, countedProfile=VECTOR.counted.PROFILE,
                projectionDigest=profiles[name].projection_digest,
                projectionManifestDigest=bindings["projectionManifestDigest"], indexRevision=0,
                rootDigest=VECTOR.counted.empty_node(profiles[name], "").digest, leafCount=0)
            for name in VECTOR.INDEX_IDS])
    raw_vector = VECTOR._encode_on_work(vector, work=meter)
    root = Ed25519PrivateKey.from_private_bytes(b"\x71" * 32)
    producers = {role: Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        for index, role in enumerate(AUTH._ROLES, 0x72)}
    payload = dict(schema=AUTH.ENROLLMENT_PAYLOAD_SCHEMA, sourceRevision=AUTH.authority.SOURCE_REVISION,
        databaseId="synthetic-request-dispatch", generationDigest=PIN, initialVector=vector,
        maxControlAgeNs=AGE, maxClockSkewNs=0, maxRecords=2)
    for role, private in producers.items():
        public = private.public_key()
        payload[role] = dict(publicKeyPem=public.public_bytes(Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            spkiDigest=AUTH.keys._spki_on_work(public, meter), measurementDigest=PIN)
    enrollment = AUTH._produce_enrollment_on_work(payload=payload,
        root_private_key=root, root_public_key=root.public_key(), work=meter)
    enrollment_digest = AUTH.plan._frame(AUTH.ENROLLMENT_IDENTITY_DOMAIN, (enrollment,), meter)
    vector_digest = VECTOR._digest_on_work(raw_vector, work=meter)
    query = HEAD._encode_query_on_work(enrollment_digest=enrollment_digest,
        context_digest=PIN, expected_vector_digest=vector_digest, challenge="3" * 64, work=meter)
    observed = dict(schema=HEAD.PAYLOAD_SCHEMA, sourceRevision=AUTH.authority.SOURCE_REVISION,
        enrollmentDigest=enrollment_digest, databaseId=payload["databaseId"], generationDigest=PIN,
        producerMeasurementDigest=PIN, operation=HEAD.OPERATION,
        queryDigest=HEAD._query_digest_on_work(query, meter), challenge="3" * 64,
        contextDigest=PIN, issuedAtEpochNs=NOW, expiresAtEpochNs=NOW + AGE,
        sequence=0, headDigest=enrollment_digest, vectorDigest=vector_digest, fence=0,
        pendingRequestDigest=None, pendingDecisionDigest=None)

    def sign_head(**changes):
        actual = dict(observed, **changes)
        message = AUTH.plan._frame(HEAD.OBSERVATION_SCHEMA, (canonical(actual),), work()).encode("ascii")
        return canonical(dict(schema=HEAD.OBSERVATION_SCHEMA, payload=actual,
            signatureBase64Url=encoded(producers["state"].sign(message))))

    arguments = dict(query_bytes=query, observation_bytes=sign_head(), enrollment_bytes=enrollment,
        root_public_key=root.public_key(), expected_context_digest=PIN,
        before_vector_bytes=raw_vector, now_epoch_ns=NOW + 1)
    return arguments, sign_head, enrollment_digest


def shape(schema):
    original = dict(base64Url=encoded(b"{}"), byteCount=2)
    key = dict(publicKeyBase64Url=encoded(b"k" * 32), spkiDigest=PIN)

    def endpoint(path):
        return dict(socketPath=path, requestTimeoutSeconds=10, listenerUid=0, listenerGid=0)

    value = dict(schema=schema, activationCallerPrivateKeyFd=205, plannerKey=key,
        currentRootEnrollment=original, grantEnrollment=original, authorizationEnrollment=original,
        authorizerEndpoint=endpoint(activation.AUTHORIZER_SOCKET_PATH))
    if schema != activation.SCHEMA:
        value.update(reserverEndpoint=endpoint(activation.RESERVER_SOCKET_PATH),
            sqlEndpoint=endpoint(activation.SQL_SOCKET_PATH))
        if schema != activation.V5_SCHEMA:
            value["statePredecessor"] = dict(sequence=0, headDigest=PIN, nextFence=1)
    if schema in (activation.V3_SCHEMA, activation.V4_SCHEMA, activation.V5_SCHEMA):
        value["completionEndpoint"] = endpoint(activation.COMPLETION_SOCKET_PATH)
    if schema in (activation.V4_SCHEMA, activation.V5_SCHEMA):
        value.update(consumePlannerEndpoint=endpoint(activation.CONSUME_PLANNER_SOCKET_PATH),
            consumePlannerKey=dict(key, measurementDigest=OTHER))
    return value


def body(name, function):
    raw = (ROOT / "serverware" / (name + ".py")).read_text("utf-8")
    matches = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == function]
    if len(matches) != 1:
        raise AssertionError(function)
    return ast.get_source_segment(raw, matches[0])


class RequestDispatchControls(unittest.TestCase):
    def test_01_old_shapes_preserved_and_v5_has_no_future_predecessor(self):
        for schema in (activation.SCHEMA, activation.V2_SCHEMA, activation.V3_SCHEMA,
                activation.V4_SCHEMA, activation.V5_SCHEMA):
            with self.subTest(schema=schema):
                self.assertIsNone(activation._shape(shape(schema)))
        self.assertEqual(activation._V5_FIELDS, activation._V4_FIELDS - {"statePredecessor"})
        self.assertFalse(next(item for item in fields(activation._ActivationExecutionMaterial)
            if item.name == "request_bound").default)
        old = shape(activation.V4_SCHEMA)
        del old["statePredecessor"]
        with self.assertRaises(ValueError):
            activation._shape(old)
        for field, value in (("statePredecessor", dict(sequence=0, headDigest=PIN, nextFence=1)),
                ("currentPending", {}), ("request_bound", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                activation._shape(dict(shape(activation.V5_SCHEMA), **{field: value}))

    def test_02_genuine_signed_head_derives_genesis_and_enforces_enrolled_capacity(self):
        arguments, sign, digest = head_fixture()
        self.assertEqual(source._predecessor_on_work(**arguments, work=work()), (0, digest, 1))
        # Re-enroll capacity rather than accepting a caller capacity verdict.
        # The positive non-genesis boundary cannot fit this actual two-record
        # enrollment, so its source-authenticated head must be refused.
        with self.assertRaisesRegex(RuntimeError, "reserve and completion capacity"):
            source._predecessor_on_work(**dict(arguments,
                observation_bytes=sign(sequence=1, fence=1, headDigest=OTHER)), work=work())

    def test_03_raw_head_pending_context_query_key_expiry_and_budget_refuse(self):
        arguments, sign, _digest = head_fixture()
        cases = [dict(observation_bytes=sign(sequence=1, fence=1, headDigest=OTHER,
                    pendingRequestDigest=PIN, pendingDecisionDigest=OTHER)),
            dict(expected_context_digest=OTHER), dict(query_bytes=arguments["query_bytes"] + b"\n"),
            dict(root_public_key=Ed25519PrivateKey.from_private_bytes(b"\x7a" * 32).public_key()),
            dict(now_epoch_ns=NOW + AGE)]
        for changes in cases:
            with self.subTest(fields=tuple(changes)), self.assertRaises((ValueError, RuntimeError)):
                source._predecessor_on_work(**dict(arguments, **changes), work=work())
        with self.assertRaises(QueryReadWorkError):
            source._predecessor_on_work(**arguments, work=work(max_input_bytes=32))

    def test_04_permission_type_and_accessor_custody_source_guards(self):
        held = body("control_plane_oidc_session_activation_request_dispatch", "_held")
        accessor = body("control_plane_oidc_session_activation_request_dispatch", "_planner_original_on_permission")
        for marker in ("type(permission) is not execution._ActivationPermission",
                "type(continuation) is not issued._Continuation", "issued._Continuation._check(continuation, permission)",
                "parent.activation_execution.request_bound is not True", "permission._planning_bounds is None"):
            self.assertIn(marker, held)
        self.assertLess(accessor.index("permission._current()"), accessor.index("after, raw = _held(permission)"))
        self.assertIn("raw is not originals", accessor)
        self.assertTrue(accessor.rstrip().endswith("return originals[3]"))

    def test_05_real_dispatch_joins_after_prepare_before_actual_grant_without_parent_mutation(self):
        selected = body("control_plane_oidc_session_activation_dispatch", "_dispatch_fixed_on_permission")
        self.assertLess(selected.index("execution._ActivationPermission.prepare_authorization("),
            selected.index("request_dispatch._prepared_on_permission("))
        self.assertLess(selected.index("request_dispatch._prepared_on_permission("),
            selected.index("grant_io._socket_request_on_work("))
        self.assertIn("request_dispatch._planner_original_on_permission(permission) is not planner_original", selected)
        self.assertIn("planner_original = planning_policy.planner_bootstrap_bytes", selected)
        self.assertIn("reserve_io._socket_request_on_work(", selected)
        self.assertIn("sql_io._socket_request_on_work(", selected)
        prepared = body("control_plane_oidc_session_activation_request_dispatch", "_prepared_on_permission")
        self.assertLess(prepared.index("_predecessor_on_work("), prepared.index("now = permission._current()"))
        self.assertIn('payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]', prepared)
        for token in ("owner._material =", "_ValidationWork(", "QueryReadValidationLimits("):
            self.assertNotIn(token, selected + prepared)


if __name__ == "__main__":
    unittest.main(verbosity=2)
