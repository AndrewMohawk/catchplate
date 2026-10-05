#!/usr/bin/env python3
"""Control-codec/key/clock/source checks, not full grant or live authority proof."""
import ast
import copy
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_execution_grant as grants
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def work():
    return _ValidationWork(QueryReadValidationLimits())


def private(seed=0):
    return Ed25519PrivateKey.from_private_bytes(bytes((value + seed) % 256 for value in range(32)))


def enrollment():
    public = private(1).public_key()
    return {"schema": grants.ENROLLMENT_PAYLOAD_SCHEMA,
        "sourceRevision": grants.authorization.authority.SOURCE_REVISION,
        "currentRootEnrollmentDigest": "sha256:" + "1" * 64, "databaseId": "fixture-db",
        "generationDigest": "sha256:" + "2" * 64, "operations": [grants.OPERATION],
        "authorizer": {"publicKeyPem": public.public_bytes(grants.authorization.Encoding.PEM,
            grants.authorization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            "spkiDigest": grants.keys._spki_on_work(public, work()), "measurementDigest": "sha256:" + "3" * 64},
        "maximumGrantAgeNs": 1000, "maximumClockSkewNs": 0}


def grant():
    return {**{name: "sha256:" + "4" * 64 for name in grants._DIGEST_FIELDS},
        "schema": grants.GRANT_PAYLOAD_SCHEMA, "sourceRevision": grants.authorization.authority.SOURCE_REVISION,
        "databaseId": "fixture-db", "operation": grants.OPERATION,
        "originalFrames": [{"position": index, "bytesDigest": "sha256:" + "5" * 64, "byteCount": 2}
            for index in range(3)], "issuedAtEpochNs": 1000, "expiresAtEpochNs": 1900}


class ChallengeExecutionGrantControls(unittest.TestCase):
    def test_delegation_is_distinct_and_exact_maintenance_only(self):
        grants._enrollment_shape(enrollment())
        self.assertNotEqual(grants.ENROLLMENT_SCHEMA, grants.mechanics.ENROLLMENT_SCHEMA)
        self.assertNotEqual(grants.ENROLLMENT_IDENTITY_DOMAIN, grants.mechanics.ENROLLMENT_IDENTITY_DOMAIN)
        for operations in ([], [grants.OPERATION, grants.OPERATION], ["webauthn.challenge.create"],
                list(grants.mechanics.OPERATIONS), (grants.OPERATION,), [True]):
            value = enrollment()
            value["operations"] = operations
            with self.subTest(operations=operations), self.assertRaises(ValueError):
                grants._enrollment_shape(value)

    def test_grant_has_exact_fields_original_frame_order_and_positive_interval(self):
        grants._grant_shape(grant())
        for field in grants.GRANT_FIELDS:
            value = grant()
            del value[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                grants._grant_shape(value)
        for name, changed in (("operation", "webauthn.challenge.create"), ("accepted", True),
                ("issuedAtEpochNs", True), ("expiresAtEpochNs", 1000), ("originalFrames", []),
                ("requestAuthorizationDigest", None), ("signedCapabilityId", "sha256:" + "1" * 64)):
            value = grant()
            value[name] = changed
            with self.subTest(name=name), self.assertRaises(ValueError):
                grants._grant_shape(value)
        for field, value in (("position", True), ("position", 2), ("byteCount", 0),
                ("byteCount", grants.FRAME_MAXIMA[0] + 1)):
            payload = grant()
            payload["originalFrames"][0][field] = value
            with self.assertRaises(ValueError):
                grants._grant_shape(payload)

    def test_actual_signatures_canonical_bytes_and_domains_are_not_interchangeable(self):
        signer = private()
        for is_enrollment, payload, maximum in ((True, enrollment(), grants.MAX_ENROLLMENT_BYTES),
                (False, grant(), grants.MAX_GRANT_BYTES)):
            raw = grants._sign(payload, private_key=signer, public_key=signer.public_key(),
                enrollment=is_enrollment, work=work())
            decoded = grants._read(raw, enrollment=is_enrollment, work=work())
            grants.mechanics._signature(decoded, signer.public_key(), maximum, work())
            with self.assertRaises(Exception):
                grants.mechanics._signature(decoded, private(2).public_key(), maximum, work())
            for changed in (raw + b"\n", bytearray(raw)):
                with self.assertRaises(ValueError):
                    grants._read(changed, enrollment=is_enrollment, work=work())
            with self.assertRaises(ValueError):
                grants._read(raw, enrollment=not is_enrollment, work=work())
            tampered = copy.deepcopy(decoded)
            tampered["schema"] = grants.mechanics.ENROLLMENT_SCHEMA if is_enrollment else grants.mechanics.GRANT_SCHEMA
            with self.assertRaises(Exception):
                grants.mechanics._signature(tampered, signer.public_key(), maximum, work())

    def test_actual_authorizer_keys_must_be_separate(self):
        authorizer = private(1).public_key()
        grants._separate(authorizer, (private().public_key(), private(2).public_key()), work())
        with self.assertRaises(ValueError):
            grants._separate(authorizer, (private().public_key(), private(1).public_key()), work())

    def test_retained_clock_window_rejects_rollback_expiry_and_future_issue(self):
        live = grants._Live((1000, 10, 10, 2000, 1010, 1000, 0), 900)
        live.bind(grant(), enrollment())
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1100), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=110):
            self.assertEqual(live.sample(work()), 1100)
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1090), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=100), self.assertRaises(ValueError):
            live.sample(work())
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1900), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=910), self.assertRaises(ValueError):
            live.sample(work())
        future = grant()
        future["issuedAtEpochNs"] = 1101
        live = grants._Live((1000, 10, 10, 2000, 1010, 1000, 0))
        live.bind(future, enrollment())
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1100), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=110), self.assertRaises(ValueError):
            live.sample(work())

    def test_later_narrower_receiver_preserves_original_interval_and_both_deadlines(self):
        original = grant()
        window = (1100, 110, 110, 1800, 810, 1000, 0)
        live = grants._Live(window, 910)
        live.bind(original, enrollment())
        self.assertEqual(live.interval, (1000, 1900))
        self.assertEqual(live.window, window)
        self.assertEqual(live.original_deadline, 910)
        self.assertEqual(live.deadline, 810)
        self.assertEqual(original, grant())
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1200), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=210):
            self.assertEqual(live.sample(work()), 1200)
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1800), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=810), self.assertRaises(ValueError):
            live.sample(work())
        earlier_context = grants._Live(window, 700)
        earlier_context.bind(original, enrollment())
        self.assertEqual(earlier_context.deadline, 700)
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1690), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=700), self.assertRaises(ValueError):
            earlier_context.sample(work())
        expired_original = grants._Live((1850, 860, 860, 1950, 960, 1000, 0), 940)
        expired_original.bind(original, enrollment())
        with mock.patch.object(grants.clock.time, "time_ns", return_value=1900), \
                mock.patch.object(grants.clock.time, "monotonic_ns", return_value=910), self.assertRaises(ValueError):
            expired_original.sample(work())

    def test_tight_original_budget_denies_before_signing(self):
        meter = _ValidationWork(QueryReadValidationLimits(max_input_bytes=1))
        with mock.patch.object(grants.authorization.production, "_sign_and_verify") as sign:
            with self.assertRaises(ValueError):
                grants._sign(grant(), private_key=private(), public_key=private().public_key(),
                    enrollment=False, work=meter)
            sign.assert_not_called()

    def test_both_public_paths_replay_and_control_only_is_explicitly_separate(self):
        for function in (grants.produce_grant, grants.verify_grant):
            self.assertNotIn("observation", inspect.signature(function).parameters)
            tree = ast.parse(inspect.getsource(function))
            calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
            self.assertEqual(calls.count("_replay"), 1)
            self.assertIn("_claims", calls)
        tree = ast.parse(inspect.getsource(grants))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("current_root.replay_to_complete_vector"), 1)
        self.assertIn("authorization._admit_enrollment_on_work", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"_open_on_work", "generate", "connect",
            "execute", "commit", "rollback", "_ValidationWork"} for name in calls))
        self.assertNotIn("_replay(", inspect.getsource(grants._verify_control_on_work))


if __name__ == "__main__":
    unittest.main()
