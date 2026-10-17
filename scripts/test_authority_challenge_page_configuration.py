#!/usr/bin/env python3
"""Inert mapper controls with synthetic Service6, cohort and Ed25519 originals.

These exercise actual bounded capture/key joins, not measured admission, peer
authentication, protected descriptors, PostgreSQL, or successful proof DTOs.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_page_configuration as source
from test_authority_challenge_configuration import Fixture as BaseFixture, digest, work


class Fixture(BaseFixture):
    def __init__(self):
        super().__init__()
        self.verifier_private = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
        roles = self.payload["roles"]
        for name, uid, maximum in (("planner", 65518, 12_000_000_000),
                ("verifier", 65520, 9_000_000_000), ("planner-writer", 65519, 10_000_000_000)):
            roles[name].update(serviceUid=uid, serviceGid=uid, maximumInternalAgeNs=maximum,
                requestTimeoutSeconds=0.75, socketPath="/run/synthetic/" + name + ".sock")
        roles["planner"].update(peerUid=65520, peerGid=65520)
        roles["planner-writer"].update(peerUid=65518, peerGid=65518,
            plannerSessionIdentityDigest=roles["planner"]["plannerSessionIdentityDigest"],
            plannerSigningSpkiDigest=roles["planner"]["signingSpkiDigest"],
            plannerSigningPublicKeyBase64Url=roles["planner"]["signingPublicKeyBase64Url"],
            databaseConnectTimeoutSeconds=2.75, databaseRole="catchplate_policy_authority_planner_writer",
            tlsClientDn="CN=synthetic-writer", tlsClientSerial="19", tlsIssuerDn="CN=synthetic-ca")
        self.seal()

    def capture(self, role="planner", **changes):
        arguments = dict(local_role=role, payload=self.payload, configuration_digest=self.digest,
            generation=self.generation, runtime_role_identities=self.runtime, work=work())
        if role == "planner-writer":
            arguments["writer_dsn"] = "host=synthetic.invalid dbname=synthetic"
        else:
            arguments["private_key"] = self.private if role == "planner" else self.verifier_private
        arguments.update(changes)
        return source._from_configuration_on_work(**arguments)


def raw(key):
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class ChallengePageConfigurationControls(unittest.TestCase):
    def test_real_inert_three_role_factories_and_independent_verifier_session(self):
        fixture, meter = Fixture(), work()
        with patch.object(source.page_persistence, "_connect", side_effect=AssertionError("database opened")):
            values = {role: fixture.capture(role, work=meter) for role in source._ROLES}
        planner = fixture.payload["roles"]["planner"]
        verifier = fixture.payload["roles"]["verifier"]
        cohort = fixture.runtime["roles"]
        verifier_values = (fixture.digest, verifier["measurementDigest"], cohort["verifier"]["attestationReceiptDigest"])
        framed = b"catchplate.policyAuthorityVerifierSession/v2\x00" + b"".join(
            len(value.encode("utf-8")).to_bytes(8, "big") + value.encode("utf-8") for value in verifier_values)
        for role, selected in values.items():
            self.assertIs(type(selected), source._PageConfiguration)
            self.assertIs(source._snapshot(selected), selected._original)
            self.assertEqual(selected.local_role, role)
            self.assertEqual(selected.planner_identity, (planner["plannerSessionIdentityDigest"],
                planner["measurementDigest"], cohort["planner"]["attestationReceiptDigest"]))
            self.assertEqual(selected.verifier_identity, (digest(framed), *verifier_values[1:]))
            self.assertEqual((selected.configuration_digest, selected.generation_sequence, selected.generation_digest),
                (fixture.digest, 3, fixture.generation["digest"]))
            self.assertEqual((selected.maximum_age_ns, selected.maximum_clock_skew_ns),
                (9_000_000_000, source.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS))
            self.assertEqual(selected.planner_endpoint, ("/run/synthetic/planner.sock", 65518, 65518))
            self.assertEqual(selected.writer_endpoint, ("/run/synthetic/planner-writer.sock", 65519, 65519))
            self.assertEqual(raw(selected.planner_public_key), raw(fixture.private.public_key()))
            self.assertEqual(raw(selected.verifier_public_key), raw(fixture.verifier_private.public_key()))
        self.assertIs(values["planner"].private_key, fixture.private)
        self.assertIs(values["verifier"].private_key, fixture.verifier_private)
        self.assertIsNone(values["planner"].persistence)
        self.assertIsNone(values["verifier"].persistence)
        writer = values["planner-writer"]
        self.assertIsNone(writer.private_key)
        self.assertIs(type(writer.persistence), source.page_persistence.MaintenancePagePersistence)
        self.assertEqual(source.page_persistence._snapshot(writer.persistence),
            ("host=synthetic.invalid dbname=synthetic", 2, ("catchplate_policy_authority_planner_writer",
                "CN=synthetic-writer", "19", "CN=synthetic-ca")))
        self.assertGreater(meter.hash_work, 0)

    def test_signed_policy_enabled_source_and_peer_shape_fail_before_keys(self):
        def absent(f):
            del f.payload[source.policy.FIELD]
        def null(f):
            f.payload[source.policy.FIELD] = None
        def disabled(f):
            f.payload["roles"]["planner"]["enabledOperations"] = []
        def query(f):
            f.payload["queryManifestDigest"] = digest(b"other query")
        def age(f):
            f.payload["roles"]["verifier"]["maximumInternalAgeNs"] = True
        def peer(f):
            f.payload["roles"]["planner-writer"]["peerUid"] = 65520
        def timeout(f):
            f.payload["roles"]["planner"]["requestTimeoutSeconds"] = True
        def path(f):
            f.payload["roles"]["planner"]["socketPath"] = "/" + "é" * 60
        for mutate in (absent, null, disabled, query, age, peer, timeout, path):
            fixture = Fixture()
            mutate(fixture)
            fixture.seal()
            with self.subTest(change=mutate.__name__), patch.object(source.configuration, "_key",
                    side_effect=AssertionError("invalid selection reached key callback")):
                with self.assertRaises(ValueError):
                    fixture.capture()

    def test_actual_configuration_generation_cohort_and_signer_joins(self):
        for change in ("commitment", "generation", "cohort", "private", "reused-key", "writer-alias", "writer-role"):
            fixture, options, role = Fixture(), {}, "planner"
            if change == "commitment":
                fixture.payload["roles"]["planner"]["serviceUid"] += 1
            elif change == "generation":
                fixture.generation["digest"] = digest(b"other generation")
            elif change == "cohort":
                fixture.runtime["roles"]["planner"]["measurementDigest"] = digest(b"other measurement")
            elif change == "private":
                options["private_key"] = fixture.verifier_private
            elif change == "reused-key":
                planner, verifier = fixture.payload["roles"]["planner"], fixture.payload["roles"]["verifier"]
                for field in ("signingPublicKeyBase64Url", "signingSpkiDigest", "responseSigningSpkiDigest"):
                    verifier[field] = planner[field]
                fixture.runtime["roles"]["verifier"]["responseSigningSpkiDigest"] = planner["signingSpkiDigest"]
                fixture.seal()
            else:
                role = "planner-writer"
                field = "plannerSessionIdentityDigest" if change == "writer-alias" else "databaseRole"
                fixture.payload["roles"][role][field] = digest(b"other alias") if change == "writer-alias" else "other_role"
                fixture.seal()
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.capture(role, **options)
        fixture = Fixture()
        for role, changes in (("planner", dict(writer_dsn="synthetic")),
                ("verifier", dict(private_key=None)), ("planner-writer", dict(private_key=fixture.private)),
                ("planner-writer", dict(writer_dsn=None)), ("planner-writer", dict(writer_dsn="a\nb"))):
            with self.subTest(role=role, fields=tuple(changes)), self.assertRaises(ValueError):
                fixture.capture(role, **changes)

    def test_all_settings_are_detached_before_actual_key_callback(self):
        fixture, captured = Fixture(), []
        capture, key = source.configuration._capture_configuration_on_work, source.configuration._key
        expected_digest, expected_generation = fixture.digest, fixture.generation["digest"]

        def own(**kwargs):
            result = capture(**kwargs)
            captured.append(result)
            return result

        def mutate(*args, **kwargs):
            # Even the invocation's detached graph is no longer consulted
            # after key construction begins; all needed scalars are held.
            captured[0][0]["roles"].clear()
            captured[0][1].clear()
            fixture.payload.clear()
            fixture.runtime.clear()
            fixture.generation.clear()
            return key(*args, **kwargs)

        with patch.object(source.configuration, "_capture_configuration_on_work", side_effect=own), \
                patch.object(source.configuration, "_key", side_effect=mutate):
            selected = fixture.capture("planner-writer")
        self.assertEqual((selected.configuration_digest, selected.generation_digest),
            (expected_digest, expected_generation))
        self.assertEqual(selected.maximum_age_ns, 9_000_000_000)
        self.assertEqual(selected.writer_endpoint, ("/run/synthetic/planner-writer.sock", 65519, 65519))
        self.assertEqual(selected.persistence._configured[2][1], "CN=synthetic-writer")
        source._snapshot(selected)

    def test_snapshot_rejects_malformed_subclass_and_original_replacement(self):
        fixture, selected = Fixture(), Fixture().capture()
        with self.assertRaises(FrozenInstanceError):
            selected.maximum_age_ns = 1
        for field, value in (("maximum_age_ns", True), ("generation_sequence", True),
                ("planner_identity", list(selected.planner_identity)), ("planner_endpoint", ("relative", 1, 1)),
                ("maximum_clock_skew_ns", source.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS + 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(selected, **{field: value})
        with self.assertRaises(ValueError):
            source._snapshot(object.__new__(source._PageConfiguration))
        class Other(source._PageConfiguration):
            pass
        other = Other(**{name: getattr(selected, name) for name in source._FIELDS})
        with self.assertRaises(ValueError):
            source._snapshot(other)
        object.__setattr__(selected, "maximum_age_ns", 1)
        with self.assertRaises(ValueError):
            source._snapshot(selected)
        writer = fixture.capture("planner-writer")
        original = writer.persistence._configured
        object.__setattr__(writer.persistence, "_configured", (original[0], 3, original[2]))
        with self.assertRaises(ValueError):
            source._snapshot(writer)

    def test_remaining_budget_and_cancellation_are_not_replaced(self):
        fixture = Fixture()
        for limits in (dict(max_input_bytes=128), dict(max_json_nodes=8), dict(max_hashes=1)):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                fixture.capture(work=work(**limits))
        cancellation = KeyboardInterrupt()
        with patch.object(source.configuration, "_key", side_effect=cancellation):
            with self.assertRaises(KeyboardInterrupt) as caught:
                fixture.capture()
        self.assertIs(caught.exception, cancellation)


if __name__ == "__main__":
    unittest.main()
