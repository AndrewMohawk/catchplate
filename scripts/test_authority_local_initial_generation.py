#!/usr/bin/env python3
"""Pure initial-generation consistency, not root/cohort/launch admission."""
import copy
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_transition_custody_wire as custody_wire
from catchplate import authority_webauthn_transition_request as request_wire
from catchplate import authority_webauthn_transition_response as response_wire
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

PIN = "sha256:" + "1" * 64


def fixture():
    roles = {role: dict(measurementDigest=PIN, responseSigningSpkiDigest=PIN)
        for role in configuration._ROLE_NAMES}
    pins = {role: PIN for role in roles}
    payload = dict(credentialReleaseTrust=dict(
        schema="catchplate.trustedHostLocalCredentialReleaseTrust/v1",
        trustMode="trusted-host-local", maximumReceiptAgeNs=1_000_000_000),
        generationSequence=0, generationPredecessorDigest=None,
        generationMinimumRollbackSequence=0, generationBindingDigest=PIN,
        roleBindingDigests=pins, roleRuntimeClosureDigests=pins, roles=roles)
    launch = dict(schema=configuration.GENERATION_SCHEMA, sequence=0,
        predecessorDigest=None, minimumRollbackSequence=0, digest=PIN,
        configurationBindingDigest=PIN, operationManifestDigest=configuration.authority.OPERATION_MANIFEST_DIGEST,
        configurationPayloadBindings=[dict(fileDigest=PIN, payloadDigest=PIN,
            payloadSchema=configuration.CONFIG_SCHEMA, role="authority-service")], roleBindingDigests=pins)
    runtime = dict(schema=configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA,
        configurationDigest=PIN, generationSequence=0, generationDigest=PIN, cohortDigest=PIN,
        roles={role: dict(value, attestationReceiptDigest=PIN) for role, value in roles.items()})
    return payload, launch, runtime


def check(payload, launch, runtime):
    work = _ValidationWork(QueryReadValidationLimits())
    configuration._generation_binding(payload, launch, PIN, work)
    return configuration._capture_runtime_role_identities_on_work(runtime_role_identities=runtime,
        owned_payload=payload, configuration_digest=PIN, launch=launch, work=work)


class LocalInitialGenerationControls(unittest.TestCase):
    def test_actual_zero_is_not_remapped(self):
        value = fixture()
        self.assertEqual(check(*value), value[2])
        self.assertEqual(value[1]["sequence"], 0)

    def test_missing_native_and_open_local_policy_refused(self):
        for policy in (None, {}, dict(schema="native", trustMode="native", maximumReceiptAgeNs=1),
                dict(fixture()[0]["credentialReleaseTrust"], extra=True)):
            payload, launch, runtime = fixture()
            payload["credentialReleaseTrust"] = policy
            with self.assertRaises(ValueError): check(payload, launch, runtime)

    def test_each_zero_predecessor_floor_join_required(self):
        for target, field, value in ((0, "generationSequence", 1), (1, "sequence", 1),
                (0, "generationPredecessorDigest", PIN), (1, "predecessorDigest", PIN),
                (0, "generationMinimumRollbackSequence", 1), (1, "minimumRollbackSequence", 1),
                (0, "generationSequence", False), (1, "minimumRollbackSequence", False)):
            values = fixture(); values[target][field] = value
            with self.assertRaises(ValueError): check(*values)

    def test_runtime_sequence_must_equal_actual_generation(self):
        values = fixture(); values[2]["generationSequence"] = 1
        with self.assertRaises(ValueError): check(*values)

    def test_later_native_generation_rules_unchanged(self):
        payload, launch, runtime = fixture()
        payload.pop("credentialReleaseTrust")
        payload.update(generationSequence=1, generationPredecessorDigest=PIN)
        launch.update(sequence=1, predecessorDigest=PIN)
        runtime["generationSequence"] = 1
        self.assertEqual(check(payload, launch, runtime), runtime)
        launch["predecessorDigest"] = None
        with self.assertRaises(ValueError): check(payload, launch, runtime)

    def test_transition_wire_zero_is_syntax_not_generation_admission(self):
        operation = "webauthn.registration.finalize"
        for mapper in (custody_wire._pins, request_wire._pins, response_wire._scope):
            self.assertEqual(mapper(PIN, 0, PIN, operation), (PIN, 0, PIN, operation))
        payload, launch, runtime = fixture()
        payload.pop("credentialReleaseTrust")
        with self.assertRaises(ValueError): check(payload, launch, runtime)

    def test_transition_wire_negative_and_noninteger_sequences_refused(self):
        for mapper in (custody_wire._pins, request_wire._pins, response_wire._scope):
            for sequence in (-1, False, 0.0, "0"):
                with self.subTest(mapper=mapper.__module__, sequence=sequence):
                    with self.assertRaises(ValueError):
                        mapper(PIN, sequence, PIN, "webauthn.registration.finalize")

    def test_signed_zero_custody_controls_require_exact_independent_scope(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        operation = "webauthn.registration.finalize"
        for relay in (False, True):
            work = _ValidationWork(QueryReadValidationLimits())
            unsigned = dict(schema=custody_wire._schema(relay),
                sourceRevision=custody_wire.authority.SOURCE_REVISION,
                purpose=custody_wire.RELAY_PURPOSE if relay else custody_wire.INTENT_PURPOSE,
                configurationDigest=PIN, generationSequence=0, generationDigest=PIN,
                operation=operation, retainedRecordDigest=PIN,
                issuedAtEpochNs=1, expiresAtEpochNs=2)
            for name in (("intent",) if relay else custody_wire._BODY_NAMES):
                unsigned[name + "BytesDigest"] = PIN
                unsigned[name + "ByteCount"] = 2
            original = custody_wire._sign_control(unsigned, relay=relay,
                private_key=private, public_key=public, work=work)
            value, signature, unsigned_wire = custody_wire._read_control(original, relay=relay, work=work)
            custody_wire._signature(signature, unsigned_wire, relay=relay, public_key=public, work=work)
            expected = dict(configuration_digest=PIN, generation_sequence=0,
                generation_digest=PIN, operation=operation)
            custody_wire._bind_control(value, **expected, work=work)
            for field, other in (("generation_sequence", 1),
                    ("generation_digest", "sha256:" + "2" * 64),
                    ("configuration_digest", "sha256:" + "2" * 64),
                    ("operation", "webauthn.trust.stage")):
                with self.subTest(relay=relay, field=field):
                    with self.assertRaises(ValueError):
                        custody_wire._bind_control(value, **dict(expected, **{field: other}), work=work)


if __name__ == "__main__": unittest.main()
