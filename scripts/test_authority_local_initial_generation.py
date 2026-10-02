#!/usr/bin/env python3
"""Pure initial-generation consistency, not root/cohort/launch admission."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_revocation_configuration as configuration
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

PIN = "sha256:" + "1" * 64


def fixture():
    roles = {role: dict(measurementDigest=PIN, responseSigningSpkiDigest=PIN)
        for role in configuration._ROLE_NAMES}
    pins = {role: PIN for role in roles}
    payload = dict(credentialReleaseTrust=dict(
        schema="serverware.trustedHostLocalCredentialReleaseTrust/v1",
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


if __name__ == "__main__": unittest.main()
