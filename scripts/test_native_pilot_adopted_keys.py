#!/usr/bin/env python3
"""Synthetic hot12 public authorizations; no owner, KMS or native service."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_encrypted_authority as encrypted
from serverware import native_pilot_verifier_authority as verifier
from serverware import native_pilot_adopted_commands as commands
from serverware import native_pilot_peer_preparation as peers
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_shadow_proof_cohort_cleanup as cleanup
from test_native_pilot_adopted_closure import fixture
from test_native_pilot_key_authorizations import build, clocks, expected_payload, signed_result
from test_native_pilot_launch_authorizations import transport, set_credentials
from test_native_pilot_generation_scope import NOW, key_fixture, encoded, signed_message
from test_native_pilot_closure_set import canonical, sha
from test_native_pilot_peer_preparation import fixture as peer_fixture

ROLE = "publicationReconciliation"


def pair(f):
    first = build(f, "role-keys", ROLE, adopted=True)
    first_raw, _ = signed_result(expected_payload(f, "role-keys", ROLE), "role-keys")
    second = build(f, "admission", ROLE, role_key_raw=first_raw, adopted=True)
    second_raw, _ = signed_result(expected_payload(f, "admission", ROLE, role_key_raw=first_raw), "admission")
    return first, first_raw, second, second_raw


def paired_input(api, originals):
    return {"apiVersion": api, "role": ROLE,
        **dict(zip(verifier.PAIR_FIELDS, (raw.decode("ascii") for raw in originals), strict=True)),
        "issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}


class AdoptedKeyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()

    def setUp(self):
        self.f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.source.items()}

    def test_signed_pair_binds_publication_guest_and_hot12_leaf(self):
        originals = pair(self.f)
        actual = keys.admitted_adopted_pair(ROLE, *originals, **clocks(self.f))
        self.assertEqual(actual["expectedScope"]["guest"], self.f["guests"][ROLE])
        self.assertEqual(actual["authorization"]["payload"]["localRoles"], ["custody-publication-reconciliation"])
        self.assertEqual(actual["expectedScope"]["admissionAuthorizationSha256"], sha(originals[3]))

    def test_old_pair_and_policy_do_not_accept_adopted_inputs(self):
        with self.assertRaises(ValueError):
            keys.admitted_pair(ROLE, *pair(self.f), **clocks(self.f))
        with self.assertRaises(ValueError):
            keys.validate_policy(self.f["policy"])
        first = json.loads(pair(self.f)[0]); first["apiVersion"] = keys.API
        with self.assertRaises(ValueError):
            keys.prepare_input("role-keys", ROLE, canonical(first), **clocks(self.f))

    def test_c9_and_prior_key_payload_are_not_replaceable(self):
        originals = pair(self.f)
        changed = json.loads(originals[0]); signed = json.loads(changed["deliveryOriginal"])
        signed["payload"]["uid"] += 1
        changed["deliveryOriginal"] = canonical(signed).decode("ascii")
        with self.assertRaises(ValueError):
            keys.prepare_input("role-keys", ROLE, canonical(changed), **clocks(self.f))
        bad = json.loads(originals[1]); bad["payload"]["guest"]["uid"] += 1
        with self.assertRaises(ValueError):
            keys.admitted_adopted_pair(ROLE, originals[0], canonical(bad), originals[2], originals[3], **clocks(self.f))

    def test_verifier_successor_keeps_native_output(self):
        raw = canonical(paired_input(verifier.ADOPTED_API, pair(self.f)) | {"parentPort": 11443})
        context = verifier.prepare_input(ROLE, raw, **clocks(self.f))
        self.assertEqual(context["payload"]["apiVersion"], "serverware.nativeShadowVerifierTransportAssignment/v1")
        seed = key_fixture("custody-supervisor-capability")[0]
        result = canonical({"apiVersion": "serverware.nativeShadowVerifierTransport/v1", "authorization": {
            "payload": context["payload"], "signature": encoded(seed.sign(signed_message(verifier.DOMAIN, context["payload"])))}})
        self.assertEqual(verifier.checked_result(ROLE, raw, {"original": result.decode("ascii"), "sha256": sha(result)}, **clocks(self.f)), result)
        legacy = json.loads(raw); legacy["apiVersion"] = verifier.API
        with self.assertRaises(ValueError):
            verifier.prepare_input(ROLE, canonical(legacy), **clocks(self.f))

    def test_encrypted_successor_authenticates_c9_ciphertext_pin(self):
        credentials = copy.deepcopy(json.loads(self.f["deliveries"][ROLE])["payload"]["credentials"])
        credentials.append({"name": "shadow-encrypted-role-inventory", "original": {
            "path": "/etc/serverware/synthetic-publication-ciphertext.json",
            "sha256": transport(ROLE)["encryptedInventorySha256"]}, "length": 256, "signing": None})
        set_credentials(self.f, ROLE, credentials)
        value = paired_input(encrypted.ADOPTED_API, pair(self.f)) | {
            "operation": "delivery", "transportOriginal": canonical(transport(ROLE)).decode("ascii")}
        context = encrypted.prepare_input("delivery", ROLE, canonical(value), **clocks(self.f))
        self.assertEqual(context["payload"]["transport"], transport(ROLE))
        value["apiVersion"] = encrypted.API
        with self.assertRaises(ValueError):
            encrypted.prepare_input("delivery", ROLE, canonical(value), **clocks(self.f))

    def test_packaged_selector_rejects_old_input_before_key(self):
        first = pair(self.f)[0]
        context = commands.prepare_input(ROLE, "role-keys", first, **clocks(self.f))
        self.assertEqual(context["deadline"], int(self.f["window"]["startupDeadlineBoottimeNs"]))
        value = json.loads(first); value["apiVersion"] = keys.API
        with self.assertRaises(ValueError):
            commands.prepare_input(ROLE, "role-keys", canonical(value), **clocks(self.f))

    def test_cohort_adds_one_owned_child_not_foreign_driver(self):
        config = cohort.configuration(self.f["owner_configuration_raw"])
        self.assertEqual(cohort.roles(config), cohort.ENDPOINT_ROLES + (ROLE,))
        self.assertNotIn("bridge", cohort.roles(config))
        self.assertEqual(cohort.release_domain(config), b"serverware.nativeShadowProofCohortRelease.signature/v7\0")
        self.assertEqual(cleanup._api("Terminal", config), "serverware.nativeShadowProofCohortTerminal/v7")
        changed = copy.deepcopy(config); del changed[ROLE + "Configuration"]
        with self.assertRaises(ValueError):
            cohort.configuration(canonical(changed))

    def test_peer_successor_is_eleven_and_old_wire_stays_ten(self):
        value = peer_fixture("native-endpoints")
        row = copy.deepcopy(value["peers"]["retrieval"])
        row["processId"] += 30; row["pidfd"]["inode"] += 30
        value["apiVersion"] = peers.ADOPTED_API; value["peers"][ROLE] = row
        self.assertEqual(peers.shape(canonical(value)), value)
        value["apiVersion"] = peers.API
        with self.assertRaises(ValueError):
            peers.shape(canonical(value))


if __name__ == "__main__":
    unittest.main()
