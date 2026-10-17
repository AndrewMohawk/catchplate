#!/usr/bin/env python3
"""Synthetic public-signature controls, never KMS or live pilot evidence.

All metadata, hashes, processes, credentials and images are in-memory fixtures.
Provider/ciphertext labels are not encrypted material or attestation results.
Real deterministic test-key signatures authenticate C9, assignment and prior
authorizations; no live signer entrypoint, owner, file, KMS or service is used.
The inherited assignment omits unrelated operational policy: passing these
controls is not full native assignment, provisioning or provenance acceptance.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from catchplate import native_pilot_launch_authorization_profile as profile
from catchplate import native_pilot_encrypted_authority as encrypted
from catchplate import native_pilot_verifier_authority as verifier
from catchplate import native_pilot_closure_authority as closure
from test_native_pilot_key_authorizations import (ROLES, public_keys, fixture as key_fixture_input,
    build as key_input, expected_payload as key_payload, signed_result as key_result, clocks, key_root)
from test_native_pilot_native_deliveries import bind_set, result_for
from test_native_pilot_generation_scope import NOW, encoded, key_fixture, signed_message
from test_native_pilot_closure_set import canonical, sha, synthetic, frame

EXPECTED_JOBS = tuple((operation, role) for role in ROLES for operation in
    (("closure", "request-commitment", "encrypted-delivery", "verifier-transport") if role == "commitRequest"
     else ("closure", "encrypted-delivery", "verifier-transport")))
DOMAINS = {"closure": "catchplate.nativeCustodyClosureAssignment.signature/v3",
    "request-commitment": "catchplate.nativeShadowRequestCommitmentAssignment.signature/v2",
    "verifier-transport": "catchplate.nativeShadowVerifierTransport.signature/v1"}


def transport(role):
    extended = role == "commitRequest"
    return {"apiVersion": "catchplate.nativeShadowKeyKmsTransport/v" + ("2" if extended else "1"),
        "kmsParentPort": 10443, "kmsKeyId": "synthetic-only-not-a-provisioned-kms-key",
        "ciphertextBlobSha256": synthetic("unprovisioned-kms-ciphertext/" + role),
        "encryptionContext": {"catchplatePurpose": "native-shadow-local-role-keys-and-request-commitment/v2"
            if extended else "native-shadow-local-role-keys/v1"}, "kekSha256": synthetic("unprovisioned-kek/" + role),
        "helperImage": {"profile": "sealed-memfd-squashfs-v1", "imagePath": "/opt/catchplate/native-shadow-key-delivery-runtime.squashfs",
            **{name: synthetic("synthetic-key-helper/" + name) for name in ("imageSha256", "interpreterSha256", "helperSha256")}},
        "encryptedInventorySha256": synthetic("unprovisioned-encrypted-inventory/" + role)}


def policy_fragment():
    interval = {"issuedAtUnixNanos": NOW - 500_000_000, "expiresAtUnixNanos": NOW + 500_000_000}
    value = {"apiVersion": "catchplate.nativePilotLaunchAuthorizationPolicy/v1", "endpoints": {}}
    for role in ROLES:
        value["endpoints"][role] = {"closure": dict(interval),
            "encryptedDelivery": dict(interval, transportOriginal=canonical(transport(role)).decode("ascii")),
            "verifierTransport": dict(interval, parentPort=11443)}
    value["endpoints"]["commitRequest"]["requestCommitment"] = {
        "issuedAtUnixNanos": NOW - 750_000_000, "expiresAtUnixNanos": NOW + 750_000_000,
        "requestCommitmentOriginal": canonical({"keyId": synthetic("independent-request-key"), "keyEpoch": 7,
            "secretSha256": synthetic("public-commitment-to-unprovisioned-test-secret")}).decode("ascii")}
    return value


def set_credentials(f, role, credentials):
    value = json.loads(f["delivery_inputs"][role]); payload = json.loads(value["payloadOriginal"])
    payload["credentials"] = credentials
    value["payloadOriginal"] = canonical(payload).decode("ascii")
    raw = canonical(value)
    signed = result_for(f, role, raw)["original"].encode("ascii")
    f["delivery_inputs"][role], f["deliveries"][role] = raw, signed
    f["guests"][role]["deliverySha256"] = sha(signed)


def fixture():
    f = key_fixture_input()
    envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
    envelope["payload"]["observationWindow"].update(requestCommitmentKeyId=synthetic("independent-request-key"), requestCommitmentKeyEpoch=7)
    f["recipe_originals"]["assignmentOriginal"] = canonical(envelope).decode("ascii")
    bind_set(f, json.loads(f["recipe_originals"]["closureSetOriginal"]))
    for role in ROLES:
        credentials = copy.deepcopy(json.loads(f["deliveries"][role])["payload"]["credentials"])
        credentials.append({"name": "shadow-encrypted-role-inventory", "original": {
            "path": "/etc/catchplate/synthetic-ciphertext-" + role + ".json",
            "sha256": transport(role)["encryptedInventorySha256"]}, "length": 256, "signing": None})
        set_credentials(f, role, credentials)
    return f


def pair(f, role):
    first = key_input(f, "role-keys", role)
    first_raw, _ = key_result(key_payload(f, "role-keys", role), "role-keys")
    second = key_input(f, "admission", role, role_key_raw=first_raw)
    second_raw, _ = key_result(key_payload(f, "admission", role, role_key_raw=first_raw), "admission")
    return dict(zip(("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal"),
        (raw.decode("ascii") for raw in (first, first_raw, second, second_raw)), strict=True))


def expected(f, selected, pair_value, operation, role):
    key = json.loads(pair_value["roleKeyOriginal"])["payload"]
    admitted = json.loads(pair_value["admissionOriginal"])["payload"]
    row = selected["endpoints"][role]
    field = {"closure": "closure", "request-commitment": "requestCommitment",
        "encrypted-delivery": "encryptedDelivery", "verifier-transport": "verifierTransport"}[operation]
    common = {name: key[name] for name in ("guest", "assignmentPayloadSha256", "trustCheckpointId",
        "revocationGeneration", "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256")}
    common.update({name: row[field][name] for name in ("issuedAtUnixNanos", "expiresAtUnixNanos")})
    if operation != "closure":
        common["keyAuthorizationSha256"] = sha(pair_value["roleKeyOriginal"].encode("ascii"))
    if operation == "request-commitment":
        return {**common, "apiVersion": "catchplate.nativeShadowRequestCommitmentAssignment/v2",
            "purpose": "native-shadow-request-and-ingress-commitments",
            "requestCommitment": json.loads(row[field]["requestCommitmentOriginal"])}
    common.update(assignmentId=key["assignmentId"], assignmentRevision=key["assignmentRevision"])
    if operation == "closure":
        selected_set = json.loads(f["recipe_originals"]["closureSetOriginal"])
        manifest = next(member["manifest"] for member in selected_set["members"] if member["role"] == role)
        return {**common, "apiVersion": "catchplate.nativeCustodyClosureAssignment/v3",
            "purpose": "shadow-custody-closure-set-member", "profile": "native-multi-guest-closure-set-v1",
            "manifestSha256": manifest["manifestSha256"], "guestRole": role,
            **{name: selected_set[name] for name in ("setRootSha256", "seccompSetRootSha256")},
            "leafSha256": frame("catchplate.nativeCustodyExecutionClosureSetLeaf/v1", [role, manifest])}
    common.update(fullKeySetRootSha256=key["fullKeySetRootSha256"], challengeBase64url=key["challengeBase64url"])
    if operation == "verifier-transport":
        public = public_keys()[-2]
        return {**common, "apiVersion": "catchplate.nativeShadowVerifierTransportAssignment/v1",
            "purpose": "public-shadow-nitro-verification", "parentPort": row[field]["parentPort"],
            **{"verifier" + name[0].upper() + name[1:]: public[name]
                for name in ("keyId", "keySpkiSha256", "keyMaterialSha256")}}
    return {**common, "apiVersion": "catchplate.nativeShadowEncryptedKeyDeliveryAssignment/v" + ("2" if role == "commitRequest" else "1"),
        "purpose": "kms-recipient-shadow-local-keys-and-request-commitment" if role == "commitRequest" else "kms-recipient-shadow-local-keys",
        "localKeySetRootSha256": admitted["localKeySetRootSha256"], "transport": json.loads(row[field]["transportOriginal"])}


def signed(f, operation, role, payload, *, prior=None, key=None, domain=None):
    domain = domain or ("catchplate.nativeShadowEncryptedKeyDelivery.signature/v" + ("2" if role == "commitRequest" else "1")
        if operation == "encrypted-delivery" else DOMAINS[operation])
    signature = encoded((key or key_fixture("custody-supervisor-capability")[0]).sign(signed_message(domain, payload)))
    authorization = {"payload": payload, "signature": signature}
    if operation == "request-commitment":
        value = authorization
    elif operation == "closure":
        selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
        value = {"apiVersion": "catchplate.nativeCustodyClosure/v3", "closureSet": selected,
            "manifest": next(member["manifest"] for member in selected["members"] if member["role"] == role), "authorization": authorization}
    else:
        value = {"apiVersion": "catchplate.nativeShadowVerifierTransport/v1" if operation == "verifier-transport"
            else "catchplate.nativeShadowEncryptedKeyDelivery/v" + ("2" if role == "commitRequest" else "1"), "authorization": authorization}
        if operation == "encrypted-delivery" and role == "commitRequest":
            value["requestCommitment"] = json.loads(prior)
    raw = canonical(value)
    return raw, {"original": raw.decode("ascii"), "sha256": sha(raw)}


class LaunchAuthorizationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture(); cls.selected = policy_fragment()
        cls.pairs = {role: pair(cls.f, role) for role in ROLES}
        cls.cases = {}

    def case(self, operation, role):
        cache = (operation, role)
        if cache not in self.cases:
            prior = self.case("request-commitment", role)[2] if cache == ("encrypted-delivery", "commitRequest") else None
            raw = profile.build(operation, role, fragment=self.selected, pair_context=self.pairs[role],
                prior_authorization_originals={} if prior is None else {"request-commitment": prior}, **clocks(self.f))
            payload = expected(self.f, self.selected, self.pairs[role], operation, role)
            output, result = signed(self.f, operation, role, payload, prior=prior)
            self.cases[cache] = raw, payload, output, result
        return self.cases[cache]

    def test_all_thirty_one_preparations_and_independent_signed_results(self):
        self.assertEqual(profile.JOBS, EXPECTED_JOBS); self.assertEqual(len(profile.JOBS), 31)
        for operation, role in EXPECTED_JOBS:
            with self.subTest(operation=operation, role=role):
                raw, payload, output, result = self.case(operation, role)
                prepared = profile.prepare_input(operation, role, raw, **clocks(self.f))
                self.assertEqual(prepared["payload"], payload)
                self.assertEqual(prepared["window"], self.f["window"] if operation in ("closure", "verifier-transport")
                    else self.f["guests"][role])
                self.assertEqual(prepared["deadline"], int(self.f["window"]["startupDeadlineBoottimeNs"]))
                self.assertEqual(profile.checked_result(operation, role, raw, result, **clocks(self.f)), output)

    def test_closed_policy_versions_roles_fields_ports_and_intervals(self):
        checked = profile.validate_policy(self.selected)
        checked["endpoints"][ROLES[0]]["closure"]["expiresAtUnixNanos"] += 1
        self.assertNotEqual(checked, self.selected)
        for change in ("api", "role", "extra", "null", "port", "bool", "interval"):
            value = copy.deepcopy(self.selected)
            if change == "api": value["apiVersion"] += "-unknown"
            elif change == "role": value["endpoints"]["bridge"] = value["endpoints"][ROLES[0]]
            elif change == "extra": value["endpoints"][ROLES[0]]["approved"] = True
            elif change == "null": value["endpoints"][ROLES[0]]["closure"] = None
            elif change == "port": value["endpoints"][ROLES[0]]["verifierTransport"]["parentPort"] = 1023
            elif change == "bool": value["endpoints"][ROLES[0]]["closure"]["issuedAtUnixNanos"] = True
            else: value["endpoints"][ROLES[0]]["closure"]["expiresAtUnixNanos"] = NOW - 500_000_000
            with self.subTest(change=change), self.assertRaises(ValueError): profile.validate_policy(value)

    def test_signed_pair_tampering_cross_role_and_unsigned_inputs_reject(self):
        raw, _, _, _ = self.case("encrypted-delivery", "retrieval")
        for change in ("signature", "other-role", "extra", "null"):
            value = json.loads(raw)
            if change == "signature":
                prior = json.loads(value["roleKeyOriginal"]); prior["signature"] = encoded(bytes(64))
                value["roleKeyOriginal"] = canonical(prior).decode("ascii")
            elif change == "other-role": value["role"] = "persistence"
            elif change == "extra": value["payloadOriginal"] = "{}"
            else: value["admissionOriginal"] = None
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                encrypted.prepare_input("delivery", "retrieval", canonical(value), **clocks(self.f))

    def test_transport_profile_inventory_pin_and_no_plaintext_slots(self):
        raw, _, _, _ = self.case("encrypted-delivery", "retrieval")
        for change in ("version", "hash", "helper", "secret"):
            value = json.loads(raw); selected = json.loads(value["transportOriginal"])
            if change == "version": selected = transport("commitRequest")
            elif change == "hash": selected["encryptedInventorySha256"] = synthetic("different-inventory")
            elif change == "helper": selected["helperImage"]["imagePath"] = "/tmp/not-approved.squashfs"
            else: selected["secretBase64url"] = encoded(bytes(32))
            value["transportOriginal"] = canonical(selected).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                encrypted.prepare_input("delivery", "retrieval", canonical(value), **clocks(self.f))
        f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.f.items()}
        credentials = copy.deepcopy(json.loads(f["deliveries"]["retrieval"])["payload"]["credentials"])
        credentials.append({"name": "shadow-key-custody-ledger-append", "original": {
            "path": "/etc/catchplate/synthetic-forbidden-plaintext", "sha256": synthetic("not-real-key")}, "length": 32, "signing": None})
        set_credentials(f, "retrieval", credentials)
        with self.assertRaises(ValueError):
            profile.build("encrypted-delivery", "retrieval", fragment=self.selected, pair_context=pair(f, "retrieval"),
                prior_authorization_originals={}, **clocks(f))

    def test_original_pair_intervals_and_guest_boot_deadline_cannot_extend(self):
        for operation in ("encrypted-delivery", "verifier-transport"):
            raw, _, _, _ = self.case(operation, "retrieval")
            for field, value in (("issuedAtUnixNanos", NOW - 1_000_000_001), ("expiresAtUnixNanos", NOW + 1_000_000_001)):
                changed = json.loads(raw); changed[field] = value
                with self.assertRaises(ValueError): profile.prepare_input(operation, "retrieval", canonical(changed), **clocks(self.f))
            for clock in ({"now_boottime_ns": int(self.f["window"]["startupDeadlineBoottimeNs"])},
                    {"boot": (encoded(b"different-boot16"), 4, 5)}, {"now_unix_ns": NOW + 1_000_000_001}):
                with self.assertRaises(ValueError): profile.prepare_input(operation, "retrieval", raw, **(clocks(self.f) | clock))

    def test_request_commitment_is_separate_fixed_role_assignment_bound(self):
        raw, payload, _, _ = self.case("request-commitment", "commitRequest")
        self.assertEqual(len(payload), 13)
        for field, invalid in (("keyId", synthetic("other-request-key")), ("keyEpoch", 8), ("secretSha256", "sha256:" + "0" * 64)):
            value = json.loads(raw); descriptor = json.loads(value["requestCommitmentOriginal"]); descriptor[field] = invalid
            value["requestCommitmentOriginal"] = canonical(descriptor).decode("ascii")
            with self.assertRaises(ValueError): encrypted.prepare_input("request-commitment", "commitRequest", canonical(value), **clocks(self.f))
        with self.assertRaises(ValueError): encrypted.prepare_input("request-commitment", "retrieval", raw, **clocks(self.f))

    def test_commit_delivery_requires_exact_actual_prior_hmac_and_policy(self):
        raw, _, _, _ = self.case("encrypted-delivery", "commitRequest")
        for change in ("missing", "null", "unsigned", "signature", "legacy"):
            value = json.loads(raw)
            if change == "missing": value.pop("requestCommitmentOriginal")
            elif change == "null": value["requestCommitmentOriginal"] = None
            else:
                prior = json.loads(value["requestCommitmentOriginal"])
                if change == "unsigned": prior.pop("signature")
                elif change == "signature": prior["signature"] = encoded(bytes(64))
                else: prior["payload"]["apiVersion"] = "catchplate.nativeShadowRequestCommitmentAssignment/v1"
                value["requestCommitmentOriginal"] = canonical(prior).decode("ascii")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                encrypted.prepare_input("delivery", "commitRequest", canonical(value), **clocks(self.f))
        prior_payload = copy.deepcopy(self.case("request-commitment", "commitRequest")[1])
        prior_payload["requestCommitment"]["secretSha256"] = synthetic("different-independently-signed-secret")
        prior, _ = signed(self.f, "request-commitment", "commitRequest", prior_payload)
        with self.assertRaises(ValueError):
            profile.build("encrypted-delivery", "commitRequest", fragment=self.selected, pair_context=self.pairs["commitRequest"],
                prior_authorization_originals={"request-commitment": prior}, **clocks(self.f))

    def test_result_signature_domain_hash_payload_and_signer_are_exact(self):
        for operation, role in (("closure", "retrieval"), ("request-commitment", "commitRequest"),
                ("encrypted-delivery", "retrieval"), ("verifier-transport", "retrieval")):
            raw, payload, _, result = self.case(operation, role)
            for key in (self.f["key"], key_fixture("custody-attestation-verifier")[0]):
                _, wrong = signed(self.f, operation, role, payload, key=key)
                with self.assertRaises(InvalidSignature): profile.checked_result(operation, role, raw, wrong, **clocks(self.f))
            _, wrong = signed(self.f, operation, role, payload, domain="catchplate.synthetic-wrong-domain/v1")
            with self.assertRaises(InvalidSignature): profile.checked_result(operation, role, raw, wrong, **clocks(self.f))
            for wrong in (result | {"sha256": synthetic("bad-result")}, result | {"approved": True}):
                with self.assertRaises(ValueError): profile.checked_result(operation, role, raw, wrong, **clocks(self.f))
            changed = copy.deepcopy(payload); changed["expiresAtUnixNanos"] -= 1
            _, wrong = signed(self.f, operation, role, changed)
            with self.assertRaises(ValueError): profile.checked_result(operation, role, raw, wrong, **clocks(self.f))

    def test_closure_keeps_both_set_roots_and_exact_role_leaf(self):
        raw, payload, _, _ = self.case("closure", "retrieval")
        selected = json.loads(self.f["recipe_originals"]["closureSetOriginal"])
        self.assertEqual(payload["setRootSha256"], selected["setRootSha256"])
        self.assertEqual(payload["seccompSetRootSha256"], selected["seccompSetRootSha256"])
        self.assertNotEqual(payload["manifestSha256"], selected["members"][-1]["manifest"]["manifestSha256"])
        for field in ("setRootSha256", "seccompSetRootSha256", "leafSha256", "manifestSha256"):
            value = json.loads(raw); altered = json.loads(value["payloadOriginal"]); altered[field] = synthetic("wrong-" + field)
            value["payloadOriginal"] = canonical(altered).decode("ascii")
            with self.assertRaises(ValueError): closure.prepare_input(canonical(value), **clocks(self.f))

    def test_verifier_is_assigned_distinct_key_not_supervisor_or_provider(self):
        raw, payload, _, _ = self.case("verifier-transport", "retrieval")
        self.assertEqual(payload["verifierKeyId"], public_keys()[-2]["keyId"])
        self.assertNotEqual(payload["verifierKeyId"], payload["signingKeyId"])
        self.assertEqual(payload["fullKeySetRootSha256"], key_root(public_keys()))
        changed = copy.deepcopy(payload); changed["verifierKeyId"] = payload["signingKeyId"]
        _, result = signed(self.f, "verifier-transport", "retrieval", changed)
        with self.assertRaises(ValueError): verifier.checked_result("retrieval", raw, result, **clocks(self.f))


if __name__ == "__main__":
    unittest.main(verbosity=2)
