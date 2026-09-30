#!/usr/bin/env python3
"""Synthetic public-original controls, not fleet or custody attestation evidence.

Deterministic in-memory test keys sign the real existing envelope preimages.
The generation-trust fixture contains only the two purposes under test; it is
not complete native generation trust. Unrelated assignment fields retain the
existing fixture's empty values. No live owner, issuer entrypoint, quote,
collateral, protected file, DB/app import, service or network is exercised.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_runtime_evidence as evidence
from test_native_pilot_closure_set import canonical, merkle_fixture, sha, synthetic
from test_native_pilot_generation_scope import NOW, encoded, fixture as scope_fixture, key_fixture, signed_message

ASSIGNMENT_DOMAIN = "serverware.policyShadowAssignment/v2"
RECEIPT_DOMAIN = "serverware.policyRuntimeAttestation/v2"
MEMBER_KEYS = ("teeAttestation", "ingressSigning", "activeDecisionSigning", "shadowSigning")
RUNTIME_FIELDS = ("instanceId", "spiffeId", "bootIdSha256", "teePlatform", "teeEvidenceSha256",
    "teeMeasurementSha256", "teeAttestationKeyId", "teeAttestationKeySpkiSha256", "ingressSigningKeyId",
    "ingressSigningKeySpkiSha256", "activeDecisionSigningKeyId", "activeDecisionSigningKeySpkiSha256",
    "shadowSigningKeyId", "shadowSigningKeySpkiSha256")


def signed(payload, *, domain, kind, label):
    key, public = key_fixture(label)
    return {"apiVersion": domain, "kind": kind,
        "canonicalProfile": "serverware.canonicalJson/ascii-integer-v1", "signatureDomain": domain,
        "payload": payload, "payloadSha256": sha(canonical(payload)), "signatureAlgorithm": "Ed25519",
        "signingKeyId": public["keyId"], "signingKeySpkiSha256": public["keySpkiSha256"],
        "signature": encoded(key.sign(signed_message(domain, payload)))}


def store_trust(f):
    raw = canonical(f["trust"])
    f["fragment"].update(generationTrustOriginal=raw.decode("ascii"), generationTrustSha256=sha(raw))


def store_receipt(f, *, label="runtime-evidence-startup"):
    envelope = signed(f["receipt"], domain=RECEIPT_DOMAIN, kind="PolicyRuntimeAttestation", label=label)
    f["fragment"]["receiptOriginal"] = canonical(envelope).decode("ascii")


def store_assignment(f, *, rehash=False):
    if rehash:
        f["assignment"]["fleet"]["membershipRootSha256"] = merkle_fixture(
            [sha(canonical(member)) for member in f["assignment"]["fleet"]["members"]])
    f["arguments"]["assignment_original"] = canonical(signed(f["assignment"], domain=ASSIGNMENT_DOMAIN,
        kind="PolicyShadowAssignment", label="assignment"))


def fixture(*, assignment_original=None):
    """Return synthetic originals and independent expected RuntimeIdentity14."""
    if assignment_original is None:
        _, args, _ = scope_fixture()
        assignment_original = args["recipe_originals"]["assignmentOriginal"].encode("ascii")
    assignment = json.loads(assignment_original)["payload"]
    members = []
    for index in range(2):
        member = {"instanceId": "synthetic-fleet-" + str(index),
            "spiffeId": "spiffe://example.test/runtime/fleet-" + str(index),
            "bootIdSha256": synthetic("fleet-boot-not-custody-boot/" + str(index)),
            "teePlatform": "aws-nitro-enclave", "teeMeasurementSha256": synthetic("fleet-measurement/" + str(index))}
        for prefix in MEMBER_KEYS:
            public = key_fixture("runtime-evidence/" + str(index) + "/" + prefix)[1]
            member[prefix + "KeyId"] = public["keyId"]
            member[prefix + "KeySpkiSha256"] = public["keySpkiSha256"]
        members.append(member)
    fleet = {"fleetId": synthetic("runtime-evidence-fleet"), "membershipRevision": 7,
        "members": members, "membershipRootSha256": merkle_fixture([sha(canonical(member)) for member in members])}
    assignment["fleet"] = fleet
    keys = []
    for role, label, domain in (("assignment-authority", "assignment", ASSIGNMENT_DOMAIN),
            ("runtime-attestation-authority", "runtime-evidence-startup", RECEIPT_DOMAIN)):
        key, public = key_fixture(label)
        keys.append({"role": role, "signatureDomains": [domain], "keyId": public["keyId"],
            "keySpkiSha256": public["keySpkiSha256"], "publicKeyPem": key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            "notBeforeUnixNanos": NOW - 20_000_000_000, "notAfterUnixNanos": NOW + 90_000_000_000})
    trust = {"apiVersion": "serverware.policyShadowGenerationTrust/v1", "trustClass": "production-pinned",
        "selfSigned": False, "manifestRevision": 1, "issuedAtUnixNanos": NOW - 10_000_000_000,
        "expiresAtUnixNanos": NOW + 60_000_000_000, "revocationGeneration": 1,
        "revocationRootSha256": synthetic("runtime-evidence-revocation"),
        "assignmentSigningKeyId": keys[0]["keyId"], "assignmentSigningKeySpkiSha256": keys[0]["keySpkiSha256"],
        "startupAttestationSigningKeyId": keys[1]["keyId"], "startupAttestationSigningKeySpkiSha256": keys[1]["keySpkiSha256"],
        "keys": keys, "compiler": {name: synthetic("compiler/" + name) for name in (
            "policyCompilerBinarySha256", "policyCompilerConfigurationSha256", "policySchemaSha256",
            "adapterSchemaSha256", "policySemanticModelSha256", "policyPlanSchemaSha256", "requestFactsSchemaSha256")}}
    for name in ("runtimeAttestationPolicySha256", "runtimeAttestationVerifierSigningKeyId",
            "runtimeAttestationVerifierSigningKeySpkiSha256", "webauthnVerificationPolicySha256",
            "webauthnVerifierSigningKeyId", "webauthnVerifierSigningKeySpkiSha256",
            "publicationSigningKeyId", "publicationSigningKeySpkiSha256", "publicationReplayStoreSha256"):
        trust[name] = synthetic("unused-purpose/" + name)
    member = members[1]
    record = {"fleetId": fleet["fleetId"], "membershipRevision": 7, "memberOrdinal": 2,
        "memberId": sha(b"serverware.policyShadowFleetMember/v1\0" + canonical(member)),
        **{name: member[name] for name in ("instanceId", "bootIdSha256", "spiffeId", "teePlatform", "teeMeasurementSha256")},
        "teeEvidenceSha256": synthetic("signed-startup-evidence-reference-not-a-quote"),
        "roleKeysDigest": synthetic("signed-existing-startup-role-keys-digest")}
    f = {"assignment": assignment, "trust": trust,
        "receipt": {"issuedAtEpochNs": NOW - 5_000_000_000, "expiresAtEpochNs": NOW + 30_000_000_000, "record": record},
        "fragment": {"instanceId": member["instanceId"],
            "issuer": {name: keys[1][name] for name in ("keyId", "keySpkiSha256")}},
        "arguments": {"issued_at_unix_ns": NOW - 1_000_000_000,
            "expires_at_unix_ns": NOW + 1_000_000_000, "now_unix_ns": NOW},
        "expected": copy.deepcopy(member) | {"teeEvidenceSha256": record["teeEvidenceSha256"]}}
    store_trust(f); store_receipt(f); store_assignment(f)
    return f


def derive(f, **changes):
    return evidence.runtime(f["fragment"], **(f["arguments"] | changes))


class RuntimeEvidenceTests(unittest.TestCase):
    def refused(self, f, **changes):
        with self.assertRaises((ValueError, InvalidSignature)):
            derive(f, **changes)

    def test_exact_existing_runtime14_from_second_authenticated_member(self):
        f = fixture()
        self.assertEqual(derive(f), f["expected"])
        self.assertEqual(set(derive(f)), set(RUNTIME_FIELDS))
        checked = evidence.validate_policy(f["fragment"])
        checked["issuer"]["keyId"] = synthetic("copy-only")
        self.assertNotEqual(checked, f["fragment"])

    def test_closed_originals_and_independent_trust_pin(self):
        base = fixture()
        for field, value in (("extra", None), ("issuer", None), ("instanceId", "unassigned"),
                ("generationTrustSha256", synthetic("wrong-pin"))):
            f = copy.deepcopy(base); f["fragment"][field] = value
            self.refused(f)
        for suffix in ("\n", " "):
            f = copy.deepcopy(base); f["fragment"]["receiptOriginal"] += suffix
            self.refused(f)
        f = copy.deepcopy(base)
        f["fragment"]["receiptOriginal"] = '{"apiVersion":"duplicate",' + f["fragment"]["receiptOriginal"][1:]
        self.refused(f)

    def test_independent_issuer_and_existing_signature_domain(self):
        base = fixture()
        for label in ("assignment", "custody-supervisor-capability", "untrusted-attester"):
            f = copy.deepcopy(base); store_receipt(f, label=label)
            self.refused(f)
        f = copy.deepcopy(base)
        envelope = json.loads(f["fragment"]["receiptOriginal"])
        envelope["signatureDomain"] = "serverware.policyShadowRuntimeAttestationVerification/v2"
        f["fragment"]["receiptOriginal"] = canonical(envelope).decode("ascii")
        self.refused(f)
        f = copy.deepcopy(base); f["fragment"]["issuer"]["keyId"] = key_fixture("assignment")[1]["keyId"]
        self.refused(f)

    def test_assignment_signature_payload_hash_and_version(self):
        base = fixture()
        for field, value in (("signature", encoded(bytes(64))), ("payloadSha256", synthetic("changed-payload")),
                ("apiVersion", "serverware.policyShadowAssignment/v1")):
            f = copy.deepcopy(base); envelope = json.loads(f["arguments"]["assignment_original"])
            envelope[field] = value; f["arguments"]["assignment_original"] = canonical(envelope)
            self.refused(f)

    def test_signed_record_cannot_substitute_fleet_runtime_fields(self):
        base = fixture()
        changes = {"bootIdSha256": synthetic("custody-driver-boot-is-not-fleet"), "fleetId": synthetic("other-fleet"),
            "membershipRevision": 8, "spiffeId": "spiffe://example.test/other",
            "teePlatform": "intel-tdx", "teeMeasurementSha256": synthetic("other-measurement")}
        for name, value in changes.items():
            f = copy.deepcopy(base); f["receipt"]["record"][name] = value; store_receipt(f)
            self.refused(f)

    def test_member_ordinal_hash_root_and_uniqueness(self):
        base = fixture()
        for name, value in (("memberOrdinal", 1), ("memberId", synthetic("other-member"))):
            f = copy.deepcopy(base); f["receipt"]["record"][name] = value; store_receipt(f)
            self.refused(f)
        f = copy.deepcopy(base); f["assignment"]["fleet"]["membershipRootSha256"] = synthetic("wrong-root")
        store_assignment(f); self.refused(f)
        f = copy.deepcopy(base); f["assignment"]["fleet"]["members"].append(copy.deepcopy(f["assignment"]["fleet"]["members"][1]))
        store_assignment(f, rehash=True); self.refused(f)

    def test_original_time_intervals_cannot_be_extended(self):
        base = fixture()
        for changes in ({"issued_at_unix_ns": NOW - 6_000_000_000},
                {"expires_at_unix_ns": NOW + 31_000_000_000}, {"now_unix_ns": NOW + 1_000_000_000},
                {"issued_at_unix_ns": True}, {"expires_at_unix_ns": NOW}):
            self.refused(copy.deepcopy(base), **changes)
        f = copy.deepcopy(base); f["trust"]["expiresAtUnixNanos"] = NOW + 500_000_000
        store_trust(f); self.refused(f)
        f = copy.deepcopy(base); f["assignment"]["expiresAtUnixNanos"] = NOW + 500_000_000
        store_assignment(f); self.refused(f)

    def test_spiffe_uses_native_path_grammar_not_identifier_tokens(self):
        base = fixture()
        for path in ("spiffe://example.test/runtime/a%2Fb", "spiffe://a-b.example.test/runtime/a:b"):
            f = copy.deepcopy(base); member = f["assignment"]["fleet"]["members"][1]
            member["spiffeId"] = path; f["receipt"]["record"].update(spiffeId=path,
                memberId=sha(b"serverware.policyShadowFleetMember/v1\0" + canonical(member)))
            store_assignment(f, rehash=True); store_receipt(f)
            self.assertEqual(derive(f)["spiffeId"], path)
        for path in ("spiffe://EXAMPLE.test/runtime/a", "spiffe://example.test/runtime/..",
                "spiffe://example.test/runtime/", "spiffe://example.test/runtime/a%2f", "spiffe:runtime"):
            f = copy.deepcopy(base); f["receipt"]["record"]["spiffeId"] = path; store_receipt(f)
            self.refused(f)

    def test_trust_roles_keys_and_windows_are_not_self_selected(self):
        base = fixture()
        for name, value in (("role", "custody-attestation-verifier"),
                ("signatureDomains", [ASSIGNMENT_DOMAIN]), ("notBeforeUnixNanos", NOW)):
            f = copy.deepcopy(base); f["trust"]["keys"][1][name] = value; store_trust(f)
            self.refused(f)
        f = copy.deepcopy(base); first, second = f["trust"]["keys"]
        for name in ("keyId", "keySpkiSha256", "publicKeyPem"):
            second[name] = first[name]
        f["trust"].update(startupAttestationSigningKeyId=first["keyId"],
            startupAttestationSigningKeySpkiSha256=first["keySpkiSha256"])
        f["fragment"]["issuer"] = {name: first[name] for name in ("keyId", "keySpkiSha256")}
        store_trust(f); store_receipt(f, label="assignment"); self.refused(f)

    def test_receipt_is_not_a_handoff_or_unbound_evidence_placeholder(self):
        base = fixture()
        for name, value in (("teeEvidenceSha256", "sha256:" + "0" * 64),
                ("roleKeysDigest", None), ("memberOrdinal", True), ("extra", "not-wire")):
            f = copy.deepcopy(base); f["receipt"]["record"][name] = value; store_receipt(f)
            self.refused(f)
        f = copy.deepcopy(base)
        f["fragment"]["receiptOriginal"] = canonical({"apiVersion":
            "serverware.policyShadowRuntimeAttestationHandoff/v2", "receipt": json.loads(f["fragment"]["receiptOriginal"])}).decode("ascii")
        self.refused(f)


if __name__ == "__main__":
    unittest.main()
