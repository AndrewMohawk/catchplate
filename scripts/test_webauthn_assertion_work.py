#!/usr/bin/env python3
"""Real signed verifier receipts under one cumulative private work context.

Fixed local Ed25519 test keys sign independently framed receipt commitments.
They are not production pins, hardware assertions, enrollment or current-root
authority. No successful verification result is substituted. All authored
controls are source-only and unrun.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_webauthn_assertion as admission


OPERATION = "webauthn.credential.revoke"
DOMAIN = "serverware.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1"
SIGNATURE_FIELDS = {"verifiedAssertionReceiptDigest", "verifierSignatureBase64url", "verifierSignatureDigest"}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def framed(domain, *frames):
    value = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        value.update(len(frame).to_bytes(8, "big"))
        value.update(frame)
    return "sha256:" + value.hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(item) for item in value.values())
    if type(value) in (list, tuple):
        return 1 + sum(nodes(item) for item in value)
    return 1


class ReceiptFixture:
    """Deterministic receipt signer and independently derived raw byte claims."""
    def __init__(self, *, unicode_ids=False):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        self.identity = {"sessionIdentityDigest": digest(b"component verifier session"),
            "measurementDigest": digest(b"component verifier measurement"),
            "attestationReceiptDigest": digest(b"component verifier attestation")}
        self.now = 1_900_000_000_000_000_000
        self.request_digest = digest(b"component revocation request")
        self.operation_id = framed("serverware.policyAuthorityOperation/v2",
                                   OPERATION.encode("ascii"), self.request_digest.encode("ascii"))
        self.capability_id = digest(b"component capability")
        self.challenge = bytes(range(32))
        self.rp_id = "unit.example"
        self.origin = "https://unit.example"
        self.authenticator = hashlib.sha256(self.rp_id.encode("utf-8")).digest() + bytes([5]) + (3).to_bytes(4, "big")
        self.client = {"type": "webauthn.get", "challenge": encoded(self.challenge),
                       "origin": self.origin, "crossOrigin": False}
        self.client_bytes = wire(self.client)
        # Only the pinned verifier's Ed25519 signature is verified here. These
        # bytes are NOT a fabricated successful physical authenticator proof.
        self.assertion_signature = b"synthetic authenticator signature byte binding"
        suffix = "-雪😀" if unicode_ids else ""
        self.evidence = self.sign({
            "operation": OPERATION, "operationId": self.operation_id, "requestDigest": self.request_digest,
            "capabilityId": self.capability_id, "challengeId": "component-challenge" + suffix,
            "challengeDigest": digest(b"authoritative challenge component"),
            "clientChallengeDigest": digest(self.challenge),
            "credentialRecordId": "component-record" + suffix, "credentialId": "component-credential" + suffix,
            "credentialPolicyDigest": digest(b"component credential policy"),
            "authenticatorDataBase64url": encoded(self.authenticator), "authenticatorDataDigest": digest(self.authenticator),
            "clientDataJSONBase64url": encoded(self.client_bytes), "clientDataJSONDigest": digest(self.client_bytes),
            "signatureBase64url": encoded(self.assertion_signature), "signatureDigest": digest(self.assertion_signature),
            "rpId": self.rp_id, "rpIdHashDigest": digest(self.rp_id.encode("utf-8")), "origin": self.origin,
            "flags": 5, "userPresent": True, "userVerified": True, "priorCounter": 2, "counter": 3,
            "trustHighWaterDigest": digest(b"component trust high water"), "metadataPublicationSequence": 1,
            "verifierSessionIdentityDigest": self.identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": self.identity["measurementDigest"],
            "verifierAttestationReceiptDigest": self.identity["attestationReceiptDigest"],
            "verifiedAtEpochNs": self.now - 1_000_000_000, "expiresAtEpochNs": self.now + 60_000_000_000,
        })

    def sign(self, value, *, key=None):
        unsigned = {name: item for name, item in value.items() if name not in SIGNATURE_FIELDS}
        receipt = framed(DOMAIN, wire(unsigned))
        signature = (self.key if key is None else key).sign(receipt.encode("ascii"))
        return {**unsigned, "verifiedAssertionReceiptDigest": receipt,
                "verifierSignatureBase64url": encoded(signature), "verifierSignatureDigest": digest(signature)}

    def bindings(self, **changes):
        result = {"operation_id": self.operation_id, "request_digest": self.request_digest,
            "capability_id": self.capability_id, "verifier_identity": copy.deepcopy(self.identity),
            "verifier_public_key": self.key.public_key(), "now_epoch_ns": self.now,
            "deadline_epoch_ns": self.now + 120_000_000_000, "maximum_age_ns": 300_000_000_000}
        result.update(changes)
        return result

    def with_client_bytes(self, value):
        return self.sign({**self.evidence, "clientDataJSONBase64url": encoded(value),
                          "clientDataJSONDigest": digest(value)})


def shared_work(*, hashes=8_000_000, input_bytes=64 * 1024 * 1024, json_nodes=1_000_000):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(hashes, input_bytes, json_nodes))


def metrics(work):
    return work.hash_work, work.input_bytes, work.json_nodes


class ExpectedWork:
    """Independent declared units, not samples of the production meter."""
    def __init__(self):
        self.hashes = self.input_bytes = self.json_nodes = 0

    def graph(self, value, passes=2):
        self.input_bytes += passes * len(wire(value))
        self.json_nodes += passes * nodes(value)

    def utf8(self, value):
        self.input_bytes += 2 * len(value.encode("utf-8"))
        self.json_nodes += 2

    def compare(self, left, right):
        self.graph(left)
        self.graph(right)

    def codec(self, value):
        length = len(value)
        padded = 4 * ((length + 3) // 4)
        decoded_bound = 3 * (padded // 4)
        reencoded_bound = 4 * ((decoded_bound + 2) // 3)
        self.input_bytes += 2 * length + 4 * padded + 2 * decoded_bound + 5 * reencoded_bound

    @property
    def total(self):
        return self.hashes, self.input_bytes, self.json_nodes


def expected_work(fixture):
    """Enumerate successful semantic passes with literal evidence field names.

    Fixed small source predicates/hex formatting are not graph work units. The
    parser and codec costs are intentionally conservative reservations, whereas
    the eight SHA calls and one Ed25519 attempt are actual successful work.
    """
    result = ExpectedWork()
    evidence = fixture.evidence
    unsigned = {key: value for key, value in evidence.items() if key not in SIGNATURE_FIELDS}
    # Snapshot copy, snapshot canonical encoding, and the unsigned filter copy
    # each conservatively traverse the full evidence graph twice.
    result.graph(evidence, 6)
    result.graph(unsigned)
    for field in ("operation", "challengeId", "credentialRecordId", "credentialId", "rpId", "origin"):
        text = evidence[field]
        # Strip copy, strip equality's two operands, control scan; then UTF-8.
        result.graph(text, 8)
        result.utf8(text)
    result.utf8(OPERATION)
    result.utf8(fixture.request_digest)
    for left, right in (
        (evidence["operation"], OPERATION),
        (evidence["operationId"], fixture.operation_id),
        (fixture.operation_id, fixture.operation_id),
        (evidence["requestDigest"], fixture.request_digest),
        (evidence["capabilityId"], fixture.capability_id),
        (evidence["verifierSessionIdentityDigest"], fixture.identity["sessionIdentityDigest"]),
        (evidence["verifierMeasurementDigest"], fixture.identity["measurementDigest"]),
        (evidence["verifierAttestationReceiptDigest"], fixture.identity["attestationReceiptDigest"]),
    ):
        result.compare(left, right)
    result.codec(evidence["verifierSignatureBase64url"])
    for field in ("verifiedAssertionReceiptDigest", "verifierSignatureDigest"):
        result.compare(evidence[field], evidence[field])
    result.utf8(evidence["verifiedAssertionReceiptDigest"])
    for field in ("authenticatorDataBase64url", "clientDataJSONBase64url", "signatureBase64url"):
        result.codec(evidence[field])
    result.utf8(evidence["rpId"])
    client_size = len(fixture.client_bytes)
    result.input_bytes += 4 * client_size
    result.json_nodes += 2 * (client_size + 1)
    for field in ("authenticatorDataDigest", "clientDataJSONDigest", "signatureDigest", "rpIdHashDigest"):
        result.compare(evidence[field], evidence[field])
    result.compare(fixture.client["type"], "webauthn.get")
    result.compare(fixture.client["origin"], evidence["origin"])
    result.codec(fixture.client["challenge"])
    result.compare(evidence["clientChallengeDigest"], evidence["clientChallengeDigest"])
    result.hashes = 8
    return result


class WebAuthnAssertionWorkTests(unittest.TestCase):
    def verify(self, fixture, *, evidence=None, wrapper=None, **changes):
        return admission._verify_revoke_assertion_evidence(
            fixture.evidence if evidence is None else evidence,
            **fixture.bindings(**changes), work=wrapper)

    def test_real_receipt_signature_and_all_eight_hashes(self):
        fixture = ReceiptFixture()
        shared = shared_work()
        wrapper = admission._ReceiptWork(shared)
        real_signature = admission._verify_receipt_signature
        real_hash = hashlib.sha256
        with patch.object(admission, "_verify_receipt_signature", wraps=real_signature) as signatures, \
                patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            result = self.verify(fixture, wrapper=wrapper)
        self.assertEqual(dict(result), fixture.evidence)
        self.assertEqual(hashes.call_count, 8)
        self.assertEqual(shared.hash_work, 8)
        self.assertEqual(signatures.call_count, 1)
        self.assertIs(signatures.call_args.kwargs["work"], wrapper)
        self.assertIs(wrapper.shared, shared)
        self.assertEqual(wrapper.signature_attempts, 1)
        self.assertEqual(signatures.call_args.args[1],
                         base64.urlsafe_b64decode(fixture.evidence["verifierSignatureBase64url"] + "=="))
        self.assertEqual(signatures.call_args.args[2],
                         fixture.evidence["verifiedAssertionReceiptDigest"].encode("ascii"))

    def test_public_none_parity_and_detached_immutable_scalar_snapshot(self):
        fixture = ReceiptFixture(unicode_ids=True)
        public = admission.verify_revoke_assertion_evidence(fixture.evidence, **fixture.bindings())
        private = self.verify(fixture)
        measured = self.verify(fixture, wrapper=admission._ReceiptWork(shared_work()))
        self.assertEqual(dict(public), dict(private))
        self.assertEqual(dict(public), dict(measured))
        expected = copy.deepcopy(fixture.evidence)
        fixture.evidence["credentialId"] = "changed after verification"
        for result in (public, private, measured):
            self.assertEqual(dict(result), expected)
            with self.assertRaises(TypeError):
                result["credentialId"] = "cannot modify retained result"
        # This observes a signed component receipt, not hardware presence,
        # current primary roots, a durable commit, or production key enrollment.

    def test_failed_real_signature_consumes_the_only_attempt(self):
        fixture = ReceiptFixture()
        other_signed = fixture.sign(fixture.evidence, key=fixture.other_key)
        shared = shared_work()
        wrapper = admission._ReceiptWork(shared)
        real_hash = hashlib.sha256
        with patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaisesRegex(admission.AssertionEvidenceError, "signature is invalid") as rejected:
                self.verify(fixture, evidence=other_signed, wrapper=wrapper)
        self.assertIsInstance(rejected.exception.__cause__, admission.InvalidSignature)
        self.assertEqual(hashes.call_count, 3)
        self.assertEqual(shared.hash_work, 3)
        self.assertEqual(wrapper.signature_attempts, 1)
        # A genuine signature failure does not refund a fixed expensive attempt.
        with self.assertRaisesRegex(admission.AssertionEvidenceError, "allowance is exhausted"):
            self.verify(fixture, wrapper=wrapper)
        self.assertEqual(wrapper.signature_attempts, 1)

    def test_same_wrapper_cannot_restart_signature_allowance_after_success(self):
        fixture = ReceiptFixture()
        shared = shared_work()
        wrapper = admission._ReceiptWork(shared)
        self.verify(fixture, wrapper=wrapper)
        first_work = metrics(shared)
        with self.assertRaisesRegex(admission.AssertionEvidenceError, "allowance is exhausted"):
            self.verify(fixture, wrapper=wrapper)
        self.assertEqual(wrapper.signature_attempts, 1)
        self.assertGreaterEqual(shared.hash_work, first_work[0])
        self.assertGreaterEqual(shared.input_bytes, first_work[1])
        self.assertGreaterEqual(shared.json_nodes, first_work[2])
        # This quota belongs to this private wrapper; it is not a global replay
        # store and does not assert lifecycle authority over arbitrary callers.

    def test_context_pins_and_time_rejections_precede_signature(self):
        fixture = ReceiptFixture()
        changed_identity = dict(fixture.identity, measurementDigest=digest(b"different measurement"))
        cases = (
            {"operation_id": digest(b"different operation")},
            {"request_digest": digest(b"different request")},
            {"capability_id": digest(b"different capability")},
            {"verifier_identity": changed_identity},
            {"now_epoch_ns": fixture.now - 2_000_000_000},
            {"now_epoch_ns": fixture.now + 60_000_000_000},
            {"deadline_epoch_ns": fixture.now + 59_000_000_000},
            {"maximum_age_ns": 60_000_000_000},
            {"now_epoch_ns": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                wrapper = admission._ReceiptWork(shared_work())
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, wrapper=wrapper, **changes)
                self.assertEqual(wrapper.signature_attempts, 0)

    def test_signed_policy_scalar_rejections_precede_signature(self):
        fixture = ReceiptFixture()
        cases = (
            {"operation": "webauthn.credential.register"},
            {"userPresent": False}, {"userVerified": False},
            {"priorCounter": 3}, {"counter": 2_147_483_648},
            {"counter": True}, {"flags": 1}, {"flags": 261},
            {"metadataPublicationSequence": 0},
            {"expiresAtEpochNs": fixture.now},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                evidence = fixture.sign({**fixture.evidence, **changes})
                wrapper = admission._ReceiptWork(shared_work())
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, evidence=evidence, wrapper=wrapper)
                self.assertEqual(wrapper.signature_attempts, 0)

    def test_real_hash_failure_stages_for_every_signed_byte_commitment(self):
        fixture = ReceiptFixture()
        changed_digest = digest(b"different commitment")
        cases = (("verifiedAssertionReceiptDigest", 2, False),
                 ("verifierSignatureDigest", 3, False),
                 ("authenticatorDataDigest", 5, True),
                 ("clientDataJSONDigest", 6, True),
                 ("signatureDigest", 7, True),
                 ("rpIdHashDigest", 7, True),
                 ("clientChallengeDigest", 8, True))
        real_hash = hashlib.sha256
        for field, expected_hashes, resign in cases:
            changed = {**fixture.evidence, field: changed_digest}
            evidence = fixture.sign(changed) if resign else changed
            wrapper = admission._ReceiptWork(shared_work())
            with self.subTest(field=field), patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, evidence=evidence, wrapper=wrapper)
            self.assertEqual(hashes.call_count, expected_hashes)
            self.assertEqual(wrapper.shared.hash_work, expected_hashes)
            self.assertEqual(wrapper.signature_attempts, int(resign))

    def test_signed_duplicate_invalid_utf8_and_depth_fail_before_raw_digest_trio(self):
        fixture = ReceiptFixture()
        duplicate = fixture.client_bytes[:-1] + b',"type":"webauthn.get"}'
        cases = ((duplicate, 1), (b'\xff', 0), (b'{"incomplete":', 1),
                 (b'[' * 129 + b'0' + b']' * 129, 0))
        real_hash = hashlib.sha256
        real_loads = json.loads
        for raw, parses in cases:
            evidence = fixture.with_client_bytes(raw)
            wrapper = admission._ReceiptWork(shared_work())
            with self.subTest(length=len(raw)), \
                    patch.object(hashlib, "sha256", wraps=real_hash) as hashes, \
                    patch.object(json, "loads", wraps=real_loads) as loads:
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, evidence=evidence, wrapper=wrapper)
            self.assertEqual(hashes.call_count, 4)
            self.assertEqual(loads.call_count, parses)
            self.assertEqual(wrapper.signature_attempts, 1)

    def test_signed_client_shape_ceremony_and_challenge_guards(self):
        fixture = ReceiptFixture()
        cases = (({**fixture.client, "crossOrigin": True}, 7),
                 ({**fixture.client, "type": "webauthn.create"}, 7),
                 ({**fixture.client, "origin": "https://other.example"}, 7),
                 ({**fixture.client, "extra": 0}, 7), ([], 7),
                 ({**fixture.client, "challenge": encoded(b"different challenge")}, 8),
                 ({**fixture.client, "challenge": fixture.client["challenge"] + "="}, 7))
        real_hash = hashlib.sha256
        for client, expected_hashes in cases:
            evidence = fixture.with_client_bytes(wire(client))
            wrapper = admission._ReceiptWork(shared_work())
            with self.subTest(client=client), patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, evidence=evidence, wrapper=wrapper)
            self.assertEqual(hashes.call_count, expected_hashes)
            self.assertEqual(wrapper.signature_attempts, 1)

    def test_base64_exact_conservative_work_and_real_codec_calls(self):
        real_decode = base64.urlsafe_b64decode
        real_encode = base64.urlsafe_b64encode
        for raw in (b'a', b'ab', b'abc', bytes(range(64))):
            value = encoded(raw)
            length = len(value)
            padded = 4 * ((length + 3) // 4)
            decoded_bound = 3 * (padded // 4)
            encoded_bound = 4 * ((decoded_bound + 2) // 3)
            expected_bytes = 2 * length + 4 * padded + 2 * decoded_bound + 5 * encoded_bound
            shared = shared_work(input_bytes=expected_bytes)
            wrapper = admission._ReceiptWork(shared)
            with self.subTest(length=len(raw)), \
                    patch.object(base64, "urlsafe_b64decode", wraps=real_decode) as decode, \
                    patch.object(base64, "urlsafe_b64encode", wraps=real_encode) as encode:
                self.assertEqual(admission._decode(value, work=wrapper), raw)
            self.assertEqual(metrics(shared), (0, expected_bytes, 0))
            self.assertEqual((decode.call_count, encode.call_count), (1, 1))
            with patch.object(base64, "urlsafe_b64decode", wraps=real_decode) as decode, \
                    patch.object(base64, "urlsafe_b64encode", wraps=real_encode) as encode:
                with self.assertRaises(accounting.QueryReadWorkError):
                    admission._decode(value, work=admission._ReceiptWork(
                        shared_work(input_bytes=expected_bytes - 1)))
            self.assertEqual((decode.call_count, encode.call_count), (0, 0))

    def test_noncanonical_base64_and_cheap_fixed_size_admission(self):
        # Zh has nonzero unused bits: permissive decoding yields b'f', whose
        # canonical spelling is Zg. The real re-encoder must reject it.
        real_decode = base64.urlsafe_b64decode
        for value in ("Zg=", "Zh", "!g", "A", "", None):
            with self.subTest(value=value), self.assertRaises(admission.AssertionEvidenceError):
                admission._decode(value, work=admission._ReceiptWork(shared_work()))
        for value, size in (("A" * (4 * 1024 * 1024 + 1), None), ("Zg", 64)):
            wrapper = admission._ReceiptWork(shared_work())
            with patch.object(base64, "urlsafe_b64decode", wraps=real_decode) as decode:
                with self.assertRaises(admission.AssertionEvidenceError):
                    admission._decode(value, size=size, work=wrapper)
            self.assertEqual(decode.call_count, 0)

    def test_real_five_codec_calls_two_canonical_encodings_and_one_parse(self):
        fixture = ReceiptFixture()
        wrapper = admission._ReceiptWork(shared_work())
        real_decode = base64.urlsafe_b64decode
        real_encode = base64.urlsafe_b64encode
        real_loads = json.loads
        real_canonical = admission.core.canonical_bytes
        with patch.object(base64, "urlsafe_b64decode", wraps=real_decode) as decode, \
                patch.object(base64, "urlsafe_b64encode", wraps=real_encode) as encode, \
                patch.object(json, "loads", wraps=real_loads) as loads, \
                patch.object(admission.core, "canonical_bytes", wraps=real_canonical) as canonical:
            self.verify(fixture, wrapper=wrapper)
        self.assertEqual((decode.call_count, encode.call_count, loads.call_count), (5, 5, 1))
        self.assertEqual(canonical.call_count, 2)
        self.assertEqual(canonical.call_args_list[0].args[0], fixture.evidence)
        self.assertEqual(canonical.call_args_list[1].args[0],
                         {key: value for key, value in fixture.evidence.items() if key not in SIGNATURE_FIELDS})
        self.assertEqual(loads.call_args.args[0], fixture.client_bytes.decode("utf-8"))

    def test_independent_complete_byte_node_and_hash_schedule(self):
        for unicode_ids in (False, True):
            fixture = ReceiptFixture(unicode_ids=unicode_ids)
            expected = expected_work(fixture)
            shared = shared_work(hashes=expected.hashes, input_bytes=expected.input_bytes,
                                 json_nodes=expected.json_nodes)
            wrapper = admission._ReceiptWork(shared)
            with self.subTest(unicode_ids=unicode_ids):
                self.assertEqual(dict(self.verify(fixture, wrapper=wrapper)), fixture.evidence)
                self.assertEqual(metrics(shared), expected.total)
                self.assertEqual(wrapper.signature_attempts, 1)
        ascii_expected = expected_work(ReceiptFixture())
        unicode_expected = expected_work(ReceiptFixture(unicode_ids=True))
        self.assertGreater(unicode_expected.input_bytes, ascii_expected.input_bytes)
        self.assertEqual(unicode_expected.json_nodes, ascii_expected.json_nodes)

    def test_each_exact_cumulative_limit_minus_one_denies_real_work(self):
        fixture = ReceiptFixture()
        expected = expected_work(fixture)
        real_hash = hashlib.sha256
        for field in ("hashes", "input_bytes", "json_nodes"):
            limits = {"hashes": expected.hashes, "input_bytes": expected.input_bytes,
                      "json_nodes": expected.json_nodes}
            limits[field] -= 1
            shared = shared_work(**limits)
            wrapper = admission._ReceiptWork(shared)
            with self.subTest(field=field), patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.verify(fixture, wrapper=wrapper)
            self.assertLessEqual(hashes.call_count, limits["hashes"])
            self.assertLessEqual(shared.input_bytes, limits["input_bytes"])
            self.assertLessEqual(shared.json_nodes, limits["json_nodes"])
            self.assertEqual(shared.hash_work, hashes.call_count)
            if field == "hashes":
                self.assertEqual(hashes.call_count, 7)
                self.assertEqual(wrapper.signature_attempts, 1)

    def test_preconsumed_shared_meter_is_not_replaced_or_refunded(self):
        fixture = ReceiptFixture()
        expected = expected_work(fixture)
        prior = (3, 53, 7)
        exact = {"hashes": expected.hashes + prior[0],
                 "input_bytes": expected.input_bytes + prior[1],
                 "json_nodes": expected.json_nodes + prior[2]}
        shared = shared_work(**exact)
        shared.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        wrapper = admission._ReceiptWork(shared)
        self.verify(fixture, wrapper=wrapper)
        self.assertIs(wrapper.shared, shared)
        self.assertEqual(metrics(shared), tuple(a + b for a, b in zip(expected.total, prior)))
        for field in exact:
            limits = dict(exact)
            limits[field] -= 1
            consumed = shared_work(**limits)
            consumed.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            with self.subTest(field=field), self.assertRaises(accounting.QueryReadWorkError):
                self.verify(fixture, wrapper=admission._ReceiptWork(consumed))

    def test_real_parser_reservation_depth_and_escaped_string_controls(self):
        # Direct codec/parser accounting components; accepting this nested JSON
        # alone does not accept it as a closed WebAuthn client ceremony.
        cases = (b'[' * 128 + b'0' + b']' * 128,
                 wire({"quoted": '[{\\"}]' * 129}))
        real_loads = json.loads
        for raw in cases:
            size = len(raw)
            expected_value = real_loads(raw)
            shared = shared_work(input_bytes=4 * size, json_nodes=2 * (size + 1))
            with patch.object(json, "loads", wraps=real_loads) as loads:
                actual = admission._client_json(raw, work=admission._ReceiptWork(shared))
            self.assertEqual(actual, expected_value)
            self.assertEqual(metrics(shared), (0, 4 * size, 2 * (size + 1)))
            self.assertEqual(loads.call_count, 1)
            for limits in ({"input_bytes": 4 * size - 1}, {"json_nodes": 2 * (size + 1) - 1}):
                shared = shared_work(**limits)
                with patch.object(json, "loads", wraps=real_loads) as loads:
                    with self.assertRaises(accounting.QueryReadWorkError):
                        admission._client_json(raw, work=admission._ReceiptWork(shared))
                self.assertEqual(loads.call_count, 0)
                self.assertEqual(metrics(shared), (0, size, 0))
        oversized_nodes = b'"' + b'a' * 500_000 + b'"'
        with patch.object(json, "loads", wraps=real_loads) as loads:
            with self.assertRaises(accounting.QueryReadWorkError):
                admission._client_json(oversized_nodes, work=admission._ReceiptWork(shared_work()))
        self.assertEqual(loads.call_count, 0)
        excessive_depth = b'[' * 129 + b'0' + b']' * 129
        shared = shared_work()
        with patch.object(json, "loads", wraps=real_loads) as loads:
            with self.assertRaises(admission.AssertionEvidenceError):
                admission._client_json(excessive_depth, work=admission._ReceiptWork(shared))
        self.assertEqual(loads.call_count, 0)
        self.assertEqual(metrics(shared), (0, len(excessive_depth), 0))
        # If UTF-8 decode ran before the node reservation, this would instead
        # fail as AssertionEvidenceError. The actual decoder is not replaced.
        with patch.object(json, "loads", wraps=real_loads) as loads:
            with self.assertRaises(accounting.QueryReadWorkError):
                admission._client_json(b'\xff', work=admission._ReceiptWork(shared_work(json_nodes=3)))
        self.assertEqual(loads.call_count, 0)

    def test_exact_private_wrapper_graphs_and_source_bounded_limits(self):
        fixture = ReceiptFixture()

        class SharedSubclass(accounting._ValidationWork):
            pass

        class ReceiptSubclass(admission._ReceiptWork):
            pass

        for invalid in (None, object(), SharedSubclass(accounting.QueryReadValidationLimits())):
            with self.assertRaises(admission.AssertionEvidenceError):
                admission._ReceiptWork(invalid)
        incomplete = object.__new__(admission._ReceiptWork)
        bad_shared = admission._ReceiptWork(shared_work())
        bad_shared._shared = object()
        bad_counter = admission._ReceiptWork(shared_work())
        bad_counter._signature_attempts = True
        for invalid in (object(), shared_work(), incomplete, bad_shared, bad_counter,
                        ReceiptSubclass(shared_work())):
            with self.assertRaises(admission.AssertionEvidenceError):
                self.verify(fixture, wrapper=invalid)
        wrapper = admission._ReceiptWork(shared_work())
        with self.assertRaises(AttributeError):
            wrapper.shared = shared_work()
        with self.assertRaises(AttributeError):
            wrapper.signature_attempts = 0
        # The private worker accepts already-owned exact dictionaries. The old
        # public Mapping facade intentionally retains its broader input shape.
        mapped = MappingProxyType(fixture.evidence)
        self.assertEqual(dict(admission.verify_revoke_assertion_evidence(mapped, **fixture.bindings())),
                         fixture.evidence)
        malformed = (None, mapped, {**fixture.evidence, "extra": 0},
                     {key: value for key, value in fixture.evidence.items() if key != "origin"})
        real_hash = hashlib.sha256
        for evidence in malformed:
            with patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(admission.AssertionEvidenceError):
                    admission._verify_revoke_assertion_evidence(
                        evidence, **fixture.bindings(), work=admission._ReceiptWork(shared_work()))
            self.assertEqual(hashes.call_count, 0)
        for changes in ({"verifier_identity": mapped}, {"verifier_public_key": None}):
            with self.assertRaises(admission.AssertionEvidenceError):
                self.verify(fixture, wrapper=admission._ReceiptWork(shared_work()), **changes)
        for limits in ({"hashes": True}, {"hashes": 8_000_001},
                       {"input_bytes": 64 * 1024 * 1024 + 1}, {"json_nodes": 1_000_001}):
            with self.assertRaises(accounting.QueryReadWorkError):
                shared_work(**limits)

    def test_canonical_allocation_and_utf8_bounds_precede_real_encoding_or_hash(self):
        value = {"text": "Unicode 雪😀", "flag": True}
        length, count = len(wire(value)), nodes(value)
        real_canonical = admission.core.canonical_bytes
        shared = shared_work(input_bytes=2 * length, json_nodes=2 * count)
        with patch.object(admission.core, "canonical_bytes", wraps=real_canonical) as canonical:
            self.assertEqual(admission._canonical(value, work=admission._ReceiptWork(shared)), wire(value))
        self.assertEqual(canonical.call_count, 1)
        self.assertEqual(metrics(shared), (0, 2 * length, 2 * count))
        for limits in ({"input_bytes": 2 * length - 1}, {"json_nodes": 2 * count - 1}):
            with patch.object(admission.core, "canonical_bytes", wraps=real_canonical) as canonical:
                with self.assertRaises(accounting.QueryReadWorkError):
                    admission._canonical(value, work=admission._ReceiptWork(shared_work(**limits)))
            self.assertEqual(canonical.call_count, 0)
        fixture = ReceiptFixture()
        evidence_length, evidence_nodes = len(wire(fixture.evidence)), nodes(fixture.evidence)
        real_hash = hashlib.sha256
        for limits in ({"input_bytes": 2 * evidence_length - 1},
                       {"json_nodes": 2 * evidence_nodes - 1}):
            with patch.object(admission.core, "canonical_bytes", wraps=real_canonical) as canonical, \
                    patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.verify(fixture, wrapper=admission._ReceiptWork(shared_work(**limits)))
            self.assertEqual((canonical.call_count, hashes.call_count), (0, 0))
        too_large = {**fixture.evidence, "signatureBase64url": "A" * (4 * 1024 * 1024)}
        with patch.object(admission.core, "canonical_bytes", wraps=real_canonical) as canonical, \
                patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaises(admission.AssertionEvidenceError):
                self.verify(fixture, evidence=too_large, wrapper=admission._ReceiptWork(shared_work()))
        self.assertEqual((canonical.call_count, hashes.call_count), (0, 0))
        for characters in (2048, 2049):
            evidence = fixture.sign({**fixture.evidence, "challengeId": "é" * characters})
            wrapper = admission._ReceiptWork(shared_work())
            if characters == 2048:
                self.assertEqual(dict(self.verify(fixture, evidence=evidence, wrapper=wrapper)), evidence)
            else:
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(fixture, evidence=evidence, wrapper=wrapper)
                self.assertEqual(wrapper.shared.hash_work, 0)
                self.assertEqual(wrapper.signature_attempts, 0)


if __name__ == "__main__":
    unittest.main()
