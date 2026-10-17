#!/usr/bin/env python3
"""Real clock-free ACK signatures and independent pure-work components.

Literal scalar requests are not admitted database rows. These tests establish
only original-byte cryptography and independent pin/field comparisons, never
commit, fresh authorization, measured launch, current roots or durable custody.
The owning startup/storage fixtures separately keep the actual gate and both
proof replays. No active service, request/composition fixture or registry is
imported here. All controls are authored source, not executed evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract as authority
from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
import test_authority_revocation_plan as oracle
import test_authority_revocation_capability as signature_oracle
import test_authority_revocation_wire as wire_oracle


ACK_SCHEMA = "catchplate.policyAuthorityRevocationWriterAcknowledgment/v1"
ACK_ID_DOMAIN = "catchplate.policyAuthorityRevocationWriterAcknowledgmentIdentity/v1"
PURPOSE = "acknowledge-revocation-writer-custody"
STATE = "retained-and-reserved"
REQUEST_FIELDS = frozenset({
    "intent_envelope_id", "relay_envelope_id", "execution_envelope_id", "planner_transaction_id",
    "plan_protocol", "retained_record_digest", "configuration_digest", "generation_sequence",
    "generation_digest", "exact_intent_bytes_digest", "exact_intent_byte_count",
    "exact_relay_bytes_digest", "exact_relay_byte_count", "historical_expectations_bytes_digest",
    "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
    "planned_at_epoch_ns", "source_revision",
})
ENVELOPE_FIELDS = frozenset({"schema", "acknowledgmentId", "purpose", "custodyState",
    "writerResponseSpkiDigest", "request", "signatureBase64Url"})


def spki_digest(key):
    return "sha256:" + hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def unsigned_ack(request_fields, writer_pin):
    return {"schema": ACK_SCHEMA, "acknowledgmentId": oracle.framed(ACK_ID_DOMAIN,
        request_fields["intent_envelope_id"].encode("ascii")), "purpose": PURPOSE,
        "custodyState": STATE, "writerResponseSpkiDigest": writer_pin,
        "request": copy.deepcopy(request_fields)}


def expected_wire(request_fields, writer_pin, writer_key):
    unsigned = unsigned_ack(request_fields, writer_pin)
    signature = writer_key.sign(oracle.framed(ACK_SCHEMA, oracle.wire(unsigned)).encode("ascii"))
    return oracle.wire({**unsigned, "signatureBase64Url": oracle.encoded(signature)})


def default_request():
    fields = {name: oracle.sha(("independent " + name).encode("ascii")) for name in REQUEST_FIELDS}
    fields.update(plan_protocol="revocation-v4", source_revision=authority.SOURCE_REVISION,
        generation_sequence=3, planned_at_epoch_ns=1_700_000_000_000_000_123,
        exact_intent_byte_count=431, exact_relay_byte_count=287, historical_expectations_byte_count=1703)
    return fields


class AckFixture:
    def __init__(self, request_fields=None, writer_key=None, launch_key=None):
        self.request_fields = copy.deepcopy(default_request() if request_fields is None else request_fields)
        self.writer_key = Ed25519PrivateKey.from_private_bytes(bytes([55]) * 32) if writer_key is None else writer_key
        self.launch_key = Ed25519PrivateKey.from_private_bytes(bytes([56]) * 32) if launch_key is None else launch_key
        self.writer_public_key, self.launch_public_key = self.writer_key.public_key(), self.launch_key.public_key()
        self.writer_pin = spki_digest(self.writer_public_key)
        self.other_pins = tuple(spki_digest(Ed25519PrivateKey.from_private_bytes(bytes([value]) * 32).public_key())
            for value in (57, 58, 59, 60))
        self.acknowledgment_bytes = expected_wire(self.request_fields, self.writer_pin, self.writer_key)


def independent_bind_work(writer_public_key, launch_public_key, writer_pin):
    """Two real DER44 exports/hashes and the two actual comparison recipes."""
    writer_digest, launch_digest = spki_digest(writer_public_key), spki_digest(launch_public_key)
    total = oracle.add((2, 176, 0), oracle.canonical_comparison(writer_digest, writer_pin),
        oracle.graph_cost(writer_digest), oracle.graph_cost(launch_digest))
    return {"total": total, "admission": total}


def independent_ack_work(request_fields, writer_pin, acknowledgment_bytes):
    """Literal successful paths; no measured receiver output supplies a cost.

    Signatures have a fixed86-character transport, so the placeholder produces
    the exact successful graph sizes without decoding the received original.
    Pure components have no clamped proof hold; admission equals final total.
    """
    unsigned = unsigned_ack(request_fields, writer_pin)
    envelope = {**unsigned, "signatureBase64Url": "A" * 86}
    add, graph = oracle.add, oracle.graph_cost
    capture = graph(request_fields, 1, 1)
    key = add((1, 88, 0), oracle.canonical_comparison(writer_pin, writer_pin))
    identity = add(oracle.utf8_cost(request_fields["intent_envelope_id"]),
        oracle.frame_cost(ACK_ID_DOMAIN, (request_fields["intent_envelope_id"].encode("ascii"),)))
    signing = add(graph(unsigned, 6, 4), graph(envelope), (0, 566, 0),
        oracle.frame_cost(ACK_SCHEMA, (oracle.wire(unsigned),)), (0, 142, 2))
    transport = add(wire_oracle.decoder_units(acknowledgment_bytes, envelope),
        graph(envelope, 4, 4), (0, 2 * len(acknowledgment_bytes), 0), graph(unsigned))
    authentication = signature_oracle.signature_work(ACK_SCHEMA, unsigned)
    after_callback = add(graph(unsigned), (0, 2 * len(oracle.wire(unsigned)), 0))
    comparison = oracle.canonical_comparison(unsigned, unsigned)
    sign = {"capture": capture, "key": key, "pair": (0, 128, 0), "identity": identity, "signing": signing}
    verify = {"capture": capture, "transport": transport, "key": key,
        "authentication": authentication, "after_callback": after_callback,
        "identity": identity, "comparison": comparison}
    for phases in (sign, verify):
        phases["total"] = add(*phases.values())
        phases["admission"] = phases["total"]
    return {"sign": sign, "verify": verify}


class _PublicKey(Ed25519PublicKey):
    """Every signature verdict and export delegates to an actual fixture key."""
    def __init__(self, key, callback=lambda stage: None, *, role="writer", transform=lambda value: value):
        self.key, self.callback, self.role, self.transform = key, callback, role, transform
        self.verifications = 0

    def public_bytes(self, encoding, format):
        actual = self.key.public_bytes(encoding, format)
        self.callback(self.role + (".der" if encoding is Encoding.DER else ".raw"))
        return self.transform(actual)

    def verify(self, signature, data):
        self.verifications += 1
        result = self.key.verify(signature, data)
        self.callback(self.role + ".verify")
        return result

    def public_bytes_raw(self):
        return self.key.public_bytes_raw()

    def __copy__(self):
        return self


class _PrivateKey(Ed25519PrivateKey):
    def __init__(self, key, callback=lambda stage: None, *, signing_key=None,
                 public_transform=lambda value: value, signature_transform=lambda value: value):
        self.key, self.callback = key, callback
        self.signing_key = key if signing_key is None else signing_key
        self.public_transform, self.signature_transform = public_transform, signature_transform
        self.signatures = 0

    def public_key(self):
        actual = self.key.public_key()
        self.callback("derive")
        return self.public_transform(_PublicKey(actual, self.callback, role="derived"))

    def sign(self, data):
        signature = self.signing_key.sign(data)
        self.signatures += 1
        self.callback("sign")
        return self.signature_transform(signature)

    def private_bytes(self, encoding, format, encryption_algorithm):
        return self.key.private_bytes(encoding, format, encryption_algorithm)

    def private_bytes_raw(self):
        return self.key.private_bytes_raw()

    def __copy__(self):
        return self


class RevocationWriterAcknowledgmentTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def bind(self, fixture, meter=None, **changes):
        return acknowledgment._bind_signer_on_work(**{"writer_private_key": fixture.writer_key,
            "launch_public_key": fixture.launch_public_key, "expected_writer_spki_digest": fixture.writer_pin,
            "other_response_spki_digests": fixture.other_pins,
            "work": self.work() if meter is None else meter, **changes})

    def sign(self, fixture, meter=None, **changes):
        return acknowledgment._sign_on_work(**{"request_fields": fixture.request_fields,
            "writer_private_key": fixture.writer_key, "writer_public_key": fixture.writer_public_key,
            "expected_writer_spki_digest": fixture.writer_pin,
            "work": self.work() if meter is None else meter, **changes})

    def verify(self, fixture, meter=None, **changes):
        return acknowledgment._verify_on_work(**{"acknowledgment_bytes": fixture.acknowledgment_bytes,
            "request_fields": fixture.request_fields, "writer_public_key": fixture.writer_public_key,
            "expected_writer_spki_digest": fixture.writer_pin,
            "work": self.work() if meter is None else meter, **changes})

    def test_real_binding_signing_and_original_verification_match_literal_bytes_and_work(self):
        fixture = AckFixture()
        bound, signed, verified = self.work(), self.work(), self.work()
        key = self.bind(fixture, bound)
        self.assertEqual(key.public_bytes(Encoding.Raw, PublicFormat.Raw),
            fixture.writer_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.assertEqual(oracle.units(bound.metrics), (2, 906, 8))
        self.assertEqual(oracle.units(bound.metrics), independent_bind_work(
            fixture.writer_public_key, fixture.launch_public_key, fixture.writer_pin)["total"])
        private, public = _PrivateKey(fixture.writer_key), _PublicKey(fixture.writer_public_key)
        raw = self.sign(fixture, signed, writer_private_key=private, writer_public_key=public)
        self.assertEqual(raw, fixture.acknowledgment_bytes)
        self.assertEqual((private.signatures, public.verifications), (1, 1))
        self.assertIsNone(self.verify(fixture, verified, writer_public_key=public))
        self.assertEqual((private.signatures, public.verifications), (1, 2))
        expected = independent_ack_work(fixture.request_fields, fixture.writer_pin, raw)
        self.assertEqual(oracle.units(signed.metrics), expected["sign"]["total"])
        self.assertEqual(oracle.units(verified.metrics), expected["verify"]["total"])
        self.assertEqual((signed.hash_work, verified.hash_work), (3, 3))
        value = json.loads(raw)
        self.assertEqual(set(value), ENVELOPE_FIELDS)
        self.assertEqual(set(value["request"]), REQUEST_FIELDS)
        self.assertEqual(value["request"]["planned_at_epoch_ns"], fixture.request_fields["planned_at_epoch_ns"])

    def test_stable_ack_identity_binds_only_the_global_original_intent(self):
        fixture = AckFixture()
        intent = fixture.request_fields["intent_envelope_id"]
        expected = oracle.framed(ACK_ID_DOMAIN, intent.encode("ascii"))
        meter = self.work()
        self.assertEqual(acknowledgment._ack_id_on_work(intent, meter), expected)
        self.assertEqual(oracle.units(meter.metrics), oracle.add(oracle.utf8_cost(intent),
            oracle.frame_cost(ACK_ID_DOMAIN, (intent.encode("ascii"),))))
        changed = copy.deepcopy(fixture.request_fields)
        changed.update(configuration_digest=oracle.sha(b"rotated config"), generation_sequence=4,
            generation_digest=oracle.sha(b"rotated generation"), planned_at_epoch_ns=1)
        other = AckFixture(changed, writer_key=fixture.launch_key)
        self.assertEqual(unsigned_ack(other.request_fields, other.writer_pin)["acknowledgmentId"], expected)
        self.assertNotEqual(self.sign(other), fixture.acknowledgment_bytes)
        # Same identity does not permit overwriting custody. Storage owns that
        # conflict rule; this pure signer does not claim transaction admission.
        for value in (None, True, "sha256:" + "A" * 64, "sha256:" + "0" * 63):
            meter = self.work()
            with self.assertRaises(ValueError): acknowledgment._ack_id_on_work(value, meter)
            self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))

    def test_closed_nineteen_scalars_and_source_limits_fail_before_key_callbacks(self):
        fixture = AckFixture()
        malformed = []
        for name in REQUEST_FIELDS:
            missing = copy.deepcopy(fixture.request_fields)
            missing.pop(name)
            malformed.append(missing)
            changed = copy.deepcopy(fixture.request_fields)
            changed[name] = False
            malformed.append(changed)
        malformed.extend((None, [], {**fixture.request_fields, "exact_intent_base64url": "eA"},
            {**fixture.request_fields, "unknown": 1}))
        for name in ("generation_sequence", "planned_at_epoch_ns"):
            malformed.extend({**fixture.request_fields, name: value} for value in (0, -1, 1.0, "1", 2**63))
        for name, maximum in (("exact_intent_byte_count", 4 * 1024 * 1024),
                ("exact_relay_byte_count", 4 * 1024 * 1024),
                ("historical_expectations_byte_count", 64 * 1024 * 1024)):
            malformed.extend({**fixture.request_fields, name: value} for value in (0, 1, -1, 2.0, maximum + 1))
        malformed.extend(({**fixture.request_fields, "plan_protocol": "revocation-v3"},
            {**fixture.request_fields, "source_revision": "other source"},
            {**fixture.request_fields, "configuration_digest": "sha256:" + "A" * 64}))
        for index, fields in enumerate(malformed):
            for method in (self.sign, self.verify):
                meter, events = self.work(), []
                with self.subTest(index=index, method=method.__name__), self.assertRaises(ValueError):
                    method(fixture, meter, request_fields=fields,
                        writer_public_key=_PublicKey(fixture.writer_public_key, events.append))
                self.assertEqual(events, [])
                self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        maximums = {**fixture.request_fields, "generation_sequence": 2**63 - 1,
            "planned_at_epoch_ns": 2**63 - 1, "exact_intent_byte_count": 4 * 1024 * 1024,
            "exact_relay_byte_count": 4 * 1024 * 1024, "historical_expectations_byte_count": 64 * 1024 * 1024}
        # Counts and original planned time are scalar claims, not original-body
        # possession or truth. The storage owner is responsible for that link.
        raw = self.sign(fixture, request_fields=maximums)
        self.assertIsNone(self.verify(fixture, request_fields=maximums, acknowledgment_bytes=raw))

    def test_genuine_signatures_do_not_override_any_independent_request_or_header_binding(self):
        fixture = AckFixture()
        for name in REQUEST_FIELDS - {"plan_protocol", "source_revision"}:
            changed = copy.deepcopy(fixture.request_fields)
            changed[name] = changed[name] + 1 if type(changed[name]) is int else oracle.sha(("changed " + name).encode())
            raw = expected_wire(changed, fixture.writer_pin, fixture.writer_key)
            public = _PublicKey(fixture.writer_public_key)
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.verify(fixture, acknowledgment_bytes=raw, writer_public_key=public)
            self.assertEqual(public.verifications, 1)
        base = unsigned_ack(fixture.request_fields, fixture.writer_pin)
        for name, replacement, attempts in (("acknowledgmentId", oracle.sha(b"other stable ID"), 1),
                ("writerResponseSpkiDigest", fixture.other_pins[0], 1),
                ("schema", "foreign/v1", 0), ("purpose", "acknowledge-execution", 0),
                ("custodyState", "executed", 0)):
            changed = {**base, name: replacement}
            signature = fixture.writer_key.sign(oracle.framed(ACK_SCHEMA, oracle.wire(changed)).encode("ascii"))
            raw = oracle.wire({**changed, "signatureBase64Url": oracle.encoded(signature)})
            public = _PublicKey(fixture.writer_public_key)
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.verify(fixture, acknowledgment_bytes=raw, writer_public_key=public)
            self.assertEqual(public.verifications, attempts)

    def test_original_canonical_transport_and_signature_encoding_are_not_reconstructed_or_relaxed(self):
        fixture = AckFixture()
        decoded = json.loads(fixture.acknowledgment_bytes)
        cases = (b" " + fixture.acknowledgment_bytes,
            json.dumps(decoded, sort_keys=False, indent=1).encode("ascii"),
            fixture.acknowledgment_bytes.replace(b'"purpose":', b'"purpose":"duplicate","purpose":', 1),
            oracle.wire({**decoded, "unsignedExtra": 1}),
            oracle.wire({**decoded, "request": {**fixture.request_fields, "generation_sequence": 3.0}}),
            oracle.wire({**decoded, "request": {**fixture.request_fields, "generation_sequence": {"deep": 3}}}),
            oracle.wire({**decoded, "signatureBase64Url": decoded["signatureBase64Url"] + "=="}),
            oracle.wire({**decoded, "signatureBase64Url": "A" * 85 + "B"}))
        for raw in cases:
            public = _PublicKey(fixture.writer_public_key)
            with self.subTest(raw_prefix=raw[:24]), self.assertRaises(ValueError):
                self.verify(fixture, acknowledgment_bytes=raw, writer_public_key=public)
            self.assertEqual(public.verifications, 0)
        bad_signature = oracle.wire({**decoded, "signatureBase64Url": oracle.encoded(bytes(64))})
        public = _PublicKey(fixture.writer_public_key)
        with self.assertRaises(ValueError):
            self.verify(fixture, acknowledgment_bytes=bad_signature, writer_public_key=public)
        self.assertEqual(public.verifications, 1)
        for raw in (None, bytearray(fixture.acknowledgment_bytes), memoryview(fixture.acknowledgment_bytes),
                "not bytes", b"", b"x", b"x" * 16385):
            meter = self.work()
            with self.assertRaises(ValueError): self.verify(fixture, meter, acknowledgment_bytes=raw)
            self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))

    def test_bound_signer_excludes_all_role_and_launch_aliases_and_real_wrong_keys(self):
        fixture = AckFixture()
        for index in range(4):
            pins = fixture.other_pins[:index] + (fixture.writer_pin,) + fixture.other_pins[index + 1:]
            meter, events = self.work(), []
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.bind(fixture, meter, other_response_spki_digests=pins,
                    writer_private_key=_PrivateKey(fixture.writer_key, events.append))
            self.assertEqual((events, oracle.units(meter.metrics)), ([], (0, 0, 0)))
        for changes in ({"other_response_spki_digests": list(fixture.other_pins)},
                {"other_response_spki_digests": fixture.other_pins[:3]},
                {"other_response_spki_digests": (False,) + fixture.other_pins[1:]},
                {"expected_writer_spki_digest": "sha256:" + "A" * 64},
                {"writer_private_key": fixture.writer_public_key}, {"launch_public_key": fixture.launch_key}):
            meter = self.work()
            with self.assertRaises(ValueError): self.bind(fixture, meter, **changes)
            self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        for changes in ({"launch_public_key": fixture.writer_public_key},
                {"writer_private_key": fixture.launch_key},
                {"expected_writer_spki_digest": oracle.sha(b"unrelated measured pin")}):
            with self.assertRaises(ValueError): self.bind(fixture, **changes)
        for method in (self.sign, self.verify):
            public = _PublicKey(fixture.writer_public_key)
            with self.assertRaises(ValueError):
                method(fixture, writer_public_key=public, expected_writer_spki_digest=fixture.other_pins[0])
            self.assertEqual(public.verifications, 0)
        private = _PrivateKey(fixture.launch_key)
        with self.assertRaises(ValueError): self.sign(fixture, writer_private_key=private)
        self.assertEqual(private.signatures, 0)

    def test_real_signer_outputs_are_paired_verified_and_key_serializations_remain_exact(self):
        fixture = AckFixture()
        for transform, attempts in ((lambda value: value[:-1], 0), (bytearray, 0),
                                   (lambda value: bytes(64), 1)):
            private = _PrivateKey(fixture.writer_key, signature_transform=transform)
            public = _PublicKey(fixture.writer_public_key)
            with self.subTest(attempts=attempts), self.assertRaises(ValueError):
                self.sign(fixture, writer_private_key=private, writer_public_key=public)
            self.assertEqual((private.signatures, public.verifications), (1, attempts))
        private = _PrivateKey(fixture.writer_key, signing_key=fixture.launch_key)
        public = _PublicKey(fixture.writer_public_key)
        with self.assertRaises(ValueError): self.sign(fixture, writer_private_key=private, writer_public_key=public)
        self.assertEqual((private.signatures, public.verifications), (1, 1))
        for transform in (bytearray, lambda value: value[:-1], lambda value: b"\x31" + value[1:]):
            public = _PublicKey(fixture.writer_public_key, transform=transform)
            private = _PrivateKey(fixture.writer_key)
            with self.assertRaises(ValueError): self.sign(fixture, writer_public_key=public, writer_private_key=private)
            self.assertEqual(private.signatures, 0)
        for output in (None, object(), fixture.writer_key):
            private = _PrivateKey(fixture.writer_key, public_transform=lambda actual: output)
            with self.assertRaises(ValueError): self.sign(fixture, writer_private_key=private)
            self.assertEqual(private.signatures, 0)

    def test_owned_scalar_request_and_held_key_pins_precede_all_genuine_crypto_callbacks(self):
        routes = (("bind", self.bind, ("derive", "derived.der", "launch.der")),
            ("sign", self.sign, ("writer.der", "derive", "derived.raw", "writer.raw", "sign", "writer.verify")),
            ("verify", self.verify, ("writer.der", "writer.verify")))
        for name, method, stages in routes:
            for target in stages:
                fixture, events = AckFixture(), []
                expected_raw, expected_request = fixture.acknowledgment_bytes, copy.deepcopy(fixture.request_fields)
                expected = (independent_bind_work(fixture.writer_public_key, fixture.launch_public_key, fixture.writer_pin)
                    if name == "bind" else independent_ack_work(expected_request, fixture.writer_pin, expected_raw)[name])

                def mutate(stage):
                    events.append(stage)
                    if stage == target:
                        fixture.request_fields.clear()
                        fixture.writer_pin = oracle.sha(b"changed outside pin")
                        fixture.other_pins = (fixture.writer_pin,) * 4
                        fixture.acknowledgment_bytes = b"{}"

                private, public = _PrivateKey(fixture.writer_key, mutate), _PublicKey(fixture.writer_public_key, mutate)
                changes = {"writer_private_key": private} if name == "bind" else {"writer_public_key": public}
                if name == "bind": changes["launch_public_key"] = _PublicKey(fixture.launch_public_key, mutate, role="launch")
                if name == "sign": changes["writer_private_key"] = private
                meter = self.work(expected["total"])
                with self.subTest(route=name, target=target):
                    result = method(fixture, meter, **changes)
                    self.assertEqual(events, list(stages))
                    if name == "sign": self.assertEqual(result, expected_raw)
                    if name == "verify": self.assertIsNone(result)
                    self.assertEqual(oracle.units(meter.metrics), expected["total"])

    def test_postcallback_mutation_of_the_actual_signed_graph_is_denied(self):
        fixture = AckFixture()
        encode = acknowledgment.plan.core.canonical_bytes
        for method in (self.sign, self.verify):
            observed = []

            def capture_unsigned(value):
                raw = encode(value)
                if type(value) is dict and value.get("schema") == ACK_SCHEMA and "signatureBase64Url" not in value:
                    observed.append(value)
                return raw

            def mutate(stage):
                if stage == ("sign" if method == self.sign else "writer.verify"):
                    self.assertTrue(observed)
                    # Same-length scalar replacement must fail the byte check,
                    # not merely a change in measured size or structure.
                    observed[0]["purpose"] = "X" * len(PURPOSE)

            private = _PrivateKey(fixture.writer_key, mutate)
            public = _PublicKey(fixture.writer_public_key, mutate)
            changes = {"writer_public_key": public}
            if method == self.sign: changes["writer_private_key"] = private
            with patch.object(acknowledgment.plan.core, "canonical_bytes", side_effect=capture_unsigned):
                with self.assertRaises(ValueError): method(fixture, **changes)
            self.assertEqual(public.verifications, 1)

    def test_callback_work_poison_and_native_errors_preserve_original_failure_state(self):
        routes = (("bind", self.bind, ("derive", "derived.der", "launch.der")),
            ("sign", self.sign, ("writer.der", "derive", "derived.raw", "writer.raw", "sign", "writer.verify")),
            ("verify", self.verify, ("writer.der", "writer.verify")))
        for name, method, stages in routes:
            for target in stages:
                for mode in ("spend", "refund", "retype", "limits"):
                    fixture, meter, failures = AckFixture(), self.work(), []
                    replacement = accounting.QueryReadValidationLimits()

                    def poison(stage):
                        if stage != target: return
                        if mode == "spend": meter.charge(input_bytes=1)
                        elif mode == "refund": meter.input_bytes -= 1
                        elif mode == "retype": meter.hash_work = float(meter.hash_work)
                        else: meter.limits = replacement
                        failures.append((meter.hash_work, meter.input_bytes, meter.json_nodes))

                    changes = {"writer_private_key": _PrivateKey(fixture.writer_key, poison)} if name == "bind" else {
                        "writer_public_key": _PublicKey(fixture.writer_public_key, poison)}
                    if name == "bind": changes["launch_public_key"] = _PublicKey(fixture.launch_public_key, poison, role="launch")
                    if name == "sign": changes["writer_private_key"] = _PrivateKey(fixture.writer_key, poison)
                    with self.subTest(route=name, target=target, mode=mode), self.assertRaises(ValueError):
                        method(fixture, meter, **changes)
                    self.assertEqual(len(failures), 1)
                    self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), failures[0])
                    if mode == "retype": self.assertIs(type(meter.hash_work), float)
                    if mode == "limits": self.assertIs(meter.limits, replacement)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
            fixture, meter = AckFixture(), self.work()
            failure = RuntimeError("native ACK key failure")

            def fail(stage):
                if stage == stages[-1]: raise failure

            changes = {"writer_private_key": _PrivateKey(fixture.writer_key, fail)} if name == "bind" else {
                "writer_public_key": _PublicKey(fixture.writer_public_key, fail)}
            if name == "bind": changes["launch_public_key"] = _PublicKey(fixture.launch_public_key, fail, role="launch")
            if name == "sign": changes["writer_private_key"] = _PrivateKey(fixture.writer_key, fail)
            with self.assertRaises(RuntimeError) as raised: method(fixture, meter, **changes)
            self.assertIs(raised.exception, failure)

    def test_full_output_reservation_and_source_bounds_precede_real_signing(self):
        fixture = AckFixture()
        expected = independent_ack_work(fixture.request_fields, fixture.writer_pin, fixture.acknowledgment_bytes)
        encoder = acknowledgment.plan.core.canonical_bytes
        for axis in (None, 0, 1, 2):
            limits = list(expected["sign"]["total"])
            if axis is not None: limits[axis] -= 1
            meter, private, encoded = self.work(tuple(limits)), _PrivateKey(fixture.writer_key), []

            def observe(value):
                if type(value) is dict and value.get("schema") == ACK_SCHEMA:
                    encoded.append("signatureBase64Url" in value)
                return encoder(value)

            with self.subTest(axis=axis), patch.object(acknowledgment.plan.core, "canonical_bytes", side_effect=observe):
                if axis is None:
                    self.assertEqual(self.sign(fixture, meter, writer_private_key=private), fixture.acknowledgment_bytes)
                else:
                    with self.assertRaises(ValueError): self.sign(fixture, meter, writer_private_key=private)
            self.assertEqual(private.signatures, 1 if axis is None else 0)
            self.assertEqual(encoded, [False, False, True] if axis is None else [])
        envelope = {**unsigned_ack(fixture.request_fields, fixture.writer_pin), "signatureBase64Url": "A" * 86}
        for bound, exact in (("MAX_ACK_BYTES", len(fixture.acknowledgment_bytes)),
                ("MAX_ACK_NODES", wire_oracle.counts(envelope)[0])):
            with self.subTest(bound=bound), patch.object(acknowledgment, bound, exact):
                self.assertEqual(self.sign(fixture), fixture.acknowledgment_bytes)
                self.assertIsNone(self.verify(fixture))
            private = _PrivateKey(fixture.writer_key)
            with patch.object(acknowledgment, bound, exact - 1), self.assertRaises(ValueError):
                self.sign(fixture, writer_private_key=private)
            self.assertEqual(private.signatures, 0)
        with patch.object(acknowledgment, "MAX_ACK_DEPTH", 1), self.assertRaises(ValueError):
            self.verify(fixture)

    def test_exact_prior_and_every_one_below_budget_use_only_the_original_work(self):
        fixture = AckFixture()
        expected = independent_ack_work(fixture.request_fields, fixture.writer_pin, fixture.acknowledgment_bytes)
        totals = {"bind": independent_bind_work(fixture.writer_public_key, fixture.launch_public_key,
            fixture.writer_pin)["total"], "sign": expected["sign"]["total"], "verify": expected["verify"]["total"]}
        for name, method in (("bind", self.bind), ("sign", self.sign), ("verify", self.verify)):
            for prior in ((0, 0, 0), (3, 23, 11)):
                for axis in (None, 0, 1, 2):
                    limits = list(oracle.add(prior, totals[name]))
                    if axis is not None: limits[axis] -= 1
                    meter = self.work(tuple(limits))
                    entering = meter.limits
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    # These inert paths contain no proof child. The owning
                    # store's separate fixtures retain genuine clamped children.
                    with self.subTest(route=name, prior=prior, axis=axis), patch.object(
                            accounting._ValidationWork, "__init__", side_effect=AssertionError("new work allowance")):
                        if axis is None:
                            method(fixture, meter)
                            self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, totals[name]))
                        else:
                            with self.assertRaises(ValueError): method(fixture, meter)
                    self.assertIs(meter.limits, entering)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_repeat_verification_preserves_original_bytes_and_never_invokes_the_signer(self):
        fixture = AckFixture()
        expected = independent_ack_work(fixture.request_fields, fixture.writer_pin, fixture.acknowledgment_bytes)
        sign_total, verify_total = expected["sign"]["total"], expected["verify"]["total"]
        for axis in (None, 0, 1, 2):
            limits = list(oracle.add(sign_total, verify_total, verify_total))
            if axis is not None: limits[axis] -= 1
            meter, private = self.work(tuple(limits)), _PrivateKey(fixture.writer_key)
            raw = self.sign(fixture, meter, writer_private_key=private)
            self.assertEqual((raw, private.signatures), (fixture.acknowledgment_bytes, 1))
            public = _PublicKey(fixture.writer_public_key)
            self.assertIsNone(self.verify(fixture, meter, acknowledgment_bytes=raw, writer_public_key=public))
            self.assertEqual(oracle.units(meter.metrics), oracle.add(sign_total, verify_total))
            with patch.object(acknowledgment, "_sign_on_work", side_effect=AssertionError("retry must not resign")):
                if axis is None:
                    self.assertIsNone(self.verify(fixture, meter, acknowledgment_bytes=raw, writer_public_key=public))
                    self.assertEqual(oracle.units(meter.metrics), oracle.add(sign_total, verify_total, verify_total))
                    self.assertEqual(public.verifications, 2)
                else:
                    with self.assertRaises(ValueError):
                        self.verify(fixture, meter, acknowledgment_bytes=raw, writer_public_key=public)
            self.assertEqual(private.signatures, 1)
            self.assertEqual(raw, fixture.acknowledgment_bytes)
        # This verifies a pure retry contract, not the store branch's choice or
        # global exactly-once signing across concurrent aborted transactions.

    def test_private_apis_accept_no_clock_proof_or_verification_callback_override(self):
        fixture = AckFixture()
        for method in (self.bind, self.sign, self.verify):
            for name in ("now_epoch_ns", "committed_at", "receipt", "verification", "opener", "signer_callback"):
                with self.subTest(method=method.__name__, name=name), self.assertRaises(TypeError):
                    method(fixture, **{name: object()})


if __name__ == "__main__":
    unittest.main()
