#!/usr/bin/env python3
"""UNRUN real Ed25519/synthetic-control components, not peer or proof authority.

Only clock samples are doubled. Canonical source control, actual role/key pins,
signatures and original interval checks remain real. No SQL, network, protected
key, successful proof DTO or new clock-window admission is exercised.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_original_authorization as source
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


EPOCH, MONOTONIC, LIFETIME = 1_800_000_000_000_000_000, 1_000_000_000, 1_000_000_000
WINDOW = (EPOCH, MONOTONIC, MONOTONIC + 10, EPOCH + LIFETIME, MONOTONIC + LIFETIME, LIFETIME, 0)
DEADLINE = MONOTONIC + LIFETIME // 2
ORIGINAL_EXPIRY = min(WINDOW[3], EPOCH + DEADLINE - MONOTONIC)
IDENTITY = dict(zip(("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"),
    ("sha256:" + digit * 64 for digit in "123")))
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x41" * 32)
PUBLIC = PRIVATE.public_key()
SPKI = "sha256:" + hashlib.sha256(PUBLIC.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
CONFIGURATION = "sha256:" + "c" * 64
REFUSALS = (ValueError, InvalidSignature)


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def frame(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0"
        + len(raw).to_bytes(8, "big") + raw).hexdigest()


def control(action="read"):
    context = dict(parent_plan_digest="sha256:" + "1" * 64,
        original_manifest_digest="sha256:" + "2" * 64,
        source_revision=source.evidence.authority.SOURCE_REVISION, operation="jit.assertion.issue",
        operation_id="sha256:" + "3" * 64, request_digest="sha256:" + "4" * 64,
        configuration_digest=CONFIGURATION, page_kind="primary-chunk", page_ordinal=0)
    descriptor = None if action == "read" else {
        "digest": "sha256:" + hashlib.sha256(b"[]").hexdigest(), "byteCount": 2}
    return source.control.encode_control(action=action, context=context,
        original_deadline_ns=DEADLINE, descriptor=descriptor, work=work())


@contextmanager
def clocks(state=None):
    state = {"elapsed": 100} if state is None else state
    with patch.object(source.time, "monotonic_ns", side_effect=lambda: MONOTONIC + state["elapsed"]), \
            patch.object(source.clock.time, "time_ns", side_effect=lambda: EPOCH + state["elapsed"]):
        yield state


def sign(raw, *, action="read", role="planner", **changes):
    args = dict(control_bytes=raw, action=action, signer_role=role,
        signer_identity=copy.deepcopy(IDENTITY), signer_spki_digest=SPKI,
        signer_private_key=PRIVATE, signer_public_key=PUBLIC,
        configuration_digest=CONFIGURATION, live_window=WINDOW, work=work())
    args.update(changes)
    return source.sign_control(**args)


def verify(signed, raw, *, action="read", role="planner", **changes):
    args = dict(authorization_bytes=signed, control_bytes=raw, action=action,
        expected_role=role, expected_identity=copy.deepcopy(IDENTITY), expected_spki_digest=SPKI,
        public_key=PUBLIC, configuration_digest=CONFIGURATION, live_window=WINDOW, work=work())
    args.update(changes)
    return source.verify_control(**args)


class JitOriginalAuthorizationControls(unittest.TestCase):
    def test_real_signatures_exact_jit_domains_and_all_allowed_directions(self):
        with clocks():
            for role, action in (("planner", "persist"), ("planner", "read"), ("verifier", "read")):
                with self.subTest(role=role, action=action):
                    raw = control(action)
                    signed = sign(raw, action=action, role=role)
                    observed = verify(signed, raw, action=action, role=role)
                    envelope = json.loads(signed)
                    self.assertEqual(signed, canonical(envelope))
                    payload = envelope["payload"]
                    self.assertEqual(set(payload), source.FIELDS)
                    signature = base64.urlsafe_b64decode(envelope["signatureBase64Url"] + "==")
                    PUBLIC.verify(signature, frame(source.SIGNATURE_DOMAIN, canonical(payload)).encode("ascii"))
                    self.assertEqual(payload["controlDigest"], frame(source.CONTROL_DOMAIN, raw))
                    self.assertEqual(observed.authorization_digest, frame(source.IDENTITY_DOMAIN, signed))
                    self.assertEqual((observed.issued_at_epoch_ns, observed.expires_at_epoch_ns,
                        observed.original_deadline_ns), (WINDOW[0], ORIGINAL_EXPIRY, DEADLINE))
                    self.assertEqual(observed.control, json.loads(raw))
                    self.assertNotIn("originalDeadlineNs", observed.control["context"])
                    self.assertEqual(observed.control["context"]["operation"], "jit.assertion.issue")
                    other_domain = "catchplate.policyAuthorityChallengeMaintenancePageAuthorizationSignature/v1"
                    with self.assertRaises(InvalidSignature):
                        PUBLIC.verify(signature, frame(other_domain, canonical(payload)).encode("ascii"))

    def test_role_configuration_identity_and_actual_key_substitution_refuse(self):
        with clocks():
            raw = control()
            signed = sign(raw)
            other = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
            for changes in (dict(role="verifier"), dict(expected_identity=dict(IDENTITY, measurementDigest="sha256:" + "f" * 64)),
                    dict(expected_spki_digest="sha256:" + "f" * 64), dict(public_key=other.public_key()),
                    dict(configuration_digest="sha256:" + "f" * 64)):
                with self.subTest(fields=tuple(changes)), self.assertRaises(REFUSALS):
                    verify(signed, raw, **changes)
            with self.assertRaises(REFUSALS):
                sign(raw, signer_private_key=other)
            with patch.object(source.evidence.production, "_sign_and_verify",
                    side_effect=AssertionError("forbidden direction must not sign")) as native:
                with self.assertRaises(ValueError):
                    sign(control("persist"), action="persist", role="verifier")
                native.assert_not_called()

    def test_independent_identity_is_owned_before_native_key_callbacks(self):
        identity = copy.deepcopy(IDENTITY)
        actual = source.evidence.keys._public_binding

        def binding(*args, **kwargs):
            identity["measurementDigest"] = "sha256:" + "f" * 64
            return actual(*args, **kwargs)

        with clocks():
            raw = control()
            with patch.object(source.evidence.keys, "_public_binding", side_effect=binding):
                signed = sign(raw, signer_identity=identity)
            self.assertEqual(json.loads(signed)["payload"]["identity"], IDENTITY)
            identity = copy.deepcopy(IDENTITY)
            with patch.object(source.evidence.keys, "_public_binding", side_effect=binding):
                verify(signed, raw, expected_identity=identity)
            self.assertNotEqual(identity, IDENTITY)

    def test_closed_canonical_exact_scalars_and_top_level_control_joins(self):
        with clocks():
            raw = control()
            signed = sign(raw)
            for name, value in (("controlByteCount", True), ("issuedAtEpochNs", True),
                    ("expiresAtEpochNs", None), ("originalDeadlineNs", False),
                    ("schema", None), ("sourceRevision", False), ("role", "writer"),
                    ("identity", None), ("accepted", True)):
                changed = json.loads(signed)
                changed["payload"][name] = value
                with self.subTest(field=name), self.assertRaises(REFUSALS):
                    verify(canonical(changed), raw)
            for changed in (signed + b"\n", bytearray(signed),
                    signed.replace(b'"schema":', b'"extra":0,"schema":', 1)):
                with self.assertRaises(REFUSALS):
                    verify(changed, raw)
            for mutate in (lambda value: value.update(originalDeadlineNs=DEADLINE - 1),
                    lambda value: value["context"].update(configuration_digest="sha256:" + "f" * 64),
                    lambda value: value["context"].update(operation="jit.decide"),
                    lambda value: value["context"].update(originalDeadlineNs=DEADLINE)):
                changed = json.loads(raw)
                mutate(changed)
                with self.assertRaises(REFUSALS):
                    verify(signed, canonical(changed))
            with self.assertRaises(REFUSALS):
                verify(signed, raw, action="persist")
            changed = json.loads(signed)
            changed["signatureBase64Url"] = "A" * 86
            with self.assertRaises(REFUSALS):
                verify(canonical(changed), raw)

    def test_original_expiry_deadline_and_narrower_receiver_never_renew(self):
        state = {"elapsed": 100}
        with clocks(state), patch.object(source.clock, "_open_on_work",
                side_effect=AssertionError("authorization must not open a new window")):
            raw = control()
            signed = sign(raw)
            narrower = (EPOCH + 50, MONOTONIC + 50, MONOTONIC + 60,
                EPOCH + LIFETIME // 4, MONOTONIC + LIFETIME // 4, WINDOW[5], WINDOW[6])
            observed = verify(signed, raw, live_window=narrower)
            self.assertEqual((observed.issued_at_epoch_ns, observed.expires_at_epoch_ns,
                observed.original_deadline_ns), (EPOCH, ORIGINAL_EXPIRY, DEADLINE))
            for issue, expiry in ((EPOCH + 101, EPOCH + 1000),
                    (EPOCH - LIFETIME, EPOCH + 1000), (EPOCH - 100, EPOCH + 100)):
                payload = json.loads(signed)["payload"]
                payload.update(issuedAtEpochNs=issue, expiresAtEpochNs=expiry)
                actual_signed = source._sign(payload, PRIVATE, PUBLIC, work())
                with self.subTest(issue=issue, expiry=expiry), self.assertRaises(REFUSALS):
                    verify(actual_signed, raw)
            state["elapsed"] = LIFETIME // 4
            with self.assertRaises(REFUSALS):
                verify(signed, raw, live_window=narrower)
            state["elapsed"] = LIFETIME // 2
            with self.assertRaises(REFUSALS):
                verify(signed, raw)
            with self.assertRaises(REFUSALS):
                sign(raw)
            state["elapsed"] = 100
            actual = source.evidence.production._sign_and_verify

            def expires(*args, **kwargs):
                signature = actual(*args, **kwargs)
                state["elapsed"] = LIFETIME // 2
                return signature

            with patch.object(source.evidence.production, "_sign_and_verify", side_effect=expires):
                with self.assertRaises(REFUSALS):
                    sign(raw)

    def test_private_relay_composition_preserves_genuinely_verified_original_interval(self):
        verifier = Ed25519PrivateKey.from_private_bytes(b"\x43" * 32)
        public = verifier.public_key()
        spki = "sha256:" + hashlib.sha256(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        verifier_identity = dict(IDENTITY, sessionIdentityDigest="sha256:" + "8" * 64)
        with clocks():
            raw = control()
            signed = sign(raw, role="verifier", signer_identity=verifier_identity,
                signer_private_key=verifier, signer_public_key=public, signer_spki_digest=spki)
            window = (EPOCH + 50, MONOTONIC + 50, MONOTONIC + 60,
                EPOCH + LIFETIME // 4, MONOTONIC + LIFETIME // 4, WINDOW[5], WINDOW[6])
            observed = verify(signed, raw, role="verifier", expected_identity=verifier_identity,
                expected_spki_digest=spki, public_key=public, live_window=window)
            meter = work()
            pins = source._pins("planner", IDENTITY, SPKI, CONFIGURATION, meter)
            source.evidence.keys._public_binding(PUBLIC, SPKI, meter)
            source.evidence.keys._pair_on_work(PRIVATE, PUBLIC, meter)
            payload = {"schema": source.SCHEMA, "sourceRevision": source.evidence.authority.SOURCE_REVISION,
                "role": "planner", "identity": pins[1], "spkiDigest": pins[2], "configurationDigest": pins[3],
                "controlDigest": frame(source.CONTROL_DOMAIN, raw), "controlByteCount": len(raw),
                "issuedAtEpochNs": observed.issued_at_epoch_ns, "expiresAtEpochNs": observed.expires_at_epoch_ns,
                "originalDeadlineNs": observed.original_deadline_ns}
            source._bind(payload, raw, observed.control, pins, window, meter)
            relayed = source._sign(payload, PRIVATE, PUBLIC, meter)
            source._bind(payload, raw, observed.control, pins, window, meter)
            actual = verify(relayed, raw, live_window=window)
            self.assertEqual((actual.issued_at_epoch_ns, actual.expires_at_epoch_ns, actual.original_deadline_ns),
                (EPOCH, ORIGINAL_EXPIRY, DEADLINE))
            self.assertEqual(actual.control, observed.control)
            self.assertNotEqual(actual.authorization_digest, observed.authorization_digest)

    def test_original_monotonic_bound_is_signed_as_narrow_epoch_expiry_before_native_keys(self):
        with clocks():
            raw = control()
            signed = sign(raw)
            selected = json.loads(signed)["payload"]
            self.assertEqual(selected["issuedAtEpochNs"], WINDOW[0])
            self.assertEqual(selected["expiresAtEpochNs"], ORIGINAL_EXPIRY)
            self.assertEqual(selected["originalDeadlineNs"], DEADLINE)
            self.assertLess(ORIGINAL_EXPIRY, WINDOW[3])
            # Wall time advances to the original narrower expiry while the
            # actual monotonic sample remains before the control deadline.
            with patch.object(source.clock.time, "time_ns", return_value=ORIGINAL_EXPIRY):
                with self.assertRaises(REFUSALS):
                    verify(signed, raw)
            invalid = json.loads(raw)
            invalid["originalDeadlineNs"] = MONOTONIC
            with patch.object(source.evidence.keys, "_public_binding",
                    side_effect=AssertionError("invalid interval reached native key")), self.assertRaises(ValueError):
                sign(canonical(invalid))

    def test_complete_comparison_reservation_precedes_actual_signature(self):
        with clocks():
            payload = json.loads(sign(control()))["payload"]
        measured = work()
        ledger = source.evidence.capture._SharedLedger(measured)
        unsigned = source.evidence.capability._wire(payload, ledger, source.MAX_BYTES, source.MAX_NODES)
        source.evidence.plan._ascii(source.evidence.plan._frame(source.SIGNATURE_DOMAIN, (unsigned,), measured), measured)
        placeholder = {"schema": source.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        size, _nodes = measured.measure(placeholder)
        payload_size, _payload_nodes = measured.measure(payload)
        reserve = 3 * payload_size + size + source.evidence.production._SIGNATURE_TRANSPORT_BYTES
        restricted = work(max_input_bytes=measured.input_bytes + reserve + payload_size - 1)
        original_limits = restricted.limits
        with patch.object(source.evidence.production, "_sign_and_verify",
                side_effect=AssertionError("incomplete output must not sign")) as native:
            with self.assertRaises(ValueError):
                source._sign(payload, PRIVATE, PUBLIC, restricted)
            native.assert_not_called()
        self.assertIs(restricted.limits, original_limits)

    def test_post_callback_graph_is_bounded_and_original_cancellation_propagates(self):
        with clocks():
            payload = json.loads(sign(control()))["payload"]
        actual = source.evidence.production._sign_and_verify
        encoder = source.evidence.plan.core.canonical_bytes
        changed = False

        def mutate(*args, **kwargs):
            nonlocal changed
            signature = actual(*args, **kwargs)
            payload["identity"]["measurementDigest"] = "x" * (source.MAX_BYTES + 1)
            changed = True
            return signature

        def encode(value):
            if changed:
                raise AssertionError("changed graph reached encoding")
            return encoder(value)

        with patch.object(source.evidence.production, "_sign_and_verify", side_effect=mutate), \
                patch.object(source.evidence.plan.core, "canonical_bytes", side_effect=encode):
            with self.assertRaises(ValueError):
                source._sign(payload, PRIVATE, PUBLIC, work())

        class Cancel(BaseException):
            pass

        failure = Cancel()
        with clocks(), patch.object(source.evidence.production, "_sign_and_verify", side_effect=failure):
            with self.assertRaises(Cancel) as caught:
                sign(control())
            self.assertIs(caught.exception, failure)


if __name__ == "__main__":
    unittest.main()
