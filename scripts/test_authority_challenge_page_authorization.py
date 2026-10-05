#!/usr/bin/env python3
"""Real Ed25519 on synthetic controls; no peer/key enrollment or proof claim.

Clock doubles model only an original local interval. Actual source control
decoding, key binding, signing and signature verification are exercised. No
transport, SQL, protected keys, hardware or successful evidence DTO is used.
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

from serverware import authority_challenge_page_authorization as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_page_control import arguments as control_arguments


EPOCH, MONOTONIC, LIFETIME = 1_800_000_000_000_000_000, 1_000_000_000, 1_000_000_000
WINDOW = (EPOCH, MONOTONIC, MONOTONIC + 10, EPOCH + LIFETIME, MONOTONIC + LIFETIME, LIFETIME, 0)
DEADLINE = MONOTONIC + LIFETIME // 2
IDENTITY = dict(zip(("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"),
    ("sha256:" + digit * 64 for digit in "123")))
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
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
    values = control_arguments(action)
    values["context"]["originalDeadlineNs"] = DEADLINE
    return source.control.encode_control(**values, work=work())


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


class ChallengePageAuthorizationControls(unittest.TestCase):
    def test_actual_signatures_and_independent_domains_for_allowed_directions(self):
        with clocks():
            for role, action in (("planner", "persist"), ("planner", "read"), ("verifier", "read")):
                with self.subTest(role=role, action=action):
                    raw = control(action)
                    signed = sign(raw, action=action, role=role)
                    observed = verify(signed, raw, action=action, role=role)
                    envelope = json.loads(signed)
                    self.assertEqual(signed, canonical(envelope))
                    payload = envelope["payload"]
                    signature = base64.urlsafe_b64decode(envelope["signatureBase64Url"] + "==")
                    PUBLIC.verify(signature, frame(source.SIGNATURE_DOMAIN, canonical(payload)).encode("ascii"))
                    self.assertEqual(payload["controlDigest"], frame(source.CONTROL_DOMAIN, raw))
                    self.assertEqual(observed.authorization_digest, frame(source.IDENTITY_DOMAIN, signed))
                    self.assertEqual((observed.issued_at_epoch_ns, observed.expires_at_epoch_ns,
                        observed.original_deadline_ns), (WINDOW[0], WINDOW[3], DEADLINE))
                    self.assertEqual(observed.control["action"], action)
                    # This observation contains only the original control, not
                    # a claimed verified body, accepted proof or live DB result.
                    self.assertEqual(set(observed.control), source.control.FIELDS)

    def test_role_configuration_and_real_key_binding_refuse_substitution(self):
        with clocks():
            raw = control()
            signed = sign(raw)
            other = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
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

    def test_expected_identity_is_owned_before_first_native_key_callback(self):
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

    def test_closed_canonical_originals_exact_scalars_and_detached_control_join(self):
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
            for changed in (signed + b"\n", bytearray(signed), signed.replace(b'"schema":', b'"extra":0,"schema":', 1)):
                with self.assertRaises(REFUSALS):
                    verify(changed, raw)
            altered = json.loads(raw)
            altered["context"]["originalDeadlineNs"] -= 1
            with self.assertRaises(REFUSALS):
                verify(signed, canonical(altered))
            with self.assertRaises(REFUSALS):
                verify(signed, raw, action="persist")
            changed = json.loads(signed)
            changed["signatureBase64Url"] = "A" * 86
            with self.assertRaises(REFUSALS):
                verify(canonical(changed), raw)

    def test_original_deadline_expiry_and_narrow_receiver_do_not_renew(self):
        state = {"elapsed": 100}
        with clocks(state):
            raw = control()
            signed = sign(raw)
            narrower = (EPOCH + 50, MONOTONIC + 50, MONOTONIC + 60,
                EPOCH + LIFETIME // 4, MONOTONIC + LIFETIME // 4, WINDOW[5], WINDOW[6])
            observed = verify(signed, raw, live_window=narrower)
            self.assertEqual(observed.issued_at_epoch_ns, EPOCH)
            self.assertEqual(observed.expires_at_epoch_ns, WINDOW[3])
            self.assertEqual(observed.original_deadline_ns, DEADLINE)
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

    def test_complete_signing_comparison_is_reserved_before_native_sign(self):
        with clocks():
            payload = json.loads(sign(control()))["payload"]
        # Independently advance only the real pre-sign measurements to select
        # one byte less than the exact required post-callback reservation.
        measured = work()
        ledger = source.evidence.capture._SharedLedger(measured)
        unsigned = source.evidence.capability._wire(payload, ledger, source.MAX_BYTES, source.MAX_NODES)
        source.evidence.plan._ascii(source.evidence.plan._frame(source.SIGNATURE_DOMAIN, (unsigned,), measured), measured)
        placeholder = {"schema": source.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        size, nodes = measured.measure(placeholder)
        payload_size, payload_nodes = measured.measure(payload)
        reserve = 3 * payload_size + size + source.evidence.production._SIGNATURE_TRANSPORT_BYTES
        restricted = work(max_input_bytes=measured.input_bytes + reserve + payload_size - 1)
        original_limits = restricted.limits
        with patch.object(source.evidence.production, "_sign_and_verify",
                side_effect=AssertionError("incomplete output must not sign")) as native:
            with self.assertRaises(ValueError):
                source._sign(payload, PRIVATE, PUBLIC, restricted)
            native.assert_not_called()
        self.assertIs(restricted.limits, original_limits)

    def test_changed_graph_is_bounded_before_post_sign_encoding_and_cancellation_propagates(self):
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
