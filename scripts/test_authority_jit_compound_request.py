"""UNRUN real-signature/synthetic-original controls and measured source joins.

The codec uses real Ed25519 and genuine typed-request/root fixtures. Only
native clock samples are doubled. Source inspection does not import
AuthorityProcess or fabricate measured/native/custody success. The socketpair
control covers local descriptor/peer identity only, not configured peer admission.
The clock-only private-owner control isolates processing-bound arithmetic; it
does not stand in for the measured factory or any producer/page I/O acceptance.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import copy
import hashlib
import inspect
import json
import os
import socket
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from catchplate import authority_jit_compound_request as source
from catchplate import authority_jit_compound_request_service as measured
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_connected_originals import connected_fixture


EPOCH, MONO, LIFE = 1_800_000_000_000_000_000, 1_000_000_000, 1_000_000_000
WINDOW = (EPOCH, MONO, MONO + 10, EPOCH + LIFE, MONO + LIFE, LIFE, 1000)
DEADLINE = MONO + LIFE // 2
BOOT, PID = "01234567-89ab-cdef-0123-456789abcdef", 1234
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
PUBLIC = PRIVATE.public_key()
PLANNER = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32).public_key()
REFUSALS = (ValueError, InvalidSignature)


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def frame(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0"
        + len(raw).to_bytes(8, "big") + raw).hexdigest()


def digest(value):
    return "sha256:" + value * 64


def spki(key):
    return "sha256:" + hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def pins():
    fields = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
    return dict(configurationDigest=digest("a"), generationSequence=2, generationDigest=digest("b"),
        verifierIdentity=dict(zip(fields, map(digest, "123"), strict=True)), verifierSpkiDigest=spki(PUBLIC),
        plannerIdentity=dict(zip(fields, map(digest, "456"), strict=True)), plannerSpkiDigest=spki(PLANNER))


@contextmanager
def clocks(state=None):
    state = {"elapsed": 100} if state is None else state
    with patch.object(source.time, "monotonic_ns", side_effect=lambda: MONO + state["elapsed"]), \
            patch.object(source.clock.time, "time_ns",
                side_effect=lambda: EPOCH + state.get("epoch_elapsed", state["elapsed"])):
        yield state


def arguments():
    fixture = connected_fixture()
    return dict(request_bytes=canonical(fixture["request"]),
        business_before_roots=tuple(root.json_projection() for root in fixture["business_before_roots"]),
        authorization_before_roots=tuple(root.json_projection() for root in fixture["authorization_before_roots"]),
        expected_counted_heads=tuple(dict(indexId=head.index_id, indexRevision=head.index_revision,
            rootDigest=head.index_root.digest, leafCount=head.index_root.count)
            for head in fixture["counted_before_heads"]), pins=pins(), verifier_private_key=PRIVATE,
        verifier_public_key=PUBLIC, original_window=WINDOW, original_deadline_ns=DEADLINE,
        sender_process_id=PID, sender_boot_id=BOOT, work=work())


def verify(control, raw, **changes):
    values = dict(control_bytes=control, request_bytes=raw, pins=pins(), verifier_public_key=PUBLIC,
        receiver_window=WINDOW, expected_sender_process_id=PID, expected_boot_id=BOOT, work=work())
    values.update(changes)
    return source.verify_request(**values)


class JitCompoundRequestControls(unittest.TestCase):
    def test_real_signature_binds_exact_original_request_rosters_and_sender_bracket(self):
        values = arguments()
        with clocks():
            control = source.sign_request(**values)
            observed = verify(control, values["request_bytes"])
        envelope = json.loads(control)
        self.assertEqual(control, canonical(envelope))
        payload = envelope["payload"]
        self.assertEqual(set(payload), source.FIELDS)
        PUBLIC.verify(base64.urlsafe_b64decode(envelope["signatureBase64Url"] + "=="),
            frame(source.SIGNATURE_DOMAIN, canonical(payload)).encode("ascii"))
        self.assertEqual(payload["requestBytesDigest"], frame(source.parent.REQUEST_DOMAIN, values["request_bytes"]))
        self.assertEqual((len(payload["businessBeforeRoots"]), len(payload["authorizationBeforeRoots"]),
            len(payload["countedBeforeHeads"])), (4, 4, 12))
        self.assertEqual(observed.original_window, WINDOW)
        self.assertEqual(observed.request, json.loads(values["request_bytes"]))
        self.assertEqual(payload["expiresAtEpochNs"], EPOCH + DEADLINE - MONO)
        self.assertEqual((payload["senderProcessId"], payload["senderBootId"]), (PID, BOOT))
        with self.assertRaises(InvalidSignature):
            PUBLIC.verify(base64.urlsafe_b64decode(envelope["signatureBase64Url"] + "=="),
                frame(source.parent.SIGNATURE_DOMAIN, canonical(payload)).encode("ascii"))

    def test_wrong_signature_configuration_generation_identity_boot_and_peer_pid_refuse(self):
        values = arguments()
        with clocks():
            control = source.sign_request(**values)
            wrong = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32).public_key()
            choices = [dict(verifier_public_key=wrong), dict(expected_sender_process_id=PID + 1),
                dict(expected_boot_id="11234567-89ab-cdef-0123-456789abcdef")]
            for field, value in (("configurationDigest", digest("c")), ("generationSequence", 3),
                    ("generationDigest", digest("d")), ("verifierSpkiDigest", digest("e")),
                    ("plannerSpkiDigest", digest("f"))):
                altered = pins()
                altered[field] = value
                choices.append(dict(pins=altered))
            for change in choices:
                with self.subTest(change=tuple(change)), self.assertRaises(REFUSALS):
                    verify(control, values["request_bytes"], **change)
            envelope = json.loads(control)
            envelope["signatureBase64Url"] = "A" * 86
            with self.assertRaises(REFUSALS):
                verify(canonical(envelope), values["request_bytes"])

    def test_closed_scalar_and_roster_shapes_refuse_before_key_verification(self):
        values = arguments()
        with clocks():
            control = source.sign_request(**values)
            for field, value in (("operation", "jit.decide"), ("requestByteCount", True),
                    ("originalDeadlineNs", False), ("senderProcessId", True),
                    ("senderBootId", None), ("originalWindow", list(WINDOW[:-1])),
                    ("businessBeforeRoots", []), ("accepted", True)):
                envelope = json.loads(control)
                envelope["payload"][field] = value
                with self.subTest(field=field), patch.object(source.evidence.capability, "_signature",
                        side_effect=AssertionError("invalid shape reached signature")), self.assertRaises(ValueError):
                    verify(canonical(envelope), values["request_bytes"])
            for raw in (control + b"\n", bytearray(control)):
                with self.assertRaises(ValueError):
                    source.decode_control(raw, work=work())
            envelope = json.loads(control)
            envelope["payload"]["countedBeforeHeads"].reverse()
            with self.assertRaises(ValueError):
                source.decode_control(canonical(envelope), work=work())
            envelope = json.loads(control)
            envelope["payload"]["authorizationBeforeRoots"][0]["leafCount"] = True
            with self.assertRaises(ValueError):
                source.decode_control(canonical(envelope), work=work())

    def test_actual_request_commitment_and_mutable_inputs_are_owned_before_native_keys(self):
        values = arguments()
        original_pins, original_roots = copy.deepcopy(values["pins"]), copy.deepcopy(values["business_before_roots"])
        actual = source.evidence.keys._public_binding
        def mutate(*args, **kwargs):
            values["pins"]["configurationDigest"] = digest("f")
            values["business_before_roots"][0]["rootDigest"] = digest("f")
            return actual(*args, **kwargs)
        with clocks(), patch.object(source.evidence.keys, "_public_binding", side_effect=mutate):
            control = source.sign_request(**values)
        payload = json.loads(control)["payload"]
        self.assertEqual(payload["configurationDigest"], original_pins["configurationDigest"])
        self.assertEqual(payload["businessBeforeRoots"], list(original_roots))
        changed = json.loads(values["request_bytes"])
        changed["requestDigest"] = digest("f")
        values["request_bytes"] = canonical(changed)
        with patch.object(source.evidence.keys, "_public_binding", side_effect=AssertionError("key")), \
                self.assertRaises(ValueError):
            source.sign_request(**values)

    def test_receiver_is_independent_and_original_epoch_and_monotonic_are_never_renewed(self):
        values = arguments()
        state = {"elapsed": 100}
        receiver = (EPOCH + 50, MONO + 50, MONO + 60,
            EPOCH + LIFE // 4, MONO + LIFE // 4, LIFE, 1000)
        with clocks(state), patch.object(source.clock, "_open_on_work", side_effect=AssertionError("new clock")):
            control = source.sign_request(**values)
            observed = verify(control, values["request_bytes"], receiver_window=receiver)
            self.assertEqual(observed.original_window, WINDOW)
            self.assertNotEqual(observed.original_window, receiver)
            state["elapsed"] = LIFE // 4
            with self.assertRaises(ValueError):
                verify(control, values["request_bytes"], receiver_window=receiver)
            state["elapsed"] = LIFE // 2
            with self.assertRaises(ValueError):
                verify(control, values["request_bytes"])
            state.update(elapsed=LIFE // 2 - 100, epoch_elapsed=LIFE // 2)
            with self.assertRaises(ValueError):
                verify(control, values["request_bytes"])

    def test_tiny_work_refuses_before_signing_and_postsign_mutation_cannot_escape(self):
        values = arguments()
        values["work"] = work(max_input_bytes=128)
        with patch.object(source.evidence.production, "_sign_and_verify", side_effect=AssertionError("sign")), \
                self.assertRaises(ValueError):
            source.sign_request(**values)
        values = arguments()
        with clocks():
            control = source.sign_request(**values)
            payload = json.loads(control)["payload"]
            actual = source.evidence.production._sign_and_verify
            def mutate(*args, **kwargs):
                signature = actual(*args, **kwargs)
                payload["requestDigest"] = digest("f")
                return signature
            with patch.object(source.evidence.production, "_sign_and_verify", side_effect=mutate), \
                    self.assertRaises(ValueError):
                source._sign(payload, PRIVATE, PUBLIC, work())

    def test_actual_unix_socket_peer_descriptor_and_closed_socket_refusal(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            identity = measured._peer(left)
            self.assertEqual(identity[3:], (os.getuid(), os.getgid(), os.getpid()))
            self.assertEqual(identity, measured._peer(left))
            self.assertNotEqual(identity[:3], measured._peer(right)[:3])
            left.close()
            with self.assertRaises((ValueError, OSError)):
                measured._peer(left)
        finally:
            left.close()
            right.close()

    def test_private_page_bounds_keep_originals_and_refuse_shorter_receiver_epoch(self):
        values = arguments()
        receiver = (EPOCH + 50, MONO + 50, MONO + 60,
            EPOCH + LIFE // 4, MONO + LIFE // 4, LIFE, 1000)
        stage = work()

        class ClockOnlyCaller:
            window, deadline = receiver, MONO + 200

            def local(self):
                pass

            def check(self, actual_work):
                source.clock._check_on_work(self.window, work=actual_work)

        state = {"elapsed": 100}
        with clocks(state):
            control = source.sign_request(**values)
            verified = verify(control, values["request_bytes"], receiver_window=receiver)
            caller = ClockOnlyCaller()

            def owner():
                return measured._RequestOwner(caller, verified, pins(),
                    (control, values["request_bytes"]))

            actual = owner()
            before = stage.hash_work, stage.input_bytes, stage.json_nodes
            self.assertEqual(measured._page_bounds(actual, original_window=actual.original,
                original_deadline_ns=DEADLINE, work=stage), (MONO + 200, EPOCH + 200))
            self.assertEqual((stage.hash_work, stage.input_bytes, stage.json_nodes), before)
            self.assertIs(actual.original, verified.original_window)
            self.assertEqual(actual.original_deadline, DEADLINE)
            for window, deadline in ((tuple(list(actual.original)), DEADLINE),
                    (actual.original, DEADLINE - 1), (actual.original, True)):
                rejected = owner()
                with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                    measured._page_bounds(rejected, original_window=window,
                        original_deadline_ns=deadline, work=stage)
                self.assertTrue(rejected.failed)
            inactive = owner()
            inactive.active = False
            with self.assertRaises(ValueError):
                measured._page_bounds(inactive, original_window=inactive.original,
                    original_deadline_ns=DEADLINE, work=stage)
            # Original/receiver epoch ends and all monotonic bounds are live;
            # only the effective receiver-mapped transport expiry has elapsed.
            state.update(elapsed=150, epoch_elapsed=200)
            source._live(actual.original, receiver, DEADLINE, stage)
            with self.assertRaises(ValueError):
                measured._page_bounds(actual, original_window=actual.original,
                    original_deadline_ns=DEADLINE, work=stage)
            self.assertTrue(actual.failed)

    def test_source_calls_only_actual_process_producer_and_preserves_send_owner(self):
        tree = ast.parse(inspect.getsource(measured))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "service.AuthorityProcess._produce_jit_compound"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].args[0]), "self.caller.process")
        arguments_by_name = {item.arg: ast.unparse(item.value) for item in calls[0].keywords}
        self.assertEqual(arguments_by_name["live_window"], "self.original")
        self.assertEqual(arguments_by_name["original_deadline_ns"], "self.original_deadline")
        self.assertEqual(arguments_by_name["processing_owner"], "self")
        text = inspect.getsource(measured)
        self.assertIn("type(produced) is production.ProducedJitCompoundPlan", text)
        self.assertIn("type(produced.verified) is request.parent.VerifiedJitCompoundPlan", text)
        self.assertIn("request._join_parent(originals, payload, self.pins,", text)
        self.assertIn("yield owner\n        owner.check(work)", text)
        self.assertIn("owner.active = False", text)
        self.assertIn("type(owner) is _RequestOwner", text)
        self.assertIn("original_window is owner.original", text)
        self.assertIn("return owner._deadline_ns, owner._epoch_bound", text)
        for forbidden in ("_ValidationWork(", "_open_on_work(", "socket.socket(", "connection.close(",
                "WRITER_POSTGRES_DSN", "retain_original=", "read_original="):
            self.assertNotIn(forbidden, text)
        self.assertEqual(source.RAW4_MAXIMA, (32768, 4194304, 65536, 131072))


if __name__ == "__main__":
    unittest.main()
