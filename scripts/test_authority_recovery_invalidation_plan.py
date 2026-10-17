"""Original-byte/signature controls, not native or witness admission.

Real independent trees and actual Ed25519 keys exercise the proof/signature
path. Clock samples are synthetic. Native acquisition is inspected at source
and tested only for failure propagation; no successful database DTO is used.
"""
from __future__ import annotations

import ast
import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from catchplate import authority_recovery_invalidation_plan as plan
from catchplate import authority_recovery_invalidation_plan_owner as source
from test_authority_recovery_invalidation import fixture, meter
from test_authority_recovery_invalidation_acquisition import request_for


def digest(value):
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def materials(**changes):
    call = fixture(**changes)
    request = request_for(call)
    call["context"]["arguments"] = copy.deepcopy(request["arguments"])
    call["context"]["requestDigest"] = request["requestDigest"]
    raw = plan.proof.produce_originals(**call, work=meter())
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    spki = "sha256:" + hashlib.sha256(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    identity = {name: digest(name) for name in source._IDENTITY_FIELDS}
    epoch = plan._cutoff_ns(call["context"]["databaseNow"])
    age, skew, before = 5_000_000_000, 1000, 1000
    window = (epoch, before, before + 1, epoch + age, before + age, age, skew)
    expected = dict(context=copy.deepcopy(call["context"]), configurationDigest=digest("configuration"),
        plannerIdentity=identity, plannerSpkiDigest=spki, operationId=request["operationId"],
        originalDeadlineNs=before + 4_000_000_000, maximumPlanAgeNs=age, maximumClockSkewNs=skew)
    return call, request, raw, private, public, window, expected


@contextmanager
def clocks(window, *, advance=1000):
    values = [window[0] + advance, window[1] + advance]
    with patch.object(plan.clock.time, "time_ns", side_effect=lambda: values[0]), \
            patch.object(plan.clock.time, "monotonic_ns", side_effect=lambda: values[1]):
        yield values


def sign(parts, *, work=None, check=lambda: None, raw=None):
    _call, request, original, private, public, window, expected = parts
    work = work if work is not None else meter()
    return plan._produce_on_work(request_bytes=plan.proof.core.canonical_bytes(request),
        proof_bytes=original if raw is None else raw, expectations=expected,
        planner_private_key=private, planner_public_key=public, issued_at_epoch_ns=window[0],
        expires_at_epoch_ns=window[0] + expected["originalDeadlineNs"] - window[1],
        live_window=window, check=check, work=work)


def verify(parts, signed, *, expected=None, window=None, work=None, check=lambda: None):
    return plan.verify_originals(envelope_bytes=signed.envelope_bytes,
        request_bytes=signed.request_bytes, proof_bytes=signed.proof_bytes,
        expectations=parts[6] if expected is None else expected, planner_public_key=parts[4],
        live_window=parts[5] if window is None else window, check=check,
        work=meter() if work is None else work)


def owner(parts, **changes):
    _call, _request, _raw, private, public, _window, expected = parts
    native = source.planning.RecoveryInvalidationReadPlanner(read_dsn="host=synthetic.invalid dbname=synthetic",
        connect_timeout_seconds=2, database_identity=("synthetic_read", "CN=synthetic", "17", "CN=syntheticCA",
            *(expected["plannerIdentity"][name] for name in source._IDENTITY_FIELDS)),
        terminal_retention_seconds=expected["context"]["terminalRetentionSeconds"],
        maximum_retained=expected["context"]["maximumRetained"])
    arguments = dict(read_planner=native, planner_private_key=private, planner_public_key=public,
        expected_planner_identity=expected["plannerIdentity"], expected_planner_spki_digest=expected["plannerSpkiDigest"],
        configuration_digest=expected["configurationDigest"], maximum_plan_age_ns=expected["maximumPlanAgeNs"],
        maximum_clock_skew_ns=expected["maximumClockSkewNs"])
    return source.RecoveryInvalidationPlanOwner(**{**arguments, **changes})


def produce_arguments(parts, work, check=lambda: None):
    context, expected = parts[0]["context"], parts[6]
    return dict(request=parts[1], business_before_roots=tuple(context["businessBeforeRoots"]),
        authorization_before_roots=tuple(context["authorizationBeforeRoots"]),
        expected_counted_heads=tuple(context["countedBeforeHeads"]), live_window=parts[5],
        original_deadline_ns=expected["originalDeadlineNs"], check=check, work=work)


class RecoveryInvalidationPlanControls(unittest.TestCase):
    def test_audited_recovery_contracts_require_the_real_shared_counter(self):
        capacity = plan.proof.terminal.capacity
        for name in ("create", "candidate", "finalize", "invalidate"):
            with self.subTest(operation=name):
                spec = plan.proof.contract.operation_spec("webauthn.recovery." + name)
                self.assertTrue(capacity._participates(spec))
                capacity._require_counter_permission(spec)
        for name in ("expire", "prune"):
            with self.subTest(operation=name):
                spec = plan.proof.contract.operation_spec("webauthn.recovery." + name)
                self.assertFalse(capacity._participates(spec))
                self.assertNotIn("aggregate-high-water", spec["proofPrimitives"])
                self.assertNotIn(capacity.AGGREGATE_TABLE, spec["businessWrites"])

    def test_real_raw_replay_and_signature_close_both_active_branches(self):
        for kind in ("replacement-registration", "lost-active-key-decommission"):
            parts = materials(kind=kind)
            with self.subTest(kind=kind), clocks(parts[5]):
                signed = sign(parts)
                replayed = verify(parts, signed)
            self.assertTrue(replayed.replay.affected)
            self.assertEqual(signed.plan_digest, replayed.plan_digest)
            self.assertEqual(signed.replay.mutations, replayed.replay.mutations)
            self.assertEqual(len(replayed.replay.write.primary.business_after_roots), 5)
            self.assertEqual(replayed.replay.write.primary.authorization_after_roots, ())
            self.assertEqual(len(replayed.replay.counted_after_heads), 9)

    def test_absent_and_terminal_targets_remain_genuine_noops(self):
        for absent in (True, False):
            parts = materials(absent=absent, status="expired")
            with self.subTest(absent=absent), clocks(parts[5]):
                signed = sign(parts)
                replayed = verify(parts, signed)
            self.assertFalse(replayed.replay.affected)
            self.assertEqual(replayed.replay.mutations, ())
            self.assertEqual(tuple(root.json_projection()
                for root in replayed.replay.write.primary.business_after_roots),
                tuple(parts[0]["context"]["businessBeforeRoots"]))

    def test_independent_pins_and_corrupt_raw_membership_refuse_before_signing(self):
        parts = materials()
        with clocks(parts[5]):
            signed = sign(parts)
            for field in ("configurationDigest", "operationId", "context"):
                changed = copy.deepcopy(parts[6])
                if field == "context":
                    changed[field]["maximumRetained"] += 1
                else:
                    changed[field] = digest("different")
                with self.subTest(field=field), self.assertRaises((ValueError, RuntimeError)):
                    verify(parts, signed, expected=changed)
            raw = json.loads(parts[2])
            raw["selectedRows"][0]["row"]["status"] = "invalidated"
            corrupted = plan.proof.core.canonical_bytes(raw)
            with patch.object(plan.evidence.production, "_sign_and_verify",
                    side_effect=AssertionError("corrupt proof reached signer")):
                with self.assertRaises((ValueError, RuntimeError)):
                    sign(parts, raw=corrupted)
            changed = json.loads(signed.envelope_bytes)
            changed["payload"]["expiresAtEpochNs"] -= 1
            with self.assertRaises(InvalidSignature):
                plan.verify_originals(envelope_bytes=plan.proof.core.canonical_bytes(changed),
                    request_bytes=signed.request_bytes, proof_bytes=signed.proof_bytes,
                    expectations=parts[6], planner_public_key=parts[4], live_window=parts[5],
                    check=lambda: None, work=meter())

    def test_later_shorter_receiver_preserves_original_interval_and_refuses_at_local_bound(self):
        parts = materials()
        with clocks(parts[5]):
            signed = sign(parts)
        epoch, before, _after, _expiry, _deadline, age, skew = parts[5]
        receiver = (epoch + 1_000_000, before + 1_000_000, before + 1_000_001,
            epoch + 2_000_000_000, before + 2_000_000_000, age, skew)
        with clocks(receiver) as ticks:
            replayed = verify(parts, signed, window=receiver)
            self.assertEqual(replayed.envelope_bytes, signed.envelope_bytes)
            ticks[:] = [receiver[3], receiver[4]]
            with self.assertRaises(ValueError):
                verify(parts, signed, window=receiver)
        original = json.loads(signed.envelope_bytes)["payload"]
        self.assertEqual(original["issuedAtEpochNs"], epoch)
        self.assertEqual(original["expiresAtEpochNs"], epoch + 4_000_000_000)

    def test_clock_after_real_sign_and_original_work_callback_failures_do_not_escape(self):
        parts = materials(absent=True)
        actual_sign = plan.evidence.production._sign_and_verify
        with clocks(parts[5]) as ticks:
            def expire(*args):
                result = actual_sign(*args)
                ticks[:] = [parts[5][0] + 4_000_000_000, parts[6]["originalDeadlineNs"]]
                return result
            with patch.object(plan.evidence.production, "_sign_and_verify", side_effect=expire):
                with self.assertRaises(ValueError):
                    sign(parts)
        with clocks(parts[5]):
            work = meter()
            with self.assertRaises(ValueError):
                sign(parts, work=work, check=lambda: work.charge(hashes=1))
            with self.assertRaises(KeyboardInterrupt):
                sign(parts, check=lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
            with self.assertRaises(ValueError):
                sign(parts, work=meter(max_input_bytes=1024))

    def test_exact_native_owner_is_inert_and_failure_is_single_use_not_success(self):
        parts = materials(absent=True)
        instance = owner(parts)
        self.assertEqual(instance.operation, "webauthn.recovery.invalidate")
        with self.assertRaises(ValueError):
            owner(parts, read_planner=object())
        with self.assertRaises(ValueError):
            owner(parts, expected_planner_identity={name: digest("other") for name in source._IDENTITY_FIELDS})
        work = meter()
        class NativeStopped(BaseException):
            pass
        with clocks(parts[5]), patch.object(source.planning.RecoveryInvalidationReadPlanner,
                "acquire_originals", side_effect=NativeStopped) as boundary:
            with self.assertRaises(NativeStopped):
                instance.produce(**produce_arguments(parts, work))
            self.assertEqual(boundary.call_count, 1)
            self.assertIs(boundary.call_args.kwargs["work"], work)
            self.assertIs(boundary.call_args.kwargs["live_window"], parts[5])
            with self.assertRaises(ValueError):
                instance.produce(**produce_arguments(parts, meter()))
            self.assertEqual(boundary.call_count, 1)

    def test_source_joins_direct_native_bytes_to_reconstruction_replay_and_original_work(self):
        text = Path(source.__file__).read_text("utf-8")
        tree = ast.parse(text)
        owner_type = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "RecoveryInvalidationPlanOwner")
        produce = next(node for node in owner_type.body if isinstance(node, ast.FunctionDef)
            and node.name == "produce")
        calls = {ast.unparse(node.func): node for node in ast.walk(produce) if isinstance(node, ast.Call)}
        native = calls["planning.RecoveryInvalidationReadPlanner.acquire_originals"]
        context = calls["_native_context"]
        signed = calls["plan._produce_on_work"]
        self.assertLess(native.lineno, context.lineno)
        self.assertLess(context.lineno, signed.lineno)
        self.assertEqual(ast.unparse(context.args[0]), "raw")
        for call in (native, signed):
            self.assertEqual(next(ast.unparse(item.value) for item in call.keywords if item.arg == "work"), "work")
        self.assertNotIn("_open_on_work", text)
        self.assertFalse(any(isinstance(node, ast.Call) and ast.unparse(node.func) == "_ValidationWork"
            for node in ast.walk(tree)))
        plan_tree = ast.parse(Path(plan.__file__).read_text("utf-8"))
        for name in ("_produce_on_work", "verify_originals"):
            method = next(node for node in plan_tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
            replay = [node for node in ast.walk(method) if isinstance(node, ast.Call)
                and ast.unparse(node.func) == "proof.replay_originals"]
            self.assertEqual(len(replay), 1)
            self.assertEqual(next(ast.unparse(item.value) for item in replay[0].keywords
                if item.arg == "expected_context"), "expected['context']")


if __name__ == "__main__":
    unittest.main()
