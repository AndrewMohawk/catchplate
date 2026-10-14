#!/usr/bin/env python3
"""Functional literal framing and owner refusals, not cold/SQL acceptance.

The >4 MiB fixture contains real native-row chunk spellings, but its roots and
membership proofs are deliberately not authenticated. No successful kernel or
native verdict is mocked. Positive framing is not positive protected review.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_native_jit_review_plan_owner as owner
from serverware import authority_native_jit_review_plan_stream as stream
from serverware import authority_release_private_request as request_source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_native_jit_review_current_chunks import canonical, frames, native, row

reads, wire = stream.reads, stream.reads.contract
DIGEST = "sha256:" + "a" * 64
TOKEN = b"Z" * 64


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def window():
    return reads.head.clock._open_on_work(deadline_epoch_ns=time.time_ns() + 30_000_000_000,
        maximum_lifetime_ns=30_000_000_000, maximum_clock_skew_ns=0, work=meter())


def literals(operation=wire.AUTHORIZE, *, large=False):
    rows = []
    for slot in range(13 if operation == wire.RECEIPT else 9):
        value = row(slot)
        if slot == 3 and large:
            # Literal string fields, not parsed or authenticated trust material.
            value["bundle_json"] = "b" * (2 * 1024 * 1024)
            value["withdrawn_credential_ids_json"] = "w" * (1024 * 1024)
        rows.append({"chunks": tuple(canonical({"rows": [part]}) for part in frames(native(value))),
            "proof": canonical({"syntheticUnverifiedMembershipSlot": slot})})
    result = {"schema": reads.SCHEMA, "operation": operation, "requestDigest": DIGEST,
        "databaseNowEpochNs": time.time_ns(), "trustPublicationId": "publication-one", "rows": tuple(rows)}
    result.update((name, canonical({"syntheticUnverifiedRootSlot": index}))
        for index, (name, _maximum) in enumerate(stream._ROOTS))
    return result


class StreamTests(unittest.TestCase):
    def encode(self, values, *, live=None, deadline=None):
        live = window() if live is None else live
        return stream.encode_on_work(values, operation=values["operation"], request_digest=DIGEST,
            live_window=live, deadline_ns=live[4] if deadline is None else deadline, work=meter())

    def decode(self, original, chunks, *, operation=wire.AUTHORIZE, digest=DIGEST, live=None, deadline=None):
        live = window() if live is None else live
        return stream.decode_on_work(original, chunks, operation=operation, request_digest=digest,
            live_window=live, deadline_ns=live[4] if deadline is None else deadline, work=meter())

    def test_literal_roundtrip_both_fixed_row_inventories(self):
        for operation in wire.OPERATIONS:
            with self.subTest(operation=operation):
                value = literals(operation)
                original, chunks = self.encode(value)
                self.assertEqual(self.decode(original, chunks, operation=operation), value)
                self.assertIs(type(chunks), tuple)
                self.assertTrue(all(type(raw) is bytes and len(raw) <= stream.FRAME_BYTES for raw in chunks))

    def test_more_than_four_mib_originals_roundtrip_without_whole_packet_expansion(self):
        value = literals(large=True)
        original, chunks = self.encode(value)
        self.assertGreater(sum(map(len, chunks)), 4 * 1024 * 1024)
        self.assertLessEqual(sum(map(len, chunks)), stream.MAX_ORIGINAL_BYTES)
        self.assertLessEqual(len(original), stream.MAX_MANIFEST_BYTES)
        self.assertTrue(any(len(raw) == stream.FRAME_BYTES for raw in chunks))
        self.assertEqual(self.decode(original, chunks), value)
        self.assertNotIn(TOKEN, original)
        self.assertTrue(all(TOKEN not in raw for raw in chunks))

    def test_changed_reordered_truncated_missing_extra_and_mutable_frames_refuse(self):
        original, chunks = self.encode(literals())
        candidates = (
            (b"!" + chunks[0][1:],) + chunks[1:],
            (chunks[1], chunks[0]) + chunks[2:],
            (chunks[0][:-1],) + chunks[1:],
            chunks[:-1], chunks + (b"{}",),
            (bytearray(chunks[0]),) + chunks[1:], list(chunks),
        )
        for candidate in candidates:
            with self.subTest(kind=type(candidate).__name__, length=len(candidate)):
                with self.assertRaises(ValueError):
                    self.decode(original, candidate)

    def test_manifest_wrong_purpose_digest_layout_and_literal_spelling_refuse(self):
        original, chunks = self.encode(literals())
        manifest = json.loads(original)
        changes = []
        for name, value in (("schema", "other-purpose"), ("extra", True)):
            changed = copy.deepcopy(manifest)
            changed[name] = value
            changes.append(canonical(changed))
        for counts in ([1] * 13, [99] + [1] * 8, [True] + [1] * 8):
            changed = copy.deepcopy(manifest)
            changed["rowChunkCounts"] = counts
            changes.append(canonical(changed))
        changes.extend((b" " + original, original[:-1], original.replace(b'"schema":', b'"schema":null,"schema":', 1)))
        for changed in changes:
            with self.assertRaises(ValueError):
                self.decode(changed, chunks)
        with self.assertRaises(ValueError):
            self.decode(original, chunks, operation=wire.RECEIPT)
        with self.assertRaises(ValueError):
            self.decode(original, chunks, digest="sha256:" + "b" * 64)

    def test_original_container_and_leaf_bounds_refuse_before_streaming(self):
        for mutation in ("extra", "wrong_rows", "mutable", "oversize", "surplus_chunks"):
            value = literals()
            if mutation == "extra":
                value["sessionToken"] = TOKEN
            elif mutation == "wrong_rows":
                value["rows"] += (value["rows"][0],)
            elif mutation == "mutable":
                value["rows"][0]["proof"] = bytearray(b"{}")
            elif mutation == "oversize":
                value["rows"][0]["proof"] = b"x" * (reads.MAX_PROOF_BYTES + 1)
            else:
                value["rows"][0]["chunks"] = (b"{}",) * 99
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.encode(value)

    def test_expired_original_deadline_refuses_both_directions(self):
        value = literals()
        original, chunks = self.encode(value)
        live = window()
        with self.assertRaises(ValueError):
            self.encode(value, live=live, deadline=live[1])
        with self.assertRaises(ValueError):
            self.decode(original, chunks, live=live, deadline=live[1])

    def test_original_parent_and_completed_stage_ledgers_cannot_be_replaced_or_reset(self):
        for mutation in ("parent_charge", "parent_limits", "completed_stage", "repeat_stage"):
            parent, live = meter(), window()
            budget = stream._StreamWork(parent, live, live[4], 6)
            with budget.stage(0) as child:
                child.charge(input_bytes=3)
            if mutation == "parent_charge":
                parent.charge(input_bytes=1)
            elif mutation == "parent_limits":
                parent.limits = QueryReadValidationLimits()
            elif mutation == "completed_stage":
                child.charge(input_bytes=1)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                with budget.stage(0 if mutation == "repeat_stage" else 1):
                    pass
            self.assertTrue(budget.failed)


class PlanOwnerRefusals(unittest.TestCase):
    def configured(self, operation=wire.AUTHORIZE, **overrides):
        key, live = Ed25519PrivateKey.from_private_bytes(b"k" * 32).public_key(), window()
        reader = reads.NativeJitReviewCurrentReader(operation=operation, dsn="dbname=unconnected-synthetic",
            connect_timeout_seconds=2, database_role="synthetic_reader", tls_client_dn="synthetic",
            tls_client_serial="1", tls_issuer_dn="synthetic", query_manifest_digest=DIGEST,
            root_public_key=key, enrollment_original=b"{}", current_root_client=reads.transport.CurrentRootDecisionClient(
                path="/synthetic-native-review-do-not-connect.sock", timeout_seconds=1,
                expected_peer_uid=123, expected_peer_gid=123))
        values = dict(read_planner=reader, configuration_payload={"syntheticUnadmitted": True},
            configuration_root_key=key, authn_policy={}, trust_policy={},
            live_window=live, deadline_ns=live[4], work=meter())
        values.update(overrides)
        return owner.NativeJitReviewPlanOwner(**values)

    def test_arbitrary_reader_and_work_cannot_replace_actual_owner_types(self):
        for replacement in ({"read_planner": object()}, {"work": object()},
                {"configuration_root_key": object()}):
            with self.subTest(fields=list(replacement)), self.assertRaises(ValueError):
                self.configured(**replacement)

    def test_malformed_request_is_terminal_and_does_not_retain_secret(self):
        selected = self.configured()
        for _ in range(2):
            with self.assertRaises(owner.NativeJitReviewPlanOwnerError) as caught:
                selected.produce({"sessionToken": TOKEN.decode()}, session_token_original=TOKEN,
                    challenge_original="{}")
            self.assertEqual(str(caught.exception), "Native review plan preparation is unavailable")
            self.assertNotIn(TOKEN.decode(), str(caught.exception))
            self.assertTrue(selected._used and selected._failed)
        self.assertTrue(all(getattr(selected, field) is not TOKEN for field in selected.__slots__))

    def test_real_typed_request_does_not_admit_malformed_native_original(self):
        request = request_source._derive_request(wire.AUTHORIZE, {"approval_request_id": "approval-one",
            "session_id": "session-one", "challenge_sha256": DIGEST})
        selected = self.configured()
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            selected.produce(request, session_token_original=TOKEN, challenge_original="{}")
        self.assertTrue(selected._failed)

    def test_configuration_detached_and_reader_rebinding_refuses(self):
        policy = {"nested": ["original"]}
        selected = self.configured(configuration_payload=policy)
        policy["nested"][0] = "changed"
        self.assertEqual(json.loads(selected._configuration_original), {"nested": ["original"]})
        object.__setattr__(selected._reader, "_enrollment", b'{"rebound":true}')
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            selected.produce({}, session_token_original=TOKEN, challenge_original="{}")

    def test_fractional_configuration_preserves_exact_canonical_values_and_detaches(self):
        policy = {"roles": {"planner": {"requestTimeoutSeconds": 1.25,
            "databaseConnectTimeoutSeconds": 0.75}}, "unused": [1.0, -0.0, 1e-20]}
        original = canonical(policy)
        selected = self.configured(configuration_payload=policy)
        self.assertEqual(selected._configuration_original, original)
        policy["roles"]["planner"]["requestTimeoutSeconds"] = 2.5
        decoded = owner._configuration(selected._configuration_original, meter())
        self.assertEqual(canonical(decoded), original)
        self.assertIs(type(decoded["unused"][0]), float)
        self.assertEqual(math.copysign(1, decoded["unused"][1]), -1)
        self.assertEqual(decoded["roles"]["planner"]["requestTimeoutSeconds"], 1.25)

    def test_nonfinite_configuration_and_noncanonical_originals_refuse(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=repr(number)), self.assertRaises(ValueError):
                self.configured(configuration_payload={"timeout": number})
        for raw in (b'{"timeout":NaN}', b'{"timeout":Infinity}', b'{"timeout":-Infinity}',
                b'{"timeout":1e309}', b'{"timeout":1.25,"timeout":2.5}', b'{"timeout":1.250}'):
            with self.subTest(original=raw), self.assertRaises(ValueError):
                owner._configuration(raw, meter())

    def test_fractional_permission_is_not_shared_with_requests_policies_results_or_rows(self):
        for field in ("authn_policy", "trust_policy"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.configured(configuration_payload={"timeout": 1.25}, **{field: {"value": 1.25}})
        for value in ({"arguments": {"value": 1.25}}, {"result": 1.25}, [{"row": {"value": 1.25}}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                owner._json_original(value, reads.vector.authority.MAX_REQUEST_BYTES, meter())
        with self.assertRaises(ValueError):
            owner._json(b'{"value":1.25}', 1024, meter())

    def test_configuration_byte_depth_type_and_aggregate_bounds_remain_closed(self):
        maximum = reads.vector.authority.MAX_REQUEST_BYTES
        # The constructor also holds two exact empty policies (two bytes each).
        policy = {"value": "x" * (maximum - len(canonical({"value": ""})) - 4)}
        self.assertEqual(len(self.configured(configuration_payload=policy)._configuration_original), maximum - 4)
        policy["value"] += "x"
        with self.assertRaises(ValueError):
            self.configured(configuration_payload=policy)
        policy["value"] += "xxxx"
        with self.assertRaises(ValueError):
            self.configured(configuration_payload=policy)
        with self.assertRaises(ValueError):
            owner._configuration(canonical(policy), meter())
        deep = {"value": 1.25}
        for _ in range(129):
            deep = {"nested": deep}
        cyclic = {}; cyclic["nested"] = cyclic
        class ForeignFloat(float):
            pass
        for policy in (deep, cyclic, {"value": ForeignFloat(1.25)}):
            with self.subTest(kind=type(policy).__name__), self.assertRaises(ValueError):
                self.configured(configuration_payload=policy)

    def test_configuration_encoding_and_decoding_charge_exact_bytes_and_nodes(self):
        value = {"timeout": 1.25, "nested": [-0.0, 1.0, 1e-20]}
        raw = canonical(value)
        # Independent closed fixture: root + two keys + scalar + list + 3 scalars.
        nodes = 8
        config = owner.configuration_capture
        actions = ((lambda work: config._configuration_wire(value, config.capability.capture._SharedLedger(work)),
                    2 * len(raw), 2 * nodes),
                   (lambda work: owner._configuration(raw, work), 4 * len(raw), nodes))
        for action, expected_bytes, expected_nodes in actions:
            for byte_delta, node_delta, accepted in ((0, 0, True), (-1, 0, False), (0, -1, False)):
                with self.subTest(bytes=expected_bytes, byte_delta=byte_delta, node_delta=node_delta):
                    work = _ValidationWork(QueryReadValidationLimits(max_input_bytes=7 + expected_bytes + byte_delta,
                        max_json_nodes=11 + expected_nodes + node_delta))
                    work.charge(input_bytes=7, json_nodes=11)
                    if accepted:
                        actual = action(work)
                        self.assertEqual(actual if type(actual) is bytes else canonical(actual), raw)
                        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                            (0, 7 + expected_bytes, 11 + expected_nodes))
                    else:
                        with self.assertRaises(ValueError):
                            action(work)

    def test_parent_counter_rewind_and_null_replay_poison_the_owner(self):
        selected = self.configured()
        selected._work.input_bytes = 0
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            selected.produce({}, session_token_original=TOKEN, challenge_original="{}")
        self.assertTrue(selected._failed)
        selected = self.configured()
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            selected.replay({}, session_token_original=TOKEN, challenge_original="{}",
                read_manifest_original=None, read_frames=None)
        self.assertTrue(selected._failed)
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            selected.produce({}, session_token_original=TOKEN, challenge_original="{}")


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        raise AssertionError("native review plan tests forbid external effects")


if __name__ == "__main__":
    sys.addaudithook(no_external_effects)
    unittest.main()
