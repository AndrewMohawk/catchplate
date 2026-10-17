#!/usr/bin/env python3
"""Typed candidates over signed synthetic transcripts, not a cold ceremony.

Only existing deterministic public fixtures are used. No owner, protected
signer, approval, installed runtime or successful execution is manufactured.
Unconsumed catalogue positions are labelled padding, never owner receipts.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from scripts import test_native_pilot_genesis_jobs as job_tests
from scripts import test_native_pilot_ordinary_initial as initial_wire
from catchplate import native_pilot_genesis_ordinary_inputs as compiler

jobs, g, p = compiler.jobs, compiler.g, compiler.p
FAILURES = (ValueError, InvalidSignature, KeyError)
SELECTED = tuple(job for job in jobs.JOBS if job.family in ("initial", "ordinary-runtime", "ordinary"))


def fixture():
    """Complete inputs/results for all 16 jobs, with real-format signatures."""
    value = job_tests.fixture()
    records, observations = value["records"], value["observations"]
    source = value["source"]
    first = jobs.ordinary.input_document(records["ordinary-runtime-" + jobs.ORDINARY[0]]["input"])
    selections = {selected.name: {} for selected in SELECTED}
    for role in jobs.ORDINARY:
        row = source["f"]["rows"][role]
        wrapper = g.document(first["historyOriginals"][role].encode("ascii"), g.MAX_BYTES)
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        payload, anchor = checkpoint["payload"], wrapper["history"]["firstRetainedEpoch"]
        anchor_raw = initial_wire.canonical([anchor[name] for name in initial_wire.ANCHOR_FIELDS])
        signatures = {name: {"apiVersion": jobs.initial.SIGNATURE_API, "signer": name,
            "anchorPayloadSha256": p.sha(anchor_raw), "keyId": row["authorities"][name]["keyId"],
            "keySpkiSha256": row["authorities"][name]["keySpkiSha256"], "signatureBase64": anchor[field]}
            for name, field in zip(jobs.initial.KEY_NAMES, initial_wire.SIGNATURE_FIELDS, strict=True)}
        base = {"apiVersion": jobs.initial.INPUT_API, "serviceRole": role,
            **{name: first["source"][name] for name in jobs.initial.SOURCE_FIELDS if name != "configurationOriginal"},
            "configurationOriginal": first["source"]["configurationOriginals"][role],
            "initialStateOriginal": g.canonical(state).decode("ascii"), "authorities": row["authorities"],
            "payloadOriginal": g.canonical(payload).decode("ascii")}
        for operation in jobs.initial.OPERATIONS:
            supplied = base | {"operation": operation}
            if operation != "checkpoint":
                supplied["initialCheckpointOriginal"] = g.canonical(checkpoint).decode("ascii")
            if operation == "assemble":
                supplied["anchorSignatures"] = {name: g.canonical(result).decode("ascii")
                    for name, result in signatures.items()}
                result = g.canonical(wrapper)
            elif operation == "checkpoint":
                result = g.canonical(checkpoint)
            else:
                result = g.canonical(signatures[operation.removesuffix("-anchor")])
            records["initial-" + operation + "-" + role] = job_tests.record(g.canonical(supplied), result)
        selections["initial-checkpoint-" + role] = {"configurationOriginal": base["configurationOriginal"],
            "endpointRole": payload["endpointRole"], "counters": {name: state[name] for name in compiler.COUNTERS},
            "authorities": copy.deepcopy(row["authorities"]), "checkpointPolicy": {
                **{name: payload[name] for name in compiler.CHECKPOINT_POLICY[:3]},
                "validFromBoottimeNanos": payload["validFromBoottime"]["absoluteBoottimeNanos"],
                "validUntilBoottimeNanos": payload["validUntilBoottime"]["absoluteBoottimeNanos"]}}
        header = jobs.runtime.validate_runtime(role, records["ordinary-runtime-" + role]["result"])["runtime"]
        observations["ordinary.runtime-inputs." + role] = g.canonical({name: header[name]
            for name in ("listenerSocketPath", "activationDirectoryIdentities")})
        grant = jobs.ordinary.input_document(records["ordinary-grant-" + role]["input"])
        selections["ordinary-grant-" + role] = {"initialTransitionHeadSha256": grant["initialTransitionHeadSha256"]}
    selections["ordinary-runtime-" + jobs.ORDINARY[0]] = {
        "runtimePolicy": copy.deepcopy(first["runtimePolicy"]),
        "peerPolicy": {name: first["expectedPeer"][name] for name in compiler.PEER_POLICY}}
    return {"records": records, "observations": observations, "clocks": value["clocks"], "selections": selections}


def compose(value, name, *, selection=None, records=None, observations=None, clocks=None):
    records = value["records"] if records is None else records
    return compiler.compose(jobs.job(name), value["selections"][name] if selection is None else selection,
        prior=job_tests.prefix(name, records), observations=value["observations"] if observations is None else observations,
        **(value["clocks"] if clocks is None else clocks))


class GenesisOrdinaryInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = fixture()

    def test_all_sixteen_candidates_equal_existing_full_inputs_and_pass_actual_dispatch(self):
        self.assertEqual(len(SELECTED), 16)
        for selected in SELECTED:
            with self.subTest(job=selected.name):
                self.assertEqual(set(compiler.selection_fields(selected)), set(self.value["selections"][selected.name]))
                raw = compose(self.value, selected.name)
                self.assertEqual(raw, self.value["records"][selected.name]["input"])
                prepared = jobs.prepare_input(selected.name, raw,
                    prior=job_tests.prefix(selected.name, self.value["records"]),
                    observations=self.value["observations"], **self.value["clocks"])
                self.assertGreater(prepared["deadline"], self.value["clocks"]["now_boottime_ns"])
                if selected.family == "ordinary-runtime":
                    self.assertEqual(prepared["nativeContext"]["outputOriginal"], self.value["records"][selected.name]["result"])

    def test_initial_sequences_roots_identity_and_original_windows_are_derived_not_supplied(self):
        for role in jobs.ORDINARY:
            name = "initial-checkpoint-" + role
            value = jobs.initial.input_document(compose(self.value, name))
            state = g.document(value["initialStateOriginal"].encode("ascii"), jobs.initial.profile.MAX_STATE)
            payload = g.document(value["payloadOriginal"].encode("ascii"), jobs.initial.MAX_CHECKPOINT)
            self.assertEqual(payload["checkpointSequence"], 1)
            self.assertEqual(payload["predecessorCheckpointSha256"], jobs.initial.profile.commitments(state)["predecessorCheckpointSha256"])
            self.assertEqual(payload["endpointProcessIdentitySha256"], state["endpointProcessIdentitySha256"])
            for extra in ("initialStateOriginal", "payloadOriginal", "predecessorCheckpointSha256", "issuedAtBoottimeNs"):
                with self.subTest(role=role, extra=extra), self.assertRaises(FAILURES):
                    compose(self.value, name, selection=self.value["selections"][name] | {extra: "caller override"})

    def test_initial_anchor_and_assembly_require_literal_signed_predecessors(self):
        role = jobs.ORDINARY[0]
        for signer in jobs.initial.KEY_NAMES:
            records = copy.deepcopy(self.value["records"])
            name = "initial-" + signer + "-anchor-" + role
            signature = g.document(records[name]["result"], jobs.initial.MAX_SIGNATURE)
            signature["signatureBase64"] = p.encoded(bytes(64))
            records[name]["result"] = g.canonical(signature)
            with self.subTest(signer=signer), self.assertRaises(InvalidSignature):
                compose(self.value, "initial-assemble-" + role, records=records)
        records = copy.deepcopy(self.value["records"])
        checkpoint = "initial-checkpoint-" + role
        records[checkpoint]["result"] = self.value["records"]["initial-checkpoint-" + jobs.ORDINARY[1]]["result"]
        with self.assertRaises(FAILURES): compose(self.value, "initial-root-anchor-" + role, records=records)

    def test_actual_source_process_directory_and_parent_originals_cannot_be_replaced(self):
        name = "initial-checkpoint-" + jobs.ORDINARY[0]
        for kind in ("ordinary.preparation", "ordinary.resources", "parent.observation"):
            observations = copy.deepcopy(self.value["observations"])
            value = g.document(observations[kind], 65536)
            if kind == "ordinary.preparation":
                value["services"][jobs.ORDINARY[0]]["processId"] += 1
            elif kind == "ordinary.resources":
                value["services"][jobs.ORDINARY[0]]["directories"]["journal"]["entryCount"] = 1
            else:
                value["precreationSha256"] = p.sha(b"different signed parent")
            observations[kind] = g.canonical(value)
            # A different valid process observation changes candidate identity;
            # the downstream signed checkpoint must not survive that change.
            target = "initial-root-anchor-" + jobs.ORDINARY[0] if kind == "ordinary.preparation" else name
            with self.subTest(kind=kind), self.assertRaises(FAILURES): compose(self.value, target, observations=observations)

    def test_runtime_peer_uses_observed_process_and_independent_labels_only(self):
        name = "ordinary-runtime-" + jobs.ORDINARY[0]
        value = jobs.ordinary.input_document(compose(self.value, name))
        observed = g.document(self.value["observations"]["parent.peer"], 131072)
        peer = observed["peers"][jobs.runtime.coordinator.ROLE]
        self.assertEqual((value["expectedPeer"]["pid"], value["expectedPeer"]["startTimeTicks"]),
            (peer["processId"], peer["startTimeTicks"]))
        self.assertEqual({field: value["expectedPeer"][field] for field in compiler.PEER_POLICY},
            self.value["selections"][name]["peerPolicy"])
        selected = copy.deepcopy(self.value["selections"][name])
        selected["peerPolicy"]["pid"] = peer["processId"]
        with self.assertRaises(FAILURES): compose(self.value, name, selection=selected)
        observations = copy.deepcopy(self.value["observations"])
        peer["processId"] += 1
        observations["parent.peer"] = g.canonical(observed)
        with self.assertRaises(FAILURES): compose(self.value, name, observations=observations)

    def test_runtime_requires_both_signed_histories_and_exact_resource_observations(self):
        name = "ordinary-runtime-" + jobs.ORDINARY[0]
        records = copy.deepcopy(self.value["records"])
        role = jobs.ORDINARY[1]
        wrapper = g.document(records["initial-assemble-" + role]["result"], g.MAX_BYTES)
        wrapper["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = p.encoded(bytes(64))
        records["initial-assemble-" + role]["result"] = g.canonical(wrapper)
        with self.assertRaises(InvalidSignature): compose(self.value, name, records=records)
        for suffix in ("activation.", "runtime-inputs."):
            observations = copy.deepcopy(self.value["observations"])
            raw = observations["ordinary." + suffix + jobs.ORDINARY[0]]
            observed = jobs.delivery._activation(raw) if suffix == "activation." else g.document(raw, 65536)
            if suffix == "activation.": observed[1]["inode"] += 1
            else: observed["listenerSocketPath"] = "/run/unselected-listener.sock"
            observations["ordinary." + suffix + jobs.ORDINARY[0]] = g.canonical(observed)
            with self.subTest(suffix=suffix), self.assertRaises(FAILURES): compose(self.value, name, observations=observations)

    def test_activation_original_is_a_bounded_canonical_list_not_a_document(self):
        role = jobs.ORDINARY[0]
        key = "ordinary.activation." + role
        original = self.value["observations"][key]
        self.assertIsInstance(jobs.delivery._activation(original), list)
        for raw in (b"{}", original + b"\n", b'[{"fd":6,"fd":7}]', b'[{"fd":6.0}]',
                b"[" + b" " * 32768 + b"]"):
            observations = self.value["observations"] | {key: raw}
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                compose(self.value, "ordinary-runtime-" + role, observations=observations)

    def test_second_runtime_and_deliveries_cannot_reselect_policy_or_reframe_input(self):
        first, second = ("ordinary-runtime-" + role for role in jobs.ORDINARY)
        one, two = (jobs.ordinary.input_document(compose(self.value, name)) for name in (first, second))
        for field in jobs.ordinary.COMMON:
            if field not in ("serviceRole", "operation"): self.assertEqual(one[field], two[field])
        with self.assertRaises(FAILURES): compose(self.value, second, selection=self.value["selections"][first])
        for role in jobs.ORDINARY:
            name = "ordinary-delivery-" + role
            self.assertEqual(compose(self.value, name), self.value["records"]["ordinary-runtime-" + role]["input"])
            with self.assertRaises(FAILURES): compose(self.value, name, selection={"payloadOriginal": "{}"})
        records = copy.deepcopy(self.value["records"])
        records[first]["result"] += b"\n"
        with self.assertRaises(FAILURES): compose(self.value, "ordinary-delivery-" + jobs.ORDINARY[0], records=records)

    def test_grants_consume_both_actual_deliveries_and_native_grants_without_signing(self):
        name = "ordinary-grant-" + jobs.ORDINARY[0]
        value = jobs.ordinary.input_document(compose(self.value, name))
        for role in jobs.ORDINARY:
            self.assertEqual(value["deliveryOriginals"][role].encode("ascii"),
                self.value["records"]["ordinary-delivery-" + role]["result"])
        for job in ("native-publication-grant", "native-retrieval-grant"):
            records = copy.deepcopy(self.value["records"])
            grant = g.document(records[job]["result"], g.MAX_BYTES)
            grant["signature"] = p.encoded(bytes(64))
            records[job]["result"] = g.canonical(grant)
            with self.subTest(job=job), self.assertRaises(InvalidSignature): compose(self.value, name, records=records)
        with self.assertRaises(FAILURES):
            compose(self.value, name, selection=self.value["selections"][name] | {"nativePublicationOriginal": "{}"})

    def test_original_startup_checkpoint_and_unix_limits_remain_closed(self):
        for selected in (SELECTED[0], jobs.job("ordinary-runtime-" + jobs.ORDINARY[0]),
                jobs.job("ordinary-grant-" + jobs.ORDINARY[0])):
            for update in ({"now_boottime_ns": 5_000_000_000},
                    {"boot": (self.value["clocks"]["boot"][0], 7, 999)}, {"now_boottime_ns": True}):
                with self.subTest(job=selected.name, update=update), self.assertRaises(FAILURES):
                    compose(self.value, selected.name, clocks=self.value["clocks"] | update)
        grant = "ordinary-grant-" + jobs.ORDINARY[0]
        with self.assertRaises(FAILURES): compose(self.value, grant,
            clocks=self.value["clocks"] | {"now_unix_ns": self.value["clocks"]["now_unix_ns"] + 20_000_000_000})
        name = SELECTED[0].name
        selection = copy.deepcopy(self.value["selections"][name])
        selection["checkpointPolicy"]["validUntilBoottimeNanos"] = 100_000_000_000
        with self.assertRaises(FAILURES): compose(self.value, name, selection=selection)

    def test_composition_is_nonmutating_and_rejects_cross_family_or_missing_evidence(self):
        before = copy.deepcopy(self.value)
        for selected in SELECTED: compose(self.value, selected.name)
        self.assertEqual(self.value, before)
        for selected in (jobs.job("parent-precreation"), jobs.job("ordinary-prepare"),
                tuple(SELECTED[0]), SELECTED[0]._replace(operation="assemble")):
            with self.subTest(selected=selected), self.assertRaises(FAILURES):
                compiler.compose(selected, {}, prior={}, observations={}, **self.value["clocks"])
        with self.assertRaises(FAILURES): compose(self.value, SELECTED[0].name, observations={})


if __name__ == "__main__":
    unittest.main()
