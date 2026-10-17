#!/usr/bin/env python3
"""Pure retained candidate controls, not an approved or executed lifecycle.

Existing synthetic signatures authenticate real-format bootstrap, assignment
and cold-binding sources. Tiny public inventory fixtures use temporary trees.
No live owner, protected file, approval, signer endpoint or complete66/176
ceremony is fabricated. The exercised prefix is bootstrap/rendezvous/cold3;
late result semantics remain covered by the separate completion codec suites.
The current-head evidence controls authenticate the signed five-service source
projection and all eight requests, not a fabricated complete adopted prefix.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts import test_native_pilot_lifecycle_inputs as bootstrap_fixture
from scripts.test_native_pilot_publication_cold_binding import fixture as cold_fixture
from scripts.test_native_pilot_adopted_current_head import fixture as head_fixture
from catchplate import native_pilot_approval_transcript as transcript

p = transcript.p
FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)


def configuration(value):
    return {name: copy.deepcopy(value["parameters"][name]) for name in transcript.BOOTSTRAP_FIELDS}


def rendezvous_selection(value):
    return dict(expected_request_sha256=p.sha(value["request_raw"]), expected_receiver=copy.deepcopy(value["receiver"]))


def cold_sources():
    value = cold_fixture()
    selected = p.document(value["closureSetOriginal"].encode("ascii"), transcript.cold.jobs.sets.MAX_BYTES)
    assignment = p.document(value["assignmentOriginal"].encode("ascii"), transcript.cold.jobs.assignment.MAX_BYTES)
    selections = {
        "closure-set": {"members": selected["members"]},
        "assignment": {"trustOriginal": value["trustOriginal"], "payload": {
            name: assignment["payload"][name] for name in transcript.cold.jobs.assignment.NATIVE_FIELDS}},
        "cold-binding": {name: value[name] for name in ("commissioningIdSha256", "initialPublicationRevision", "window")}}
    results = {"closure-set": value["closureSetOriginal"].encode("ascii"),
        "assignment": value["assignmentOriginal"].encode("ascii")}
    return value, selections, results


def request(value, index, results):
    previous = None
    if index:
        job = transcript.cold.CATALOGUE[index - 1].name
        raw = results[job]
        previous = dict(job=job, resultOriginal=raw.decode("ascii"), resultSha256=p.sha(raw))
    return p.canonical(dict(apiVersion=transcript.cold.wire.HANDOFF_REQUEST_API,
        sequence=index + 1, job=transcript.cold.CATALOGUE[index].name,
        deadlineBoottimeNs=value["listener"]["window"]["startupDeadlineBoottimeNs"],
        observation={}, previousResult=previous))


def head_sources():
    """Real-format signed source subgraph, deliberately not a complete prefix."""
    source = head_fixture()
    args = source["args"]
    def record(raw, output=None):
        return dict(input=raw, result={} if output is None else
            dict(original=output.decode("ascii"), sha256=p.sha(output)))
    prior = {"driver-bootstrap": record(p.canonical({
        "configurationOriginal": args["driver_configuration_raw"].decode("ascii"),
        "windowOriginal": args["driver_window_raw"].decode("ascii")}))}
    initial = transcript.adopted.ordinary.initial_authority
    for role, row in args["ordinary_context"].items():
        wrapper = p.document(row["historyOriginal"].encode("ascii"), transcript.adopted.profile.g.MAX_BYTES)
        # These complete checkpoint inputs preserve the earlier selected policy
        # fields; actual signatures remain in the history and checkpoint bytes.
        checkpoint = dict(apiVersion=initial.ADOPTED_INPUT_API, operation="checkpoint",
            driverConfigurationOriginal=args["driver_configuration_raw"].decode("ascii"),
            driverWindowOriginal=args["driver_window_raw"].decode("ascii"),
            launchOriginal=args["launch_raw"].decode("ascii"), configurationOriginal=row["configurationOriginal"],
            preparationOriginal=args["preparation_raw"].decode("ascii"),
            resourcesOriginal=args["resources_raw"].decode("ascii"),
            initialStateOriginal=p.canonical(wrapper["initialState"]).decode("ascii"),
            authorities=copy.deepcopy(args["initial_policy"]["services"][role]["authorities"]),
            payloadOriginal=p.canonical(wrapper["initialCheckpoint"]["payload"]).decode("ascii"))
        prior["ordinary-initial-checkpoint-" + role] = record(p.canonical(checkpoint), p.canonical(wrapper["initialCheckpoint"]))
        prior["ordinary-generation-" + role] = record(p.canonical({
            "launchOriginal": args["launch_raw"].decode("ascii"),
            "services": {role: {name: value for name, value in row.items() if name != "generationGrantOriginal"}}}),
            row["generationGrantOriginal"].encode("ascii"))
    payloads = {"endpoint-inputs": dict(ordinaryPreparationOriginal=args["preparation_raw"].decode("ascii"),
        ordinaryInitialResourcesOriginal=args["resources_raw"].decode("ascii")),
        "bridge-runtime": dict(bridgePreparationOriginal=args["bridge_preparation_raw"].decode("ascii"))}
    return dict(source=source, prior=prior, payloads=payloads, clocks=copy.deepcopy(source["clocks"]))


class ApprovalTranscriptControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="approval-transcript-fixture-")
        cls.addClassCleanup(temporary.cleanup)
        cls.addClassCleanup(bootstrap_fixture.runtime_fixture.thaw, Path(temporary.name))
        cls.value = bootstrap_fixture.fixture(Path(temporary.name))
        cls.cold, cls.selections, cls.results = cold_sources()

    def new(self):
        return transcript.CandidateTranscript(configuration(self.value))

    def ready(self):
        retained = self.new()
        first = retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        retained.accept(first["originals"])
        second = retained.prepare("rendezvous", self.value["request_raw"],
            rendezvous_selection(self.value), **self.value["clocks"])
        retained.accept(second["originals"])
        return retained

    def cold_candidate(self, retained, index, *, raw=None, clocks=None):
        job = transcript.cold.CATALOGUE[index].name
        return retained.prepare("cold", request(self.value, index, self.results) if raw is None else raw,
            copy.deepcopy(self.selections[job]), **(self.value["clocks"] if clocks is None else clocks))

    def test_closed_static_configuration_has_no_clock_or_authority_overrides(self):
        original = configuration(self.value)
        for extra in ("boot", "now_boottime_ns", "approval", "private_key", "prior"):
            with self.subTest(extra=extra), self.assertRaises(FAILURES):
                transcript.CandidateTranscript(original | {extra: None})
        for name in ("recipe_sha256", "supervisor_inventory_sha256"):
            with self.subTest(name=name), self.assertRaises(FAILURES):
                transcript.CandidateTranscript(original | {name: p.sha(b"other public original")})
        self.assertEqual((transcript.COLD_END, transcript.END), (68, 244))

    def test_bootstrap_copies_static_data_and_returns_exact_real_compiler_output(self):
        supplied = configuration(self.value)
        retained = transcript.CandidateTranscript(supplied)
        supplied["key_bindings"]["driver-bootstrap"] = p.sha(b"caller changed its own copy")
        result = retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        self.assertEqual(result, bootstrap_fixture.bootstrap(self.value))
        self.assertEqual(set(result), {"originals", "pins", "deadline", "epochLimit"})
        self.assertEqual(tuple(result["originals"]), transcript.lifecycle.ORIGINALS)
        self.assertEqual(retained.next_stage, "bootstrap")
        self.assertFalse(retained.done)
        retained.accept(result["originals"])
        self.assertEqual(retained.next_stage, "rendezvous")

    def test_only_exact_candidate_acceptance_advances_and_receipt_is_not_result(self):
        retained = self.new()
        with self.assertRaises(FAILURES): retained.accept({"input": b"{}"})
        result = retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        exact = copy.deepcopy(result["originals"])
        result["originals"]["policy"] = b"{}"
        for wrong in (result["originals"], exact | {"approval": b"{}"}, {"input": exact["policy"]}):
            with self.assertRaises(FAILURES): retained.accept(wrong)
        with self.assertRaises(FAILURES): retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        retained.accept(exact)
        with self.assertRaises(FAILURES): retained.accept(exact)
        with self.assertRaises(FAILURES): retained.complete("cold", b"{}", **self.value["clocks"])
        self.assertFalse(retained.done)

    def test_rendezvous_retains_sender_configuration_and_independent_receiver_selection(self):
        retained = self.new()
        result = retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        retained.accept(result["originals"])
        selection = rendezvous_selection(self.value)
        for wrong in (selection | {"expected_request_sha256": p.sha(b"other ticket")},
                selection | {"expected_receiver": self.value["receiver"] | {"pid": 201}}, selection | {"approve": True}):
            with self.assertRaises(FAILURES): retained.prepare("rendezvous", self.value["request_raw"], wrong, **self.value["clocks"])
        # A self-consistent different sender transcript still cannot replace
        # the original already accepted at bootstrap.
        profile = transcript.lifecycle.rendezvous_profile
        ticket = profile.verify_request(self.value["request_raw"])
        sender = p.document(ticket["senderRequestOriginal"].encode("ascii"), profile.MAX_SENDER)
        observed = p.document(sender["listenerOriginal"].encode("ascii"), profile.MAX_SENDER)
        observed["processId"] += 1
        observed_raw = p.canonical(observed)
        sender.update(listenerOriginal=observed_raw.decode("ascii"), listenerSha256=p.sha(observed_raw))
        sender_raw = p.canonical(sender)
        receiver = p.document(ticket["receiverOriginal"].encode("ascii"), profile.MAX_RECEIVER)
        receiver["senderRequestSha256"] = p.sha(sender_raw)
        raw = profile.request(sender_raw, p.canonical(receiver), ticket["configurationOriginal"].encode("ascii"))
        with self.assertRaises(FAILURES): retained.prepare("rendezvous", raw,
            selection | {"expected_request_sha256": p.sha(raw)}, **self.value["clocks"])
        result = retained.prepare("rendezvous", self.value["request_raw"], selection, **self.value["clocks"])
        expected = bootstrap_fixture.rendezvous(self.value)
        self.assertEqual(result["originals"], {"input": expected["input_original"]})
        retained.accept(result["originals"])
        self.assertEqual(retained.next_stage, "cold")

    def test_three_cold_candidates_consume_literal_results_of_exact_accepted_inputs(self):
        retained = self.ready()
        candidates = []
        for index in range(3):
            candidate = self.cold_candidate(retained, index)
            self.assertEqual(set(candidate["originals"]), {"input"})
            self.assertEqual(candidate["pins"], {"input": p.sha(candidate["originals"]["input"])})
            candidates.append(candidate["originals"]["input"])
            retained.accept(candidate["originals"])
        assignment = transcript.cold.jobs.assignment.input_document(candidates[1])[0]
        self.assertEqual(assignment["closureSetOriginal"].encode("ascii"), self.results["closure-set"])
        binding = transcript.cold.jobs.binding.input_document(candidates[2])
        self.assertEqual(binding["assignmentOriginal"].encode("ascii"), self.results["assignment"])
        self.assertEqual(candidates[2], transcript.cold.g.canonical(self.cold))
        self.assertEqual(retained.next_stage, "cold")
        self.assertFalse(retained.done)

    def test_cold_sequence_hash_result_and_future_observation_substitution_refuse(self):
        retained = self.ready()
        first = self.cold_candidate(retained, 0); retained.accept(first["originals"])
        ticket = p.document(request(self.value, 1, self.results), transcript.cold.installation.MAX_REQUEST)
        cases = [ticket | {"sequence": 3}, ticket | {"previousResult": None},
            ticket | {"observation": {"core.observation": "{}"}},
            ticket | {"previousResult": ticket["previousResult"] | {"resultSha256": p.sha(b"unrelated")}},
            ticket | {"previousResult": ticket["previousResult"] | {"resultOriginal": "{}", "resultSha256": p.sha(b"{}")}}]
        for value in cases:
            with self.subTest(value=value["sequence"]), self.assertRaises(FAILURES):
                self.cold_candidate(retained, 1, raw=p.canonical(value))
        valid = self.cold_candidate(retained, 1)
        retained.accept(valid["originals"])
        self.assertEqual(retained.next_stage, "cold")

    def test_correct_result_hash_does_not_replace_assignment_signature_validation(self):
        retained = self.ready()
        for index in range(2):
            candidate = self.cold_candidate(retained, index)
            retained.accept(candidate["originals"])
        assignment = p.document(self.results["assignment"], transcript.cold.jobs.assignment.MAX_BYTES)
        assignment["signature"] = p.encoded(bytes(64))
        raw = p.canonical(assignment)
        ticket = request(self.value, 2, self.results | {"assignment": raw})
        with self.assertRaises(FAILURES): self.cold_candidate(retained, 2, raw=ticket)
        valid = self.cold_candidate(retained, 2)
        retained.accept(valid["originals"])
        self.assertFalse(retained.done)

    def test_terminal_and_adopted_cannot_skip_uncompleted_cold_prefix(self):
        retained = self.ready()
        for stage in ("cold", "adopted"):
            with self.assertRaises(FAILURES): retained.complete(stage, b"{}", **self.value["clocks"])
        with self.assertRaises(FAILURES): retained.prepare("adopted", {}, {}, **self.value["clocks"])
        with self.assertRaises(FAILURES): retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
        self.assertEqual(retained.next_stage, "cold")

    def test_public_evidence_cannot_skip_acceptance_or_cold_completion_or_supply_sources(self):
        retained = self.new()
        pending = {"sequence": 1, "job": transcript.adopted.bridge.current_heads.JOB_NAMES[0]}
        for stage in ("bootstrap", "rendezvous", "cold"):
            if stage == "rendezvous":
                candidate = retained.prepare("bootstrap", self.value["pending"], {}, **self.value["clocks"])
                before = copy.deepcopy((retained._data, retained._candidate))
                with self.assertRaises(FAILURES): retained.current_head_evidence(pending, **self.value["clocks"])
                self.assertEqual((retained._data, retained._candidate), before)
                retained.accept(candidate["originals"])
            elif stage == "cold":
                candidate = retained.prepare("rendezvous", self.value["request_raw"],
                    rendezvous_selection(self.value), **self.value["clocks"])
                retained.accept(candidate["originals"])
            before = copy.deepcopy((retained._data, retained._candidate))
            with self.assertRaises(FAILURES): retained.current_head_evidence(pending, **self.value["clocks"])
            for name in ("prior", "observations", "currentness"):
                with self.subTest(source=name), self.assertRaises(TypeError):
                    retained.current_head_evidence(pending, **self.value["clocks"], **{name: {}})
            self.assertEqual((retained._data, retained._candidate), before)
            self.assertEqual(retained.next_stage, stage)
            self.assertFalse(retained.done)

    def test_retained_boot_and_both_original_clocks_cannot_be_rewound_or_renewed(self):
        retained = self.ready()
        clocks = self.value["clocks"]
        for changed in (clocks | {"boot": (clocks["boot"][0], 4, 6)},
                clocks | {"now_boottime_ns": clocks["now_boottime_ns"] - 1},
                clocks | {"now_unix_ns": clocks["now_unix_ns"] - 1},
                clocks | {"now_boottime_ns": int(self.value["listener"]["window"]["startupDeadlineBoottimeNs"])},
                clocks | {"now_unix_ns": self.value["parameters"]["expires_at_unix_ns"]}):
            with self.assertRaises(FAILURES): self.cold_candidate(retained, 0, clocks=changed)
        candidate = self.cold_candidate(retained, 0)
        self.assertLessEqual(candidate["epochLimit"], self.value["parameters"]["expires_at_unix_ns"])

    def test_fixed_aggregate_accounting_boundary_without_large_allocation(self):
        self.assertEqual(transcript.MAX_RETAINED_BYTES, 512 * 1024 * 1024)
        transcript._retained(transcript.MAX_RETAINED_BYTES)
        for count in (-1, True, transcript.MAX_RETAINED_BYTES + 1):
            with self.assertRaises(ValueError): transcript._retained(count)
        with self.assertRaises(ValueError): transcript._budget(object())


class CurrentHeadEvidenceProjectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = head_sources()

    def context(self, value):
        return transcript._current_head_context(value["prior"], value["payloads"], **value["clocks"])

    def test_all_eight_exports_equal_existing_signed_source_evidence_without_decision(self):
        value = copy.deepcopy(self.value)
        before = copy.deepcopy(value)
        context = self.context(value)
        heads = transcript.adopted.bridge.current_heads
        self.assertTrue(heads.adoption_selected(context))
        self.assertEqual(context["sources"]["initial_policy"], value["source"]["args"]["initial_policy"])
        for name in heads.JOB_NAMES:
            raw = heads.observed_original(name, context)
            self.assertEqual(raw, heads.observed_original(name, value["source"]["context"]))
            observed = p.document(raw, heads.MAX_OBSERVED)
            self.assertEqual(observed["apiVersion"], heads.OBSERVED_API)
            self.assertEqual(observed["jobName"], name)
            self.assertNotIn("currentness", observed)
            self.assertNotIn("approval", observed)
            self.assertNotIn("currentness", observed["originals"])
        self.assertEqual(value, before)

    def test_checkpoint_policy_is_derived_from_prior_selection_not_observed_history(self):
        role = transcript.adopted.profile.g.ROLES[0]
        name = "ordinary-initial-checkpoint-" + role
        for field in ("authorities", "initialStateOriginal", "payloadOriginal"):
            value = copy.deepcopy(self.value)
            raw = p.document(value["prior"][name]["input"], transcript.adopted.profile.MAX_FRAME)
            if field == "authorities":
                other = transcript.adopted.profile.g.ROLES[1]
                raw[field] = copy.deepcopy(value["source"]["args"]["initial_policy"]["services"][other]["authorities"])
            else:
                item = p.document(raw[field].encode("ascii"), 65536)
                item["endpointGeneration" if field == "initialStateOriginal" else "revocationGenerationHighWater"] += 1
                raw[field] = p.canonical(item).decode("ascii")
            value["prior"][name]["input"] = p.canonical(raw)
            with self.subTest(field=field), self.assertRaises(FAILURES): self.context(value)

    def test_generation_result_hash_does_not_substitute_for_signature_or_literal_source(self):
        role = transcript.adopted.profile.g.ROLES[0]
        name = "ordinary-generation-" + role
        for mistake in ("result-pin", "signature", "history", "launch"):
            value = copy.deepcopy(self.value)
            row = value["prior"][name]
            if mistake == "result-pin": row["result"]["sha256"] = p.sha(b"other generation")
            elif mistake == "signature":
                result = p.document(row["result"]["original"].encode("ascii"), transcript.adopted.profile.MAX_FRAME)
                result["signatureBase64url"] = p.encoded(bytes(64))
                raw = p.canonical(result)
                row["result"].update(original=raw.decode("ascii"), sha256=p.sha(raw))
            else:
                source = p.document(row["input"], transcript.adopted.profile.MAX_FRAME)
                if mistake == "history":
                    other = transcript.adopted.profile.g.ROLES[1]
                    source["services"][role]["historyOriginal"] = value["source"]["args"]["ordinary_context"][other]["historyOriginal"]
                else: source["launchOriginal"] = "{}"
                row["input"] = p.canonical(source)
            with self.subTest(mistake=mistake), self.assertRaises(FAILURES): self.context(value)

    def test_evidence_preserves_original_boot_deadline_and_requires_every_source(self):
        for mistake in ("boot", "deadline", "checkpoint", "generation", "preparation"):
            value = copy.deepcopy(self.value)
            if mistake == "boot":
                original = value["clocks"]["boot"]
                value["clocks"]["boot"] = original[:2] + (original[2] + 1,)
            elif mistake == "deadline": value["clocks"]["now_boottime_ns"] = value["source"]["context"]["deadline"]
            elif mistake in ("checkpoint", "generation"):
                prefix = "ordinary-initial-checkpoint-" if mistake == "checkpoint" else "ordinary-generation-"
                del value["prior"][prefix + transcript.adopted.profile.g.ROLES[-1]]
            else: del value["payloads"]["bridge-runtime"]["bridgePreparationOriginal"]
            with self.subTest(mistake=mistake), self.assertRaises(FAILURES): self.context(value)


if __name__ == "__main__": unittest.main(verbosity=2)
