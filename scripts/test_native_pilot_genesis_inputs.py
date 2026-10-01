#!/usr/bin/env python3
"""Cold candidate facade controls, not a commissioning or approval ceremony.

Consumed public originals carry genuine-format synthetic signatures from the
existing fixtures. Unexamined catalogue slots are explicitly labelled padding;
observation receipts are explicitly synthetic wire fixtures, not successful
owners. No validator, private-key loader, process or installation is mocked.
A valid candidate and a public transcript are never approval.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_genesis_inputs as facade
from serverware import native_pilot_genesis_execution_protocol as wire
from serverware import native_pilot_genesis_jobs as jobs
import test_native_pilot_genesis_jobs as job_tests
import test_native_pilot_genesis_native_inputs as native_tests
import test_native_pilot_genesis_ordinary_inputs as ordinary_tests

p, g = jobs.p, jobs.g
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)
CATALOGUE = jobs.catalogue(handoff=True)
OUTPUTS = {
    "parent-start": ("parent.configuration", "parent.cold", "parent.precreation", "parent.observation", "parent.peer"),
    "ordinary-prepare": ("ordinary.configuration", "ordinary.preparation", "ordinary.resources",
        *("ordinary.activation." + role for role in jobs.ORDINARY),
        *("ordinary.runtime-inputs." + role for role in jobs.ORDINARY)),
    "endpoints-prepare": ("endpoints.configuration", "endpoints.preparation", "endpoints.resources",
        *("endpoints.activation." + role for role in jobs.NATIVE[:2])),
    "initialize-retrieval-store": ("endpoints.store",),
    "coordinator-prepare": ("coordinator.observation", "coordinator.activation"),
    "coordinator-assemble": ("coordinator.runtime",),
    "acquire-cold-core": ("core.observation",),
}


def foundation_selections(records):
    closure = p.document(records["closure-set"]["input"], jobs.sets.MAX_BYTES)
    assignment, _ = jobs.assignment.input_document(records["assignment"]["input"])
    payload = g.document(assignment["payloadOriginal"].encode("ascii"), g.MAX_BYTES)
    binding = jobs.binding.input_document(records["cold-binding"]["input"])
    parent = jobs.parent.input_document(records["parent-precreation"]["input"])
    return {"closure-set": {"members": closure["members"]},
        "assignment": {"trustOriginal": assignment["trustOriginal"],
            "payload": {name: payload[name] for name in jobs.assignment.NATIVE_FIELDS}},
        "cold-binding": {name: binding[name] for name in ("commissioningIdSha256", "initialPublicationRevision", "window")},
        "parent-precreation": {name: parent[name] for name in ("configurationOriginal", "deliveryConfigurationOriginal")}}


def execution_configuration(records, clocks):
    parent = g.document(records["parent-precreation"]["result"], jobs.parent.MAX_OUTPUT)["payload"]
    return g.canonical({"apiVersion": wire.HANDOFF_CONFIGURATION_API,
        "window": {name: parent[name] for name in wire.endpoints.WINDOW},
        "expiresAtUnixNanos": clocks["now_unix_ns"] + 1_000_000_000,
        "coreHandoff": {"peerPid": 123, "peerUid": 0, "peerGid": 0}})


def request_case(name, *, records, observed, clocks, configuration_raw):
    """Shape the actual delta/previous-result wire; establish no provenance."""
    selected = jobs.job(name, handoff=True)
    index = CATALOGUE.index(selected)
    prior = {row.name: copy.deepcopy(records.get(row.name,
        job_tests.record(job_tests.PADDING, job_tests.PADDING))) for row in CATALOGUE[:index]}
    # These consumed owner-result frames are synthetic associations only. We
    # never construct or claim an owner; all received observation bytes remain
    # the existing explicitly synthetic public fixtures. Unexamined inputs
    # retain their padding label, and unrelated results are not rewritten.
    for row in CATALOGUE[:index]:
        outputs = OUTPUTS.get(row.name, ())
        if not outputs:
            continue
        assert prior[row.name]["result"] == job_tests.PADDING
        if row.name in ("initialize-retrieval-store", "coordinator-assemble", "acquire-cold-core"):
            assert len(outputs) == 1
            prior[row.name]["result"] = observed[outputs[0]]
        else:
            prior[row.name]["result"] = g.canonical({"apiVersion": "serverware.nativePilotGenesisOwnerResult/v1",
                "action": row.name, "observationSha256": {key: p.sha(observed[key]) for key in outputs}})
    old_keys = {key for row in CATALOGUE[:max(index - 1, 0)] for key in OUTPUTS.get(row.name, ())}
    new_keys = OUTPUTS.get(CATALOGUE[index - 1].name, ()) if index else ()
    retained = {key: observed[key] for key in old_keys}
    delta = {key: observed[key] for key in new_keys}
    previous = None
    if index:
        previous_name = CATALOGUE[index - 1].name
        raw = prior[previous_name]["result"]
        previous = {"job": previous_name, "resultOriginal": raw.decode("ascii"), "resultSha256": p.sha(raw)}
    configuration = g.document(configuration_raw, 4096)
    window = configuration["window"]
    lifetime = p.ns(window["lifetimeDeadlineBoottimeNs"])
    deadline = lifetime if name in ("cleanup", "handoff-cold-core") else lifetime - wire.RESERVE if (
        name in ("coordinator-finish", "acquire-cold-core")) else min(
        p.ns(window["startupDeadlineBoottimeNs"]), lifetime - wire.RESERVE)
    _, request = wire.request(sequence=index + 1, job=name, deadline=deadline,
        observation=delta, previous=previous, handoff=True)
    return {"request_original": request, "configuration_original": configuration_raw,
        "configuration_sha256": p.sha(configuration_raw), "request_sha256": p.sha(request),
        "prior": prior, "observations": retained, **clocks}


def replace_request(case, **changes):
    value = p.document(case["request_original"], wire.MAX_REQUEST)
    raw = p.canonical(value | changes)
    return case | {"request_original": raw, "request_sha256": p.sha(raw)}


def replace_configuration(case, **changes):
    value = g.document(case["configuration_original"], 4096)
    raw = g.canonical(value | changes)
    return case | {"configuration_original": raw, "configuration_sha256": p.sha(raw)}


class GenesisInputFacadeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ordinary = ordinary_tests.fixture()
        cls.native = native_tests.fixture()
        assert cls.ordinary["clocks"] == cls.native["clocks"]
        cls.clocks = cls.ordinary["clocks"]
        cls.config = execution_configuration(cls.ordinary["records"], cls.clocks)
        cls.foundation = foundation_selections(cls.ordinary["records"])
        # Prefer the selected family's consumed sources. Extra actual-format
        # observations only fill unrelated, unconsumed transport inventory.
        cls.observed = cls.native["observations"] | cls.ordinary["observations"]
        cls.native_observed = cls.ordinary["observations"] | cls.native["observations"]

    def case(self, name, *, native=False):
        records = self.ordinary["records"]
        observed = self.observed
        if native:
            records = records | self.native["prior"]
            observed = self.native_observed
        return request_case(name, records=records, observed=observed,
            clocks=self.clocks, configuration_raw=self.config)

    def compose(self, case, selection):
        return facade.compose(selection=selection, **case)

    def test_closed_catalogue_and_exact_observation_emission_points(self):
        self.assertEqual((len(jobs.JOBS), len(CATALOGUE)), (64, 66))
        self.assertEqual(facade.CATALOGUE, CATALOGUE)
        self.assertEqual(facade.OBSERVATION_OUTPUTS, OUTPUTS)
        for name in ("driver-bootstrap", "publication-adoption", "anything-else"):
            with self.subTest(name=name), self.assertRaises(ERRORS): facade.selection_fields(name)

    def test_every_cold66_job_has_an_exact_defined_selector_inventory(self):
        expected = {name: set(value) for name, value in (
            self.foundation | self.ordinary["selections"] | self.native["selections"]).items()}
        expected["parent-release"] = set()
        owner_fields = {"parent-start": {"controllerExecutableSha256"},
            "ordinary-prepare": {"launchOriginal"}, "endpoints-prepare": {"configurationOriginal"},
            "coordinator-assemble": {"peers"}}
        expected.update({row.name: owner_fields.get(row.name, set()) for row in CATALOGUE if row.family == "owner"})
        self.assertEqual(set(expected), {row.name for row in CATALOGUE})
        for row in CATALOGUE:
            with self.subTest(job=row.name):
                fields = facade.selection_fields(row.name)
                self.assertIsInstance(fields, tuple)
                self.assertEqual(len(fields), len(set(fields)))
                self.assertEqual(set(fields), expected[row.name])

    def test_foundation_candidates_equal_authentic_existing_inputs_without_approval(self):
        for name, selection in self.foundation.items():
            with self.subTest(job=name):
                case = self.case(name)
                original = copy.deepcopy((selection, case))
                result = self.compose(case, selection)
                self.assertEqual(set(result), {"inputOriginal", "inputSha256", "deadline", "epochLimit", "observations"})
                self.assertEqual(result["inputOriginal"], self.ordinary["records"][name]["input"])
                self.assertEqual(result["inputSha256"], p.sha(result["inputOriginal"]))
                self.assertEqual((selection, case), original)
                self.assertEqual(self.compose(case, selection), result)
                self.assertLessEqual(result["epochLimit"], g.document(self.config, 4096)["expiresAtUnixNanos"])
                self.assertGreater(result["deadline"], self.clocks["now_boottime_ns"])

    def test_parent_release_derives_actual_signed_coordinator_sources_and_passes_dispatch(self):
        # Exercise the new foundation branch directly plus the same final
        # validator used by the facade. Unrelated late owner observations are
        # deliberately not invented to claim a complete coordinator ceremony.
        name, role = "parent-release", jobs.COORDINATOR
        prior = job_tests.prefix(name, self.ordinary["records"] | self.native["prior"])
        configuration = g.document(self.config, 4096)
        raw = facade.foundation.compose(jobs.job(name), {}, prior=prior,
            observations=self.native_observed, execution_configuration=configuration)
        prepared = jobs.prepare_input(name, raw, prior=prior,
            observations=self.native_observed, **self.clocks)
        value = jobs.parent.input_document(raw)
        payload = g.document(value["payloadOriginal"].encode("ascii"), jobs.parent.MAX_OUTPUT)
        bundle = p.document(self.native["prior"]["native-launch-" + role]["result"], jobs.launch.MAX_OUTPUT)
        delivery = jobs.delivery.input_document(self.native["prior"]["native-delivery-" + role]["input"])
        parent = g.document(self.native_observed["parent.configuration"], jobs.parent.MAX_WIRE)
        self.assertEqual(payload["launch"], bundle["launchPin"])
        self.assertEqual(payload["image"], delivery["image"])
        self.assertEqual(payload["signingKeyId"], parent["releaseAuthority"]["keyId"])
        self.assertEqual(payload["invocationId"], configuration["window"]["invocationId"])
        self.assertEqual(value["launchOriginal"], bundle["launchOriginal"])
        self.assertEqual(value["closureOriginal"].encode("ascii"), self.native["prior"]["native-closure-" + role]["result"])
        for field, observed in (("configurationSha256", "parent.configuration"),
                ("precreationSha256", "parent.precreation"), ("observationSha256", "parent.observation")):
            self.assertEqual(payload[field], p.sha(self.native_observed[observed]))
        self.assertGreater(prepared["deadline"], self.clocks["now_boottime_ns"])

    def test_all_sixteen_ordinary_candidates_pass_real_dispatch_with_transport_prefix(self):
        self.assertEqual(len(self.ordinary["selections"]), 16)
        for name, selection in self.ordinary["selections"].items():
            with self.subTest(job=name):
                result = self.compose(self.case(name), selection)
                self.assertEqual(result["inputOriginal"], self.ordinary["records"][name]["input"])

    def test_early_native_families_join_signed_predecessors_and_actual_format_observations(self):
        selected = [row for row in CATALOGUE if row.family in native_tests.compiler.FAMILIES
            and row.role != jobs.COORDINATOR]
        self.assertEqual({row.family for row in selected}, set(native_tests.compiler.FAMILIES))
        for row in selected:
            with self.subTest(job=row.name):
                result = self.compose(self.case(row.name, native=True), self.native["selections"][row.name])
                if row.name in self.native["expected"]:
                    self.assertEqual(result["inputOriginal"], self.native["expected"][row.name])
                self.assertGreater(result["deadline"], self.clocks["now_boottime_ns"])

    def test_fixed_owner_action_is_only_a_candidate_and_store_scope_is_not_synthesized(self):
        names = (*("admit-delivery-" + role for role in jobs.NATIVE[:2]),
            "endpoints-release", "ordinary-release", "coordinator-prepare")
        for name in names:
            with self.subTest(job=name):
                result = self.compose(self.case(name, native=True), {})
                self.assertEqual(g.document(result["inputOriginal"], 65536),
                    {"apiVersion": wire.ACTION_API, "action": name})
                with self.assertRaises(ERRORS): self.compose(self.case(name, native=True), {"approved": True})
        result = self.compose(self.case("initialize-retrieval-store", native=True), {})
        binding = jobs.binding.result_document(self.native["prior"]["cold-binding"]["result"])
        self.assertEqual(result["inputOriginal"], binding["proofScopeOriginal"].encode("ascii"))
        self.assertNotIn("genesisOriginal", g.document(result["inputOriginal"], 65536))

    def test_complete_request_and_execution_original_pins_are_independent(self):
        case, selection = self.case("closure-set"), self.foundation["closure-set"]
        for field in ("request_sha256", "configuration_sha256"):
            with self.subTest(pin=field), self.assertRaises(ERRORS):
                self.compose(case | {field: p.sha(b"different literal original")}, selection)

    def test_old_or_wrong_request_and_execution_versions_remain_closed(self):
        case, selection = self.case("closure-set"), self.foundation["closure-set"]
        for api in (wire.REQUEST_API, "serverware.nativePilotAuthorityJobRequest/v2"):
            with self.subTest(api=api), self.assertRaises(ERRORS):
                self.compose(replace_request(case, apiVersion=api), selection)
        with self.assertRaises(ERRORS):
            self.compose(replace_configuration(case, apiVersion=wire.CONFIGURATION_API), selection)
        for change in ({"sequence": 2}, {"job": "assignment"}, {"sequence": True}, {"sequence": 67}):
            with self.subTest(change=change), self.assertRaises(ERRORS):
                self.compose(replace_request(case, **change), selection)

    def test_exact_completed_prefix_rejects_dropped_added_and_malformed_records(self):
        case, selection = self.case("cold-binding"), self.foundation["cold-binding"]
        for change in ("missing", "future", "extra-field", "text-not-bytes"):
            prior = copy.deepcopy(case["prior"])
            if change == "missing": del prior["closure-set"]
            elif change == "future": prior["parent-precreation"] = job_tests.record(job_tests.PADDING, job_tests.PADDING)
            elif change == "extra-field": prior["assignment"]["approved"] = True
            else: prior["assignment"]["result"] = prior["assignment"]["result"].decode("ascii")
            with self.subTest(change=change), self.assertRaises(ERRORS): self.compose(case | {"prior": prior}, selection)

    def test_previous_result_requires_both_exact_hash_and_retained_literal(self):
        case, selection = self.case("cold-binding"), self.foundation["cold-binding"]
        request = p.document(case["request_original"], wire.MAX_REQUEST)
        previous = request["previousResult"]
        wrong = b'{"testOnly":"different preceding result"}'
        for row in (previous | {"resultSha256": p.sha(wrong)},
                previous | {"resultOriginal": wrong.decode("ascii"), "resultSha256": p.sha(wrong)},
                previous | {"job": "closure-set"}):
            with self.subTest(previous=row), self.assertRaises(ERRORS):
                self.compose(replace_request(case, previousResult=row), selection)

    def test_observations_are_exact_prior_snapshot_plus_immediate_delta(self):
        name = "initial-checkpoint-" + jobs.ORDINARY[0]
        case, selection = self.case(name), self.ordinary["selections"][name]
        request = p.document(case["request_original"], wire.MAX_REQUEST)
        self.assertEqual(set(request["observation"]), set(OUTPUTS["endpoints-prepare"]))
        result = self.compose(case, selection)
        self.assertEqual(result["observations"], case["observations"] | {
            name: raw.encode("ascii") for name, raw in request["observation"].items()})
        self.assertIsNot(result["observations"], case["observations"])
        for kind in ("missing-earlier", "missing-delta", "preloaded-delta", "future-delta", "rebind"):
            supplied, delta = dict(case["observations"]), dict(request["observation"])
            if kind == "missing-earlier": del supplied["parent.peer"]
            elif kind == "missing-delta": del delta["endpoints.resources"]
            elif kind == "preloaded-delta": supplied["endpoints.resources"] = delta["endpoints.resources"].encode("ascii")
            elif kind == "future-delta": delta["endpoints.store"] = job_tests.PADDING.decode("ascii")
            else: delta["parent.peer"] = job_tests.PADDING.decode("ascii")
            with self.subTest(kind=kind), self.assertRaises(ERRORS):
                self.compose(replace_request(case, observation=delta) | {"observations": supplied}, selection)

    def test_source_joins_still_authenticate_after_request_hash_is_recomputed(self):
        name = "initial-root-anchor-" + jobs.ORDINARY[0]
        case, selection = self.case(name), self.ordinary["selections"][name]
        prior = copy.deepcopy(case["prior"])
        checkpoint = "initial-checkpoint-" + jobs.ORDINARY[0]
        prior[checkpoint]["result"] = self.ordinary["records"]["initial-checkpoint-" + jobs.ORDINARY[1]]["result"]
        raw = prior[checkpoint]["result"]
        changed = replace_request(case, previousResult={"job": checkpoint,
            "resultOriginal": raw.decode("ascii"), "resultSha256": p.sha(raw)}) | {"prior": prior}
        with self.assertRaises(ERRORS): self.compose(changed, selection)

    def test_earlier_unconsumed_observation_cannot_rebind_its_retained_owner_receipt(self):
        name = "ordinary-runtime-" + jobs.ORDINARY[0]
        case = self.case(name)
        # This ordinary producer does not otherwise use endpoint configuration.
        # The facade must still join that accumulated byte string to the exact
        # earlier endpoint-preparation receipt already in the transcript.
        observed = dict(case["observations"])
        observed["endpoints.configuration"] = b'{"testOnly":"changed earlier endpoint observation"}'
        with self.assertRaises(ERRORS):
            self.compose(case | {"observations": observed}, self.ordinary["selections"][name])

    def test_selection_cannot_supply_future_hashes_payloads_or_authority(self):
        for name, field, value in (("closure-set", "approved", True),
                ("cold-binding", "assignmentOriginal", "caller replacement"),
                ("parent-precreation", "window", {})):
            with self.subTest(job=name), self.assertRaises(ERRORS):
                self.compose(self.case(name), self.foundation[name] | {field: value})
        selection = copy.deepcopy(self.foundation["assignment"])
        selection["payload"]["nativeClosureSet"] = {"setRootSha256": p.sha(b"future"), "seccompSetRootSha256": p.sha(b"future")}
        with self.assertRaises(ERRORS): self.compose(self.case("assignment"), selection)

    def test_original_request_boottime_and_execution_unix_caps_are_intersected(self):
        case, selection = self.case("closure-set"), self.foundation["closure-set"]
        stop, expiry = self.clocks["now_boottime_ns"] + 10, self.clocks["now_unix_ns"] + 20
        clipped = replace_configuration(replace_request(case, deadlineBoottimeNs=str(stop)), expiresAtUnixNanos=expiry)
        result = self.compose(clipped, selection)
        self.assertEqual((result["deadline"], result["epochLimit"]), (stop, expiry))
        for update in ({"now_boottime_ns": stop}, {"now_unix_ns": expiry},
                {"boot": (p.encoded(bytes([99]) * 16), *self.clocks["boot"][1:])}):
            with self.subTest(update=update), self.assertRaises(ERRORS): self.compose(clipped | update, selection)
        configuration = g.document(self.config, 4096)
        past = p.ns(configuration["window"]["startupDeadlineBoottimeNs"]) + 1
        with self.assertRaises(ERRORS): self.compose(replace_request(case, deadlineBoottimeNs=str(past)), selection)

    def test_authentic_current_producer_keeps_its_narrower_original_window(self):
        name, selection = "cold-binding", self.foundation["cold-binding"]
        case = self.case(name)
        expected = jobs.prepare_input(name, self.ordinary["records"][name]["input"],
            prior=case["prior"], observations=case["observations"], **self.clocks)
        result = self.compose(case, selection)
        request = p.document(case["request_original"], wire.MAX_REQUEST)
        self.assertEqual(result["deadline"], min(p.ns(request["deadlineBoottimeNs"]), expected["deadline"]))
        self.assertEqual(result["epochLimit"], min(g.document(self.config, 4096)["expiresAtUnixNanos"], expected["epochLimit"]))


if __name__ == "__main__":
    unittest.main()
