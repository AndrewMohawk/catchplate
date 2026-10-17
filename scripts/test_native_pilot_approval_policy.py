#!/usr/bin/env python3
"""Pure independent-policy boundaries, not an approved 244-job ceremony.

Static bootstrap associations use existing signed synthetic public originals
and actual inventory producers over tiny non-executable trees. Unreached job
fragments are field-inventory placeholders, deliberately not claims of valid
producer inputs. Only the selected compiler authenticates their full semantics
when the actual transcript is available. No policy custody, peers, independent
currentness, private credentials or process owners are fabricated here.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_lifecycle_inputs as source_fixture
from catchplate import native_pilot_approval_policy as policy

p = policy.p
ERRORS = (ValueError, InvalidSignature)


def fixture(parent):
    source = source_fixture.fixture(parent)
    parameters = source["parameters"]
    value = {"apiVersion": policy.API, "purpose": policy.PURPOSE, "source": source["recipe"]["source"],
        "catalogueSha256": p.sha(policy.catalogue_original()),
        "supervisorInventorySha256": parameters["supervisor_inventory_sha256"],
        "conductorInventorySha256": p.sha(parameters["conductor_inventory_original"]),
        "authorityInventorySha256": p.sha(parameters["authority_inventory_original"]),
        "measuredRecipeSha256": parameters["recipe_sha256"],
        "listenerConfigurationOriginal": source["pending"]["listenerConfigurationOriginal"],
        "listenerConfigurationSha256": p.sha(source["pending"]["listenerConfigurationOriginal"].encode("ascii")),
        "issuedAtUnixNanos": parameters["issued_at_unix_ns"], "expiresAtUnixNanos": parameters["expires_at_unix_ns"],
        "lifecyclePeer": {"pid": 300, "uid": 0, "gid": 0, "startTimeTicks": 345},
        "currentHeadPeer": {"pid": 400, "uid": 1000, "gid": 1000, "startTimeTicks": 456},
        "keyBindings": parameters["key_bindings"],
        "bootstrap": {"rule": policy.BOOTSTRAP, "policySelection": parameters["policy_selection"]},
        "rendezvous": {"rule": policy.RENDEZVOUS}, "cold": {}, "adopted": {}}
    for stage, jobs, compiler in (("cold", policy.COLD, policy.cold),
            ("adopted", tuple(job for _, job in policy.ADOPTED), policy.adopted)):
        for job in jobs:
            if stage == "adopted" and job.name in policy.HEADS:
                value[stage][job.name] = {"rule": policy.EXTERNAL_HEAD}
            else:
                # Outer policy grammar only. These unreached placeholder
                # fragments cannot pass their respective producer validators.
                fragment = {name: None for name in compiler.selection_fields(job.name)}
                if stage == "adopted" and job.family == "stop": fragment = {"action": {"action": "stop"}}
                value[stage][job.name] = {"rule": policy.DERIVE, "selection": fragment}
    arguments = {name: parameters[name] for name in ("recipe_original", "supervisor_inventory_original",
        "conductor_inventory_original", "authority_inventory_original")}
    return {"source": source, "value": value, "arguments": arguments, "clocks": source["clocks"]}


def prepare(source, value=None, **changes):
    return policy.prepare(policy.canonical(source["value"] if value is None else value),
        **(source["arguments"] | source["clocks"] | changes))


def pending(prepared, job="driver-bootstrap", *, payload=None):
    """Synthetic exact transport metadata only; never a retained request owner."""
    phase, selected = policy.adopted.profile.BY_NAME[job]
    index = tuple(item.name for _, item in policy.ADOPTED).index(job)
    conductor_sequence = tuple(policy.adopted.profile.JOBS).index(phase) + 1
    deadline = prepared["deadline"] - prepared["_reserve"] if phase in ("generation-origin", "shutdown") else prepared["startupDeadline"]
    conductor = {"apiVersion": "catchplate.nativePilotOperatorRequest/v2", "sequence": conductor_sequence,
        "phase": phase, "payload": {} if payload is None else payload,
        "deadlineBoottimeNs": str(deadline), "expiresAtUnixNanos": str(prepared["epochLimit"])}
    conductor_raw = p.canonical(conductor)
    observed = {"apiVersion": "catchplate.nativePilotAdoptedSupervisorObservation/v1",
        "policySha256": p.sha(b"synthetic actual bootstrap policy pin"),
        "catalogueSha256": p.sha(policy.lifecycle.policy.catalogue_original()),
        "intakeConfigurationSha256": p.sha(b"synthetic actual intake pin"),
        "conductorRequestOriginal": conductor_raw.decode("ascii"), "measuredConfiguration": None, "recipeOriginals": None}
    ticket = {"apiVersion": policy.adopted.profile.API, "sequence": index + 1,
        "conductorSequence": conductor_sequence, "conductorRequestSha256": p.sha(conductor_raw),
        "phase": phase, "jobIndex": policy.adopted.profile.job_index(phase, job), "job": job,
        "deadlineBoottimeNs": str(deadline), "expiresAtUnixNanos": str(prepared["epochLimit"]),
        "conductorRequest": conductor, "previousResult": None}
    request_raw, observation_raw = p.canonical(ticket), p.canonical(observed)
    return {"phase": phase, "job": selected.name, "sequence": index + 1,
        "status": "awaiting-independent-job-approval", "requestOriginal": request_raw.decode("ascii"),
        "requestSha256": p.sha(request_raw), "observationOriginal": observation_raw.decode("ascii"),
        "observationSha256": p.sha(observation_raw)}


class ApprovalPolicyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="approval-policy-")
        cls.addClassCleanup(temporary.cleanup)
        cls.addClassCleanup(source_fixture.runtime_fixture.thaw, Path(temporary.name))
        cls.source = fixture(Path(temporary.name))

    def options(self, prepared):
        return dict(peer=prepared["peer"], **self.source["clocks"])

    def test_selected_catalogues_and_external_eight_are_closed(self):
        value = policy.shape(policy.canonical(self.source["value"]))
        self.assertEqual((len(value["cold"]), len(value["adopted"]), len(policy.HEADS)), (66, 176, 8))
        self.assertEqual(set(value["keyBindings"]), set(policy.adopted.profile.KEY_PURPOSES))
        self.assertEqual(len(value["keyBindings"]), 123)
        self.assertTrue(all(value["adopted"][name] == {"rule": policy.EXTERNAL_HEAD} for name in policy.HEADS))

    def test_authenticated_static_bootstrap_returns_exact_ten_parameters(self):
        prepared = prepare(self.source)
        expected = {name: item for name, item in self.source["source"]["parameters"].items()
            if name not in self.source["clocks"]}
        self.assertEqual(prepared["bootstrap_configuration"], expected)
        self.assertEqual(prepared["currentHeadPeer"], self.source["value"]["currentHeadPeer"])
        decision = policy.authorize(prepared, "bootstrap", self.source["source"]["pending"],
            selection={}, **self.options(prepared))
        result = policy.lifecycle.bootstrap(self.source["source"]["pending"],
            **prepared["bootstrap_configuration"], **self.source["clocks"])
        self.assertEqual((decision["deadline"], decision["epochLimit"]), (result["deadline"], result["epochLimit"]))
        self.assertNotIn("approval", result["originals"])

    def test_adopted_supervisor_policy_is_not_delegation_authority(self):
        actual = source_fixture.bootstrap(self.source["source"])["originals"]["policy"]
        with self.assertRaises(ValueError): policy.shape(actual)

    def test_unknown_fields_wildcards_and_rule_promotion_refuse(self):
        for change in ("field", "wildcard", "missing", "rule", "head"):
            value = copy.deepcopy(self.source["value"])
            if change == "field": value["approve"] = True
            elif change == "wildcard": value["cold"]["*"] = {"rule": policy.DERIVE, "selection": {}}
            elif change == "missing": del value["adopted"]["driver-bootstrap"]
            elif change == "rule": value["rendezvous"]["rule"] = "accept-any-peer"
            else: value["adopted"][policy.HEADS[0]] = {"rule": policy.DERIVE, "selection": {"currentness": {}}}
            with self.subTest(change=change), self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_pins_source_and_key_purpose_bindings_are_not_optional(self):
        for name in ("catalogueSha256", "measuredRecipeSha256", "supervisorInventorySha256",
                "authorityInventorySha256", "conductorInventorySha256", "listenerConfigurationSha256"):
            value = copy.deepcopy(self.source["value"]); value[name] = p.sha(b"other original")
            with self.subTest(name=name), self.assertRaises(ERRORS): prepare(self.source, value)
        value = copy.deepcopy(self.source["value"])
        value["keyBindings"]["driver-bootstrap"] = p.sha(b"other signer")
        with self.assertRaises(ERRORS): prepare(self.source, value)
        value = copy.deepcopy(self.source["value"]); del value["keyBindings"]["driver-bootstrap"]
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))
        value = copy.deepcopy(self.source["value"])
        value["keyBindings"] = {"adopted": value["keyBindings"], "cold": {
            name: p.sha(b"inert cold key declaration") for name in policy.cold.jobs.KEY_PURPOSES}}
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_bootstrap_and_all_decisions_require_exact_lifecycle_peer(self):
        prepared = prepare(self.source)
        for name in policy.PEER_FIELDS:
            peer = dict(prepared["peer"]); peer[name] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.authorize(prepared, "bootstrap", self.source["source"]["pending"], selection={},
                    **(self.options(prepared) | {"peer": peer}))
        value = copy.deepcopy(self.source["value"]); value["currentHeadPeer"] = dict(value["lifecyclePeer"])
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))
        value = copy.deepcopy(self.source["value"]); value["lifecyclePeer"]["pid"] = True
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_original_boot_and_both_expiries_bound_decisions(self):
        prepared = prepare(self.source)
        for changes in ({"boot": (self.source["clocks"]["boot"][0], 0, 999)},
                {"now_boottime_ns": prepared["startupDeadline"]}, {"now_unix_ns": prepared["epochLimit"]},
                {"now_boottime_ns": prepared["_issued"] - 1}, {"now_unix_ns": prepared["_epoch_issued"] - 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                policy.authorize(prepared, "bootstrap", self.source["source"]["pending"], selection={},
                    **(self.options(prepared) | changes))

    def test_rendezvous_only_selects_exact_delegated_observed_receiver(self):
        prepared = prepare(self.source); raw = self.source["source"]["request_raw"]
        fragment = policy.selection(prepared, "rendezvous", pending=raw)
        self.assertEqual(fragment, {"expected_request_sha256": p.sha(raw), "expected_receiver": self.source["source"]["receiver"]})
        policy.authorize(prepared, "rendezvous", raw, selection=fragment, **self.options(prepared))
        for name in ("expected_request_sha256", "expected_receiver"):
            altered = copy.deepcopy(fragment)
            if name == "expected_request_sha256": altered[name] = p.sha(b"other request")
            else: altered[name]["pid"] += 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.authorize(prepared, "rendezvous", raw, selection=altered, **self.options(prepared))

    def test_static_selection_cannot_be_replaced_by_compiler_output(self):
        prepared = prepare(self.source); packet = pending(prepared)
        self.assertEqual(policy.selection(prepared, "adopted", "driver-bootstrap"), {})
        policy.authorize(prepared, "adopted", packet, selection={}, **self.options(prepared))
        with self.assertRaises(ValueError): policy.authorize(prepared, "adopted", packet,
            selection={"inputOriginal": "validated is not delegated"}, **self.options(prepared))
        with self.assertRaises(ValueError): policy.selection(prepared, "adopted", "not-a-job")

    def test_cold_request_binds_exact_named_selection_and_original_cap(self):
        prepared = prepare(self.source)
        job = policy.COLD[0]
        _, raw = policy.cold.wire.request(sequence=1, job=job.name,
            deadline=prepared["startupDeadline"], observation={}, previous=None, handoff=True)
        fragment = policy.selection(prepared, "cold", job.name)
        # This authorizes only the pinned derivation. The unreachable placeholder
        # members still need the real compiler's independent semantic validation.
        caps = policy.authorize(prepared, "cold", raw, selection=fragment, **self.options(prepared))
        self.assertEqual(caps["deadline"], prepared["startupDeadline"])
        with self.assertRaises(ValueError): policy.authorize(prepared, "cold", raw,
            selection={"members": []}, **self.options(prepared))
        with self.assertRaises(ValueError): policy.authorize(prepared, "cold", b" " + raw,
            selection=fragment, **self.options(prepared))

    def test_ordinary_runtime_policy_cannot_preselect_future_driver_identity(self):
        self.assertEqual(policy.adopted.selection_fields("install-ordinary-runtime"), ("runtimePolicy", "peerExpectations"))
        value = copy.deepcopy(self.source["value"])
        value["adopted"]["install-ordinary-runtime"]["selection"] = {
            "runtimePolicy": None, "peerOriginal": "{}", "peerSha256": p.sha(b"{}")}
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_all_eight_heads_refuse_automatic_and_only_allow_external_scope(self):
        prepared = prepare(self.source)
        for name in policy.HEADS:
            packet = pending(prepared, name)
            with self.subTest(name=name):
                with self.assertRaises(ValueError): policy.selection(prepared, "adopted", name)
                with self.assertRaises(ValueError): policy.authorize(prepared, "adopted", packet,
                    selection={"currentness": {}}, **self.options(prepared))
                caps = policy.admit_external(prepared, packet, **self.options(prepared))
                self.assertEqual(caps, {"deadline": prepared["startupDeadline"], "epochLimit": prepared["epochLimit"]})
        with self.assertRaises(ValueError): policy.admit_external(prepared, pending(prepared), **self.options(prepared))

    def test_integer_request_sequences_are_not_boolean_aliases(self):
        prepared = prepare(self.source)
        for name in ("sequence", "jobIndex", "conductorSequence"):
            packet = pending(prepared)
            value = json.loads(packet["requestOriginal"]); value[name] = True
            raw = p.canonical(value); packet.update(requestOriginal=raw.decode("ascii"), requestSha256=p.sha(raw))
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.authorize(prepared, "adopted", packet, selection={}, **self.options(prepared))

    def test_interactive_selection_derives_only_actual_origin_binding(self):
        value = copy.deepcopy(self.source["value"])
        clocks = self.source["clocks"]
        interval = {"apiVersion": policy.lifecycle.interactive.API,
            "stopAtBoottimeNanos": clocks["now_boottime_ns"] + 10_000_000,
            "expiresAtUnixNanos": clocks["now_unix_ns"] + 100_000_000}
        value["bootstrap"]["policySelection"] = {"apiVersion": policy.lifecycle.policy.INTERACTIVE_API,
            "purpose": policy.lifecycle.policy.INTERACTIVE_PURPOSE, "interactive": interval}
        value["adopted"]["stop"] = {"rule": policy.INTERACTIVE_STOP, "selection": {"action": {
            "action": "run-interactive", **{name: interval[name] for name in policy.lifecycle.interactive.FIELDS[1:]}}}}
        prepared = prepare(self.source, value)
        handoff = {"apiVersion": "catchplate.nativeGenerationOriginHandoff/v1", "okForAction": False,
            "automaticRetryAllowed": False, "originSha256": p.sha(b"actual transcript origin test bytes")}
        packet = pending(prepared, "stop", payload={"originHandoff": handoff})
        selected = policy.selection(prepared, "adopted", "stop", packet)
        self.assertEqual(selected["action"]["originHandoffSha256"], p.sha(p.canonical(handoff)))
        caps = policy.authorize(prepared, "adopted", packet, selection=selected, **self.options(prepared))
        self.assertEqual(caps["epochLimit"], interval["expiresAtUnixNanos"])
        selected["action"]["originHandoffSha256"] = p.sha(b"another origin")
        with self.assertRaises(ValueError): policy.authorize(prepared, "adopted", packet,
            selection=selected, **self.options(prepared))
        value["bootstrap"]["policySelection"] = copy.deepcopy(self.source["value"]["bootstrap"]["policySelection"])
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_static_policy_mutation_or_future_stop_hash_is_not_a_decision(self):
        prepared = prepare(self.source)
        prepared["value"]["adopted"]["driver-bootstrap"]["selection"]["unexpected"] = True
        with self.assertRaises(ValueError): policy.selection(prepared, "adopted", "driver-bootstrap")
        value = copy.deepcopy(self.source["value"])
        value["adopted"]["stop"]["selection"]["action"]["originHandoffSha256"] = p.sha(b"predicted future")
        with self.assertRaises(ValueError): policy.shape(policy.canonical(value))

    def test_policy_codec_preserves_unsigned_fragments_without_widening_grants(self):
        value = copy.deepcopy(self.source["value"])
        name = next(job.name for job in policy.COLD if job.family == "ordinary-runtime" and policy.cold.selection_fields(job.name))
        value["cold"][name]["selection"]["runtimePolicy"] = {"syntheticUnsignedCounter": p.MAX_U64}
        self.assertEqual(policy.shape(policy.canonical(value))["cold"][name]["selection"]["runtimePolicy"]["syntheticUnsignedCounter"], p.MAX_U64)
        with self.assertRaises(ValueError): p.canonical({"stillSignedI64": p.MAX_U64})
        for raw in (b'{"apiVersion":"a","apiVersion":"b"}', b'{"fraction":0.1}', b' {}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): policy.shape(raw)


if __name__ == "__main__": unittest.main()
