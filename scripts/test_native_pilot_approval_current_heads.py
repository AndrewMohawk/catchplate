#!/usr/bin/env python3
"""Synthetic signed-source ingress controls, never fresh operational decisions.

The existing eight-target fixture contains genuine-format synthetic signatures
and explicitly test-only currentness decisions. Pair approvals below are test
framing, not external authority. No descriptor, process owner or decision
service is fabricated, and no successful validator is mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts.test_native_pilot_adopted_bridge_inputs import head_case, compose
from scripts.test_native_pilot_adopted_current_head import fixture as head_fixture
from scripts.test_native_pilot_adopted_supervisor import ticket
from scripts.test_native_pilot_current_head import refresh_decision, refresh_request
from catchplate import native_pilot_approval_current_heads as intake
from catchplate.native_pilot_adopted_supervisor_policy import catalogue_original

p = intake.p
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture(name=None):
    name = intake.JOB_NAMES[0] if name is None else name
    f = head_fixture()
    index = intake.INDICES[intake.JOB_NAMES.index(name)]
    request, conductor = ticket(index, deadline=5000, expiry=9000)
    conductor["payload"] = {"bridgePreparationOriginal": f["args"]["bridge_preparation_raw"].decode("ascii")}
    request["conductorRequestSha256"] = p.sha(p.canonical(conductor))
    if request["jobIndex"] == 1: request["conductorRequest"] = copy.deepcopy(conductor)
    request_raw = p.canonical(request)
    observation_raw = p.canonical(dict(apiVersion="catchplate.nativePilotAdoptedSupervisorObservation/v1",
        policySha256=p.sha(b"synthetic-policy"),
        catalogueSha256=p.sha(catalogue_original()),
        intakeConfigurationSha256=p.sha(b"synthetic-intake"),
        conductorRequestOriginal=p.canonical(conductor).decode("ascii"), measuredConfiguration=None, recipeOriginals=None))
    pending = dict(phase=request["phase"], job=name, sequence=request["sequence"],
        status="awaiting-independent-job-approval", requestOriginal=request_raw.decode("ascii"),
        requestSha256=p.sha(request_raw), observationOriginal=observation_raw.decode("ascii"),
        observationSha256=p.sha(observation_raw))
    raw = f["inputs"][name]
    approval = {"apiVersion": intake.profile.APPROVAL_API,
        **{field: request[field] for field in intake.profile.APPROVAL_FIELDS[1:-1]}, "inputSha256": p.sha(raw)}
    return dict(source=f, name=name, pending=pending, input_raw=raw, approval_raw=p.canonical(approval),
        clocks=f["clocks"] | {"now_unix_ns": 1000})


def selected(f, **clocks):
    return intake.selection(f["pending"], f["input_raw"], f["approval_raw"], **(f["clocks"] | clocks))


def approval_for(f, input_raw):
    """Only shape a synthetic test approval; production never calls this."""
    value = p.document(f["approval_raw"], intake.MAX_APPROVAL)
    value["inputSha256"] = p.sha(input_raw)
    return p.canonical(value)


def candidate(f):
    # Exercise the real pure family compiler over its labelled source records.
    # This is not represented as an actual retained CandidateTranscript owner.
    _, options = head_case(f["name"])
    raw = compose(f["name"], selected(f), options)
    return dict(originals={"input": raw}, pins={"input": p.sha(raw)}, deadline=5000, epochLimit=9000)


def joined(f, value=None, **clocks):
    return intake.require_candidate(candidate(f) if value is None else value,
        f["input_raw"], f["approval_raw"], pending=f["pending"], **(f["clocks"] | clocks))


class CurrentHeadDecisionIngressControls(unittest.TestCase):
    def test_exact_eight_adopted_jobs_accept_only_supplied_decision_and_pair(self):
        self.assertEqual(len(intake.JOB_NAMES), 8)
        self.assertEqual(len(set(intake.INDICES)), 8)
        for name in intake.JOB_NAMES:
            f = fixture(name); before = copy.deepcopy(f)
            decision = selected(f)
            self.assertEqual(decision, {"currentness": p.document(f["input_raw"], intake.MAX_INPUT)["currentness"]})
            decision["currentness"]["issuedAtBoottimeNanos"] += 1
            self.assertEqual(f, before)
            self.assertNotEqual(decision, selected(f))

    def test_real_family_candidate_preserves_external_input_and_approval_bytes(self):
        for name in (intake.JOB_NAMES[0], intake.JOB_NAMES[-1]):
            f = fixture(name); value = candidate(f); result = joined(f, value)
            self.assertEqual(result["originals"], {"input": f["input_raw"], "approval": f["approval_raw"]})
            self.assertEqual(result["pins"], {kind: p.sha(raw) for kind, raw in result["originals"].items()})
            self.assertEqual(set(result), {"originals", "pins", "deadline", "epochLimit"})
            self.assertNotIn("approval", value["originals"])

    def test_legacy_or_nonhead_slot_never_receives_adopted_decision_authority(self):
        for update in ({"job": "driver-bootstrap"}, {"phase": "shutdown"}, {"sequence": True}):
            f = fixture(); f["pending"].update(update)
            with self.subTest(update=update), self.assertRaises(ERRORS): selected(f)
        for api in (intake.head.API, intake.head.HELPER_API):
            f = fixture(); value = p.document(f["input_raw"], intake.MAX_INPUT); value["apiVersion"] = api
            f["input_raw"] = p.canonical(value); f["approval_raw"] = approval_for(f, f["input_raw"])
            with self.subTest(api=api), self.assertRaises(ERRORS): selected(f)
        f = fixture(); f["input_raw"] = f["source"]["inputs"][intake.JOB_NAMES[1]]
        f["approval_raw"] = approval_for(f, f["input_raw"])
        with self.assertRaises(ERRORS): selected(f)

    def test_independent_approval_is_required_exact_and_cannot_be_recreated_from_validation(self):
        for update in ({"apiVersion": "catchplate.nativePilotAuthorityJobApproval/v1"},
                {"inputSha256": p.sha(b"other input")}, {"conductorRequestSha256": p.sha(b"other request")},
                {"jobIndex": True}, {"deadlineBoottimeNs": "5001"}, {"expiresAtUnixNanos": "9001"}, {"extra": True}):
            f = fixture(); value = p.document(f["approval_raw"], intake.MAX_APPROVAL); value.update(update)
            f["approval_raw"] = p.canonical(value)
            with self.subTest(update=update), self.assertRaises(ERRORS): selected(f)
        f = fixture(); f["approval_raw"] = b"{}"
        with self.assertRaises(ERRORS): selected(f)

    def test_internally_valid_fresh_nonce_is_not_the_actual_conductor_request(self):
        f = fixture(); value = p.document(f["input_raw"], intake.MAX_INPUT)
        request = p.document(value["requestOriginal"].encode("ascii"), intake.head.MAX_REQUEST)
        request["requestEntropyBase64"] = p.encoded(b"Z" * 32)
        refresh_request(request); value["requestOriginal"] = p.canonical(request).decode("ascii"); refresh_decision(value)
        changed = p.canonical(value)
        intake.head.prepare_input(changed, **f["source"]["clocks"], adopted=True)
        f["input_raw"] = changed; f["approval_raw"] = approval_for(f, changed)
        with self.assertRaises(ERRORS): selected(f)

    def test_full_head_validator_runs_before_decision_is_extracted(self):
        for mutation in ("missing-decision", "wrong-history", "wrong-checkpoint", "future-decision"):
            f = fixture(); value = p.document(f["input_raw"], intake.MAX_INPUT)
            if mutation == "missing-decision": del value["currentness"]
            elif mutation == "wrong-history": value["currentness"]["initialHistorySha256"] = p.sha(b"wrong history")
            elif mutation == "wrong-checkpoint": value["currentness"]["checkpointSha256"] = p.sha(b"wrong checkpoint")
            else: value["currentness"]["issuedAtBoottimeNanos"] = f["clocks"]["now_boottime_ns"] + 1
            f["input_raw"] = p.canonical(value); f["approval_raw"] = approval_for(f, f["input_raw"])
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS): selected(f)

    def test_candidate_cannot_replace_approved_bytes_pin_or_add_an_approval(self):
        f = fixture(); value = candidate(f)
        for mutation in ("bytes", "pin", "extra-original", "extra-field"):
            changed = copy.deepcopy(value)
            if mutation == "bytes":
                changed["originals"]["input"] += b"\n"; changed["pins"]["input"] = p.sha(changed["originals"]["input"])
            elif mutation == "pin": changed["pins"]["input"] = p.sha(b"different bytes")
            elif mutation == "extra-original": changed["originals"]["approval"] = f["approval_raw"]
            else: changed["approved"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS): joined(f, changed)

    def test_original_boot_and_both_clock_ceilings_remain_in_force(self):
        f = fixture(); now = f["clocks"]["now_boottime_ns"]
        value = candidate(f) | {"deadline": now + 1, "epochLimit": 1001}
        result = joined(f, value)
        self.assertEqual((result["deadline"], result["epochLimit"]), (now + 1, 1001))
        for clocks in ({"now_boottime_ns": 5000}, {"now_unix_ns": 9000},
                {"now_boottime_ns": True}, {"now_unix_ns": True},
                {"boot": (f["clocks"]["boot"][0], 12, 13)}):
            with self.subTest(clocks=clocks), self.assertRaises(ERRORS): selected(f, **clocks)
        for cap in ({"deadline": now}, {"epochLimit": 1000}, {"deadline": True}, {"epochLimit": None}):
            with self.subTest(cap=cap), self.assertRaises(ERRORS): joined(f, candidate(f) | cap)

    def test_external_wait_is_bounded_by_inner_request_without_needing_a_decision(self):
        f = fixture()
        input_value = p.document(f["input_raw"], intake.MAX_INPUT)
        trust = intake.head.request(input_value["requestOriginal"].encode("ascii"))
        inner = trust["deadline"]["absoluteBoottimeNanos"]
        pending = copy.deepcopy(f["pending"])
        request = p.document(pending["requestOriginal"].encode("ascii"), intake.channel.MAX_REQUEST)
        observed = p.document(pending["observationOriginal"].encode("ascii"), intake.channel.MAX_REQUEST)
        conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), intake.channel.MAX_REQUEST)
        request["deadlineBoottimeNs"] = conductor["deadlineBoottimeNs"] = str(inner + 100)
        conductor_raw = p.canonical(conductor)
        observed["conductorRequestOriginal"] = conductor_raw.decode("ascii")
        request["conductorRequestSha256"] = p.sha(conductor_raw)
        request["conductorRequest"] = conductor
        for name, value in (("request", request), ("observation", observed)):
            raw = p.canonical(value)
            pending[name + "Original"], pending[name + "Sha256"] = raw.decode("ascii"), p.sha(raw)
        self.assertEqual(intake.pending_bounds(pending), {"deadline": inner, "epochLimit": 9000})
        pending["job"] = "driver-scope"
        with self.assertRaises(ERRORS): intake.pending_bounds(pending)


if __name__ == "__main__": unittest.main()
