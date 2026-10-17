#!/usr/bin/env python3
"""Pure completion framing controls, not native execution or cleanup evidence.

The synthetic transcript skips unrelated exchanges when selecting the final
request. No live owner, validator, approval decision, EOF or reap is fabricated.
Real channel sequencing and actual process completion remain separate gates.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts.test_native_pilot_adopted_completion import fixture as adopted_fixture
from scripts.test_native_pilot_genesis_rendezvous import fixture as rendezvous_fixture
from catchplate import native_pilot_lifecycle_approval_wire as wire

p = wire.p
FAILURES = (ValueError, KeyError, TypeError)
CAPS = dict(deadline_boottime_ns=4_000_000_000, expires_at_unix_ns=9_000_000_000)


def accepted(context, header, index, *, input_raw=None):
    """Synthetic already-transferred pins; never an approval constructor."""
    pins = {name: p.sha(("synthetic-" + name).encode("ascii"))
        for name, _ in wire.descriptor_limits(index)}
    if input_raw is not None: pins["input"] = p.sha(input_raw)
    reply = dict(apiVersion=wire.REPLY_API, requestBindingSha256=p.sha(p.canonical(header)), pins=pins)
    wire.reply(reply, header, index)
    return wire.committed(context, header["stage"], reply)


def base_context(*, completions=True, rendezvous=True):
    f = rendezvous_fixture()
    pending = dict(senderRequestOriginal=f["sender_raw"].decode("ascii"),
        listenerConfigurationOriginal=f["configuration_raw"].decode("ascii"))
    header, raws, context = wire.request("bootstrap", pending, 0, **CAPS, context={},
        boot=f["boot"], now_boottime_ns=f["now_boottime_ns"], completions=completions)
    context = accepted(context, header, 0)
    if rendezvous:
        header, raws, context = wire.request("rendezvous", f["request_raw"], 1, **CAPS,
            context=context, boot=f["boot"], now_boottime_ns=f["now_boottime_ns"], completions=completions)
        context = accepted(context, header, 1, input_raw=f["input_raw"])
    return f, header, raws, context


def cold_case():
    f, _, _, context = base_context()
    index = 1 + len(wire.COLD)
    request_raw = p.canonical(dict(apiVersion=wire.cold_install.wire.HANDOFF_REQUEST_API,
        sequence=len(wire.COLD), job=wire.COLD[-1].name, deadlineBoottimeNs="4000000000", observation={},
        previousResult=dict(job=wire.COLD[-2].name, resultOriginal="{}", resultSha256=p.sha(b"{}"))))
    header, _, context = wire.request("cold", request_raw, index, **CAPS, context=context,
        boot=f["boot"], now_boottime_ns=f["now_boottime_ns"], completions=True)
    input_raw = p.canonical(dict(apiVersion=wire.cold_install.wire.ACTION_API, action="handoff-cold-core"))
    context = accepted(context, header, index, input_raw=input_raw)
    # This placeholder is explicitly NOT a native Bundle or a successful owner.
    # The framing layer preserves its bytes; process/provider admission is separate.
    bundle_raw = b"{}"
    result_raw = p.canonical(dict(status="cold-core-custody-acknowledged", bundleSha256=p.sha(bundle_raw),
        observationSha256=p.sha(b"synthetic-core-observation"), operationalAdoptionVerified=False))
    value = dict(apiVersion=wire.process.replies.RENDEZVOUS_TERMINAL_API,
        status="cold-core-custody-acknowledged", jobsCompleted=len(wire.COLD),
        bundleOriginal=bundle_raw.decode("ascii"), bundleSha256=p.sha(bundle_raw),
        pilotAcceptanceVerified=False, productionReleaseEligible=False, operationalAdoptionVerified=False,
        configurationSha256=p.sha(f["input_raw"]), deadlineBoottimeNs="3900000000", expiresAtUnixNanos=8_900_000_000,
        finalResult=dict(job="handoff-cold-core", inputSha256=p.sha(input_raw),
            resultOriginal=result_raw.decode("ascii"), resultSha256=p.sha(result_raw)))
    return dict(value=value, context=context, request_raw=request_raw, input_raw=input_raw,
        index=index + 1, completed=0, source=f)


def adopted_case(*, run=False):
    f, _, _, context = base_context()
    case = adopted_fixture(run=run)
    request = copy.deepcopy(case["request"])
    request.update(deadlineBoottimeNs="3900000000", expiresAtUnixNanos="8900000000")
    request["conductorRequest"].update(deadlineBoottimeNs=request["deadlineBoottimeNs"],
        expiresAtUnixNanos=request["expiresAtUnixNanos"])
    request["conductorRequestSha256"] = p.sha(p.canonical(request["conductorRequest"]))
    request_raw = p.canonical(request)
    observation_raw = p.canonical(dict(apiVersion="catchplate.nativePilotAdoptedSupervisorObservation/v1",
        policySha256=context["bootstrapPins"]["policy"], catalogueSha256=p.sha(wire.policy.catalogue_original()),
        intakeConfigurationSha256=context["bootstrapPins"]["intake_configuration"],
        conductorRequestOriginal=p.canonical(request["conductorRequest"]).decode("ascii"),
        measuredConfiguration=None, recipeOriginals=None))
    index = len(wire.ORDER) - 1
    pending = wire.pending("adopted", dict(request=request_raw, observation=observation_raw))
    header, _, context = wire.request("adopted", pending, index, **CAPS, context=context,
        boot=f["boot"], now_boottime_ns=f["now_boottime_ns"], completions=True)
    context = accepted(context, header, index, input_raw=case["input_raw"])
    value = case["value"] | dict(deadlineBoottimeNs="3800000000", expiresAtUnixNanos="8800000000")
    return dict(value=value, context=context, request_raw=request_raw, input_raw=case["input_raw"],
        index=index + 1, completed=1, source=f)


def checked(case, *, raw=None, caps=None):
    return wire.completion(p.canonical(case["value"]) if raw is None else raw,
        case["index"], case["completed"], context=case["context"], **(CAPS if caps is None else caps))


class LifecycleCompletionWireControls(unittest.TestCase):
    def test_selected_request2_starts_at_first_exchange_and_default_stays_v1(self):
        old, old_header, old_raws, old_context = base_context(completions=False, rendezvous=False)
        new, new_header, new_raws, new_context = base_context(rendezvous=False)
        self.assertEqual(old_header["apiVersion"], wire.REQUEST_API)
        self.assertEqual(new_header["apiVersion"], wire.COMPLETION_REQUEST_API)
        self.assertEqual(old_raws, new_raws)
        self.assertNotIn("completionMode", old_context)
        self.assertIs(new_context["completionMode"], True)
        wire.header(old_header, 0, **CAPS)
        wire.header(new_header, 0, **CAPS, completions=True)
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wire.header(new_header, 0, **CAPS, completions=value)
            with self.assertRaises(ValueError):
                wire.request("bootstrap", wire.pending("bootstrap", new_raws), 0, **CAPS,
                    context={}, boot=new["boot"], now_boottime_ns=new["now_boottime_ns"], completions=value)
        with self.assertRaises(ValueError): wire.header(new_header, 0, **CAPS)
        with self.assertRaises(ValueError): wire.header(old_header, 0, **CAPS, completions=True)

    def test_mode_cannot_upgrade_or_downgrade_after_bootstrap(self):
        for selected in (False, True):
            f, _, _, context = base_context(completions=selected, rendezvous=False)
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                wire.request("rendezvous", f["request_raw"], 1, **CAPS, context=context,
                    boot=f["boot"], now_boottime_ns=f["now_boottime_ns"], completions=not selected)

    def test_completion_schedule_has_exact_two_nonapproval_notifications(self):
        self.assertEqual(len(wire.ORDER), 244)
        self.assertEqual(wire.completion_stage(68, 0), "cold")
        self.assertEqual(wire.completion_stage(244, 1), "adopted")
        for index, completed in ((67, 0), (69, 0), (68, 1), (244, 0), (244, 2), (245, 1), (True, 0), (68, False)):
            with self.subTest(index=index, completed=completed), self.assertRaises(ValueError):
                wire.completion_stage(index, completed)
        self.assertNotEqual(wire.COMPLETION_RECEIPT_API, wire.RECEIPT_API)

    def test_cold_literal_terminal_binds_execution_not_listener_configuration(self):
        case = cold_case(); header, raws = checked(case)
        self.assertEqual(raws, {"terminal": p.canonical(case["value"])})
        self.assertEqual(header["originals"]["terminal"], dict(length=len(raws["terminal"]), sha256=p.sha(raws["terminal"])))
        self.assertEqual(header["exchangeSequence"], 68)
        self.assertEqual(case["context"]["executionConfigurationSha256"], p.sha(case["source"]["input_raw"]))
        self.assertNotEqual(p.sha(case["source"]["input_raw"]), p.sha(case["source"]["configuration_raw"]))
        case["value"]["configurationSha256"] = p.sha(case["source"]["configuration_raw"])
        with self.assertRaises(ValueError): checked(case)

    def test_adopted_literal_final_result_and_optional_interval_are_preserved(self):
        for run in (False, True):
            case = adopted_case(run=run); before = copy.deepcopy(case)
            header, raws = checked(case)
            self.assertEqual(header["stage"], "adopted")
            self.assertEqual(header["exchangeSequence"], 244)
            self.assertEqual(header["expiresAtUnixNanos"], "5000" if run else "8800000000")
            self.assertEqual(raws["terminal"], p.canonical(case["value"]))
            self.assertEqual(case, before)

    def test_missing_selection_or_uncommitted_or_other_input_refuses(self):
        for field in ("completionMode", "terminalInputSha256", "terminalRequest", "executionConfigurationSha256"):
            case = cold_case(); case["context"].pop(field)
            with self.subTest(field=field), self.assertRaises(FAILURES): checked(case)
        for make in (cold_case, adopted_case):
            case = make(); case["value"]["finalResult"]["inputSha256"] = p.sha(b"different approved input")
            with self.subTest(stage=case["index"]), self.assertRaises(ValueError): checked(case)

    def test_final_result_is_exact_job_input_and_literal_canonical_hash(self):
        for make in (cold_case, adopted_case):
            for update in (dict(job="cleanup"), dict(resultSha256=p.sha(b"different result")), dict(extra=True)):
                case = make(); case["value"]["finalResult"].update(update)
                with self.subTest(stage=case["index"], update=update), self.assertRaises(ValueError): checked(case)
            for raw in (b'{ "action":"stop"}', b'[]', b'{"duplicate":1,"duplicate":2}'):
                case = make(); case["value"]["finalResult"].update(resultOriginal=raw.decode("ascii"), resultSha256=p.sha(raw))
                with self.subTest(stage=case["index"], raw=raw), self.assertRaises(ValueError): checked(case)

    def test_terminal_profiles_flags_and_inner_clock_types_stay_closed(self):
        for make in (cold_case, adopted_case):
            for update in (dict(apiVersion="catchplate.nativePilotAuthorityCoordinatorResult/v1"),
                    dict(status="approved"), dict(pilotAcceptanceVerified=True),
                    dict(productionReleaseEligible=0), dict(extra=True), dict(deadlineBoottimeNs=123)):
                case = make(); case["value"].update(update)
                with self.subTest(stage=case["index"], update=update), self.assertRaises(ValueError): checked(case)
        for update in (dict(expiresAtUnixNanos="8900000000"), dict(jobsCompleted=True),
                dict(operationalAdoptionVerified=True), dict(bundleSha256=p.sha(b"other bundle"))):
            case = cold_case(); case["value"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError): checked(case)
        case = adopted_case(); case["value"]["expiresAtUnixNanos"] = 8_800_000_000
        with self.assertRaises(ValueError): checked(case)

    def test_all_original_caps_intersect_without_rewriting_terminal(self):
        for make in (cold_case, adopted_case):
            case = make(); raw = p.canonical(case["value"])
            header, _ = checked(case)
            self.assertEqual(header["deadlineBoottimeNs"], case["value"]["deadlineBoottimeNs"])
            self.assertEqual(header["expiresAtUnixNanos"], str(case["value"]["expiresAtUnixNanos"]))
            header, raws = checked(case, caps=dict(deadline_boottime_ns=3_100_000_000, expires_at_unix_ns=8_100_000_000))
            self.assertEqual((header["deadlineBoottimeNs"], header["expiresAtUnixNanos"]), ("3100000000", "8100000000"))
            self.assertEqual(raws["terminal"], raw)
            case["context"]["terminalRequest"].update(deadlineBoottimeNs=3_200_000_000, expiresAtUnixNanos=8_200_000_000)
            header, _ = checked(case)
            self.assertEqual((header["deadlineBoottimeNs"], header["expiresAtUnixNanos"]), ("3200000000", "8200000000"))
            request = p.document(case["request_raw"], wire.MAX_REQUEST)
            request["deadlineBoottimeNs"] = "3100000000"
            if case["index"] == 244: request["expiresAtUnixNanos"] = "8100000000"
            case["context"]["terminalRequest"]["requestOriginal"] = p.canonical(request)
            header, _ = checked(case)
            self.assertEqual(header["deadlineBoottimeNs"], "3100000000")
            if case["index"] == 244: self.assertEqual(header["expiresAtUnixNanos"], "8100000000")

    def test_header_metadata_and_outer_caps_are_exact_and_bounded(self):
        case = cold_case(); header, _ = checked(case)
        self.assertEqual(wire.completion_header(header, 68, 0, **CAPS), ("cold", 3_900_000_000, 8_900_000_000))
        for update in (dict(apiVersion=wire.COMPLETION_REQUEST_API), dict(exchangeSequence=69), dict(stage="adopted"),
                dict(extra=True), dict(deadlineBoottimeNs="4000000001"), dict(expiresAtUnixNanos="9000000001")):
            with self.subTest(update=update), self.assertRaises(ValueError):
                wire.completion_header(header | update, 68, 0, **CAPS)
        for update in (dict(length=0), dict(length=True), dict(length=wire.MAX_REQUEST + 1), dict(sha256="not-a-digest"), dict(extra=True)):
            changed = copy.deepcopy(header); changed["originals"]["terminal"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                wire.completion_header(changed, 68, 0, **CAPS)
        with self.assertRaises(ValueError): checked(case, raw=p.canonical(case["value"]) + b"\n")

    def test_final_request_marker_must_be_the_selected_last_job_and_stage(self):
        for make in (cold_case, adopted_case):
            for update in (dict(job="cleanup"), dict(sequence=True), dict(sequence=1), dict(apiVersion=wire.REQUEST_API)):
                case = make(); request = p.document(case["request_raw"], wire.MAX_REQUEST); request.update(update)
                case["context"]["terminalRequest"]["requestOriginal"] = p.canonical(request)
                with self.subTest(stage=case["index"], update=update), self.assertRaises(ValueError): checked(case)
        case = cold_case(); case["context"]["terminalRequest"]["stage"] = "adopted"
        with self.assertRaises(ValueError): checked(case)


if __name__ == "__main__": unittest.main()
