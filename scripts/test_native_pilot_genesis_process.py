#!/usr/bin/env python3
"""Pure cold-process dialogue controls; no process, PIDFD or cleanup claim.

The reused core fixture is synthetic public association only, not a valid
native commissioning transcript or proof of received descriptor custody.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.test_native_pilot_genesis_core import fixture as core_fixture
from scripts.test_native_pilot_genesis_rendezvous import fixture
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_process as process

p = process.p


def sender(value, raw=None, **identity):
    return process.sender_value(value["sender_raw"] if raw is None else raw,
        configuration_raw=value["configuration_raw"], boot=value["boot"],
        identity=dict(pid=100, startTimeTicks=123) | identity)


def job(index=0):
    previous = None if index == 0 else dict(job=process._JOBS[index - 1].name,
        resultOriginal="{}", resultSha256=p.sha(b"{}"))
    return dict(apiVersion=process.wire.HANDOFF_REQUEST_API, sequence=index + 1,
        job=process._JOBS[index].name, deadlineBoottimeNs="2000000000",
        observation={}, previousResult=previous)


def terminal():
    bundle, _, observation = core_fixture()
    raw = g.canonical(bundle)
    return dict(apiVersion=process.replies.HANDOFF_TERMINAL_API,
        status="cold-core-custody-acknowledged", jobsCompleted=66,
        bundleOriginal=raw.decode("ascii"), bundleSha256=p.sha(raw),
        pilotAcceptanceVerified=False, productionReleaseEligible=False,
        operationalAdoptionVerified=False), g.canonical(observation), raw


class ColdProcessProtocolControls(unittest.TestCase):
    def test_sender_joins_supplied_actual_identity_and_original_bounds(self):
        value = fixture()
        checked = sender(value)
        self.assertEqual(checked["sequence"], 0)
        self.assertEqual(checked["deadlineBoottimeNs"], "2000000000")
        self.assertEqual(checked["configurationSha256"], p.sha(value["configuration_raw"]))

    def test_sender_cannot_substitute_owned_pid_or_start(self):
        value = fixture()
        for identity in ({"pid": 101}, {"startTimeTicks": 124}):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                sender(value, **identity)
        parsed = p.document(value["sender_raw"], 8192)
        observed = p.document(parsed["listenerOriginal"].encode("ascii"), 8192)
        observed["processId"] = True
        parsed.update(listenerOriginal=p.canonical(observed).decode("ascii"),
            listenerSha256=p.sha(p.canonical(observed)))
        with self.assertRaises(ValueError): sender(value, p.canonical(parsed))

    def test_sender_refuses_namespace_and_unbound_listener_changes(self):
        value = fixture()
        with self.assertRaises(ValueError): sender(value | {"boot": (value["boot"][0], 12, 11)})
        parsed = p.document(value["sender_raw"], 8192)
        observed = p.document(parsed["listenerOriginal"].encode("ascii"), 8192)
        observed["processStartTimeTicks"] += 1
        parsed["listenerOriginal"] = p.canonical(observed).decode("ascii")
        with self.assertRaises(ValueError): sender(value, p.canonical(parsed))

    def test_sender_is_closed_canonical_and_not_legacy_upgrade(self):
        value = fixture()
        parsed = p.document(value["sender_raw"], 8192)
        for update in ({"sequence": False}, {"approved": True}, {"deadlineBoottimeNs": "2000000001"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                sender(value, p.canonical(parsed | update))
        with self.assertRaises(ValueError): sender(value, value["sender_raw"] + b"\n")
        configuration = p.document(value["configuration_raw"], 4096)
        configuration["apiVersion"] = "catchplate.nativePilotGenesisListenerConfiguration/v1"
        with self.assertRaises(ValueError): sender(value | {"configuration_raw": p.canonical(configuration)})

    def test_selected_catalogue_has_exact_66_actual_dialogue_slots(self):
        self.assertEqual(len(process._JOBS), 66)
        for index in range(len(process._JOBS)):
            selected = job(index)
            self.assertEqual(process.job_value(p.canonical(selected), index=index,
                upper_deadline=2000000000), selected)
        self.assertEqual(tuple(item.name for item in process._JOBS[-4:]),
            ("coordinator-finish", "acquire-cold-core", "cleanup", "handoff-cold-core"))

    def test_job_refuses_wrong_slot_old_wire_and_later_deadline(self):
        value = job()
        for update in ({"job": process._JOBS[1].name}, {"sequence": True},
                {"apiVersion": process.wire.REQUEST_API}, {"deadlineBoottimeNs": "2000000001"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.job_value(p.canonical(value | update), index=0, upper_deadline=2000000000)
        with self.assertRaises(ValueError):
            process.job_value(p.canonical(value), index=66, upper_deadline=2000000000)

    def test_previous_result_literal_and_predecessor_are_exact(self):
        value = job(1)
        for update in ({"job": process._JOBS[2].name}, {"resultOriginal": '{"other":true}'},
                {"resultSha256": p.sha(b"other")}, {"resultOriginal": "\u00e9"}):
            changed = copy.deepcopy(value); changed["previousResult"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.job_value(p.canonical(changed), index=1, upper_deadline=2000000000)
        value = job(); value["previousResult"] = job(1)["previousResult"]
        with self.assertRaises(ValueError):
            process.job_value(p.canonical(value), index=0, upper_deadline=2000000000)

    def test_observation_keys_and_values_cannot_create_an_owner(self):
        value = job()
        value["observation"] = {"core.observation": "{}"}
        self.assertEqual(process.job_value(p.canonical(value), index=0,
            upper_deadline=2000000000)["observation"], value["observation"])
        for observed in ({"liveOwner": "{}"}, {"core.observation": 10}, {"core.observation": ""}):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                process.job_value(p.canonical(value | {"observation": observed}), index=0,
                    upper_deadline=2000000000)

    def test_terminal_associates_literal_bundle_but_asserts_no_adoption(self):
        value, observed, bundle = terminal()
        checked, original = process.terminal_value(p.canonical(value), observation_raw=observed)
        self.assertEqual(original, bundle)
        self.assertIs(checked["operationalAdoptionVerified"], False)
        self.assertIs(checked["pilotAcceptanceVerified"], False)

    def test_terminal_refuses_replaced_bundle_counts_or_success_claims(self):
        value, observed, _ = terminal()
        for update in ({"bundleOriginal": "{}"}, {"bundleSha256": p.sha(b"other")},
                {"jobsCompleted": 64}, {"jobsCompleted": True}, {"operationalAdoptionVerified": True},
                {"productionReleaseEligible": True}, {"status": "adopted"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.terminal_value(p.canonical(value | update), observation_raw=observed)
        replaced = g.document(observed, process.core.MAX_OBSERVATION)
        replaced["bundleSha256"] = p.sha(b"other")
        with self.assertRaises(ValueError):
            process.terminal_value(p.canonical(value), observation_raw=g.canonical(replaced))

    def test_public_dictionaries_cannot_construct_process_or_pipe_token(self):
        with self.assertRaises(ValueError): process.GenesisAuthorityProcess(object())
        with self.assertRaises(ValueError): process.GenesisRequest(object(), "job", p.canonical(job()), job())


if __name__ == "__main__":
    unittest.main()
