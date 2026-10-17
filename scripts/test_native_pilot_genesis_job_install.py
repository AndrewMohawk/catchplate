#!/usr/bin/env python3
"""Pure cold66 installer association controls, never protected publication.

Synthetic public requests and approvals exercise literal/hash/window joins.
They do not assert an independent decision, a complete valid producer input,
an executed predecessor, a retained child, or successful filesystem cleanup.
No protected writer, validator success, process owner or signature is mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import install_native_pilot_genesis_job as command
from scripts.test_native_pilot_genesis_execution import configuration
from catchplate import native_pilot_genesis_authority_channel as channel
from catchplate import native_pilot_genesis_execution_protocol as wire
from catchplate import native_pilot_genesis_job_install as installation
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_rendezvous_install as rendezvous

p, g = wire.p, wire.g


def fixture(sequence=1, *, deadline=2_000_000_000, now=1_500_000_000, input_raw=b"{}"):
    selected = jobs.catalogue(handoff=True)[sequence - 1]
    config = configuration()
    config.update(apiVersion=wire.HANDOFF_CONFIGURATION_API,
        coreHandoff=dict(peerPid=123, peerUid=0, peerGid=0))
    prior_raw = b'{"syntheticResult":"not a completed producer"}'
    previous = None if sequence == 1 else dict(job=jobs.HANDOFF_JOBS[sequence - 2].name,
        resultOriginal=prior_raw.decode("ascii"), resultSha256=p.sha(prior_raw))
    _, request_raw = wire.request(sequence=sequence, job=selected.name, deadline=deadline,
        observation={}, previous=previous, handoff=True)
    value = dict(configuration_raw=g.canonical(config), request_raw=request_raw, input_raw=input_raw,
        boot=tuple(config["window"][name] for name in wire.endpoints.WINDOW[:3]),
        now_boottime_ns=now, now_unix_ns=8_000_000_000)
    return approve(value)


def approve(value):
    """Synthetic fixture association, not the installer or a decision issuer."""
    request = p.document(value["request_raw"], installation.MAX_REQUEST)
    approval = dict(apiVersion=wire.HANDOFF_APPROVAL_API,
        **{name: request[name] for name in ("sequence", "job", "deadlineBoottimeNs")},
        requestSha256=p.sha(value["request_raw"]), inputSha256=p.sha(value["input_raw"]))
    return value | {"approval_raw": g.canonical(approval)}


def prepare(value, **changes):
    parameters = {name + "_sha256": p.sha(value[name + "_raw"])
        for name in ("request", "input", "approval", "configuration")}
    parameters.update({name: value[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")})
    parameters.update(changes)
    return installation.prepare_input(*(value[name + "_raw"] for name in
        ("request", "input", "approval", "configuration")), **parameters)


def ticket(value, **changes):
    request = p.document(value["request_raw"], installation.MAX_REQUEST)
    return approve(value | {"request_raw": p.canonical(request | changes)})


def installer_arguments(value=None):
    value, result = fixture() if value is None else value, []
    for fd, name in enumerate(command.ORIGINALS, 3):
        result.extend(("--" + name + "-fd", str(fd), "--" + name + "-sha256", p.sha(value[name + "_raw"])))
    return result


class ColdJobInstallationControls(unittest.TestCase):
    def test_all_66_associations_use_only_existing_fixed_paths_and_reply(self):
        self.assertEqual((len(jobs.JOBS), len(jobs.HANDOFF_JOBS)), (64, 66))
        for sequence, selected in enumerate(jobs.HANDOFF_JOBS, 1):
            with self.subTest(sequence=sequence, job=selected.name):
                value = fixture(sequence)
                prepared = prepare(value)
                self.assertEqual(prepared["paths"], channel.paths(selected.name, handoff=True))
                self.assertEqual(prepared["maximum"], selected.maximum)
                self.assertEqual((prepared["deadline"], prepared["epochLimit"]), (2_000_000_000, 9_000_000_000))
                reply = channel.reply(p.canonical(prepared["reply"]), value["request_raw"])
                self.assertEqual(set(reply), {"apiVersion", "sequence", "job", "requestSha256",
                    "inputSha256", "approvalSha256"})
                self.assertEqual(reply["apiVersion"], channel.HANDOFF_REPLY_API)
                self.assertNotIn("approved", reply)
                self.assertNotIn("installed", reply)

    def test_every_independent_original_pin_is_required(self):
        value = fixture()
        for name in command.ORIGINALS:
            with self.subTest(pin=name), self.assertRaises(ValueError):
                prepare(value, **{name + "_sha256": p.sha(b"another public original")})

    def test_old_request_approval_and_configuration_do_not_select_cold66(self):
        value = fixture()
        for api in (wire.REQUEST_API, "catchplate.nativePilotAuthorityJobRequest/v2"):
            with self.subTest(api=api), self.assertRaises(ValueError):
                prepare(ticket(value, apiVersion=api))
        approval = g.document(value["approval_raw"], installation.MAX_APPROVAL)
        with self.assertRaises(ValueError):
            prepare(value | {"approval_raw": g.canonical(approval | {"apiVersion": wire.APPROVAL_API})})
        config = g.document(value["configuration_raw"], installation.MAX_CONFIGURATION)
        with self.assertRaises(ValueError):
            prepare(value | {"configuration_raw": g.canonical(config | {"apiVersion": wire.CONFIGURATION_API})})

    def test_job_sequence_is_source_fixed_not_an_approved_command_list(self):
        value = fixture()
        for changes in ({"sequence": True}, {"sequence": 0}, {"sequence": 67},
                {"job": jobs.HANDOFF_JOBS[1].name}, {"job": "../../elsewhere"},
                {"path": "/tmp/alternate"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                prepare(ticket(value, **changes))

    def test_literal_previous_result_is_bound_without_claiming_success(self):
        value = fixture(2)
        previous = p.document(value["request_raw"], installation.MAX_REQUEST)["previousResult"]
        for changed in (None, previous | {"job": jobs.HANDOFF_JOBS[1].name},
                previous | {"resultSha256": p.sha(b"different result")},
                previous | {"resultOriginal": ""}, previous | {"success": True}):
            with self.subTest(previous=changed), self.assertRaises(ValueError):
                prepare(ticket(value, previousResult=changed))
        with self.assertRaises(ValueError): prepare(ticket(fixture(), previousResult=previous))

    def test_observation_delta_keeps_literal_originals_and_closed_names(self):
        value = fixture()
        literal = g.canonical({"nativeInode": p.MAX_U64}).decode("ascii")
        changed = ticket(value, observation={"parent.observation": literal})
        self.assertEqual(prepare(changed)["reply"]["requestSha256"], p.sha(changed["request_raw"]))
        for observation in ({"unknown.owner": literal}, {"parent.observation": {}},
                {"parent.observation": ""}, []):
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                prepare(ticket(value, observation=observation))

    def test_no_input_approval_or_destination_is_synthesized(self):
        value = fixture()
        approval = g.document(value["approval_raw"], installation.MAX_APPROVAL)
        for changes in ({"requestSha256": p.sha(b"different request")},
                {"inputSha256": p.sha(b"different input")}, {"sequence": 2},
                {"deadlineBoottimeNs": "2000000001"}, {"path": "/tmp/replacement"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                prepare(value | {"approval_raw": g.canonical(approval | changes)})
        for raw in (b"{}", value["input_raw"], value["approval_raw"] + b"\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError): prepare(value | {"approval_raw": raw})

    def test_actual_boot_scope_and_both_original_clock_limits(self):
        value = fixture()
        # Configuration is unsigned public metadata; its original native u64
        # boot identifiers remain literal, unlike signed-i64 producer payloads.
        self.assertGreater(value["boot"][1], p.MAX_I64)
        for changes in ({"boot": (value["boot"][0], 1, value["boot"][2])},
                {"now_boottime_ns": 999_999_999}, {"now_boottime_ns": 2_000_000_000},
                {"now_unix_ns": 9_000_000_000}, {"now_boottime_ns": True}, {"now_unix_ns": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): prepare(value, **changes)

    def test_only_actual_late_jobs_use_lifetime_without_renewed_startup(self):
        for sequence, selected in enumerate(jobs.HANDOFF_JOBS, 1):
            if selected.name not in ("coordinator-finish", "acquire-cold-core", "cleanup", "handoff-cold-core"):
                continue
            maximum = 4_000_000_000 if selected.name in ("cleanup", "handoff-cold-core") else 3_750_000_000
            with self.subTest(job=selected.name):
                value = fixture(sequence, deadline=maximum, now=3_000_000_000)
                self.assertEqual(prepare(value)["deadline"], maximum)
                with self.assertRaises(ValueError): prepare(ticket(value, deadlineBoottimeNs=str(maximum + 1)))
        with self.assertRaises(ValueError): prepare(fixture(deadline=3_000_000_001, now=3_000_000_000))
        self.assertEqual(prepare(fixture(deadline=1_600_000_000))["deadline"], 1_600_000_000)

    def test_configuration_original_shape_interval_and_root_peer_are_closed(self):
        value = fixture()
        config = g.document(value["configuration_raw"], installation.MAX_CONFIGURATION)
        changed_window = copy.deepcopy(config["window"])
        changed_window["lifetimeDeadlineBoottimeNs"] = "1200000000"
        for changed in (config | {"window": changed_window}, config | {"path": "/tmp/core"},
                config | {"coreHandoff": {"peerPid": True, "peerUid": 0, "peerGid": 0}},
                config | {"coreHandoff": {"peerPid": 123, "peerUid": 1, "peerGid": 0}}):
            with self.subTest(config=changed), self.assertRaises(ValueError):
                prepare(value | {"configuration_raw": g.canonical(changed)})

    def test_selected_public_input_bound_and_unsigned_metadata_not_global_expansion(self):
        sequence = next(index for index, job in enumerate(jobs.HANDOFF_JOBS, 1) if job.name == "parent-start")
        self.assertEqual(jobs.HANDOFF_JOBS[sequence - 1].maximum, 65536)
        for raw in (b" " * 65537, b"[]", b"{}\n", b'{"duplicate":1,"duplicate":2}'):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError): prepare(fixture(sequence, input_raw=raw))
        unsigned = g.canonical({"nativeMetadata": p.MAX_U64})
        value = fixture(sequence, input_raw=unsigned)
        self.assertEqual(prepare(value)["reply"]["inputSha256"], p.sha(unsigned))
        self.assertEqual(installation.MAX_REQUEST, wire.MAX_REQUEST - 1)
        self.assertEqual((installation.MAX_CONFIGURATION, installation.MAX_APPROVAL), (4096, 8192))

    def test_cli_requires_four_distinct_canonical_fd_sha_pairs(self):
        values = installer_arguments()
        parsed = command.arguments(values)
        self.assertEqual(tuple(parsed[name + "_fd"] for name in command.ORIGINALS), (3, 4, 5, 6))
        for changed in (values[:-2], values + values[:2], values[:5] + ["3"] + values[6:],
                values[:1] + ["03"] + values[2:], values[:3] + ["unknown"] + values[4:],
                ["--configuration-path", *values[1:]]):
            with self.subTest(arguments=changed), self.assertRaises(ValueError): command.arguments(changed)

    def test_public_data_cannot_construct_owner_or_change_rendezvous_default(self):
        with self.assertRaises(ValueError): installation.GenesisJobInstallation(object())
        self.assertEqual(rendezvous._PATHS, (rendezvous.profile.INPUT_PATH, rendezvous.profile.APPROVAL_PATH))
        self.assertNotEqual(channel.paths("closure-set", handoff=True), rendezvous._PATHS)
        for name in ("acquire-cold-core", "handoff-cold-core"):
            with self.assertRaises(ValueError): channel.paths(name)


if __name__ == "__main__":
    unittest.main()
