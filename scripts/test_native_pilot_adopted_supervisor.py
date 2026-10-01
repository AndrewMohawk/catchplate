#!/usr/bin/env python3
"""Pure selected-policy/approval/plan controls plus real local FD transport.

Signed fixtures are synthetic. The socket test proves Linux packet/descriptor
transport only: it does not manufacture a supervisor, native validation,
approval decision, installed file, running service, or cleanup proof.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import sys
import time
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_adopted_phase_profile as jobs
from serverware import native_pilot_adopted_ordinary_install as install
from serverware import native_pilot_adopted_supervisor as supervisor
from serverware import native_pilot_adopted_supervisor_policy as policy
from serverware import native_pilot_approval_install as approvals
from serverware import native_pilot_phase_execution as legacy
from serverware import native_pilot_supervisor_approval_channel as channel
from test_native_pilot_adopted_current_head import fixture as signed_fixture
from test_native_pilot_supervisor_approval_channel import peer_arguments, public_originals, start

p = jobs.p
FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)


def ticket(index=0, *, deadline=5000, expiry=9000):
    order = [(phase, row) for phase, rows in jobs.JOBS.items() for row in rows]
    phase, job = order[index]
    position = jobs.job_index(phase, job.name)
    conductor = {"apiVersion": "serverware.nativePilotOperatorRequest/v2",
        "sequence": tuple(jobs.JOBS).index(phase) + 1, "phase": phase, "payload": {},
        "deadlineBoottimeNs": str(deadline), "expiresAtUnixNanos": str(expiry)}
    request = {"apiVersion": jobs.API, "sequence": index + 1, "conductorSequence": conductor["sequence"],
        "conductorRequestSha256": p.sha(p.canonical(conductor)), "phase": phase, "jobIndex": position,
        "job": job.name, "deadlineBoottimeNs": str(deadline), "expiresAtUnixNanos": str(expiry),
        "conductorRequest": conductor if position == 1 else None,
        "previousResult": None if index == 0 else {"phase": order[index - 1][0],
            "job": order[index - 1][1].name, "result": {}}}
    return request, conductor


def pending(index=0, *, deadline=5000, expiry=9000):
    request, conductor = ticket(index, deadline=deadline, expiry=expiry)
    observation = {"apiVersion": "serverware.nativePilotAdoptedSupervisorObservation/v1",
        "policySha256": p.sha(b"synthetic-policy"), "catalogueSha256": p.sha(policy.catalogue_original()),
        "intakeConfigurationSha256": p.sha(b"synthetic-intake"),
        "conductorRequestOriginal": p.canonical(conductor).decode("ascii"),
        "measuredConfiguration": None, "recipeOriginals": None}
    raw, observed = p.canonical(request), p.canonical(observation)
    return dict(phase=request["phase"], job=request["job"], sequence=index + 1,
        status="awaiting-independent-job-approval", requestOriginal=raw.decode("ascii"),
        requestSha256=p.sha(raw), observationOriginal=observed.decode("ascii"), observationSha256=p.sha(observed))


def approval(request, raw):
    return {"apiVersion": jobs.APPROVAL_API,
        **{name: request[name] for name in jobs.APPROVAL_FIELDS[1:-1]}, "inputSha256": p.sha(raw)}


def installation_input():
    source = signed_fixture()
    f, args = source["fixture"], source["args"]
    value = {"apiVersion": install.API, "driverConfigurationOriginal": args["driver_configuration_raw"].decode("ascii"),
        "driverWindowOriginal": args["driver_window_raw"].decode("ascii"),
        "launchOriginal": args["launch_raw"].decode("ascii"),
        "preparationOriginal": args["preparation_raw"].decode("ascii"),
        "resourcesOriginal": args["resources_raw"].decode("ascii"),
        "coldOriginals": {role: p.canonical(f["cold"][role]).decode("ascii") for role in jobs.g.ROLES},
        "historyOriginals": {role: raw.decode("ascii") for role, raw in f["histories"].items()},
        "runtimeOriginals": {role: raw.decode("ascii") for role, raw in f["runtimes"].items()}}
    return value, dict(boot=args["boot"], now_boottime_ns=1400, now_unix_ns=1700000000000000000)


class AdoptedSupervisorControls(unittest.TestCase):
    def test_catalogue_separate_and_early_acyclic_order(self):
        self.assertEqual(sum(map(len, legacy.JOBS.values())), 164)
        self.assertEqual(len(legacy.KEY_PURPOSES), 113)
        supervisor.require_complete_coverage()
        self.assertEqual(sum(map(len, jobs.JOBS.values())), 176)
        early = [row.name for row in jobs.JOBS["endpoint-inputs"]]
        self.assertEqual(early[40], "install-ordinary-runtime")
        self.assertLess(early.index("ordinary-delivery-" + jobs.g.ROLES[-1]), early.index("publication-adoption"))
        self.assertEqual(early[-1], "endpoint-inputs")
        self.assertTrue(jobs.JOBS["service-originals"][0].name.startswith("ordinary-generation-"))
        self.assertNotEqual(jobs.APPROVAL_ROOT, legacy.APPROVAL_ROOT)

    def test_exact_approval2_hash_and_original_bounds(self):
        request, _ = ticket(); raw = b'{}'; signed = approval(request, raw)
        admitted = approvals._prepare_adopted(p.canonical(request), p.canonical(signed), raw,
            p.sha(p.canonical(signed)), p.sha(raw), now_boottime_ns=1400, now_unix_ns=8000)
        self.assertEqual(admitted[2:], (5000, 9000))
        for clocks in ((5000, 8000), (1400, 9000)):
            with self.subTest(clocks=clocks), self.assertRaises(FAILURES):
                approvals._prepare_adopted(p.canonical(request), p.canonical(signed), raw,
                    p.sha(p.canonical(signed)), p.sha(raw), now_boottime_ns=clocks[0], now_unix_ns=clocks[1])

    def test_approval_not_synthesized_or_cross_version(self):
        request, _ = ticket(); raw = b'{}'
        for field, changed in (("apiVersion", "serverware.nativePilotAuthorityJobApproval/v1"),
                ("job", "cohort-precreation"), ("expiresAtUnixNanos", "9001"), ("inputSha256", p.sha(b"other"))):
            signed = approval(request, raw); signed[field] = changed
            with self.subTest(field=field), self.assertRaises(FAILURES):
                approvals._prepare_adopted(p.canonical(request), p.canonical(signed), raw,
                    p.sha(p.canonical(signed)), p.sha(raw), now_boottime_ns=1400, now_unix_ns=8000)

    def test_pending_all_jobs_exact_order_and_no_legacy_channel(self):
        for index in range(len(supervisor.SUPPORTED_JOBS)):
            value = pending(index)
            header, _, deadline = channel._pending_adopted(value, index)
            self.assertEqual(header["sequence"], index + 1)
            self.assertEqual(deadline, 5000)
        with self.assertRaises(FAILURES): channel._pending(pending(), 0)
        with self.assertRaises(FAILURES): channel._pending_adopted(pending(1), 0)

    def test_pending_source_pin_and_conductor_replacement_refused(self):
        for field in ("catalogueSha256", "conductorRequestOriginal"):
            value = pending(); observation = json.loads(value["observationOriginal"])
            observation[field] = p.sha(b"wrong") if field.endswith("Sha256") else '{}'
            value["observationOriginal"] = p.canonical(observation).decode("ascii")
            value["observationSha256"] = p.sha(value["observationOriginal"].encode("ascii"))
            with self.subTest(field=field), self.assertRaises(FAILURES): channel._pending_adopted(value, 0)

    def test_policy_legacy_or_unbound_catalogue_refused(self):
        for value in ({"apiVersion": "serverware.nativePilotSupervisorPolicy/v20"},
                {field: None for field in policy.FIELDS}):
            with self.assertRaises(FAILURES): policy.shape(p.canonical(value))

    def test_authenticated_selected_fifteen_file_plan(self):
        value, clocks = installation_input()
        admitted = install.prepare_input(p.canonical(value), **clocks)
        self.assertEqual(len(admitted["planned"]), 15)
        self.assertIsNone(admitted["epochLimit"])
        self.assertLessEqual(admitted["deadline"], 5000)
        for row in admitted["planned"]:
            self.assertEqual(row["mode"], 0o400)
            self.assertEqual(row["uid"] == row["gid"] == 0, row["kind"] == "runtime")

    def test_installation_cross_profile_and_changed_preparation_refused(self):
        for mutation in ("api", "launch", "resource"):
            value, clocks = installation_input()
            if mutation == "api": value["apiVersion"] = "serverware.nativePilotAdoptedOrdinaryInstallationInput/v2"
            elif mutation == "launch":
                launch = json.loads(value["launchOriginal"]); launch["apiVersion"] = "serverware.custodyFiveServiceLaunch/v6"
                value["launchOriginal"] = p.canonical(launch).decode("ascii")
            else:
                resources = json.loads(value["resourcesOriginal"])
                resources["services"][jobs.g.ROLES[0]]["directories"]["publication-journal"]["entryCount"] = 1
                value["resourcesOriginal"] = p.canonical(resources).decode("ascii")
            with self.subTest(mutation=mutation), self.assertRaises(FAILURES): install.prepare_input(p.canonical(value), **clocks)

    def test_installation_signature_and_helper_history_refused(self):
        for role in (jobs.g.ROLES[0], jobs.g.ROLES[-1]):
            value, clocks = installation_input()
            wrapper = json.loads(value["historyOriginals"][role])
            wrapper["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = p.encoded(bytes(64))
            value["historyOriginals"][role] = p.canonical(wrapper).decode("ascii")
            with self.subTest(role=role), self.assertRaises(FAILURES): install.prepare_input(p.canonical(value), **clocks)

    def test_real_selected_two_descriptor_exchange_no_owner_claim(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client = peer = None
        try:
            client = channel.ApprovalChannel.open_adopted(left.fileno(), **peer_arguments())
            peer = channel.ApprovalPeer.open_adopted(right.fileno(), **peer_arguments())
            left.close(); right.close()
            deadline, expiry = channel._clock() + 3_000_000_000, time.time_ns() + 3_000_000_000
            value = pending(deadline=deadline, expiry=expiry)
            with public_originals() as (fds, raws):
                seen = []
                def independent_peer():
                    seen.append(peer.receive(deadline_boottime_ns=deadline, expires_at_unix_ns=expiry))
                    peer.respond(input_fd=fds[0], input_sha256=p.sha(raws[0]),
                        approval_fd=fds[1], approval_sha256=p.sha(raws[1]))
                worker, errors = start(independent_peer)
                try:
                    received = client.exchange(value)
                    self.assertEqual(received.resume_kwargs()["input_sha256"], p.sha(raws[0]))
                finally:
                    worker.join(4)
                    if worker.is_alive(): client.close(); peer.close(); worker.join(1)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(seen, [value])
        finally:
            if client is not None: client.close()
            if peer is not None: peer.close()
            left.close(); right.close()


if __name__ == "__main__":
    unittest.main()
