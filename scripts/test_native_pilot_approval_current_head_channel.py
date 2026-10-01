#!/usr/bin/env python3
"""Actual fixed-eight socket/descriptor transport, not current-head admission.

One real child at a time creates its own seqpacket connection; kernel peer
credentials/PIDFDs and sealed root-owned public descriptors are checked by the
production channel. Reframed observation contents and reply contents are
explicitly synthetic. No live owner, independent decision or successful
producer validator is fabricated, and channel sequence state is never set.
"""
from __future__ import annotations

import array
import copy
from functools import lru_cache
import os
from pathlib import Path
import socket
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts.test_native_pilot_adopted_current_head import fixture as head_fixture
from scripts.test_native_pilot_adopted_supervisor import ticket
from scripts.test_native_pilot_current_head import refresh_request
from scripts.test_native_pilot_lifecycle_approval_channel import session
from scripts.test_native_pilot_supervisor_approval_channel import copies, public_originals
from serverware import native_pilot_approval_current_heads as decisions
from serverware import native_pilot_bridge_preparation as bridge
from serverware import native_pilot_supervisor_approval_channel as channel
from serverware.native_pilot_adopted_supervisor_policy import catalogue_original

p = channel.p


@lru_cache(maxsize=1)
def _source():
    # Keep the existing real-format fixture rather than inventing a second
    # bridge/request grammar. Only its public observation is used here.
    return bridge.shape(head_fixture()["args"]["bridge_preparation_raw"])


def fixture(*, inner_duration_ns=6_000_000_000):
    preparation = copy.deepcopy(_source())
    requests, peers = bridge._parts(preparation)
    rows = bridge.requests_profile.iter_requests(requests)
    now, wall, boot = channel._clock(), time.time_ns(), channel.originals._boot()
    value = dict(deadline=now + 8_000_000_000, lifetime=now + 12_000_000_000,
        expiry=wall + 12_000_000_000, inner=now + inner_duration_ns)
    issued = now - 2_000_000_000
    namespace = dict(zip(bridge.WINDOW[:3], boot, strict=True))
    for role, endpoint, row in rows:
        request = bridge.head.request(row["requestOriginal"].encode("ascii"))
        request.update(requestedAtBoottimeNanos=issued,
            deadline=dict(domain=bridge.key._boot(namespace), absoluteBoottimeNanos=value["inner"]))
        refresh_request(request)
        raw = p.canonical(request)
        row.update(requestOriginal=raw.decode("ascii"), requestSha256=bridge.head.request_sha256(raw))
        if "endpointRole" in requests["requests"][role]: requests["requests"][role] = row
        else: requests["requests"][role][endpoint] = row
    requests.update(requestedAtBoottimeNanos=issued,
        startupDeadlineBoottimeNs=str(value["deadline"]), lifetimeDeadlineBoottimeNs=str(value["lifetime"]))
    preparation["initialTrustRequestsOriginal"] = p.canonical(requests).decode("ascii")
    for field, kind in bridge.PEER_FIELDS:
        observed = peers[kind]
        observed.update(namespace, issuedAtBoottimeNs=str(issued), observedAtBoottimeNs=str(issued + 1),
            startupDeadlineBoottimeNs=str(value["deadline"]), lifetimeDeadlineBoottimeNs=str(value["lifetime"]))
        preparation[field] = p.canonical(observed).decode("ascii")
    preparation_raw = p.canonical(preparation)
    bridge.shape(preparation_raw)
    pending = []
    for name, index in zip(decisions.JOB_NAMES, decisions.INDICES, strict=True):
        request, conductor = ticket(index, deadline=value["deadline"], expiry=value["expiry"])
        conductor["payload"] = {"bridgePreparationOriginal": preparation_raw.decode("ascii")}
        conductor_raw = p.canonical(conductor)
        request["conductorRequestSha256"] = p.sha(conductor_raw)
        if request["jobIndex"] == 1: request["conductorRequest"] = copy.deepcopy(conductor)
        request_raw = p.canonical(request)
        observation_raw = p.canonical(dict(apiVersion="serverware.nativePilotAdoptedSupervisorObservation/v1",
            policySha256=p.sha(b"synthetic-policy"), catalogueSha256=p.sha(catalogue_original()),
            intakeConfigurationSha256=p.sha(b"synthetic-intake"),
            conductorRequestOriginal=conductor_raw.decode("ascii"), measuredConfiguration=None, recipeOriginals=None))
        pending.append(dict(phase=request["phase"], job=name, sequence=request["sequence"],
            status="awaiting-independent-job-approval", requestOriginal=request_raw.decode("ascii"),
            requestSha256=p.sha(request_raw), observationOriginal=observation_raw.decode("ascii"),
            observationSha256=p.sha(observation_raw)))
    value["pending"] = tuple(pending)
    return value


def exchange(client, value, pending=None, *, check=lambda: None, **caps):
    return client.exchange_current_head(value["pending"][0] if pending is None else pending,
        deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), check=check)


def receive(peer, value, **caps):
    return peer.receive_current_head(deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), check=lambda: None)


def respond(peer, fds, raws):
    peer.respond_current_head(input_fd=fds[0], input_sha256=p.sha(raws[0]),
        approval_fd=fds[1], approval_sha256=p.sha(raws[1]))


class CurrentHeadOrderControls(unittest.TestCase):
    def test_global_eight_positions_are_not_a_new_zero_based_job_catalogue(self):
        self.assertEqual(len(decisions.INDICES), 8)
        self.assertNotEqual(decisions.INDICES, tuple(range(8)))
        self.assertEqual(tuple(channel._current_head_index(i) for i in range(8)), decisions.INDICES)
        for index in (True, -1, 8):
            with self.subTest(index=index), self.assertRaises(ValueError): channel._current_head_index(index)


@unittest.skipUnless(os.getuid() == 0 and os.getgid() == 0,
    "these controls create real root-owned public originals")
class CurrentHeadKernelTransportControls(unittest.TestCase):
    def test_actual_eight_global_requests_literal_pairs_receipts_and_retirement(self):
        value = fixture()
        self.assertEqual(tuple(row["sequence"] for row in value["pending"]), tuple(i + 1 for i in decisions.INDICES))
        with public_originals() as (fds, raws):
            def peer_action(peer):
                for position, expected in enumerate(value["pending"]):
                    # The receiver may have a stricter local wait than either
                    # literal outer request or inner trust-request deadline.
                    caps = dict(deadline=value["inner"] - 1_000_000_000,
                        expiry=value["expiry"] - 1_000_000_000) if position == 0 else {}
                    self.assertEqual(receive(peer, value, **caps), expected)
                    respond(peer, fds, raws)
                with self.assertRaises(channel.ApprovalChannelError) as caught: receive(peer, value)
                self.assertIs(caught.exception.owner, peer)
            with session(value, peer_action, current_heads=True) as client:
                retained = []
                for pending in value["pending"]:
                    result = exchange(client, value, pending)
                    retained.append(result)
                    actual = result.resume_kwargs()
                    self.assertNotEqual(actual["input_fd"], actual["approval_fd"])
                    for name, raw in zip(("input", "approval"), raws, strict=True):
                        fd = actual[name + "_fd"]
                        self.assertFalse(os.get_inheritable(fd))
                        self.assertEqual(actual[name + "_sha256"], p.sha(raw))
                        self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
                with self.assertRaises(channel.ApprovalChannelError) as caught:
                    exchange(client, value, value["pending"][-1])
                self.assertIs(caught.exception.owner, client)
            for result in retained:
                with self.assertRaises(ValueError): result.resume_kwargs()
            for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_no_skipped_or_repeated_current_head(self):
        for mistake in ("skip", "repeat"):
            with self.subTest(mistake=mistake), public_originals() as (fds, raws):
                value = fixture()
                def peer_action(peer):
                    if mistake == "repeat":
                        self.assertEqual(receive(peer, value), value["pending"][0])
                        respond(peer, fds, raws)
                with session(value, peer_action, current_heads=True) as client:
                    if mistake == "repeat": exchange(client, value)
                    wrong = value["pending"][1 if mistake == "skip" else 0]
                    with self.assertRaises(channel.ApprovalChannelError) as caught: exchange(client, value, wrong)
                    self.assertIs(caught.exception.owner, client)

    def test_modes_do_not_cross_select_legacy_or_lifecycle_or_fixed_eight(self):
        for mode in ("legacy-on-current", "lifecycle-on-current", "current-on-lifecycle"):
            with self.subTest(mode=mode):
                value = fixture()
                def peer_action(peer):
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        if mode == "legacy-on-current": peer.receive(deadline_boottime_ns=value["deadline"])
                        elif mode == "lifecycle-on-current":
                            peer.receive_lifecycle(deadline_boottime_ns=value["deadline"],
                                expires_at_unix_ns=value["expiry"], check=lambda: None)
                        else: receive(peer, value)
                    self.assertIs(caught.exception.owner, peer)
                with session(value, peer_action, current_heads=mode != "current-on-lifecycle") as client:
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        if mode == "legacy-on-current": client.exchange(value["pending"][0])
                        elif mode == "lifecycle-on-current":
                            client.exchange_lifecycle("bootstrap", {}, deadline_boottime_ns=value["deadline"],
                                expires_at_unix_ns=value["expiry"], check=lambda: None)
                        else: exchange(client, value)
                    self.assertIs(caught.exception.owner, client)

    def test_malformed_binding_missing_and_excess_actual_rights_remain_owned(self):
        for mistake in ("binding", "missing", "excess"):
            with self.subTest(mistake=mistake), public_originals() as (fds, raws):
                value = fixture()
                def peer_action(peer):
                    self.assertEqual(receive(peer, value), value["pending"][0])
                    header, _, _ = channel._pending_adopted(value["pending"][0], decisions.INDICES[0])
                    reply = dict(apiVersion=channel.ADOPTED_REPLY_API,
                        requestBindingSha256=p.sha(b"wrong") if mistake == "binding" else p.sha(p.canonical(header)),
                        inputSha256=p.sha(raws[0]), approvalSha256=p.sha(raws[1]))
                    rights = fds[:1] if mistake == "missing" else (*fds, fds[0]) if mistake == "excess" else fds
                    peer._socket.sendmsg([p.canonical(reply)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))])
                with session(value, peer_action, current_heads=True) as client:
                    with self.assertRaises(channel.ApprovalChannelError) as caught: exchange(client, value)
                    self.assertIs(caught.exception.owner, client)
                for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_distinct_received_fd_numbers_do_not_admit_one_public_inode_twice(self):
        value = fixture()
        with public_originals() as (fds, raws):
            def peer_action(peer):
                self.assertEqual(receive(peer, value), value["pending"][0])
                header, _, _ = channel._pending_adopted(value["pending"][0], decisions.INDICES[0])
                reply = dict(apiVersion=channel.ADOPTED_REPLY_API, requestBindingSha256=p.sha(p.canonical(header)),
                    inputSha256=p.sha(raws[0]), approvalSha256=p.sha(raws[0]))
                peer._socket.sendmsg([p.canonical(reply)],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", (fds[0], fds[0])))])
            with session(value, peer_action, current_heads=True) as client:
                with self.assertRaises(channel.ApprovalChannelError) as caught: exchange(client, value)
                self.assertIs(caught.exception.owner, client)
            for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_both_original_clocks_and_supplied_source_callback_fail_closed(self):
        for mistake in ("inner-deadline", "unix", "source"):
            with self.subTest(mistake=mistake):
                value = fixture(inner_duration_ns=-1 if mistake == "inner-deadline" else 6_000_000_000)
                def source_check():
                    if mistake == "source": raise ValueError("synthetic source no longer held")
                with session(value, lambda peer: None, current_heads=True) as client:
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        exchange(client, value, check=source_check,
                            expiry=time.time_ns() - 1 if mistake == "unix" else value["expiry"])
                    self.assertIs(caught.exception.owner, client)

    def test_actual_wait_uses_inner_request_deadline_without_rewriting_outer_original(self):
        value = fixture(inner_duration_ns=1_500_000_000)
        pending = copy.deepcopy(value["pending"][0])
        self.assertEqual(decisions.pending_bounds(pending)["deadline"], value["inner"])
        released_r, released_w = os.pipe2(os.O_CLOEXEC)
        checks = []
        try:
            def peer_action(peer):
                self.assertEqual(receive(peer, value), pending)
                if os.read(released_r, 1) != b"1": raise RuntimeError("missing bounded wait release")
            with session(value, peer_action, current_heads=True) as client:
                before = channel._clock()
                try:
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        exchange(client, value, pending, check=lambda: checks.append(channel._clock()))
                    self.assertIs(caught.exception.owner, client)
                    self.assertLess(channel._clock() - before, 4_000_000_000)
                    self.assertLess(channel._clock(), value["deadline"])
                    self.assertGreater(len(checks), 1)
                    self.assertEqual(value["pending"][0], pending)
                finally:
                    os.write(released_w, b"1")
        finally:
            os.close(released_r); os.close(released_w)


if __name__ == "__main__": unittest.main()
