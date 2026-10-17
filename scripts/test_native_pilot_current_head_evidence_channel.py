#!/usr/bin/env python3
"""Selected public-evidence transport controls, not independent currentness.

Forked peers create their own real authenticated seqpacket connection and use
actual kernel credentials, PIDFDs and sealed public memfds. Existing signed
synthetic source evidence is reframed to present clocks for transport only;
no source ownership, currentness decision or operational admission is claimed.
"""
from __future__ import annotations

import array
from contextlib import contextmanager
import copy
from functools import lru_cache
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts.test_native_pilot_adopted_current_head import fixture as head_fixture
from scripts.test_native_pilot_approval_current_head_channel import fixture as pending_fixture, respond
from scripts.test_native_pilot_supervisor_approval_channel import copies, public_originals
from catchplate import native_pilot_approval_current_heads as decisions
from catchplate import native_pilot_supervisor_approval_channel as channel

p, heads = channel.p, channel.heads


@lru_cache(maxsize=1)
def source_evidence():
    context = head_fixture()["context"]
    return {name: heads.observed_original(name, context) for name in heads.JOB_NAMES}


def fixture(*, inner_duration_ns=6_000_000_000):
    sources = source_evidence()  # Authenticate historical test sources before live caps.
    value = pending_fixture(inner_duration_ns=inner_duration_ns)
    evidence = []
    for pending in value["pending"]:
        raw = sources[pending["job"]]
        row = p.document(raw, heads.MAX_OBSERVED)
        _, _, _, _, request_row, _, _ = decisions._pending(pending)
        observed = p.document(pending["observationOriginal"].encode("ascii"), channel.MAX_REQUEST)
        conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), channel.MAX_REQUEST)
        request = heads.head.request(request_row["requestOriginal"].encode("ascii"))
        row["originals"].update(bridgePreparation=conductor["payload"]["bridgePreparationOriginal"],
            request=request_row["requestOriginal"])
        row.update(requestSha256=request_row["requestSha256"], requestNonceSha256=request["requestNonceSha256"],
            deadlineBoottimeNanos=request["deadline"]["absoluteBoottimeNanos"])
        evidence.append(p.canonical(row))
    value["evidence"] = tuple(evidence)
    return value


def header(value, index=0, *, evidence=True):
    result, raws, _ = channel._pending_adopted(value["pending"][index], decisions.INDICES[index])
    if evidence:
        raw = value["evidence"][index]
        result.update(apiVersion=channel.EVIDENCE_REQUEST_API, evidence=dict(length=len(raw), sha256=p.sha(raw)))
        raws["evidence"] = raw
    return result, raws


def exchange(client, value, index=0, *, evidence=True, **caps):
    extra = {"evidence_original": value["evidence"][index]} if evidence else {}
    return client.exchange_current_head(value["pending"][index],
        deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), check=caps.get("check", lambda: None), **extra)


def receive(peer, value, **caps):
    return peer.receive_current_head(deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), check=lambda: None)


@contextmanager
def session(value, action, *, evidence=True, peer_evidence=None):
    """Two actual processes, no socketpair credential fiction or owner doubles."""
    peer_evidence = evidence if peer_evidence is None else peer_evidence
    def opened(kind, fd, pid, selected):
        return kind.open_current_heads(fd, peer_pid=pid, peer_uid=0, peer_gid=0,
            deadline_boottime_ns=value["lifetime"], expires_at_unix_ns=value["expiry"],
            check=lambda: None, evidence=selected)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    address = b"\0native-head-evidence-" + str(os.getpid()).encode("ascii") + os.urandom(8).hex().encode("ascii")
    listener.bind(address); listener.listen(1)
    stop_r, stop_w = os.pipe2(os.O_CLOEXEC)
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    parent = os.getpid()
    pid = os.fork()
    if pid == 0:
        status, peer, connected = 1, None, None
        signal.alarm(20)
        listener.close(); os.close(stop_w); os.close(ready_r); os.close(result_r)
        try:
            connected = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            connected.connect(address)
            try: peer = opened(channel.ApprovalPeer, connected.fileno(), parent, peer_evidence)
            except channel.ApprovalChannelError as error:
                peer = error.owner
                raise
            connected.close(); connected = None
            os.write(ready_w, b"1")
            action(peer)
            os.write(result_w, b"ok")
            os.read(stop_r, 1)
            peer.close(); peer = None
            status = 0
        except BaseException:
            try: os.write(result_w, traceback.format_exc().encode("utf-8")[-4096:])
            except OSError: pass
        finally:
            if peer is not None:
                try: peer.close()
                except BaseException: pass
            if connected is not None: connected.close()
            for fd in (stop_r, ready_w, result_w): os.close(fd)
        os._exit(status)
    os.close(stop_r); os.close(ready_w); os.close(result_w)
    pidfd = os.pidfd_open(pid, 0)
    client = accepted = None
    try:
        if not select.select([listener, pidfd], [], [], 3)[0] or select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError("real peer did not connect")
        accepted, _ = listener.accept()
        try: client = opened(channel.ApprovalChannel, accepted.fileno(), pid, evidence)
        except channel.ApprovalChannelError as error:
            client = error.owner
            raise
        accepted.close(); accepted = None
        if not select.select([ready_r, pidfd], [], [], 3)[0] or os.read(ready_r, 1) != b"1":
            raise RuntimeError("real peer admission failed")
        yield client
    finally:
        failure = None
        try:
            if client is not None: client.close()
        except BaseException as error: failure = error
        try: os.write(stop_w, b"1")
        except BrokenPipeError: pass
        if not select.select([pidfd], [], [], 3)[0]:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            if not select.select([pidfd], [], [], 1)[0]: raise RuntimeError("real test peer did not retire")
        outcome = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
        report = os.read(result_r, 8192)
        if accepted is not None: accepted.close()
        listener.close()
        for fd in (pidfd, stop_w, ready_r, result_r): os.close(fd)
        if failure is not None: raise failure
        if outcome.si_pid != pid or outcome.si_code != os.CLD_EXITED or outcome.si_status != 0 or report != b"ok":
            raise RuntimeError("actual test peer failed: " + repr(report))


class EvidenceAssociationControls(unittest.TestCase):
    def test_exact_eight_existing_evidence_originals_and_fixed_budget(self):
        value = fixture()
        self.assertEqual(len(value["evidence"]), 8)
        self.assertEqual(channel.MAX_TOTAL, 128 * 1024 * 1024)
        self.assertEqual(heads.MAX_OBSERVED, 32 * 1024 * 1024)
        self.assertTrue(any(len(raw) > channel.CHUNK_BYTES for raw in value["evidence"]))
        for pending, raw in zip(value["pending"], value["evidence"], strict=True):
            parsed = channel.current_head_evidence(pending, raw)
            self.assertEqual(parsed["jobName"], pending["job"])
            self.assertEqual(p.canonical(parsed), raw)
            self.assertNotIn("currentness", parsed)

    def test_noncanonical_extra_fields_and_actual_request_joins_refuse(self):
        value = fixture(); pending, raw = value["pending"][0], value["evidence"][0]
        for changed in (b" " + raw, raw + b"\n", p.canonical(p.document(raw, heads.MAX_OBSERVED) | {"currentness": {}})):
            with self.subTest(changed=changed[:32]), self.assertRaises(ValueError):
                channel.current_head_evidence(pending, changed)
        for field, changed in (("jobName", heads.JOB_NAMES[1]), ("endpointRole", "different"),
                ("requestSha256", p.sha(b"other")), ("requestNonceSha256", p.sha(b"other")),
                ("checkpointSha256", p.sha(b"other")), ("deadlineBoottimeNanos", True)):
            candidate = p.document(raw, heads.MAX_OBSERVED); candidate[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                channel.current_head_evidence(pending, p.canonical(candidate))

    def test_no_substitution_for_literal_bridge_request_runtime_or_selected_history(self):
        value = fixture(); pending, raw = value["pending"][0], value["evidence"][0]
        for field in ("bridgePreparation", "request", "runtime", "selectedInitialHistory"):
            candidate = p.document(raw, heads.MAX_OBSERVED)
            candidate["originals"][field] += " "
            with self.subTest(field=field), self.assertRaises(ValueError):
                channel.current_head_evidence(pending, p.canonical(candidate))


@unittest.skipUnless(os.getuid() == 0 and os.getgid() == 0,
    "these controls create actual root-owned public originals")
class EvidenceKernelControls(unittest.TestCase):
    def test_eight_selected_attachments_pairs_receipts_and_stricter_receiver_caps(self):
        value = fixture()
        with public_originals() as (fds, raws):
            def peer_action(peer):
                for index, pending in enumerate(value["pending"]):
                    observed = receive(peer, value, deadline=value["inner"] - 500_000_000,
                        expiry=value["expiry"] - 500_000_000)
                    self.assertEqual(observed, {"pending": pending,
                        "evidenceOriginal": value["evidence"][index].decode("ascii")})
                    respond(peer, fds, raws)
                with self.assertRaises(channel.ApprovalChannelError): receive(peer, value)
            with session(value, peer_action) as client:
                retained = []
                for index in range(8):
                    result = exchange(client, value, index); retained.append(result)
                    actual = result.resume_kwargs()
                    for name, raw in zip(("input", "approval"), raws, strict=True):
                        self.assertEqual(os.pread(actual[name + "_fd"], len(raw) + 1, 0), raw)
                        self.assertEqual(actual[name + "_sha256"], p.sha(raw))
                        self.assertFalse(os.get_inheritable(actual[name + "_fd"]))
                with self.assertRaises(channel.ApprovalChannelError): exchange(client, value, 7)
            for result in retained:
                with self.assertRaises(ValueError): result.resume_kwargs()
            for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_default_returns_original_pending_and_evidence_parameter_is_mode_gated(self):
        value = fixture()
        with public_originals() as (fds, raws):
            def peer_action(peer):
                self.assertEqual(receive(peer, value), value["pending"][0])
                respond(peer, fds, raws)
            with session(value, peer_action, evidence=False) as client:
                exchange(client, value, evidence=False)
        for mode in (False, True):
            with self.subTest(evidence_mode=mode), session(value, lambda peer: None, evidence=mode) as client:
                with self.assertRaises(channel.ApprovalChannelError) as caught:
                    exchange(client, value, evidence=not mode)
                self.assertIs(caught.exception.owner, client)

    def test_request_versions_cannot_cross_select_modes_and_oversize_metadata_refuses(self):
        for mistake in ("new-to-old", "old-to-new", "oversize"):
            value = fixture()
            outgoing = mistake != "old-to-new"
            target = mistake != "new-to-old"
            def peer_action(peer):
                with self.assertRaises(channel.ApprovalChannelError) as caught: receive(peer, value)
                self.assertIs(caught.exception.owner, peer)
            with self.subTest(mistake=mistake), session(value, peer_action,
                    evidence=outgoing, peer_evidence=target) as client:
                packet, _ = header(value, evidence=outgoing)
                if mistake == "oversize": packet["evidence"]["length"] = heads.MAX_OBSERVED + 1
                client._lifecycle_begin(deadline_boottime_ns=value["deadline"],
                    expires_at_unix_ns=value["expiry"], check=lambda: None)
                client._send(packet)

    def test_old_chunk_wrong_order_and_binding_refuse_without_advancing(self):
        for mistake in ("api", "offset", "binding"):
            value = fixture()
            def peer_action(peer):
                with self.assertRaises(channel.ApprovalChannelError) as caught: receive(peer, value)
                self.assertIs(caught.exception.owner, peer)
                self.assertEqual(peer._index, 0)
            with self.subTest(mistake=mistake), session(value, peer_action) as client:
                packet, raws = header(value)
                client._lifecycle_begin(deadline_boottime_ns=value["deadline"],
                    expires_at_unix_ns=value["expiry"], check=lambda: None)
                client._send(packet)
                client._send(dict(apiVersion=channel.ADOPTED_CHUNK_API if mistake == "api" else channel.EVIDENCE_CHUNK_API,
                    requestBindingSha256=p.sha(b"other") if mistake == "binding" else p.sha(p.canonical(packet)),
                    field="request", offset=1 if mistake == "offset" else 0,
                    dataBase64url=p.encoded(raws["request"][:channel.CHUNK_BYTES])))

    def test_old_reply_unbound_evidence_and_excess_rights_are_still_retained(self):
        for mistake in ("api", "binding", "excess-rights"):
            value = fixture()
            with self.subTest(mistake=mistake), public_originals() as (fds, raws):
                def peer_action(peer):
                    receive(peer, value)
                    packet, _ = header(value, evidence=mistake != "binding")
                    reply = dict(apiVersion=channel.ADOPTED_REPLY_API if mistake == "api" else channel.EVIDENCE_REPLY_API,
                        requestBindingSha256=p.sha(p.canonical(packet)), inputSha256=p.sha(raws[0]), approvalSha256=p.sha(raws[1]))
                    rights = (*fds, fds[0]) if mistake == "excess-rights" else fds
                    peer._socket.sendmsg([p.canonical(reply)],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))])
                with session(value, peer_action) as client:
                    with self.assertRaises(channel.ApprovalChannelError) as caught: exchange(client, value)
                    self.assertIs(caught.exception.owner, client)
                    self.assertTrue(client._incoming)
                    with self.assertRaises(channel.ApprovalChannelError): exchange(client, value)
                for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_unexpected_request_rights_remain_owned_until_actual_close(self):
        value = fixture()
        with public_originals() as (fds, _):
            def peer_action(peer):
                before = {fds[0]}  # The only inherited copy, before any receive.
                with self.assertRaises(channel.ApprovalChannelError) as caught: receive(peer, value)
                self.assertIs(caught.exception.owner, peer)
                self.assertTrue(copies(fds[0]) - before)
                peer.close()
                self.assertEqual(copies(fds[0]), before)
            with session(value, peer_action) as client:
                packet, _ = header(value)
                client._lifecycle_begin(deadline_boottime_ns=value["deadline"],
                    expires_at_unix_ns=value["expiry"], check=lambda: None)
                client._send(packet, (fds[0],))
            for fd in fds: self.assertEqual(copies(fd), {fd})

    def test_selected_wait_keeps_local_boottime_and_unix_caps_without_header_renewal(self):
        for clock in ("boottime", "unix"):
            value = fixture(); before = copy.deepcopy(value)
            release_r, release_w = os.pipe2(os.O_CLOEXEC)
            try:
                def peer_action(peer):
                    observed = receive(peer, value)
                    self.assertEqual(observed["pending"], value["pending"][0])
                    if os.read(release_r, 1) != b"1": raise RuntimeError("missing bounded release")
                with self.subTest(clock=clock), session(value, peer_action) as client:
                    caps = {"deadline": channel._clock() + 800_000_000} if clock == "boottime" else {
                        "expiry": time.time_ns() + 800_000_000}
                    started = channel._clock()
                    try:
                        with self.assertRaises(channel.ApprovalChannelError) as caught: exchange(client, value, **caps)
                        self.assertIs(caught.exception.owner, client)
                        self.assertLess(channel._clock() - started, 2_000_000_000)
                        self.assertEqual(value, before)
                    finally: os.write(release_w, b"1")
            finally:
                os.close(release_r); os.close(release_w)

    def test_silent_attachment_wait_expires_at_inner_request_not_outer_header(self):
        value = fixture(inner_duration_ns=1_000_000_000)
        done_r, done_w = os.pipe2(os.O_CLOEXEC)
        try:
            def peer_action(peer):
                with self.assertRaises(channel.ApprovalChannelError) as caught: receive(peer, value)
                self.assertIs(caught.exception.owner, peer)
                self.assertGreaterEqual(channel._clock(), value["inner"])
                self.assertLess(channel._clock(), value["deadline"])
                os.write(done_w, b"1")
            with session(value, peer_action) as client:
                packet, raws = header(value)
                client._lifecycle_begin(deadline_boottime_ns=value["deadline"],
                    expires_at_unix_ns=value["expiry"], check=lambda: None)
                client._send_lifecycle_originals(packet, {name: raws[name] for name in ("request", "observation")},
                    chunk_api=channel.EVIDENCE_CHUNK_API)
                self.assertTrue(select.select([done_r], [], [], 2)[0])
                self.assertEqual(os.read(done_r, 1), b"1")
        finally:
            os.close(done_r); os.close(done_w)


if __name__ == "__main__": unittest.main()
