#!/usr/bin/env python3
"""Actual local kernel transport controls, not commissioning or approval.

Real forked root peers create their own connection and transfer sealed public
memfds. Observation and completion contents are explicitly synthetic. Even
the full ordered exchange control proves transport only, not job execution,
independent approval, native admission or a successful lifecycle owner.
"""
from __future__ import annotations

import array
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.test_native_pilot_genesis_rendezvous import fixture as rendezvous_fixture
from scripts.test_native_pilot_supervisor_approval_channel import copies, pending as legacy_pending
from catchplate import native_pilot_lifecycle_approval_wire as wire
from catchplate import native_pilot_supervisor_approval_channel as channel

p = wire.p


def fixture(*, current=False):
    value = rendezvous_fixture()
    if current:
        now, wall, boot = channel._clock(), time.time_ns(), channel.originals._boot()
        config = p.document(value["configuration_raw"], 4096)
        config["window"].update(dict(zip(wire.rendezvous.wire.endpoints.WINDOW[:3], boot, strict=True)))
        config["window"].update(issuedAtBoottimeNs=str(now - 1), startupDeadlineBoottimeNs=str(now + 10_000_000_000),
            lifetimeDeadlineBoottimeNs=str(now + 20_000_000_000))
        config["expiresAtUnixNanos"] = wall + 20_000_000_000
        configuration_raw = p.canonical(config)
        sender = p.document(value["sender_raw"], 8192)
        observed = p.document(sender["listenerOriginal"].encode("ascii"), 8192)
        namespace = {name: config["window"][name] for name in wire.rendezvous.wire.endpoints.WINDOW[:3]}
        observed.update(namespace, configurationSha256=p.sha(configuration_raw))
        observed_raw = p.canonical(observed)
        bounds = dict(deadlineBoottimeNs=config["window"]["startupDeadlineBoottimeNs"],
            expiresAtUnixNanos=config["expiresAtUnixNanos"])
        sender.update(bounds, configurationSha256=p.sha(configuration_raw),
            listenerOriginal=observed_raw.decode("ascii"), listenerSha256=p.sha(observed_raw))
        sender_raw = p.canonical(sender)
        receiver = p.document(value["receiver_raw"], 8192)
        receiver.update(namespace, **bounds, configurationSha256=p.sha(configuration_raw),
            senderRequestSha256=p.sha(sender_raw))
        receiver_raw = p.canonical(receiver)
        value.update(configuration_raw=configuration_raw, sender_raw=sender_raw, receiver_raw=receiver_raw,
            request_raw=wire.rendezvous.request(sender_raw, receiver_raw, configuration_raw),
            boot=boot, now_boottime_ns=now, now_unix_ns=wall)
    config = p.document(value["configuration_raw"], 4096)
    value["deadline"] = p.ns(config["window"]["startupDeadlineBoottimeNs"])
    value["lifetime"] = p.ns(config["window"]["lifetimeDeadlineBoottimeNs"])
    value["expiry"] = config["expiresAtUnixNanos"]
    value["bootstrap"] = dict(senderRequestOriginal=value["sender_raw"].decode("ascii"),
        listenerConfigurationOriginal=value["configuration_raw"].decode("ascii"))
    return value


def request(value, stage="bootstrap", pending=None, index=0, context=None, **caps):
    return wire.request(stage, value["bootstrap"] if pending is None else pending, index,
        deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), context={} if context is None else context,
        boot=value["boot"], now_boottime_ns=value["now_boottime_ns"])


@contextmanager
def originals(extra=None):
    rows = {}
    try:
        raws = {name: p.canonical({"syntheticTransportOriginal": name})
            for name in (*wire.BOOTSTRAP, "input", "approval")}
        raws.update({} if extra is None else extra)
        for name, raw in raws.items():
            fd = os.memfd_create("lifecycle-transport-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            rows[name] = (fd, raw)
            if os.write(fd, raw) != len(raw): raise RuntimeError("short fixture write")
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        yield rows
    finally:
        for fd, _ in rows.values(): os.close(fd)


def kwargs(rows, names):
    return {name + suffix: rows[name][0] if suffix == "_fd" else p.sha(rows[name][1])
        for name in names for suffix in ("_fd", "_sha256")}


@contextmanager
def session(value, action, *, completions=False, current_heads=False):
    """One real child peer, actual accepted SO_PEERCRED and consuming reap."""
    if current_heads and completions: raise ValueError("distinct fixed channel selections")
    def opened(kind, fd, pid):
        arguments = dict(peer_pid=pid, peer_uid=0, peer_gid=0,
            deadline_boottime_ns=value["lifetime"], expires_at_unix_ns=value["expiry"], check=lambda: None)
        if current_heads: return kind.open_current_heads(fd, **arguments)
        return kind.open_lifecycle(fd, **arguments, completions=completions)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    address = b"\0native-pilot-lifecycle-control-" + str(os.getpid()).encode("ascii") + b"-" + os.urandom(8).hex().encode("ascii")
    listener.bind(address); listener.listen(1)
    stop_r, stop_w = os.pipe2(os.O_CLOEXEC)
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    parent_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        status, peer, connected = 1, None, None
        signal.alarm(15)  # Bound the actual test child even if parent acquisition fails.
        os.close(stop_w); os.close(ready_r); os.close(result_r); listener.close()
        try:
            connected = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            connected.connect(address)
            try:
                peer = opened(channel.ApprovalPeer, connected.fileno(), parent_pid)
            except channel.ApprovalChannelError as error:
                peer = error.owner
                raise
            connected.close(); connected = None
            os.write(ready_w, b"1")
            action(peer)
            os.write(result_w, b"ok")
            # Keep the real peer alive beyond these deliberately partial
            # exchanges; this is not a forged final-244 receipt retirement.
            os.read(stop_r, 1)
            peer.close(); peer = None
            status = 0
        except BaseException as error:
            try: os.write(result_w, (type(error).__name__ + ": " + str(error)).encode("utf-8")[:4096])
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
            raise RuntimeError("peer did not connect")
        accepted, _ = listener.accept()
        try:
            client = opened(channel.ApprovalChannel, accepted.fileno(), pid)
        except channel.ApprovalChannelError as error:
            client = error.owner
            raise
        accepted.close(); accepted = None
        if not select.select([ready_r, pidfd], [], [], 3)[0] or os.read(ready_r, 1) != b"1":
            raise RuntimeError("peer did not finish actual channel admission")
        yield client
    finally:
        failure = None
        try:
            if client is not None: client.close()
        except BaseException as error:
            failure = error
        try: os.write(stop_w, b"1")
        except BrokenPipeError: pass
        if not select.select([pidfd], [], [], 3)[0]:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            if not select.select([pidfd], [], [], 1)[0]:
                raise RuntimeError("actual test peer would not retire")
        outcome = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
        report = os.read(result_r, 8192)
        if accepted is not None: accepted.close()
        listener.close()
        for fd in (pidfd, stop_w, ready_r, result_r): os.close(fd)
        if failure is not None: raise failure
        if outcome.si_pid != pid or outcome.si_code != os.CLD_EXITED or outcome.si_status != 0 or report != b"ok":
            raise RuntimeError("actual test peer failed: " + repr(report))


def exchange(client, value, stage="bootstrap", pending=None, **caps):
    return client.exchange_lifecycle(stage, value["bootstrap"] if pending is None else pending,
        deadline_boottime_ns=caps.get("deadline", value["deadline"]),
        expires_at_unix_ns=caps.get("expiry", value["expiry"]), check=caps.get("check", lambda: None))


def receive(peer, value):
    return peer.receive_lifecycle(deadline_boottime_ns=value["deadline"],
        expires_at_unix_ns=value["expiry"], check=lambda: None)


def completion_fixture(value):
    """Literal synthetic terminal framing; deliberately not native admission."""
    from scripts.test_native_pilot_genesis_completion import fixture as cold_fixture
    from scripts.test_native_pilot_adopted_completion import fixture as adopted_fixture
    cold, adopted = cold_fixture(), adopted_fixture()
    configuration = p.document(value["configuration_raw"], 4096)
    receiver = p.document(value["receiver_raw"], 8192)["receiver"]
    execution_raw = p.canonical(configuration | {"apiVersion": wire.cold_install.wire.HANDOFF_CONFIGURATION_API,
        "coreHandoff": dict(peerPid=receiver["pid"], peerUid=receiver["uid"], peerGid=receiver["gid"])})
    cold["value"].update(configurationSha256=p.sha(execution_raw),
        deadlineBoottimeNs=str(value["deadline"]), expiresAtUnixNanos=value["expiry"])
    adopted["value"].update(deadlineBoottimeNs=str(value["deadline"]), expiresAtUnixNanos=str(value["expiry"]))
    return dict(execution=execution_raw, cold_input=cold["kwargs"]["final_input_raw"],
        stop_input=adopted["input_raw"], cold_terminal=p.canonical(cold["value"]),
        adopted_terminal=p.canonical(adopted["value"]))


def cold_transcript(value):
    """All genuine catalogue positions, with clearly synthetic result bytes."""
    result, previous = [("bootstrap", value["bootstrap"]), ("rendezvous", value["request_raw"])], None
    for sequence, selected in enumerate(wire.COLD, 1):
        raw = p.canonical(dict(apiVersion=wire.cold_install.wire.HANDOFF_REQUEST_API,
            sequence=sequence, job=selected.name, deadlineBoottimeNs=str(value["deadline"]),
            observation={}, previousResult=previous))
        result.append(("cold", raw))
        result_raw = p.canonical({"syntheticTransportResult": selected.name})
        previous = dict(job=selected.name, resultOriginal=result_raw.decode("ascii"), resultSha256=p.sha(result_raw))
    return tuple(result)


def adopted_transcript(value, rows):
    """No phase producer is run: only exact public request/observation grammar."""
    result, previous, sequence = [], None, 0
    for conductor_sequence, (phase, jobs) in enumerate(wire.adopted.JOBS.items(), 1):
        conductor = dict(apiVersion="catchplate.nativePilotOperatorRequest/v2", sequence=conductor_sequence,
            phase=phase, payload={"syntheticTransportPayload": True},
            deadlineBoottimeNs=str(value["deadline"]), expiresAtUnixNanos=str(value["expiry"]))
        conductor_raw = p.canonical(conductor)
        observation_raw = p.canonical(dict(apiVersion="catchplate.nativePilotAdoptedSupervisorObservation/v1",
            policySha256=p.sha(rows["policy"][1]), catalogueSha256=p.sha(wire.policy.catalogue_original()),
            intakeConfigurationSha256=p.sha(rows["intake_configuration"][1]),
            conductorRequestOriginal=conductor_raw.decode("ascii"), measuredConfiguration=None, recipeOriginals=None))
        for job_index, selected in enumerate(jobs, 1):
            sequence += 1
            request_raw = p.canonical(dict(apiVersion=wire.adopted.API, sequence=sequence,
                conductorSequence=conductor_sequence, conductorRequestSha256=p.sha(conductor_raw),
                phase=phase, jobIndex=job_index, job=selected.name, deadlineBoottimeNs=str(value["deadline"]),
                expiresAtUnixNanos=str(value["expiry"]), conductorRequest=conductor if job_index == 1 else None,
                previousResult=previous))
            result.append(("adopted", wire.pending("adopted", {"request": request_raw, "observation": observation_raw})))
            previous = dict(phase=phase, job=selected.name, result={"syntheticTransportResult": selected.name})
    return tuple(result)


def respond_transcript(peer, value, rows, expected):
    for stage, pending in expected:
        if receive(peer, value) != (stage, pending):
            raise RuntimeError("literal synthetic transport transcript differs")
        supplied = rows
        if stage == "rendezvous": supplied = rows | {"input": rows["execution"]}
        elif stage == "cold" and p.document(pending, 4096)["job"] == wire.COLD[-1].name:
            supplied = rows | {"input": rows["cold_input"]}
        elif stage == "adopted" and pending["job"] == wire.ADOPTED[-1][1].name:
            supplied = rows | {"input": rows["stop_input"]}
        peer.respond_lifecycle(**kwargs(supplied, wire.BOOTSTRAP if stage == "bootstrap" else ("input", "approval")))


def send_completion(client, value, stage, raw):
    client.send_completion(stage, raw, deadline_boottime_ns=value["deadline"],
        expires_at_unix_ns=value["expiry"], check=lambda: None)


def receive_completion(peer, value, stage, raw):
    actual = peer.receive_completion(deadline_boottime_ns=value["deadline"],
        expires_at_unix_ns=value["expiry"], check=lambda: None)
    if actual != (stage, raw): raise RuntimeError("literal terminal transport differs")
    peer.acknowledge_completion()


class LifecycleWireControls(unittest.TestCase):
    def test_catalogue_is_exact_244_stages_and_five_then_two_descriptors(self):
        self.assertEqual(len(wire.ORDER), 244)
        self.assertEqual(wire.ORDER[:2], ("bootstrap", "rendezvous"))
        self.assertEqual(wire.ORDER.count("cold"), 66)
        self.assertEqual(wire.ORDER.count("adopted"), 176)
        self.assertEqual(tuple(name for name, _ in wire.descriptor_limits(0)), wire.BOOTSTRAP)
        self.assertEqual(tuple(name for name, _ in wire.descriptor_limits(1)), ("input", "approval"))
        with self.assertRaises(ValueError): wire.stage_at(244)

    def test_originals_are_literal_and_caps_only_intersect(self):
        value = fixture()
        header, raws, context = request(value, deadline=value["lifetime"], expiry=value["expiry"] + 1)
        self.assertEqual(raws, {"sender": value["sender_raw"], "configuration": value["configuration_raw"]})
        self.assertEqual(p.ns(header["deadlineBoottimeNs"]), value["deadline"])
        self.assertEqual(p.ns(header["expiresAtUnixNanos"]), value["expiry"])
        self.assertEqual(wire.pending("bootstrap", raws), value["bootstrap"])
        other = dict(context, sender=b"{}")
        with self.assertRaises(ValueError): request(value, "rendezvous", value["request_raw"], 1, other)

    def test_stage_header_hash_and_bootstrap_pin_shapes_are_closed(self):
        value = fixture(); header, _, _ = request(value)
        for changed in (header | {"stage": "cold"}, header | {"exchangeSequence": True},
                header | {"apiVersion": channel.ADOPTED_REQUEST_API}, header | {"approved": True}):
            with self.assertRaises(ValueError): wire.header(changed, 0,
                deadline_boottime_ns=value["deadline"], expires_at_unix_ns=value["expiry"])
        reply = dict(apiVersion=wire.REPLY_API, requestBindingSha256=p.sha(p.canonical(header)),
            pins={name: p.sha(name.encode("ascii")) for name in wire.BOOTSTRAP})
        self.assertEqual(wire.reply(reply, header, 0), reply)
        with self.assertRaises(ValueError): wire.reply(reply | {"requestBindingSha256": p.sha(b"other")}, header, 0)
        with self.assertRaises(ValueError): wire.reply(reply | {"pins": {"input": p.sha(b"other")}}, header, 0)

    def test_wrong_context_namespace_and_original_deadline_refuse(self):
        value = fixture()
        with self.assertRaises(ValueError): request(value | {"boot": (value["boot"][0], 11, 13)})
        with self.assertRaises(ValueError): request(value, deadline=value["now_boottime_ns"])
        with self.assertRaises(ValueError): request(value, "rendezvous", value["request_raw"], 0)
        header, _, context = request(value)
        bound = dict(apiVersion=wire.REPLY_API, requestBindingSha256=p.sha(p.canonical(header)),
            pins={name: p.sha(name.encode("ascii")) for name in wire.BOOTSTRAP})
        retained = wire.committed(context, "bootstrap", bound)
        self.assertEqual(retained["bootstrapPins"], bound["pins"])
        self.assertNotIn("bootstrapPins", context)


@unittest.skipUnless(os.getuid() == 0 and os.getgid() == 0, "these controls create real root-owned public originals")
class LifecycleKernelTransportControls(unittest.TestCase):
    def test_actual_selected_244_exchanges_and_both_literal_completion_receipts(self):
        value = fixture(current=True); tail = completion_fixture(value)
        with originals({name: tail[name] for name in ("execution", "cold_input", "stop_input")}) as rows:
            cold, adopted = cold_transcript(value), adopted_transcript(value, rows)
            self.assertEqual((len(cold), len(adopted)), (68, 176))
            def peer_action(peer):
                respond_transcript(peer, value, rows, cold)
                receive_completion(peer, value, "cold", tail["cold_terminal"])
                respond_transcript(peer, value, rows, adopted)
                receive_completion(peer, value, "adopted", tail["adopted_terminal"])
                with self.assertRaises(channel.ApprovalChannelError) as caught:
                    peer.receive_completion(deadline_boottime_ns=value["deadline"],
                        expires_at_unix_ns=value["expiry"], check=lambda: None)
                self.assertIs(caught.exception.owner, peer)
            with session(value, peer_action, completions=True) as client:
                for stage, pending in cold: exchange(client, value, stage, pending)
                send_completion(client, value, "cold", tail["cold_terminal"])
                for stage, pending in adopted: exchange(client, value, stage, pending)
                send_completion(client, value, "adopted", tail["adopted_terminal"])
                with self.assertRaises(channel.ApprovalChannelError) as caught:
                    send_completion(client, value, "adopted", tail["adopted_terminal"])
                self.assertIs(caught.exception.owner, client)
            for name in ("policy", "execution", "cold_input", "stop_input"):
                self.assertEqual(copies(rows[name][0]), {rows[name][0]})

    def test_actual_cold_completion_cannot_be_skipped_or_repeated(self):
        for mistake in ("skip", "repeat"):
            with self.subTest(mistake=mistake):
                value = fixture(current=True); tail = completion_fixture(value)
                with originals({name: tail[name] for name in ("execution", "cold_input", "stop_input")}) as rows:
                    cold, adopted = cold_transcript(value), adopted_transcript(value, rows)
                    def peer_action(peer):
                        respond_transcript(peer, value, rows, cold)
                        if mistake == "repeat": receive_completion(peer, value, "cold", tail["cold_terminal"])
                        with self.assertRaises(channel.ApprovalChannelError) as caught:
                            if mistake == "skip": receive(peer, value)
                            else: peer.receive_completion(deadline_boottime_ns=value["deadline"],
                                expires_at_unix_ns=value["expiry"], check=lambda: None)
                        self.assertIs(caught.exception.owner, peer)
                    with session(value, peer_action, completions=True) as client:
                        for stage, pending in cold: exchange(client, value, stage, pending)
                        if mistake == "repeat": send_completion(client, value, "cold", tail["cold_terminal"])
                        with self.assertRaises(channel.ApprovalChannelError) as caught:
                            if mistake == "skip": exchange(client, value, *adopted[0])
                            else: send_completion(client, value, "cold", tail["cold_terminal"])
                        self.assertIs(caught.exception.owner, client)

    def test_actual_completion_refuses_premature_and_legacy_modes(self):
        for completions in (True, False):
            with self.subTest(completions=completions):
                value = fixture(current=True); tail = completion_fixture(value)
                def peer_action(peer):
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        peer.receive_completion(deadline_boottime_ns=value["deadline"],
                            expires_at_unix_ns=value["expiry"], check=lambda: None)
                    self.assertIs(caught.exception.owner, peer)
                with session(value, peer_action, completions=completions) as client:
                    with self.assertRaises(channel.ApprovalChannelError) as caught:
                        send_completion(client, value, "cold", tail["cold_terminal"])
                    self.assertIs(caught.exception.owner, client)

    def test_actual_bootstrap_five_rendezvous_pair_and_chunked_first_cold_request(self):
        value = fixture(current=True)
        cold_raw = p.canonical(dict(apiVersion=wire.rendezvous.wire.HANDOFF_REQUEST_API, sequence=1,
            job=wire.COLD[0].name, deadlineBoottimeNs=str(value["deadline"]), previousResult=None,
            observation={"ordinary.configuration": p.canonical({"synthetic": "x" * (channel.CHUNK_BYTES + 19)}).decode("ascii")}))
        expected = (("bootstrap", value["bootstrap"]), ("rendezvous", value["request_raw"]), ("cold", cold_raw))
        with originals() as rows:
            def peer_action(peer):
                for stage, pending in expected:
                    if receive(peer, value) != (stage, pending): raise RuntimeError("literal received transcript differs")
                    peer.respond_lifecycle(**kwargs(rows, wire.BOOTSTRAP if stage == "bootstrap" else ("input", "approval")))
            with session(value, peer_action) as client:
                bootstrap = exchange(client, value)
                actual = bootstrap.bootstrap_kwargs()
                for name in wire.BOOTSTRAP:
                    self.assertEqual(os.pread(actual[name + "_fd"], 4096, 0), rows[name][1])
                    self.assertFalse(os.get_inheritable(actual[name + "_fd"]))
                for stage, pending in expected[1:]:
                    accepted = exchange(client, value, stage, pending).resume_kwargs()
                    self.assertEqual(os.pread(accepted["input_fd"], 4096, 0), rows["input"][1])
                    self.assertEqual(os.pread(accepted["approval_fd"], 4096, 0), rows["approval"][1])
                self.assertGreater(client._total, channel.CHUNK_BYTES)
            with self.assertRaises(ValueError): bootstrap.bootstrap_kwargs()
            self.assertEqual(copies(rows["policy"][0]), {rows["policy"][0]})

    def malformed(self, mutation):
        value = fixture(current=True)
        with originals() as rows:
            fds = tuple(rows[name][0] for name in wire.BOOTSTRAP)
            before = tuple(copies(fd) for fd in fds)
            def peer_action(peer):
                receive(peer, value)
                header, _, _ = request(value)
                reply = dict(apiVersion=wire.REPLY_API, requestBindingSha256=p.sha(p.canonical(header)),
                    pins={name: p.sha(rows[name][1]) for name in wire.BOOTSTRAP})
                rights = fds
                if mutation == "hash": reply["pins"][wire.BOOTSTRAP[0]] = p.sha(b"substitute")
                elif mutation == "binding": reply["requestBindingSha256"] = p.sha(b"other request")
                elif mutation == "extra-right": rights += (fds[0],)
                elif mutation == "truncated-rights": rights = (fds[0],) * 24
                raw = p.canonical(reply)
                sent = peer._socket.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))],
                    socket.MSG_NOSIGNAL)
                if sent != len(raw): raise RuntimeError("short malformed control packet")
            with session(value, peer_action) as client:
                with self.assertRaises(ValueError): exchange(client, value)
                self.assertTrue(client._failed)
            self.assertEqual(tuple(copies(fd) for fd in fds), before)

    def test_actual_wrong_hash_or_request_binding_refuses_retained_rights(self):
        for mutation in ("hash", "binding"):
            with self.subTest(mutation=mutation): self.malformed(mutation)

    def test_actual_extra_and_truncated_rights_have_known_descriptor_cleanup(self):
        for mutation in ("extra-right", "truncated-rights"):
            with self.subTest(mutation=mutation): self.malformed(mutation)

    def test_silent_actual_peer_cannot_renew_boottime_or_unix_deadlines(self):
        for cap in ("deadline", "expiry"):
            with self.subTest(cap=cap):
                value = fixture(current=True)
                with session(value, lambda peer: None) as client:
                    before = time.monotonic()
                    limit = (channel._clock() if cap == "deadline" else time.time_ns()) + 100_000_000
                    with self.assertRaises(ValueError): exchange(client, value, **{cap: limit})
                    self.assertLess(time.monotonic() - before, 1.5)
                    self.assertTrue(client._failed)

    def test_actual_callback_and_explicit_legacy_isolation_refuse(self):
        value = fixture(current=True)
        def refuse(): raise ValueError("synthetic original-owner callback refusal")
        with session(value, lambda peer: None) as client:
            with self.assertRaises(ValueError): exchange(client, value, check=refuse)
        with session(value, lambda peer: None) as client:
            with self.assertRaises(ValueError): client.exchange(legacy_pending())

    def test_real_channel_budget_accounting_is_bounded_without_large_payload(self):
        self.assertEqual(channel.MAX_TOTAL, 128 * 1024 * 1024)
        self.assertEqual(channel.LIFECYCLE_MAX_TOTAL, 3 * channel.MAX_TOTAL)
        value = fixture(current=True)
        with session(value, lambda peer: None) as client:
            # Directly exercise the actual accounting primitive, not a claim
            # that these synthetic counted bytes were sent over the socket.
            client._count(channel.LIFECYCLE_MAX_TOTAL)
            with self.assertRaises(ValueError): client._count(1)
            self.assertEqual(client._total, channel.LIFECYCLE_MAX_TOTAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
