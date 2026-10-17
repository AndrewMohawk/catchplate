#!/usr/bin/env python3
"""Synthetic public framing, not receiver custody or independent approval."""
from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import native_pilot_genesis_rendezvous_profile as profile

p = profile.p


def fixture():
    configuration = {"apiVersion": profile.CONFIGURATION_API, "window": {
        "bootIdBase64url": "AAECAwQFBgcICQoLDA0ODw", "timeNamespaceDevice": 11, "timeNamespaceInode": 12,
        "issuedAtBoottimeNs": "1000000000", "startupDeadlineBoottimeNs": "2000000000",
        "lifetimeDeadlineBoottimeNs": "4000000000", "invocationId": "1234567890abcdef1234567890abcdef"},
        "expiresAtUnixNanos": 9000000000}
    configuration_raw = p.canonical(configuration)
    namespace = {field: configuration["window"][field] for field in profile.wire.endpoints.WINDOW[:3]}
    socket = {"device": 21, "inode": 22, "mode": stat.S_IFSOCK | 0o600, "uid": 0, "gid": 0}
    observed = {"apiVersion": profile.SENDER_API, "configurationSha256": p.sha(configuration_raw),
        "processId": 100, "processStartTimeTicks": 123, "endpoint": profile.ENDPOINT,
        **namespace, "socket": socket}
    observed_raw = p.canonical(observed)
    bounds = {"deadlineBoottimeNs": configuration["window"]["startupDeadlineBoottimeNs"],
        "expiresAtUnixNanos": configuration["expiresAtUnixNanos"]}
    sender_raw = p.canonical({"apiVersion": profile.SENDER_REQUEST_API, "sequence": 0,
        "listenerOriginal": observed_raw.decode("ascii"), "listenerSha256": p.sha(observed_raw),
        "configurationSha256": p.sha(configuration_raw), **bounds})
    receiver_raw = p.canonical({"apiVersion": profile.RECEIVER_API, "senderRequestSha256": p.sha(sender_raw),
        "configurationSha256": p.sha(configuration_raw), **namespace,
        "receiver": {"pid": 200, "uid": 0, "gid": 0, "startTimeTicks": 234},
        "socket": socket | {"device": 31, "inode": 32, "mode": stat.S_IFSOCK | 0o777}, **bounds})
    request_raw = profile.request(sender_raw, receiver_raw, configuration_raw)
    selected = configuration | {"apiVersion": profile.wire.HANDOFF_CONFIGURATION_API,
        "coreHandoff": {"peerPid": 200, "peerUid": 0, "peerGid": 0}}
    input_raw = p.canonical(selected)
    ticket = profile.verify_request(request_raw)
    # A synthetic fixture only. The executable installer never generates approval.
    approval_raw = p.canonical({"apiVersion": profile.APPROVAL_API, "requestSha256": p.sha(request_raw),
        **{field: ticket[field] for field in profile.PINS + profile.BOUNDS}, "inputSha256": p.sha(input_raw)})
    return dict(configuration_raw=configuration_raw, sender_raw=sender_raw, receiver_raw=receiver_raw,
        request_raw=request_raw, input_raw=input_raw, approval_raw=approval_raw,
        boot=tuple(namespace.values()), now_boottime_ns=1500000000, now_unix_ns=8000000000)


def execute(value, raw=None):
    return profile.execution(value["input_raw"] if raw is None else raw, value["request_raw"],
        **{name: value[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")})


class RendezvousFramingControls(unittest.TestCase):
    def test_three_literal_originals_and_exact_receiver_join(self):
        value = fixture()
        request = profile.verify_request(value["request_raw"])
        for name, key in (("configuration", "configuration_raw"), ("senderRequest", "sender_raw"), ("receiver", "receiver_raw")):
            self.assertEqual(request[name + "Original"].encode("ascii"), value[key])
            self.assertEqual(request[name + "Sha256"], p.sha(value[key]))
        self.assertEqual(execute(value)["coreHandoff"]["peerPid"], 200)

    def test_legacy_request_and_configuration_do_not_upgrade(self):
        value = fixture()
        with self.assertRaises(ValueError): profile.verify_request(value["sender_raw"])
        configuration = p.document(value["configuration_raw"], 4096)
        configuration["apiVersion"] = "catchplate.nativePilotGenesisListenerConfiguration/v1"
        with self.assertRaises(ValueError): profile.request(value["sender_raw"], value["receiver_raw"], p.canonical(configuration))

    def test_hashed_receiver_cannot_be_substituted_or_aliased(self):
        value = fixture()
        for fields in ({"pid": 201}, {"pid": 100}, {"pid": True}, {"uid": 1000}, {"startTimeTicks": 0}):
            receiver = p.document(value["receiver_raw"], 8192)
            receiver["receiver"].update(fields)
            if fields == {"pid": 201}:
                changed = value | {"request_raw": profile.request(value["sender_raw"], p.canonical(receiver), value["configuration_raw"])}
                with self.assertRaises(ValueError): execute(changed)
            else:
                with self.assertRaises(ValueError): profile.request(value["sender_raw"], p.canonical(receiver), value["configuration_raw"])

    def test_every_execution_bound_is_exact_not_renewed(self):
        value = fixture()
        for field, replacement in (("startupDeadlineBoottimeNs", "1900000000"),
                ("lifetimeDeadlineBoottimeNs", "4100000000"), ("issuedAtBoottimeNs", "1100000000")):
            selected = p.document(value["input_raw"], 4096)
            selected["window"][field] = replacement
            with self.assertRaises(ValueError): execute(value, p.canonical(selected))
        for expiry in (8999999999, 9000000001):
            selected = p.document(value["input_raw"], 4096); selected["expiresAtUnixNanos"] = expiry
            with self.assertRaises(ValueError): execute(value, p.canonical(selected))

    def test_current_clocks_and_namespace_are_checked(self):
        value = fixture()
        for update in ({"now_boottime_ns": 999999999}, {"now_boottime_ns": 2000000000},
                {"now_unix_ns": 9000000000}, {"boot": (value["boot"][0], 12, 11)}):
            with self.assertRaises(ValueError): execute(value | update)

    def test_independent_approval_binds_both_observations_and_configuration(self):
        value = fixture()
        profile.approval(value["approval_raw"], request_raw=value["request_raw"], input_sha256=p.sha(value["input_raw"]))
        for field in ("requestSha256", *profile.PINS, "inputSha256"):
            approval = p.document(value["approval_raw"], 4096); approval[field] = p.sha(b"unrelated synthetic original")
            with self.assertRaises(ValueError): profile.approval(p.canonical(approval),
                request_raw=value["request_raw"], input_sha256=p.sha(value["input_raw"]))

    def test_reply_is_only_bound_transport_not_approval(self):
        value = fixture()
        reply = profile.reply_value(value["request_raw"], input_sha256=p.sha(value["input_raw"]),
            approval_sha256=p.sha(value["approval_raw"]))
        self.assertEqual(profile.reply(p.canonical(reply), value["request_raw"]), reply)
        self.assertNotIn("approved", reply)
        reply["receiverSha256"] = p.sha(b"other receiver")
        with self.assertRaises(ValueError): profile.reply(p.canonical(reply), value["request_raw"])

    def test_wire_is_canonical_closed_and_bounded(self):
        value = fixture()
        for raw in (value["request_raw"] + b"\n", b" " * (profile.MAX_REQUEST + 1),
                value["request_raw"].replace(b'"sequence":0', b'"sequence":false'),
                value["request_raw"].replace(b'"sequence":0', b'"sequence":0,"sequence":0')):
            with self.assertRaises(ValueError): profile.verify_request(raw)
        request = profile.verify_request(value["request_raw"]); request["approved"] = True
        with self.assertRaises(ValueError): profile.verify_request(p.canonical(request))

    def test_foreign_receiver_boot_or_socket_is_not_observation(self):
        value = fixture()
        for fields in ({"timeNamespaceInode": 13}, {"deadlineBoottimeNs": "2000000001"},
                {"senderRequestSha256": p.sha(b"other sender")},
                {"socket": {"device": 31, "inode": 32, "mode": stat.S_IFREG | 0o400, "uid": 0, "gid": 0}}):
            receiver = p.document(value["receiver_raw"], 8192) | fields
            with self.assertRaises(ValueError): profile.request(value["sender_raw"], p.canonical(receiver), value["configuration_raw"])

    def test_returned_values_do_not_mutate_originals(self):
        value = fixture()
        first = copy.deepcopy(value)
        selected = execute(value); selected["coreHandoff"]["peerPid"] = 999
        ticket = profile.verify_request(value["request_raw"]); ticket["configurationOriginal"] = "{}"
        self.assertEqual(value, first)
        self.assertEqual(execute(value)["coreHandoff"]["peerPid"], 200)


if __name__ == "__main__":
    unittest.main()
