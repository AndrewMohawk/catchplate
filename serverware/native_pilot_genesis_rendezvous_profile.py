"""Observation-first cold rendezvous framing, never independent approval.

The actual listener owns the socket and kernel PIDFD. These public originals
describe its observations; parsing them neither constructs that owner nor
approves its peer. The independent operator must supply a protected complete
Execution/v2 and approval bound to this exact three-original transcript.
"""
from __future__ import annotations

import copy
import stat

from serverware import native_pilot_genesis_execution_protocol as wire

p = wire.p
CONFIGURATION_API = "serverware.nativePilotGenesisListenerConfiguration/v2"
SENDER_REQUEST_API = "serverware.nativePilotGenesisListenerRequest/v1"
SENDER_API = "serverware.nativePilotGenesisListenerObservation/v1"
RECEIVER_API = "serverware.nativePilotGenesisReceiverObservation/v1"
REQUEST_API = "serverware.nativePilotGenesisRendezvousRequest/v1"
APPROVAL_API = "serverware.nativePilotGenesisRendezvousApproval/v1"
REPLY_API = "serverware.nativePilotGenesisRendezvousReply/v1"
MAX_REQUEST = 32768
MAX_SENDER = MAX_RECEIVER = 8192
MAX_CONFIGURATION = MAX_INPUT = MAX_APPROVAL = MAX_REPLY = 4096
INPUT_PATH = "/etc/serverware/native-genesis-authority/listener-execution.input.json"
APPROVAL_PATH = "/etc/serverware/native-genesis-authority/listener-execution.approval.json"
ENDPOINT = "/run/serverware/native-pilot-core-handoff/core.sock"
PINS = ("senderRequestSha256", "receiverSha256", "configurationSha256")
BOUNDS = ("deadlineBoottimeNs", "expiresAtUnixNanos")
REQUEST_FIELDS = ("apiVersion", "sequence", "senderRequestOriginal", "senderRequestSha256",
    "receiverOriginal", "receiverSha256", "configurationOriginal", "configurationSha256", *BOUNDS)
APPROVAL_FIELDS = ("apiVersion", "requestSha256", *PINS, "inputSha256", *BOUNDS)
REPLY_FIELDS = ("apiVersion", "requestSha256", *PINS, "inputSha256", "approvalSha256")
RECEIVER_FIELDS = ("apiVersion", "senderRequestSha256", "configurationSha256",
    "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "receiver", "socket", *BOUNDS)
SENDER_REQUEST_FIELDS = ("apiVersion", "sequence", "listenerOriginal", "listenerSha256",
    "configurationSha256", *BOUNDS)
SENDER_FIELDS = ("apiVersion", "configurationSha256", "processId", "processStartTimeTicks", "endpoint",
    "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "socket")


def _document(raw, maximum, fields):
    p.require(type(raw) is bytes)
    value = p.fields(p.document(raw, maximum), fields)
    p.require(p.canonical(value) == raw)
    return value


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    return text.encode("ascii")


def _configuration(raw):
    value = _document(raw, MAX_CONFIGURATION, ("apiVersion", "window", "expiresAtUnixNanos"))
    p.require(value["apiVersion"] == CONFIGURATION_API)
    window = p.fields(value["window"], wire.endpoints.WINDOW)
    p.require(p.decoded(window["bootIdBase64url"], size=16) != bytes(16))
    p.integer(window["timeNamespaceDevice"], minimum=0, maximum=p.MAX_I64)
    p.integer(window["timeNamespaceInode"], maximum=p.MAX_I64)
    wire.endpoints.parent._invocation(window["invocationId"])
    issued, startup, lifetime = (p.ns(window[name]) for name in wire.endpoints.WINDOW[3:6])
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000
        and issued < lifetime - wire.RESERVE)
    p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    return value


def _socket(value, *, named=False):
    value = p.fields(value, ("device", "inode", "mode", "uid", "gid"))
    p.integer(value["device"], minimum=0, maximum=p.MAX_U64)
    p.integer(value["inode"], maximum=p.MAX_U64)
    p.integer(value["mode"], maximum=(1 << 32) - 1)
    p.require(stat.S_ISSOCK(value["mode"]) and type(value["uid"]) is int and type(value["gid"]) is int
        and value["uid"] == value["gid"] == 0)
    if named:
        p.require(stat.S_IMODE(value["mode"]) == 0o600)


def _parts(sender_raw, receiver_raw, configuration_raw):
    configuration = _configuration(configuration_raw)
    window = configuration["window"]
    sender = _document(sender_raw, MAX_SENDER, SENDER_REQUEST_FIELDS)
    p.require(sender["apiVersion"] == SENDER_REQUEST_API
        and type(sender["sequence"]) is int and sender["sequence"] == 0
        and sender["configurationSha256"] == p.sha(configuration_raw)
        and type(sender["deadlineBoottimeNs"]) is str
        and type(sender["expiresAtUnixNanos"]) is int
        and sender["deadlineBoottimeNs"] == window["startupDeadlineBoottimeNs"]
        and sender["expiresAtUnixNanos"] == configuration["expiresAtUnixNanos"])
    observed_raw = _original(sender["listenerOriginal"], MAX_SENDER)
    observed = _document(observed_raw, MAX_SENDER, SENDER_FIELDS)
    p.require(sender["listenerSha256"] == p.sha(observed_raw)
        and observed["apiVersion"] == SENDER_API and observed["endpoint"] == ENDPOINT
        and observed["configurationSha256"] == sender["configurationSha256"])
    p.integer(observed["processId"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(observed["processStartTimeTicks"], maximum=p.MAX_U64)
    _socket(observed["socket"], named=True)
    receiver = _document(receiver_raw, MAX_RECEIVER, RECEIVER_FIELDS)
    p.require(receiver["apiVersion"] == RECEIVER_API and receiver["senderRequestSha256"] == p.sha(sender_raw)
        and receiver["configurationSha256"] == sender["configurationSha256"])
    for field in BOUNDS:
        p.require(type(receiver[field]) is type(sender[field]) and receiver[field] == sender[field])
    for field in wire.endpoints.WINDOW[:3]:
        p.require(type(observed[field]) is type(window[field]) and observed[field] == window[field]
            and type(receiver[field]) is type(window[field]) and receiver[field] == window[field])
    peer = p.fields(receiver["receiver"], ("pid", "uid", "gid", "startTimeTicks"))
    p.integer(peer["pid"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(peer["startTimeTicks"], maximum=p.MAX_U64)
    p.require(peer["pid"] != observed["processId"] and type(peer["uid"]) is int and type(peer["gid"]) is int
        and peer["uid"] == peer["gid"] == 0)
    _socket(receiver["socket"])
    p.require(tuple(receiver["socket"][field] for field in ("device", "inode"))
        != tuple(observed["socket"][field] for field in ("device", "inode")))
    return configuration, sender, receiver


def request(sender_request_raw, receiver_raw, configuration_raw):
    _, sender, _ = _parts(sender_request_raw, receiver_raw, configuration_raw)
    value = {"apiVersion": REQUEST_API, "sequence": 0,
        "senderRequestOriginal": sender_request_raw.decode("ascii"), "senderRequestSha256": p.sha(sender_request_raw),
        "receiverOriginal": receiver_raw.decode("ascii"), "receiverSha256": p.sha(receiver_raw),
        "configurationOriginal": configuration_raw.decode("ascii"), "configurationSha256": p.sha(configuration_raw),
        **{field: sender[field] for field in BOUNDS}}
    raw = p.canonical(value)
    p.require(len(raw) <= MAX_REQUEST)
    return raw


def verify_request(raw):
    value = _document(raw, MAX_REQUEST, REQUEST_FIELDS)
    p.require(value["apiVersion"] == REQUEST_API and type(value["sequence"]) is int and value["sequence"] == 0)
    originals = tuple(_original(value[name], maximum) for name, maximum in (
        ("senderRequestOriginal", MAX_SENDER), ("receiverOriginal", MAX_RECEIVER),
        ("configurationOriginal", MAX_CONFIGURATION)))
    p.require(request(*originals) == raw)
    return copy.deepcopy(value)


def execution(input_raw, request_raw, *, boot, now_boottime_ns, now_unix_ns):
    ticket = verify_request(request_raw)
    selected = wire.configuration(input_raw, boot=boot, now_boottime_ns=now_boottime_ns,
        now_unix_ns=now_unix_ns, handoff=True)
    p.require(p.canonical(selected) == input_raw)
    configuration = _configuration(ticket["configurationOriginal"].encode("ascii"))
    receiver = p.document(ticket["receiverOriginal"].encode("ascii"), MAX_RECEIVER)["receiver"]
    p.require(p.canonical(selected["window"]) == p.canonical(configuration["window"]))
    p.require(selected["expiresAtUnixNanos"] == configuration["expiresAtUnixNanos"]
        and selected["coreHandoff"] == {"peerPid": receiver["pid"], "peerUid": receiver["uid"], "peerGid": receiver["gid"]})
    return copy.deepcopy(selected)


def approval(raw, *, request_raw, input_sha256):
    ticket = verify_request(request_raw)
    value = _document(raw, MAX_APPROVAL, APPROVAL_FIELDS)
    p.require(value["apiVersion"] == APPROVAL_API and value["requestSha256"] == p.sha(request_raw)
        and value["inputSha256"] == p.digest(input_sha256))
    p.require(all(type(value[field]) is type(ticket[field]) and value[field] == ticket[field]
        for field in PINS + BOUNDS))
    return copy.deepcopy(value)


def reply_value(request_raw, *, input_sha256, approval_sha256):
    """Encode a transport response, not an approval or installation verdict."""
    ticket = verify_request(request_raw)
    return {"apiVersion": REPLY_API, "requestSha256": p.sha(request_raw),
        **{field: ticket[field] for field in PINS}, "inputSha256": p.digest(input_sha256),
        "approvalSha256": p.digest(approval_sha256)}


def reply(raw, request_raw):
    value = _document(raw, MAX_REPLY, REPLY_FIELDS)
    p.require(value == reply_value(request_raw, input_sha256=value["inputSha256"],
        approval_sha256=value["approvalSha256"]))
    return copy.deepcopy(value)
