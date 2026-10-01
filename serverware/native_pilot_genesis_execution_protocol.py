"""Closed public job grammar; none of these values constructs a live owner."""
from __future__ import annotations

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_endpoint_profile as endpoints

p = g.p
CONFIGURATION_API = "serverware.nativePilotGenesisExecution/v1"
REQUEST_API = "serverware.nativePilotGenesisJobRequest/v1"
APPROVAL_API = "serverware.nativePilotGenesisJobApproval/v1"
ACTION_API = "serverware.nativePilotGenesisOwnerAction/v1"
MAX_REQUEST = 32 * 1024 * 1024
RESERVE = 250_000_000


def configuration(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = p.fields(g.document(raw, 4096), ("apiVersion", "window", "expiresAtUnixNanos"))
    p.require(value["apiVersion"] == CONFIGURATION_API)
    window = p.fields(value["window"], endpoints.WINDOW)
    p.require(p.decoded(window["bootIdBase64url"], size=16) != bytes(16))
    p.integer(window["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(window["timeNamespaceInode"], maximum=p.MAX_U64)
    p.require(tuple(window[name] for name in endpoints.WINDOW[:3]) == boot)
    endpoints.parent._invocation(window["invocationId"])
    issued, startup, lifetime = (p.ns(window[name]) for name in endpoints.WINDOW[3:6])
    p.require(issued <= now_boottime_ns < min(startup, lifetime - RESERVE)
        and startup <= lifetime and startup - issued <= 30_000_000_000)
    p.require(now_unix_ns < p.integer(value["expiresAtUnixNanos"]))
    return value


def require_window(window, expected):
    p.require(g.canonical({name: window[name] for name in endpoints.WINDOW}) == g.canonical(expected))


def owner_action(raw, name):
    value = p.fields(g.document(raw, 1024), ("apiVersion", "action"))
    p.require(value["apiVersion"] == ACTION_API and value["action"] == name)
    return value


def request(*, sequence, job, deadline, observation, previous):
    p.integer(sequence); p.require(type(job) is str and job.isascii())
    p.require(type(deadline) is int and 0 < deadline <= p.MAX_U64)
    p.require(type(observation) is dict and all(type(k) is str and type(v) is bytes for k, v in observation.items()))
    value = dict(apiVersion=REQUEST_API, sequence=sequence, job=job,
        deadlineBoottimeNs=str(deadline), observation={k: v.decode("ascii") for k, v in observation.items()},
        previousResult=previous)
    raw = p.canonical(value)
    p.require(len(raw) + 1 <= MAX_REQUEST)  # The fixed pipe frame includes LF.
    return value, raw


def approval(raw, *, request_raw, input_sha256):
    value = p.fields(g.document(raw, 8192), ("apiVersion", "sequence", "job", "requestSha256", "inputSha256", "deadlineBoottimeNs"))
    ticket = p.fields(p.document(request_raw, MAX_REQUEST),
        ("apiVersion", "sequence", "job", "deadlineBoottimeNs", "observation", "previousResult"))
    p.require(ticket["apiVersion"] == REQUEST_API)
    p.require(value["apiVersion"] == APPROVAL_API and value["requestSha256"] == p.sha(request_raw)
        and p.digest(value["inputSha256"]) == p.digest(input_sha256))
    p.integer(value["sequence"])
    p.require(all(value[name] == ticket[name] for name in ("sequence", "job", "deadlineBoottimeNs")))
    return value


def preceding(prior, name):
    item = p.fields(prior[name], ("input", "result"))
    p.require(type(item["input"]) is bytes and type(item["result"]) is bytes)
    return item


def native_install(raw, role, prior):
    """An approved install cannot substitute another valid launch transcript."""
    value = p.fields(p.document(raw, MAX_REQUEST), ("apiVersion", "role", "launchInputOriginal", "bundleOriginal"))
    p.require(value["apiVersion"] == "serverware.nativePilotGenesisLaunchInstallationInput/v1" and value["role"] == role)
    old = preceding(prior, "native-launch-" + role)
    p.require(all(type(value[name]) is str and value[name].isascii() for name in ("launchInputOriginal", "bundleOriginal")))
    p.require(value["launchInputOriginal"].encode("ascii") == old["input"]
        and value["bundleOriginal"].encode("ascii") == old["result"])
    return value
