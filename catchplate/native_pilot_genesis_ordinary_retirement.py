"""Closed cold-service retirement wire checks, not process ownership.

Only the retained control owner authenticates the packet's kernel sender and
consumes the same child's PIDFD wait. Parsing this public evidence cannot mint
either a native helper-reap capability or successful business execution.
"""
from __future__ import annotations

import os
import re

from catchplate import custody_generation_grants as g

p = g.p
ROLES = ("durable-recovery-store", "current-signature-authority")
STOP_API = "catchplate.custodyGenesisOrdinaryStop/v1"
TERMINAL_API = "catchplate.custodyGenesisOrdinaryTerminal/v1"
MAX_BYTES = 4096
STOP_FIELDS = ("apiVersion", "deliverySha256", "serviceRole", "invocationId", "deadlineBoottimeNs")
TERMINAL_FIELDS = (*STOP_FIELDS, "stopSha256", "helper", "serviceResult", "serviceExitStatus")


def stop_original(*, delivery_sha256, role, invocation, deadline):
    p.digest(delivery_sha256)
    p.require(role in ROLES and type(invocation) is str
        and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None)
    p.require(type(deadline) is int and 0 < deadline < (1 << 64))
    return g.canonical(dict(apiVersion=STOP_API, deliverySha256=delivery_sha256,
        serviceRole=role, invocationId=invocation, deadlineBoottimeNs=str(deadline)))


def terminal(raw, *, stop_raw, stop_sent_at, now, service_pid):
    """Check exact originals and reported facts after separate sender admission."""
    request = p.fields(g.document(stop_raw, MAX_BYTES), STOP_FIELDS)
    deadline = p.ns(request["deadlineBoottimeNs"])
    p.require(stop_original(delivery_sha256=request["deliverySha256"], role=request["serviceRole"],
        invocation=request["invocationId"], deadline=deadline) == stop_raw)
    p.require(type(stop_sent_at) is int and type(now) is int and 0 <= stop_sent_at <= now < deadline)
    p.integer(service_pid, maximum=(1 << 31) - 1)
    value = p.fields(g.document(raw, MAX_BYTES), TERMINAL_FIELDS)
    p.require(value["apiVersion"] == TERMINAL_API
        and all(type(value[name]) is type(request[name]) and value[name] == request[name]
            for name in STOP_FIELDS[1:]) and value["stopSha256"] == p.sha(stop_raw))
    helper = p.fields(value["helper"], ("pid", "startTimeTicks", "exitCode", "exitStatus", "reapedAtBoottimeNs"))
    p.integer(helper["pid"], maximum=(1 << 31) - 1)
    p.integer(helper["startTimeTicks"], maximum=(1 << 64) - 1)
    p.require(helper["pid"] != service_pid and type(helper["exitCode"]) is int
        and helper["exitCode"] == os.CLD_EXITED and type(helper["exitStatus"]) is int
        and helper["exitStatus"] == 0 and stop_sent_at <= p.ns(helper["reapedAtBoottimeNs"]) <= now)
    p.require(type(value["serviceResult"]) is str and value["serviceResult"] in ("ok", "error")
        and type(value["serviceExitStatus"]) is int
        and value["serviceExitStatus"] == (0 if value["serviceResult"] == "ok" else 1))
    return value


def require_reap(result, *, pid, uid, status):
    """Compare the caller's actual consuming wait result; no wait is performed."""
    p.require(type(result) is os.waitid_result and result.si_pid == pid and result.si_uid == uid
        and result.si_code == os.CLD_EXITED and result.si_status == status
        and type(status) is int and status in (0, 1))
