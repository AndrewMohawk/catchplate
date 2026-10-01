"""Admit eight independently supplied current-head decisions, never make one.

The runtime retains the genuine authenticated channel and protected Input/v3
and Approval/v2 descriptors. These pure checks bind their literal bytes to the
actual pending request and the separately checked candidate transcript. Signed
history is source evidence, not evidence that no newer checkpoint exists.
Neither a successful compiler nor this adapter authorizes currentness.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_approval_install as approvals
from serverware import native_pilot_bridge_preparation as bridge
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_supervisor_approval_channel as channel
from serverware import native_pilot_supervisor_current_head_profile as heads

p = head.p
JOB_NAMES = heads.JOB_NAMES
MAX_INPUT, MAX_APPROVAL = head.MAX_INPUT, profile.MAX_APPROVAL
_ORDER = tuple((phase, job) for phase, jobs in profile.JOBS.items() for job in jobs)
INDICES = tuple(index for index, (_, job) in enumerate(_ORDER) if job.family == "current-head")


def _original(raw, maximum):
    p.require(type(raw) is bytes and raw.isascii() and 0 < len(raw) <= maximum)
    return raw


def _pending(pending):
    p.require(type(pending) is dict and pending.get("job") in JOB_NAMES
        and tuple(_ORDER[index][1].name for index in INDICES) == JOB_NAMES)
    index = INDICES[JOB_NAMES.index(pending["job"])]
    header, raws, _ = channel._pending_adopted(pending, index)
    request = p.document(raws["request"], channel.MAX_REQUEST)
    p.require(all(type(request[name]) is int for name in ("sequence", "conductorSequence", "jobIndex")))
    role, endpoint = profile.legacy.CURRENT_HEAD_JOB_INFO[pending["job"]]
    observed = p.document(raws["observation"], channel.MAX_REQUEST)
    conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), channel.MAX_REQUEST)
    preparation = bridge.shape(_original(
        conductor["payload"]["bridgePreparationOriginal"].encode("ascii"), bridge.MAX_BYTES))
    p.require(preparation["apiVersion"] == bridge.ADOPTED_API)
    requests, _ = bridge._parts(preparation)
    rows = [(target, row) for actual, target, row in bridge.requests_profile.iter_requests(requests)
        if actual == role and (endpoint is None or endpoint == target)]
    p.require(len(rows) == 1)
    target, row = rows[0]
    trust_request = head.request(row["requestOriginal"].encode("ascii"))
    p.require(trust_request["endpointRole"] == target)
    deadline = min(p.ns(header["deadlineBoottimeNs"]), trust_request["deadline"]["absoluteBoottimeNanos"])
    expiry = p.ns(header["expiresAtUnixNanos"])
    p.integer(expiry, maximum=p.MAX_I64)
    return raws, request, role, target, row, deadline, expiry


def pending_bounds(pending):
    """Clip the external decision wait to the actual inner trust-request cap.

    This parses observed data only; it does not establish ownership or decide
    currentness. The retained caller still checks current clocks and peers.
    """
    *_, deadline, expiry = _pending(pending)
    return dict(deadline=deadline, epochLimit=expiry)


def _prepare(pending, input_raw, approval_raw, *, boot, now_boottime_ns, now_unix_ns):
    p.integer(now_boottime_ns, maximum=p.MAX_U64)
    p.integer(now_unix_ns, maximum=p.MAX_I64)
    raws, request, role, target, row, deadline, expiry = _pending(pending)
    _original(input_raw, MAX_INPUT); _original(approval_raw, MAX_APPROVAL)
    ticket, selected, request_deadline, request_expiry = approvals._prepare_adopted(
        raws["request"], approval_raw, input_raw, p.sha(approval_raw), p.sha(input_raw),
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(selected.family == "current-head" and selected.name == pending["job"]
        and ticket == request and expiry == request_expiry and deadline <= request_deadline)
    value = p.fields(p.document(input_raw, MAX_INPUT), head.INPUT_FIELDS + ("endpointRole", "runtimeOriginal"))
    p.require(value["apiVersion"] == head.ADOPTED_API and value["serviceRole"] == role)
    # Do not accept an internally valid decision for a different fresh nonce.
    p.require(value["endpointRole"] == target and value["requestOriginal"] == row["requestOriginal"]
        and p.sha(value["runtimeOriginal"].encode("ascii")) == row["runtimeConfigurationSha256"]
        and value["currentness"]["initialHistorySha256"] == row["initialHistorySha256"]
        and value["currentness"]["checkpointSha256"] == row["checkpointSha256"])
    prepared = head.prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns, adopted=True)
    deadline = min(deadline, prepared["deadline"])
    p.require(now_boottime_ns < deadline and now_unix_ns < expiry)
    return copy.deepcopy(value["currentness"]), deadline, expiry


def selection(pending, input_raw, approval_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Extract only the supplied fresh decision after exact input/approval joins.

    This does not attest descriptor provenance or authorize a policy rule. The
    caller must retain the real external-current-head channel and its two
    protected descriptors, then check the complete candidate before forwarding.
    """
    decision, _, _ = _prepare(pending, input_raw, approval_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return {"currentness": decision}


def require_candidate(candidate, input_raw, approval_raw, *, pending,
                      boot, now_boottime_ns, now_unix_ns):
    """Join the actual transcript candidate to the independently supplied pair.

    Candidate dictionaries are public data, not owner capabilities. The runtime
    calls its retained transcript.prepare itself; this function neither accepts
    a replacement transcript nor constructs approval from a matching candidate.
    """
    _, deadline, expiry = _prepare(pending, input_raw, approval_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(candidate, ("originals", "pins", "deadline", "epochLimit"))
    originals = p.fields(candidate["originals"], ("input",))
    pins = p.fields(candidate["pins"], ("input",))
    p.require(type(originals["input"]) is bytes and originals["input"] == input_raw
        and p.digest(pins["input"]) == p.sha(input_raw))
    deadline = min(deadline, p.integer(candidate["deadline"], maximum=p.MAX_U64))
    expiry = min(expiry, p.integer(candidate["epochLimit"], maximum=p.MAX_I64))
    p.require(now_boottime_ns < deadline and now_unix_ns < expiry)
    return dict(originals=dict(input=input_raw, approval=approval_raw),
        pins=dict(input=p.sha(input_raw), approval=p.sha(approval_raw)), deadline=deadline, epochLimit=expiry)
