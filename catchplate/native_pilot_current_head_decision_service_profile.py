"""Public joins for independently supplied current-head decisions.

Evidence is not freshness authority. A separately controlled operator supplies
the complete Input3/Approval2 pair; this module never creates either decision
or approval and does not turn root file ownership into organizational custody.
The provider authenticates the retained source graph. The receiver repeats the
full Input3 checks and literal evidence joins; supplemental generation evidence
is not independently re-admitted without its absent delivery original.
"""
from __future__ import annotations

from catchplate import native_pilot_approval_current_heads as intake
from catchplate import native_pilot_supervisor_approval_channel as channel

p = intake.p
API = "catchplate.nativePilotCurrentHeadDecisionService/v1"
PURPOSE = "independent-protected-current-head-decisions"
DIRECTORY = "/etc/catchplate/native-pilot-current-head-decisions"
MAX_CONFIGURATION = 4096
FIELDS = ("apiVersion", "purpose", "supervisorInventorySha256", "providerPeer", "directory",
    "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
SUFFIXES = ("request", "evidence", "input", "approval")


def configuration(raw, *, inventory_sha256, boot, now_boottime_ns, now_unix_ns):
    value = p.fields(p.document(raw, MAX_CONFIGURATION), FIELDS)
    p.require(p.canonical(value) == raw and value["apiVersion"] == API and value["purpose"] == PURPOSE
        and p.digest(value["supervisorInventorySha256"]) == p.digest(inventory_sha256)
        and type(boot) is tuple and tuple(value[name] for name in FIELDS[5:8]) == boot)
    p.decoded(value["bootIdBase64url"], size=16)
    p.integer(value["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(value["timeNamespaceInode"], maximum=p.MAX_U64)
    peer = p.fields(value["providerPeer"], ("pid", "uid", "gid", "startTimeTicks"))
    p.integer(peer["pid"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(peer["startTimeTicks"], maximum=p.MAX_U64)
    p.require(type(peer["uid"]) is int and type(peer["gid"]) is int and peer["uid"] == peer["gid"] == 0)
    directory = p.fields(value["directory"], ("device", "inode"))
    p.integer(directory["device"], minimum=0, maximum=p.MAX_U64)
    p.integer(directory["inode"], maximum=p.MAX_U64)
    issue, deadline = p.ns(value["issuedAtBoottimeNs"]), p.ns(value["deadlineBoottimeNs"])
    epoch_issue = p.integer(value["issuedAtUnixNanos"], maximum=p.MAX_I64)
    expiry = p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    p.require(type(now_boottime_ns) is int and type(now_unix_ns) is int
        and issue <= now_boottime_ns < deadline and epoch_issue <= now_unix_ns < expiry)
    return dict(value=value, deadline=deadline, epochLimit=expiry)


def filenames(job):
    p.require(job in intake.JOB_NAMES)
    return {suffix: job + "." + suffix + ".json" for suffix in SUFFIXES}


def require_pair(pending, evidence_raw, input_raw, approval_raw, *, boot, now_boottime_ns, now_unix_ns):
    evidence = channel.current_head_evidence(pending, evidence_raw)
    decision = intake.selection(pending, input_raw, approval_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    value = p.document(input_raw, intake.MAX_INPUT)
    source = evidence["originals"]
    for field, name in (("driverConfigurationOriginal", "driverConfiguration"),
            ("driverWindowOriginal", "driverWindow"), ("launchOriginal", "launch"),
            ("configurationOriginal", "configuration"), ("runtimeOriginal", "runtime"),
            ("preparationOriginal", "preparation"), ("resourcesOriginal", "resources"),
            ("initialHistoryOriginal", "primaryInitialHistory"), ("requestOriginal", "request")):
        p.require(value[field] == source[name])
    p.require(value["rootAuthority"] == evidence["rootAuthority"]
        and value["serviceRole"] == evidence["serviceRole"] and value["endpointRole"] == evidence["endpointRole"]
        and decision["currentness"]["initialHistorySha256"] == p.sha(source["selectedInitialHistory"].encode("ascii")))
    prepared = intake.head.prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns, adopted=True)
    p.require(prepared["authority"] == evidence["checkpointAuthority"])
    bounds = intake.pending_bounds(pending)
    return dict(deadline=min(bounds["deadline"], prepared["deadline"], evidence["deadlineBoottimeNanos"]),
        epochLimit=bounds["epochLimit"])
