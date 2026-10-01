"""Closed lifecycle transport framing, not an approval or owner constructor.

Existing sender/rendezvous/cold/adopted originals remain byte-identical. This
outer envelope only orders their transport and intersects original wait caps.
"""
from __future__ import annotations

from scripts import native_pilot_runtime_artifacts as artifacts
from serverware import native_pilot_adopted_intake as intake
from serverware import native_pilot_adopted_phase_profile as adopted
from serverware import native_pilot_adopted_supervisor_policy as policy
from serverware import native_pilot_genesis_job_install as cold_install
from serverware import native_pilot_genesis_jobs as cold
from serverware import native_pilot_genesis_process as process
from serverware import native_pilot_genesis_rendezvous_profile as rendezvous
from serverware import native_pilot_measured_configuration as measured

p = rendezvous.p
REQUEST_API = "serverware.nativePilotLifecycleApprovalRequest/v1"
CHUNK_API = "serverware.nativePilotLifecycleApprovalChunk/v1"
REPLY_API = "serverware.nativePilotLifecycleApprovalReply/v1"
RECEIPT_API = "serverware.nativePilotLifecycleApprovalReceipt/v1"
MAX_REQUEST = 32 * 1024 * 1024 - 1
COLD = cold.catalogue(handoff=True)
ADOPTED = tuple((phase, job) for phase, rows in adopted.JOBS.items() for job in rows)
ORDER = ("bootstrap", "rendezvous") + ("cold",) * len(COLD) + ("adopted",) * len(ADOPTED)
FIELDS = ("apiVersion", "exchangeSequence", "stage", "deadlineBoottimeNs", "expiresAtUnixNanos", "originals")
CHUNK_FIELDS = ("apiVersion", "requestBindingSha256", "field", "offset", "dataBase64url")
BOOTSTRAP = ("policy", "recipe", "intake_configuration", "conductor_inventory", "authority_inventory")
ORIGINALS = {"bootstrap": ("sender", "configuration"), "rendezvous": ("request",),
    "cold": ("request",), "adopted": ("request", "observation")}


def stage_at(index):
    p.integer(index, minimum=0, maximum=len(ORDER) - 1)
    return ORDER[index]


def original_limits(stage):
    p.require(type(stage) is str and stage in ORIGINALS)
    if stage == "bootstrap":
        return (rendezvous.MAX_SENDER, rendezvous.MAX_CONFIGURATION)
    if stage == "rendezvous":
        return (rendezvous.MAX_REQUEST,)
    return (MAX_REQUEST,) * len(ORIGINALS[stage])


def descriptor_limits(index):
    stage = stage_at(index)
    if stage == "bootstrap":
        return tuple(zip(BOOTSTRAP, (policy.MAX_POLICY, measured.MAX_RECIPE, intake.MAX_CONFIGURATION,
            artifacts.MAX_MANIFEST_BYTES, artifacts.MAX_MANIFEST_BYTES), strict=True))
    if stage == "rendezvous":
        return (("input", rendezvous.MAX_INPUT), ("approval", rendezvous.MAX_APPROVAL))
    maximum = COLD[index - 2].maximum if stage == "cold" else ADOPTED[index - 2 - len(COLD)][1].maximum
    return (("input", maximum), ("approval", 8192))


def _raw(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    return text.encode("ascii")


def pending(stage, raws):
    """Reconstruct only the original public pending value, never authority."""
    p.fields(raws, ORIGINALS[stage])
    if stage == "bootstrap":
        return dict(senderRequestOriginal=raws["sender"].decode("ascii"),
            listenerConfigurationOriginal=raws["configuration"].decode("ascii"))
    if stage != "adopted":
        return raws["request"]
    request = p.document(raws["request"], MAX_REQUEST)
    return {name: request[name] for name in ("phase", "job", "sequence")} | {
        "status": "awaiting-independent-job-approval",
        **{name + suffix: raw.decode("ascii") if suffix == "Original" else p.sha(raw)
            for name, raw in raws.items() for suffix in ("Original", "Sha256")}}


def request(stage, value, index, *, deadline_boottime_ns, expires_at_unix_ns,
            context, boot, now_boottime_ns):
    """Reuse existing public validators; clipping never rewrites originals."""
    p.require(stage == stage_at(index) and type(context) is dict)
    deadline = p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
    expiry = p.integer(expires_at_unix_ns, maximum=p.MAX_I64)
    retained = dict(context)
    if stage == "bootstrap":
        p.fields(value, ("senderRequestOriginal", "listenerConfigurationOriginal"))
        raws = dict(sender=_raw(value["senderRequestOriginal"], rendezvous.MAX_SENDER),
            configuration=_raw(value["listenerConfigurationOriginal"], rendezvous.MAX_CONFIGURATION))
        config = rendezvous._configuration(raws["configuration"])
        sender = p.document(raws["sender"], rendezvous.MAX_SENDER)
        observed = p.document(_raw(sender["listenerOriginal"], rendezvous.MAX_SENDER), rendezvous.MAX_SENDER)
        process.sender_value(raws["sender"], configuration_raw=raws["configuration"],
            identity=dict(pid=observed["processId"], startTimeTicks=observed["processStartTimeTicks"]), boot=boot)
        p.require(tuple(config["window"][name] for name in rendezvous.wire.endpoints.WINDOW[:3]) == boot
            and p.ns(config["window"]["issuedAtBoottimeNs"]) <= now_boottime_ns)
        deadline = min(deadline, p.ns(config["window"]["startupDeadlineBoottimeNs"]),
            p.ns(config["window"]["lifetimeDeadlineBoottimeNs"]) - rendezvous.wire.RESERVE)
        expiry = min(expiry, config["expiresAtUnixNanos"])
        retained.update(sender=raws["sender"], configuration=raws["configuration"])
    elif stage == "rendezvous":
        p.require(type(value) is bytes)
        ticket = rendezvous.verify_request(value)
        p.require(ticket["senderRequestOriginal"].encode("ascii") == context["sender"]
            and ticket["configurationOriginal"].encode("ascii") == context["configuration"])
        raws = {"request": value}
        deadline = min(deadline, p.ns(ticket["deadlineBoottimeNs"]))
        expiry = min(expiry, ticket["expiresAtUnixNanos"])
    elif stage == "cold":
        p.require(type(value) is bytes)
        config = rendezvous._configuration(context["configuration"])
        ticket, selected, limit = cold_install.request(value, config, now_boottime_ns=now_boottime_ns)
        p.require(ticket["sequence"] == index - 1 and selected == COLD[index - 2])
        raws = {"request": value}
        deadline, expiry = min(deadline, limit), min(expiry, config["expiresAtUnixNanos"])
    else:
        # Lazy reuse avoids an import cycle with the real channel implementation.
        from serverware.native_pilot_supervisor_approval_channel import _pending_adopted
        header, raws, limit = _pending_adopted(value, index - 2 - len(COLD))
        observation = p.document(raws["observation"], MAX_REQUEST)
        p.require(observation["policySha256"] == context["bootstrapPins"]["policy"]
            and observation["intakeConfigurationSha256"] == context["bootstrapPins"]["intake_configuration"])
        deadline = min(deadline, limit)
        expiry = min(expiry, p.ns(header["expiresAtUnixNanos"]))
    p.require(now_boottime_ns < deadline)
    header = dict(apiVersion=REQUEST_API, exchangeSequence=index + 1, stage=stage,
        deadlineBoottimeNs=str(deadline), expiresAtUnixNanos=str(expiry),
        originals={name: dict(length=len(raw), sha256=p.sha(raw)) for name, raw in raws.items()})
    return header, raws, retained


def header(value, index, *, deadline_boottime_ns, expires_at_unix_ns):
    p.fields(value, FIELDS)
    stage = stage_at(index)
    p.require(value["apiVersion"] == REQUEST_API and type(value["exchangeSequence"]) is int
        and value["exchangeSequence"] == index + 1 and value["stage"] == stage)
    deadline, expiry = p.ns(value["deadlineBoottimeNs"]), p.ns(value["expiresAtUnixNanos"])
    p.require(deadline <= p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
        and expiry <= p.integer(expires_at_unix_ns, maximum=p.MAX_I64))
    p.fields(value["originals"], ORIGINALS[stage])
    for name, maximum in zip(ORIGINALS[stage], original_limits(stage), strict=True):
        meta = p.fields(value["originals"][name], ("length", "sha256"))
        p.integer(meta["length"], maximum=maximum); p.digest(meta["sha256"])
    return stage, deadline, expiry


def reply(value, request_header, index):
    p.fields(value, ("apiVersion", "requestBindingSha256", "pins"))
    p.require(value["apiVersion"] == REPLY_API
        and value["requestBindingSha256"] == p.sha(p.canonical(request_header)))
    names = tuple(name for name, _ in descriptor_limits(index))
    p.fields(value["pins"], names)
    for digest in value["pins"].values(): p.digest(digest)
    return value


def committed(context, stage, reply_value):
    result = dict(context)
    if stage == "bootstrap": result["bootstrapPins"] = dict(reply_value["pins"])
    return result
