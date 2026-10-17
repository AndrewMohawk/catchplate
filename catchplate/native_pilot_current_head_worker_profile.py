"""Fixed eight-request decisions under independently delegated current state.

State is supplied by the actual authority, not inferred from signed history.
The runtime owns its latest-name read and shared writer lock, durable one-use
receipt and atomic publication. This pure module has no custody or signing
capability. It composes only existing Input3/Approval2 after exact state joins.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_approval_current_heads as intake
from catchplate import native_pilot_current_head_decision_service_profile as delivery

p, head, phase, heads = intake.p, intake.head, intake.profile, intake.heads
API = "catchplate.nativePilotCurrentHeadWorkerPolicy/v1"
PURPOSE = "authorize-eight-initial-current-heads-from-independent-live-state"
STATE_API = "catchplate.nativePilotCurrentHeadState/v1"
UPDATE_API = "catchplate.nativePilotCurrentHeadStateUpdate/v1"
RECEIPT_API = "catchplate.nativePilotCurrentHeadDecisionReceipt/v1"
STATE_DIRECTORY = "/etc/catchplate/native-pilot-current-head-state"
STATE_NAME, LOCK_NAME = "current.json", "lock"
DECISION_DIRECTORY = delivery.DIRECTORY
JOB_NAMES = intake.JOB_NAMES
MAX_POLICY, MAX_STATE, MAX_UPDATE, MAX_RECEIPT = 4096, 65536, 131072, 4096
MAX_REQUEST, MAX_EVIDENCE = phase.MAX_FRAME, heads.MAX_OBSERVED
BOOT = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")
CLOCKS = ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
POLICY_FIELDS = ("apiVersion", "purpose", "supervisorInventorySha256", "stateDirectory", "decisionDirectory",
    "initialStateSha256", "initialStateGeneration", *BOOT, *CLOCKS)
STATE_SCOPE = (*BOOT, "invocationId", "driverConfigurationSha256", "driverWindowSha256", "launchSha256")
STATE_FIELDS = ("apiVersion", "generation", *STATE_SCOPE, *CLOCKS, "targets")
TARGET_FIELDS = ("serviceRole", "endpointRole", "rootAuthority", "checkpointAuthority", "initialHistorySha256",
    "endpointProcessIdentitySha256", "deploymentGenerationSha256", "checkpointSequence", "checkpointSha256",
    "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch",
    "revocationGenerationHighWater", "revocationRootSha256", "status")
COUNTERS = ("checkpointSequence", "endpointGeneration", "serviceGeneration", "operationGeneration",
    "durableEpoch", "revocationGenerationHighWater")
TARGET_PINS = ("initialHistorySha256", "endpointProcessIdentitySha256", "deploymentGenerationSha256",
    "checkpointSha256", "revocationRootSha256")
UPDATE_FIELDS = ("apiVersion", "directory", "expectedStateSha256", "expectedGeneration", "nextStateOriginal")
RECEIPT_FIELDS = ("apiVersion", "job", "requestSha256", "evidenceSha256", "stateSha256", "stateGeneration",
    "inputSha256", "approvalSha256", "requestNonceSha256", "issuedAtBoottimeNanos",
    "deadlineBoottimeNs", "expiresAtUnixNanos")
EVIDENCE_FIELDS = ("apiVersion", "jobName", "serviceRole", "endpointRole", "originals", "rootAuthority",
    "checkpointAuthority", "checkpointSha256", "requestSha256", "requestNonceSha256", "deadlineBoottimeNanos")
EVIDENCE_ORIGINALS = ("bridgePreparation", "driverConfiguration", "driverWindow", "launch", "preparation",
    "resources", "configuration", "runtime", "primaryInitialHistory", "selectedInitialHistory", "generationGrant", "request")


def _document(raw, maximum, fields):
    value = p.fields(p.document(raw, maximum), fields)
    p.require(p.canonical(value) == raw)
    return value


def _directory(value):
    p.fields(value, ("device", "inode"))
    p.integer(value["device"], minimum=0); p.integer(value["inode"])


def _pin(value):
    p.fields(value, ("keyId", "keySpkiSha256"))
    for pin in value.values(): p.digest(pin)


def _interval(value):
    p.require(p.decoded(value[BOOT[0]], size=16) != bytes(16))
    p.integer(value[BOOT[1]], minimum=0); p.integer(value[BOOT[2]])
    p.require(p.ns(value[CLOCKS[0]]) < p.ns(value[CLOCKS[1]]))
    p.require(p.integer(value[CLOCKS[2]]) < p.integer(value[CLOCKS[3]]))


def _live(value, boot, now_boottime_ns, now_unix_ns):
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    p.require(type(boot) is tuple and tuple(value[name] for name in BOOT) == boot
        and p.ns(value[CLOCKS[0]]) <= now_boottime_ns < p.ns(value[CLOCKS[1]])
        and value[CLOCKS[2]] <= now_unix_ns < value[CLOCKS[3]])


def state(raw):
    """Validate an explicitly supplied authority assertion, not its provenance."""
    value = _document(raw, MAX_STATE, STATE_FIELDS)
    p.require(value["apiVersion"] == STATE_API); p.integer(value["generation"]); _interval(value)
    head.key._invocation(value["invocationId"])
    for name in STATE_SCOPE[4:]: p.digest(value[name])
    p.fields(value["targets"], JOB_NAMES)
    for name in JOB_NAMES:
        row = p.fields(value["targets"][name], TARGET_FIELDS)
        role, endpoint = phase.legacy.CURRENT_HEAD_JOB_INFO[name]
        p.require(row["serviceRole"] == role and row["endpointRole"] in head.key.ENDPOINT_ROLES
            and (endpoint is None or row["endpointRole"] == endpoint) and row["status"] in ("active", "revoked"))
        _pin(row["rootAuthority"]); _pin(row["checkpointAuthority"])
        for pin in TARGET_PINS: p.digest(row[pin])
        for counter in COUNTERS: p.integer(row[counter])
    p.require(len({(row["serviceRole"], row["endpointRole"]) for row in value["targets"].values()}) == len(JOB_NAMES))
    return copy.deepcopy(value)


def update(input_raw, current_raw):
    """Explicit empty-store initialization or strict same-scope monotonic CAS."""
    value = _document(input_raw, MAX_UPDATE, UPDATE_FIELDS)
    p.require(value["apiVersion"] == UPDATE_API); _directory(value["directory"])
    p.require(type(value["nextStateOriginal"]) is str and value["nextStateOriginal"].isascii())
    raw = value["nextStateOriginal"].encode("ascii"); after = state(raw)
    if current_raw is None:
        p.require(value["expectedStateSha256"] is None and type(value["expectedGeneration"]) is int
            and value["expectedGeneration"] == 0 and after["generation"] == 1)
        return raw
    before = state(current_raw)
    p.require(p.digest(value["expectedStateSha256"]) == p.sha(current_raw)
        and p.integer(value["expectedGeneration"]) == before["generation"]
        and after["generation"] == before["generation"] + 1)
    p.require(all(before[name] == after[name] for name in STATE_SCOPE)
        and p.ns(before[CLOCKS[0]]) <= p.ns(after[CLOCKS[0]]) < p.ns(after[CLOCKS[1]]) <= p.ns(before[CLOCKS[1]])
        and before[CLOCKS[2]] <= after[CLOCKS[2]] < after[CLOCKS[3]] <= before[CLOCKS[3]])
    fixed = ("serviceRole", "endpointRole", "rootAuthority", "checkpointAuthority", "initialHistorySha256",
        "endpointProcessIdentitySha256", "deploymentGenerationSha256")
    for name in JOB_NAMES:
        old, new = before["targets"][name], after["targets"][name]
        p.require(all(old[field] == new[field] for field in fixed)
            and all(old[field] <= new[field] for field in COUNTERS)
            and (old["status"] != "revoked" or new["status"] == "revoked"))
        for number, digest in (("checkpointSequence", "checkpointSha256"),
                ("revocationGenerationHighWater", "revocationRootSha256")):
            p.require(old[number] != new[number] or old[digest] == new[digest])
        # A same-checkpoint update can revoke it, but cannot reinterpret its
        # signed generation or revocation contents under the old hash.
        if old["checkpointSequence"] == new["checkpointSequence"]:
            p.require(all(old[field] == new[field] for field in ("endpointGeneration", "serviceGeneration",
                "operationGeneration", "durableEpoch")))
    return raw


def prepare(raw, *, inventory_sha256, boot, now_boottime_ns, now_unix_ns):
    value = _document(raw, MAX_POLICY, POLICY_FIELDS)
    p.require(value["apiVersion"] == API and value["purpose"] == PURPOSE
        and value["supervisorInventorySha256"] == p.digest(inventory_sha256))
    _directory(value["stateDirectory"]); _directory(value["decisionDirectory"])
    p.require(value["stateDirectory"] != value["decisionDirectory"])
    p.digest(value["initialStateSha256"]); p.integer(value["initialStateGeneration"])
    _interval(value); _live(value, boot, now_boottime_ns, now_unix_ns)
    return dict(value=copy.deepcopy(value), deadline=p.ns(value["deadlineBoottimeNs"]),
        epochLimit=value["expiresAtUnixNanos"])


def _parts(request_raw, evidence_raw, *, index, first_conductor_raw):
    p.integer(index, minimum=0, maximum=len(JOB_NAMES) - 1)
    name = JOB_NAMES[index]
    ticket = _document(request_raw, MAX_REQUEST, phase.REQUEST_FIELDS)
    phase_name, selected = phase.BY_NAME[name]
    p.require(ticket["apiVersion"] == phase.API and ticket["phase"] == phase_name == "bridge-runtime"
        and ticket["job"] == name and type(ticket["jobIndex"]) is int
        and ticket["jobIndex"] == phase.job_index(phase_name, name)
        and type(ticket["sequence"]) is int and ticket["sequence"] == intake.INDICES[index] + 1
        and type(ticket["conductorSequence"]) is int
        and ticket["conductorSequence"] == tuple(phase.JOBS).index(phase_name) + 1)
    deadline, expiry = p.ns(ticket["deadlineBoottimeNs"]), p.ns(ticket["expiresAtUnixNanos"])
    p.integer(expiry)
    if index == 0:
        p.require(first_conductor_raw is None and type(ticket["conductorRequest"]) is dict)
        conductor_raw = p.canonical(ticket["conductorRequest"])
    else:
        p.require(type(first_conductor_raw) is bytes and ticket["conductorRequest"] is None)
        conductor_raw = first_conductor_raw
    conductor = _document(conductor_raw, MAX_REQUEST,
        ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs", "expiresAtUnixNanos"))
    p.require(conductor["apiVersion"] == "catchplate.nativePilotOperatorRequest/v2"
        and type(conductor["sequence"]) is int and conductor["sequence"] == ticket["conductorSequence"]
        and conductor["phase"] == ticket["phase"] and type(conductor["payload"]) is dict
        and p.sha(conductor_raw) == p.digest(ticket["conductorRequestSha256"])
        and conductor["deadlineBoottimeNs"] == ticket["deadlineBoottimeNs"]
        and conductor["expiresAtUnixNanos"] == ticket["expiresAtUnixNanos"])
    evidence = _document(evidence_raw, MAX_EVIDENCE, EVIDENCE_FIELDS)
    originals = p.fields(evidence["originals"], EVIDENCE_ORIGINALS)
    p.require(all(type(raw) is str and raw.isascii() and raw for raw in originals.values()))
    role, endpoint = phase.legacy.CURRENT_HEAD_JOB_INFO[name]
    p.require(evidence["apiVersion"] == heads.OBSERVED_API and evidence["jobName"] == name
        and evidence["serviceRole"] == role and (endpoint is None or evidence["endpointRole"] == endpoint)
        and originals["bridgePreparation"] == conductor["payload"]["bridgePreparationOriginal"])
    bridge = intake.bridge.shape(originals["bridgePreparation"].encode("ascii"))
    p.require(bridge["apiVersion"] == intake.bridge.ADOPTED_API)
    requests, _ = intake.bridge._parts(bridge)
    matching = [(target, row) for actual, target, row in intake.bridge.requests_profile.iter_requests(requests)
        if actual == role and (endpoint is None or target == endpoint)]
    p.require(len(matching) == 1)
    target, row = matching[0]
    trust = head.request(originals["request"].encode("ascii"))
    p.require(evidence["endpointRole"] == target == trust["endpointRole"]
        and originals["request"] == row["requestOriginal"]
        and p.sha(originals["runtime"].encode("ascii")) == row["runtimeConfigurationSha256"]
        and p.sha(originals["selectedInitialHistory"].encode("ascii")) == row["initialHistorySha256"]
        and evidence["checkpointSha256"] == row["checkpointSha256"]
            == trust["operation"]["body"]["accepted_floor"]["checkpointSha256"]
        and evidence["requestSha256"] == row["requestSha256"] == head.request_sha256(originals["request"].encode("ascii"))
        and evidence["requestNonceSha256"] == trust["requestNonceSha256"]
        and type(evidence["deadlineBoottimeNanos"]) is int
        and evidence["deadlineBoottimeNanos"] == trust["deadline"]["absoluteBoottimeNanos"])
    _pin(evidence["rootAuthority"]); head.history_authority._key(evidence["checkpointAuthority"])
    return ticket, evidence, trust, conductor_raw, min(deadline, evidence["deadlineBoottimeNanos"]), expiry


def bounds(request_raw, evidence_raw, *, index, first_conductor_raw):
    """Narrow waiting limits from actual literals; no current-state permission."""
    *_, conductor, deadline, expiry = _parts(request_raw, evidence_raw, index=index,
        first_conductor_raw=first_conductor_raw)
    return dict(deadline=deadline, epochLimit=expiry, conductorOriginal=conductor)


def receipt(raw):
    value = _document(raw, MAX_RECEIPT, RECEIPT_FIELDS)
    p.require(value["apiVersion"] == RECEIPT_API and value["job"] in JOB_NAMES)
    for name in ("requestSha256", "evidenceSha256", "stateSha256", "inputSha256", "approvalSha256", "requestNonceSha256"):
        p.digest(value[name])
    p.integer(value["stateGeneration"]); p.integer(value["issuedAtBoottimeNanos"], maximum=p.MAX_U64)
    p.require(value["issuedAtBoottimeNanos"] < p.ns(value["deadlineBoottimeNs"]))
    p.integer(p.ns(value["expiresAtUnixNanos"]))
    return copy.deepcopy(value)


def compose(request_raw, evidence_raw, state_raw, policy_context, *, index, first_conductor_raw,
            boot, now_boottime_ns, now_unix_ns):
    """Pure derivation under delegated exact state; caller must own the lock."""
    p.fields(policy_context, ("value", "deadline", "epochLimit"))
    selected_policy = policy_context["value"]
    checked_policy = prepare(p.canonical(selected_policy), inventory_sha256=selected_policy["supervisorInventorySha256"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(checked_policy == policy_context)
    current = state(state_raw); _live(current, boot, now_boottime_ns, now_unix_ns)
    p.require(p.sha(state_raw) == selected_policy["initialStateSha256"]
        and current["generation"] == selected_policy["initialStateGeneration"]
        and all(row["status"] == "active" for row in current["targets"].values()))
    ticket, evidence, trust, conductor_raw, deadline, expiry = _parts(request_raw, evidence_raw,
        index=index, first_conductor_raw=first_conductor_raw)
    # Approval2 and the signed head keep the original request limits. A hidden
    # shorter worker cap cannot authorize a longer-lived downstream original.
    p.require(p.ns(ticket["deadlineBoottimeNs"]) <= min(policy_context["deadline"], p.ns(current["deadlineBoottimeNs"]))
        and expiry <= min(policy_context["epochLimit"], current["expiresAtUnixNanos"])
        and now_boottime_ns < deadline and now_unix_ns < expiry)
    originals = evidence["originals"]
    currentness = dict(profile=head.CURRENTNESS_PROFILE,
        initialHistorySha256=p.sha(originals["selectedInitialHistory"].encode("ascii")),
        checkpointSha256=evidence["checkpointSha256"], requestSha256=evidence["requestSha256"],
        requestNonceSha256=evidence["requestNonceSha256"], issuedAtBoottimeNanos=now_boottime_ns)
    value = dict(apiVersion=head.ADOPTED_API, serviceRole=evidence["serviceRole"], endpointRole=evidence["endpointRole"],
        rootAuthority=copy.deepcopy(evidence["rootAuthority"]), currentness=currentness)
    for field, source in (("driverConfigurationOriginal", "driverConfiguration"), ("driverWindowOriginal", "driverWindow"),
            ("launchOriginal", "launch"), ("configurationOriginal", "configuration"), ("runtimeOriginal", "runtime"),
            ("preparationOriginal", "preparation"), ("resourcesOriginal", "resources"),
            ("initialHistoryOriginal", "primaryInitialHistory"), ("requestOriginal", "request")):
        value[field] = originals[source]
    input_raw = p.canonical(value)
    prepared = head.prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns, adopted=True)
    p.require(prepared["authority"] == evidence["checkpointAuthority"])
    wrapper = p.document(originals["selectedInitialHistory"].encode("ascii"), head.g.MAX_BYTES)
    initial, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
    target = current["targets"][JOB_NAMES[index]]
    p.require(target["status"] == "active" and target["serviceRole"] == value["serviceRole"]
        and target["endpointRole"] == value["endpointRole"] and target["rootAuthority"] == value["rootAuthority"]
        and target["checkpointAuthority"] == {name: prepared["authority"][name] for name in ("keyId", "keySpkiSha256")}
        and target["initialHistorySha256"] == currentness["initialHistorySha256"]
        and target["checkpointSha256"] == checkpoint["checkpointSha256"] == prepared["statement"]["checkpointSha256"])
    for name in ("endpointProcessIdentitySha256", "deploymentGenerationSha256", "endpointGeneration",
            "serviceGeneration", "operationGeneration", "durableEpoch"):
        p.require(target[name] == initial[name])
    for name in ("checkpointSequence", "endpointGeneration", "revocationGenerationHighWater", "revocationRootSha256"):
        p.require(target[name] == prepared["statement"][name])
    p.require(current["invocationId"] == prepared["window"]["invocationId"]
        and all(current[field] == p.sha(originals[source].encode("ascii")) for field, source in
            (("driverConfigurationSha256", "driverConfiguration"), ("driverWindowSha256", "driverWindow"), ("launchSha256", "launch"))))
    approval_raw = p.canonical({field: phase.APPROVAL_API if field == "apiVersion" else p.sha(input_raw)
        if field == "inputSha256" else ticket[field] for field in phase.APPROVAL_FIELDS})
    intake.approvals._prepare_adopted(request_raw, approval_raw, input_raw, p.sha(approval_raw), p.sha(input_raw),
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    deadline = min(deadline, prepared["deadline"])
    consumed = p.canonical(dict(apiVersion=RECEIPT_API, job=JOB_NAMES[index], requestSha256=p.sha(request_raw),
        evidenceSha256=p.sha(evidence_raw), stateSha256=p.sha(state_raw), stateGeneration=current["generation"],
        inputSha256=p.sha(input_raw), approvalSha256=p.sha(approval_raw), requestNonceSha256=trust["requestNonceSha256"],
        issuedAtBoottimeNanos=now_boottime_ns, deadlineBoottimeNs=str(deadline), expiresAtUnixNanos=str(expiry)))
    receipt(consumed)
    return dict(inputOriginal=input_raw, approvalOriginal=approval_raw, receiptOriginal=consumed,
        conductorOriginal=conductor_raw, deadline=deadline, epochLimit=expiry)
