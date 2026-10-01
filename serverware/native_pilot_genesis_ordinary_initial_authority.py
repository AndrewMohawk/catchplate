"""Cold two-service initial checkpoint and independent three-key anchors.

Every complete input requires independent approval. Source originals describe
actual retained parked services/resources and the actual parked coordinator;
pure validation cannot establish that provenance. No directory, key, prior
receipt, currentness decision, clock or process identity is manufactured.
Native admission still measures the executed service before any genesis write.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_initial_profile as profile
from serverware import native_pilot_genesis_parent_authority as parent
from serverware import native_pilot_ordinary_initial_authority as ordinary
from serverware import native_pilot_ordinary_key_authority as history_authority
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_shadow_nitro_originals as originals

p = g.p
INPUT_API = "serverware.nativePilotGenesisOrdinaryInitialAuthorityInput/v1"
OPERATIONS = ordinary.OPERATIONS
KEY_NAMES = ordinary.KEY_NAMES
SIGNATURE_API = ordinary.SIGNATURE_API
SIGNATURE_FIELDS = ordinary.SIGNATURE_FIELDS
ANCHOR_SIGNATURE_FIELDS = ordinary.ANCHOR_SIGNATURE_FIELDS
MAX_INPUT = g.MAX_BYTES
MAX_OUTPUT = profile.MAX_HISTORY
MAX_CHECKPOINT = 65536
MAX_SIGNATURE = 4096
LAUNCH_API = "serverware.custodyGenesisTwoServiceLaunch/v1"
PREPARATION_API = "serverware.custodyGenesisTwoServicePreparation/v1"
RESOURCES_API = "serverware.custodyGenesisTwoServiceResources/v1"
COMMON_FIELDS = ("apiVersion", "operation", "serviceRole", "parentConfigurationOriginal",
    "parentDeliveryConfigurationOriginal", "parentPrecreationOriginal", "parentObservationOriginal", "launchOriginal",
    "configurationOriginal", "preparationOriginal", "resourcesOriginal", "initialStateOriginal", "authorities", "payloadOriginal")
SOURCE_FIELDS = {"parentConfigurationOriginal": ("parent_configuration_raw", parent.MAX_WIRE),
    "parentDeliveryConfigurationOriginal": ("parent_delivery_configuration_raw", parent.MAX_COLD),
    "parentPrecreationOriginal": ("parent_precreation_raw", parent.MAX_WIRE),
    "parentObservationOriginal": ("parent_observation_raw", parent.MAX_WIRE),
    "launchOriginal": ("launch_raw", MAX_CHECKPOINT), "configurationOriginal": ("configuration_raw", MAX_CHECKPOINT),
    "preparationOriginal": ("preparation_raw", MAX_CHECKPOINT), "resourcesOriginal": ("resources_raw", MAX_CHECKPOINT)}


def _original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    return raw, g.document(raw, maximum)


def source_context(*, parent_configuration_raw, parent_delivery_configuration_raw, parent_precreation_raw,
                   parent_observation_raw, launch_raw, preparation_raw, resources_raw, configuration_raw,
                   role, endpoint_role, boot, now_boottime_ns):
    """Authenticate original bounds and public joins, not observation provenance.

    launch_raw is the retained two-service control policy, not a per-service
    C9 launch wrapper. The common issue is the original approved boundary, not
    a new timestamp claiming when resources were observed.
    """
    p.require(role in profile.ROLES and endpoint_role in key.ENDPOINT_ROLES
        and (role != profile.ROLES[0] or endpoint_role == "settlement-store"))
    context = parent.validate_precreation(parent_precreation_raw, configuration_raw=parent_configuration_raw,
        delivery_configuration_raw=parent_delivery_configuration_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    coordinator = parent.validate_observation(parent_observation_raw, configuration_raw=parent_configuration_raw,
        precreation_raw=parent_precreation_raw, context=context)
    window = context["window"]
    launch = p.fields(g.document(launch_raw, MAX_CHECKPOINT), key._LAUNCH_FIELDS)
    p.require(launch["apiVersion"] == LAUNCH_API)
    for name in parent.WINDOW_FIELDS[2:]:
        if name != "issuedAtBoottimeNs":
            profile.same(launch[name], window[name])
    specs = p.fields(launch["services"], profile.ROLES)
    preparation = p.fields(g.document(preparation_raw, MAX_CHECKPOINT), key.PREPARATION_FIELDS)
    p.require(preparation["apiVersion"] == PREPARATION_API and preparation["phase"] == "parked-pre-exec"
        and preparation["configurationSha256"] == p.sha(launch_raw))
    for name in parent.WINDOW_FIELDS[2:]:
        profile.same(preparation[name], window[name])
    services = p.fields(preparation["services"], profile.ROLES)
    pids, pidfds, executables, uids, gids = {coordinator["processId"]}, {coordinator["pidfdInode"]}, set(), set(), set()
    for name in profile.ROLES:
        spec = p.fields(specs[name], ("executableSha256", "deliveryConfiguration"))
        g.c9._pin(spec["deliveryConfiguration"]); p.digest(spec["executableSha256"])
        item = p.fields(services[name], key.SERVICE_FIELDS)
        p.require(item["configurationSha256"] == spec["deliveryConfiguration"]["sha256"])
        uid, gid = (key._uint(item[field], 32) for field in ("plannedUid", "plannedGid"))
        p.require(uid < (1 << 32) - 1 and gid < (1 << 32) - 1
            and uid not in {64988, 64989, 64990, 65534, context["cold"]["uid"]}
            and gid not in {64988, 64989, 64990, 65534, context["cold"]["gid"]})
        pid = p.integer(item["processId"], minimum=2, maximum=(1 << 31) - 1)
        key._uint(item["startTimeTicks"])
        pidfd = p.fields(item["pidfdStat"], key.PIDFD_FIELDS)
        p.require(pidfd["sha256"] == key.pidfd_stat_sha256({field: pidfd[field] for field in key.PIDFD_FIELDS[:-1]}))
        key._uint(pidfd["inode"])
        executable = p.fields(item["targetExecutable"], key.EXECUTABLE_FIELDS)
        key._uint(executable["device"]); key._uint(executable["inode"])
        p.integer(executable["length"], maximum=256 * 1024 * 1024)
        for field in ("sha256", "imaSha256", "fsVeritySha256"):
            p.digest(executable[field])
        p.require(executable["sha256"] == spec["executableSha256"])
        file_identity = executable["device"], executable["inode"]
        p.require(pid not in pids and pidfd["inode"] not in pidfds and file_identity not in executables
            and uid not in uids and gid not in gids)
        pids.add(pid); pidfds.add(pidfd["inode"]); executables.add(file_identity); uids.add(uid); gids.add(gid)
    cold = g.configuration(configuration_raw, specs[role]["deliveryConfiguration"]["sha256"], role)
    measured = services[role]
    p.require((cold["uid"], cold["gid"]) == (measured["plannedUid"], measured["plannedGid"]))
    resources = p.fields(g.document(resources_raw, MAX_CHECKPOINT),
        ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services"))
    p.require(resources["apiVersion"] == RESOURCES_API and resources["preparationSha256"] == p.sha(preparation_raw)
        and resources["issuedAtBoottimeNs"] == window["issuedAtBoottimeNs"])
    rows = p.fields(resources["services"], profile.ROLES)
    directory_ids = set()
    for name in profile.ROLES:
        row = p.fields(rows[name], ("directories",))
        ids = profile.directories(row["directories"], name)
        p.require(not directory_ids & ids)
        directory_ids.update(ids)
        for directory in row["directories"].values():
            p.require((directory["identity"]["uid"], directory["identity"]["gid"])
                == (services[name]["plannedUid"], services[name]["plannedGid"]))
    target, pidfd = measured["targetExecutable"], measured["pidfdStat"]
    identity = dict(zip(key.IDENTITY_FIELDS[:-1], (endpoint_role, cold["uid"], cold["gid"], measured["processId"],
        measured["startTimeTicks"], pidfd["inode"], pidfd["sha256"], target["device"], target["inode"], target["length"],
        target["sha256"], target["imaSha256"], target["fsVeritySha256"]), strict=True))
    identity["identitySha256"] = p.framed(key.PROCESS_DOMAIN,
        (g.canonical([identity[field] for field in key.IDENTITY_FIELDS[:-1]]),))
    key.validate_identity(identity)
    return {"configuration": context["configuration"], "cold": cold, "window": window, "preparation": preparation,
        "resources": resources, "coordinator": coordinator, "coordinatorCold": context["cold"],
        "identity": identity, "deadline": context["deadline"]}


def input_document(raw):
    value = g.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == INPUT_API and value.get("operation") in OPERATIONS)
    extra = () if value["operation"] == "checkpoint" else ("initialCheckpointOriginal",)
    if value["operation"] == "assemble":
        extra += ("anchorSignatures",)
    p.fields(value, COMMON_FIELDS + extra)
    p.require(value["serviceRole"] in profile.ROLES)
    return value


def prepare_input(operation, input_original, *, boot, now_boottime_ns):
    p.require(operation in OPERATIONS)
    value = input_document(input_original)
    p.require(value["operation"] == operation)
    source = {argument: _original(value[name], maximum)[0] for name, (argument, maximum) in SOURCE_FIELDS.items()}
    _, state = _original(value["initialStateOriginal"], profile.MAX_STATE)
    state = profile.validate_state(state)
    _, payload = _original(value["payloadOriginal"], MAX_CHECKPOINT)
    key.validate_payload_shape(payload)
    context = source_context(**source, role=value["serviceRole"], endpoint_role=payload["endpointRole"],
        boot=boot, now_boottime_ns=now_boottime_ns)
    identity, window = context["identity"], context["window"]
    p.require(state["serviceRole"] == value["serviceRole"]
        and state["preparationSha256"] == p.sha(source["preparation_raw"])
        and state["resourcesSha256"] == p.sha(source["resources_raw"])
        and state["launchSha256"] == p.sha(source["launch_raw"])
        and state["endpointProcessIdentitySha256"] == identity["identitySha256"])
    profile.same(state["directories"], context["resources"]["services"][state["serviceRole"]]["directories"])
    for name in parent.WINDOW_FIELDS[2:]:
        profile.same(state[name], window[name])
    authorities = p.fields(value["authorities"], KEY_NAMES)
    public = {name: history_authority._key(authorities[name]) for name in KEY_NAMES}
    p.require(len({row["keyId"] for row in authorities.values()}) == 3
        and len({row["keySpkiSha256"] for row in authorities.values()}) == 3
        and len({history_authority._raw_key(item) for item in public.values()}) == 3)
    excluded = (context["cold"]["authority"], context["coordinatorCold"]["authority"],
        context["configuration"]["precreationAuthority"], context["configuration"]["releaseAuthority"])
    for name in KEY_NAMES:
        for row in excluded:
            p.require(history_authority._raw_key(public[name]) != p.decoded(row["publicKeyBase64url"], size=32)
                and authorities[name]["keyId"] != row["keyId"])
    _initial_payload(state, payload, authorities, identity, now=now_boottime_ns)
    deadline = min(context["deadline"], payload["validUntilBoottime"]["absoluteBoottimeNanos"])
    prepared = {"value": value, "state": state, "identity": identity, "payload": payload,
        "authorities": authorities, "deadline": deadline}
    if operation != "checkpoint":
        _, checkpoint = _original(value["initialCheckpointOriginal"], MAX_CHECKPOINT)
        profile.validate_checkpoint(state, checkpoint, checkpoint_authority=authorities["checkpoint"], service_key=authorities["service"])
        profile.same(checkpoint["payload"], payload)
        prepared["checkpoint"] = checkpoint
        _, anchor_raw, message = anchor(state, identity, authorities, checkpoint)
        prepared.update(anchorRaw=anchor_raw, message=message)
        if operation == "assemble":
            prepared["outputOriginal"] = _assemble(state, identity, authorities, checkpoint, value["anchorSignatures"])
    else:
        selected = authorities["checkpoint"]
        prepared["message"] = key.signature_preimage(payload, selected["keyId"], selected["keySpkiSha256"])
    return prepared


def state_original(*, role, endpoint_role, counters, **source_arguments):
    """Compose State/v2 from checked sources and explicit approved counters.

    This selects no counter, issue time, root or process. The complete resulting
    authority input still requires independent approval before any signature.
    """
    p.fields(counters, ("deploymentGenerationSha256", "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"))
    context = source_context(role=role, endpoint_role=endpoint_role, **source_arguments)
    state = {"apiVersion": profile.STATE_API, "serviceRole": role,
        "preparationSha256": p.sha(source_arguments["preparation_raw"]),
        "resourcesSha256": p.sha(source_arguments["resources_raw"]), "launchSha256": p.sha(source_arguments["launch_raw"]),
        "endpointProcessIdentitySha256": context["identity"]["identitySha256"],
        **{name: context["window"][name] for name in parent.WINDOW_FIELDS[2:]}, **counters,
        "directories": context["resources"]["services"][role]["directories"]}
    return g.canonical(profile.validate_state(state))


def checked_result(operation, input_original, result, *, boot, now_boottime_ns):
    prepared = prepare_input(operation, input_original, boot=boot, now_boottime_ns=now_boottime_ns)
    p.fields(result, ("original", "sha256"))
    bound = MAX_CHECKPOINT if operation == "checkpoint" else MAX_OUTPUT if operation == "assemble" else MAX_SIGNATURE
    raw, value = _original(result["original"], bound)
    p.require(result["sha256"] == p.sha(raw))
    if operation == "assemble":
        p.require(raw == prepared["outputOriginal"])
    elif operation == "checkpoint":
        profile.validate_checkpoint(prepared["state"], value,
            checkpoint_authority=prepared["authorities"]["checkpoint"], service_key=prepared["authorities"]["service"])
        profile.same(value["payload"], prepared["payload"])
    else:
        _signature(value, operation.removesuffix("-anchor"), prepared["authorities"], prepared["anchorRaw"], prepared["message"])
    return raw


def _live_owner():
    return os.getpid(), originals._start(), originals._boot()


def _live_check(owner, previous, deadline):
    p.require(_live_owner() == owner)
    now = originals._clock()
    p.require(previous <= now < deadline)
    return now


def sign(operation, *, input_original, signing_key):
    """Exercise exactly one supplied key after complete source admission."""
    p.require(operation in OPERATIONS[:-1] and isinstance(signing_key, Ed25519PrivateKey))
    owner, now = _live_owner(), originals._clock()
    prepared = prepare_input(operation, input_original, boot=owner[2], now_boottime_ns=now)
    name = "checkpoint" if operation == "checkpoint" else operation.removesuffix("-anchor")
    selected = prepared["authorities"][name]
    public = history_authority._key(selected)
    p.require(history_authority._raw_key(signing_key.public_key()) == history_authority._raw_key(public))
    before = _live_check(owner, now, prepared["deadline"])
    signature = signing_key.sign(prepared["message"])
    public.verify(signature, prepared["message"])
    if operation == "checkpoint":
        result = key.envelope(prepared["payload"], selected["keyId"], selected["keySpkiSha256"], p.encoded(signature))
    else:
        result = {"apiVersion": SIGNATURE_API, "signer": name, "anchorPayloadSha256": p.sha(prepared["anchorRaw"]),
            "keyId": selected["keyId"], "keySpkiSha256": selected["keySpkiSha256"], "signatureBase64": p.encoded(signature)}
    raw = g.canonical(result)
    after = _live_check(owner, before, prepared["deadline"])
    checked_result(operation, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after)
    _live_check(owner, after, prepared["deadline"])
    return raw, prepared["deadline"]


def assemble(*, input_original):
    """Keyless, real-clock-bracketed assembly of the three genuine signatures."""
    owner, now = _live_owner(), originals._clock()
    prepared = prepare_input("assemble", input_original, boot=owner[2], now_boottime_ns=now)
    raw = prepared["outputOriginal"]
    p.require(len(raw) <= MAX_OUTPUT)
    _live_check(owner, now, prepared["deadline"])
    return raw, prepared["deadline"]


def _initial_payload(state, payload, authorities, identity, *, now):
    key.validate_payload_shape(payload)
    roots = profile.commitments(state)
    p.require(payload["endpointRole"] == identity["endpointRole"]
        and payload["checkpointSequence"] == payload["rollbackFloorCheckpointSequence"] == 1
        and payload["predecessorCheckpointSha256"] == roots["predecessorCheckpointSha256"]
        and payload["exactEndpointGeneration"] == payload["rollbackFloorEndpointGeneration"] == state["endpointGeneration"]
        and payload["rollbackFloorConsumerSequence"] == 1
        and payload["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["authorizedSigningKeyId"] == authorities["service"]["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == authorities["service"]["keySpkiSha256"])
    low, high = payload["validFromBoottime"], payload["validUntilBoottime"]
    profile.same(low["domain"], key._boot(state)); profile.same(high["domain"], low["domain"])
    p.require(p.ns(state["issuedAtBoottimeNs"]) <= low["absoluteBoottimeNanos"] <= now
        < high["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))


def anchor(state, identity, authorities, checkpoint):
    """The unchanged native retained-epoch/anchor recipe over State/v2."""
    state = profile.validate_state(state)
    roots = profile.commitments(state)
    epoch = {"apiVersion": history_authority.HISTORY_API,
        "authorityRole": {"authorityKind": "isolated-service", "role": state["serviceRole"]},
        "authorityEpochSequence": 1, "predecessorEpochSha256": None, "checkpointSequence": 1,
        "checkpointSha256": checkpoint["checkpointSha256"], "checkpointAuthority": authorities["checkpoint"],
        "serviceSigningKey": authorities["service"], "endpointProcessIdentity": identity,
        "endpointProcessIdentitySha256": state["endpointProcessIdentitySha256"],
        "endpointGeneration": state["endpointGeneration"], "serviceGeneration": state["serviceGeneration"],
        "operationGeneration": state["operationGeneration"], "durableEpoch": state["durableEpoch"],
        "durableEpochHeadSha256": roots["durableEpochHeadSha256"], "deploymentGenerationSha256": state["deploymentGenerationSha256"]}
    groups = (("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256"),
        ("checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey"),
        ("endpointProcessIdentity", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration"),
        ("operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256"))
    epoch["epochSha256"] = p.framed(history_authority.EPOCH_DOMAIN,
        (g.canonical([[epoch[name] for name in group] for group in groups]),))
    value = {"apiVersion": history_authority.HISTORY_API, "retainedEpoch": epoch,
        "prunedThroughEpochSequence": 0, "prunedHistoryRootSha256": roots["prunedHistoryRootSha256"],
        "prunedTerminalEpochSha256": None, "rootAuthorityKeyId": authorities["root"]["keyId"],
        "rootAuthorityKeySpkiSha256": authorities["root"]["keySpkiSha256"]}
    raw = g.canonical([value[name] for name in history_authority.ANCHOR_FIELDS[:7]])
    return value, raw, history_authority._signature_preimage(history_authority.ANCHOR_SIGNATURE_DOMAIN, raw)


def _signature(record, name, authorities, anchor_raw, message):
    p.fields(record, SIGNATURE_FIELDS)
    selected = authorities[name]
    p.require(record["apiVersion"] == SIGNATURE_API and record["signer"] == name
        and record["anchorPayloadSha256"] == p.sha(anchor_raw)
        and record["keyId"] == selected["keyId"] and record["keySpkiSha256"] == selected["keySpkiSha256"])
    history_authority._key(selected).verify(p.decoded(record["signatureBase64"], size=64), message)


def _assemble(state, identity, authorities, checkpoint, signatures):
    value, raw, message = anchor(state, identity, authorities, checkpoint)
    p.fields(signatures, KEY_NAMES)
    for name, field in zip(KEY_NAMES, ANCHOR_SIGNATURE_FIELDS, strict=True):
        _, record = _original(signatures[name], MAX_SIGNATURE)
        _signature(record, name, authorities, raw, message)
        value[field] = record["signatureBase64"]
    value["retainedAnchorSha256"] = p.framed(history_authority.ANCHOR_DIGEST_DOMAIN,
        (raw, *(value[name].encode("ascii") for name in ANCHOR_SIGNATURE_FIELDS)))
    retention = {"oldestRetainedEpochSequence": 1, "currentEpochSequence": 1,
        "oldestRetainedCheckpointSequence": 1, "currentCheckpointSequence": 1,
        "oldestReplayableRecordSequence": 0, "currentRecordSequence": 0,
        "oldestRetainedCompactionSequence": 0, "currentCompactionSequence": 0,
        "maximumRetainedEpochs": 1, "maximumCompactionAnchors": 1, "maximumReplayTombstones": 1}
    for first, last, source in (("oldestRetainedEndpointGeneration", "currentEndpointGeneration", "endpointGeneration"),
            ("oldestRetainedServiceGeneration", "currentServiceGeneration", "serviceGeneration"),
            ("oldestRetainedOperationGeneration", "currentOperationGeneration", "operationGeneration"),
            ("oldestRetainedDurableEpoch", "currentDurableEpoch", "durableEpoch")):
        retention[first] = retention[last] = state[source]
    history = {"apiVersion": history_authority.HISTORY_API,
        "authorityRole": {"authorityKind": "isolated-service", "role": state["serviceRole"]},
        "rootAuthority": authorities["root"], "retention": retention, "firstRetainedEpoch": value,
        "adjacentTransitions": [], "compactionAnchors": [], "replayTombstones": []}
    history["manifestSha256"] = p.framed(history_authority.HISTORY_DOMAIN,
        (g.canonical([history[name] for name in g.HISTORY[:-1]]),))
    output = g.canonical({"apiVersion": profile.WRAPPER_API, "initialState": state,
        "initialCheckpoint": checkpoint, "history": history})
    profile.same(profile.manifest(output, role=state["serviceRole"], root_pin={name: authorities["root"][name]
        for name in ("keyId", "keySpkiSha256")}), history)
    return output
