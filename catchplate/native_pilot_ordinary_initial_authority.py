"""Separate one-key steps of the explicit ordinary initial-history ceremony.

The complete input must be independently approved. Initial checkpoint one is
bound to actual supplied preparation/empty-resource originals and the explicit
initial-state commitments, not to a fabricated prior checkpoint or history.
Each anchor signer receives and verifies that real checkpoint, then signs the
same existing retained-anchor preimage with exactly one supplied key. Keyless
assembly verifies all three signatures before emitting the opt-in wrapper.

The wrapper is admitted only by its explicit initial-history receiver, which
checks the actual executed process and still-empty retained directories. These
data producers do not observe a process, install files, approve inputs, claim
running services, or make the initial checkpoint independently admissible.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_key_authority as history_authority
from catchplate import native_pilot_ordinary_key_profile as key_profile
from catchplate import native_pilot_service_authority as service
from catchplate import native_pilot_window_authority as window_authority
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_nitro_originals as originals

p = generation.p
MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = generation.MAX_BYTES
MAX_CHECKPOINT = 65536
MAX_SIGNATURE = 4096
OPERATIONS = ("checkpoint", "root-anchor", "checkpoint-anchor", "service-anchor", "assemble")
INPUT_API = "catchplate.nativePilotOrdinaryInitialAuthorityInput/v1"
ADOPTED_INPUT_API = "catchplate.nativePilotOrdinaryInitialAuthorityInput/v2"
SIGNATURE_API = "catchplate.custodyOrdinaryInitialAnchorSignature/v1"
WRAPPER_API = "catchplate.custodyOrdinaryInitialHistory/v1"
COMMON_FIELDS = ("apiVersion", "operation", "driverConfigurationOriginal", "driverWindowOriginal",
    "launchOriginal", "configurationOriginal", "preparationOriginal", "resourcesOriginal",
    "initialStateOriginal", "authorities", "payloadOriginal")
KEY_NAMES = ("root", "checkpoint", "service")
SIGNATURE_FIELDS = ("apiVersion", "signer", "anchorPayloadSha256", "keyId", "keySpkiSha256", "signatureBase64")
ANCHOR_SIGNATURE_FIELDS = ("rootSignatureBase64", "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64")


def _original(value, maximum):
    return history_authority._original(value, maximum)


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _initial_payload(state, payload, authorities, *, adopted=False):
    """Reject a wrong boundary before exercising a signing capability."""
    key_profile.validate_payload_shape(payload)
    commitment = initial.commitments(state, adopted=adopted)
    service_key = authorities["service"]
    p.require(payload["checkpointSequence"] == payload["rollbackFloorCheckpointSequence"] == 1
        and payload["predecessorCheckpointSha256"] == commitment["predecessorCheckpointSha256"]
        and payload["exactEndpointGeneration"] == payload["rollbackFloorEndpointGeneration"] == state["endpointGeneration"]
        and payload["rollbackFloorConsumerSequence"] == 1
        and payload["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["authorizedSigningKeyId"] == service_key["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == service_key["keySpkiSha256"]
        and payload["validFromBoottime"]["absoluteBoottimeNanos"] >= p.ns(state["issuedAtBoottimeNs"])
        and payload["validUntilBoottime"]["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))


def _context(operation, input_original, *, adopted=False, clocks=None):
    p.require(operation in OPERATIONS)
    extra = () if operation == "checkpoint" else ("initialCheckpointOriginal",)
    if operation == "assemble":
        extra += ("anchorSignatures",)
    value = p.fields(p.document(input_original, MAX_INPUT), COMMON_FIELDS + extra)
    p.require(type(adopted) is bool and value["apiVersion"] == (ADOPTED_INPUT_API if adopted else INPUT_API)
        and value["operation"] == operation)
    configuration_raw, _ = _original(value["driverConfigurationOriginal"], 65536)
    configuration = window_authority.validate_configuration(configuration_raw)
    _, signed_window = _original(value["driverWindowOriginal"], 32768)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(configuration["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    boot, now = (originals._boot(), originals._clock()) if clocks is None else clocks
    window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=now)
    launch_raw, _ = _original(value["launchOriginal"], 65536)
    launch, startup, lifetime = service._launch(launch_raw, boot, now, adopted=adopted)
    _, state = _original(value["initialStateOriginal"], 65536)
    initial.validate_state(state, adopted=adopted)
    p.require(state["serviceRole"] in generation.ROLES
        and startup == p.ns(window["startupDeadlineBoottimeNs"])
        and lifetime == p.ns(window["lifetimeDeadlineBoottimeNs"])
        and launch["invocationId"] == window["invocationId"])
    cold_raw, _ = _original(value["configurationOriginal"], 65536)
    cold = generation.configuration(cold_raw,
        launch["services"][state["serviceRole"]]["deliveryConfiguration"]["sha256"], state["serviceRole"])
    preparation_raw, _ = _original(value["preparationOriginal"], key_profile.MAX_PREPARATION)
    resources_raw, _ = _original(value["resourcesOriginal"], 65536)
    initial.resources(resources_raw, adopted=adopted)
    authorities = p.fields(value["authorities"], KEY_NAMES)
    public_keys = {name: history_authority._key(authorities[name]) for name in KEY_NAMES}
    p.require(len({authorities[name]["keyId"] for name in KEY_NAMES}) == 3
        and len({authorities[name]["keySpkiSha256"] for name in KEY_NAMES}) == 3
        and len({history_authority._raw_key(public_keys[name]) for name in KEY_NAMES}) == 3)
    excluded = (cold["authority"], configuration["bootstrapAuthority"], configuration["phaseTwoAuthority"],
        configuration["lifecycle"]["constructedAdmissionAuthority"])
    for name in KEY_NAMES:
        for key in excluded:
            p.require(history_authority._raw_key(public_keys[name]) != p.decoded(key["publicKeyBase64url"], size=32)
                and authorities[name]["keyId"] != key["keyId"])
    _, payload = _original(value["payloadOriginal"], MAX_CHECKPOINT)
    key_profile.validate_payload_shape(payload)
    identity = initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
        launch_raw=launch_raw, configuration=cold, window=window, endpoint_role=payload["endpointRole"], now=now, adopted=adopted)
    key_profile.validate_payload(payload, identity=identity, window=window, now=now)
    _initial_payload(state, payload, authorities, adopted=adopted)
    deadline = min(startup, p.ns(state["startupDeadlineBoottimeNs"]),
        payload["validUntilBoottime"]["absoluteBoottimeNanos"])

    def check():
        observed_boot = originals._boot() if clocks is None else boot
        after = originals._clock() if clocks is None else now
        p.require(observed_boot == boot and now <= after < deadline)
        window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=after)
        current_identity = initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
            launch_raw=launch_raw, configuration=cold, window=window, endpoint_role=payload["endpointRole"], now=after, adopted=adopted)
        _same(current_identity, identity)
        key_profile.validate_payload(payload, identity=identity, window=window, now=after)
        _initial_payload(state, payload, authorities, adopted=adopted)
        if clocks is None:
            p.require(originals._boot() == boot and after <= originals._clock() < deadline)

    check()
    return value, state, identity, payload, authorities, public_keys, deadline, check


def _checkpoint(value, state, payload, authorities, *, adopted=False):
    _, checkpoint = _original(value["initialCheckpointOriginal"], MAX_CHECKPOINT)
    initial.validate_checkpoint(state, checkpoint, checkpoint_authority=authorities["checkpoint"],
        service_key=authorities["service"], adopted=adopted)
    _same(checkpoint["payload"], payload)
    return checkpoint


def _anchor(state, identity, authorities, checkpoint, *, adopted=False):
    """Derive existing epoch/unsigned-anchor fields from the explicit boundary."""
    commitment = initial.commitments(state, adopted=adopted)
    epoch = {"apiVersion": history_authority.HISTORY_API,
        "authorityRole": {"authorityKind": "isolated-service", "role": state["serviceRole"]},
        "authorityEpochSequence": 1, "predecessorEpochSha256": None, "checkpointSequence": 1,
        "checkpointSha256": checkpoint["checkpointSha256"], "checkpointAuthority": authorities["checkpoint"],
        "serviceSigningKey": authorities["service"], "endpointProcessIdentity": identity,
        "endpointProcessIdentitySha256": state["endpointProcessIdentitySha256"],
        "endpointGeneration": state["endpointGeneration"], "serviceGeneration": state["serviceGeneration"],
        "operationGeneration": state["operationGeneration"], "durableEpoch": state["durableEpoch"],
        "durableEpochHeadSha256": commitment["durableEpochHeadSha256"],
        "deploymentGenerationSha256": state["deploymentGenerationSha256"]}
    epoch_values = [
        [epoch[name] for name in ("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256")],
        [epoch[name] for name in ("checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey")],
        [epoch[name] for name in ("endpointProcessIdentity", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration")],
        [epoch[name] for name in ("operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")],
    ]
    epoch["epochSha256"] = p.framed(history_authority.EPOCH_DOMAIN, (generation.canonical(epoch_values),))
    anchor = {"apiVersion": history_authority.HISTORY_API, "retainedEpoch": epoch,
        "prunedThroughEpochSequence": 0, "prunedHistoryRootSha256": commitment["prunedHistoryRootSha256"],
        "prunedTerminalEpochSha256": None, "rootAuthorityKeyId": authorities["root"]["keyId"],
        "rootAuthorityKeySpkiSha256": authorities["root"]["keySpkiSha256"]}
    raw = generation.canonical([anchor[name] for name in history_authority.ANCHOR_FIELDS[:7]])
    return anchor, raw, history_authority._signature_preimage(history_authority.ANCHOR_SIGNATURE_DOMAIN, raw)


def prepare_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns, adopted=False):
    """Validate the entire selected ceremony step before a private-key read."""
    value, state, identity, payload, authorities, public_keys, deadline, check = _context(
        operation, input_original, adopted=adopted, clocks=(boot, now_boottime_ns))
    if operation != "checkpoint":
        checkpoint = _checkpoint(value, state, payload, authorities, adopted=adopted)
        _, anchor_raw, message = _anchor(state, identity, authorities, checkpoint, adopted=adopted)
        if operation == "assemble":
            for name, text in p.fields(value["anchorSignatures"], KEY_NAMES).items():
                _, record = _original(text, MAX_SIGNATURE)
                p.fields(record, SIGNATURE_FIELDS)
                p.require(record["apiVersion"] == SIGNATURE_API and record["signer"] == name
                    and record["anchorPayloadSha256"] == p.sha(anchor_raw)
                    and record["keyId"] == authorities[name]["keyId"]
                    and record["keySpkiSha256"] == authorities[name]["keySpkiSha256"])
                public_keys[name].verify(p.decoded(record["signatureBase64"], size=64), message)
    check()
    return {"deadline": deadline, "epochLimit": None, "state": state, "payload": payload}


def sign(operation: str, *, input_original: bytes, signing_key, adopted=False) -> tuple[bytes, int]:
    """One actual checkpoint or anchor signature, under exactly one key."""
    p.require(operation in OPERATIONS[:-1] and isinstance(signing_key, Ed25519PrivateKey))
    value, state, identity, payload, authorities, public_keys, deadline, check = _context(operation, input_original, adopted=adopted)
    name = "checkpoint" if operation == "checkpoint" else operation.removesuffix("-anchor")
    selected, public = authorities[name], public_keys[name]
    p.require(history_authority._raw_key(signing_key.public_key()) == history_authority._raw_key(public))
    if operation == "checkpoint":
        # Fixed-length accounting only; no placeholder checkpoint/signature.
        fields = {"payload": payload, "authorityKeyId": selected["keyId"],
            "authorityKeySpkiSha256": selected["keySpkiSha256"], "authoritySignatureBase64": "", "checkpointSha256": ""}
        p.require(len(generation.canonical(fields)) + 86 + 71 <= MAX_CHECKPOINT)
        message = key_profile.signature_preimage(payload, selected["keyId"], selected["keySpkiSha256"])
        check()
        signature = signing_key.sign(message)
        public.verify(signature, message)
        result = key_profile.envelope(payload, selected["keyId"], selected["keySpkiSha256"], p.encoded(signature))
        initial.validate_checkpoint(state, result, checkpoint_authority=selected, service_key=authorities["service"], adopted=adopted)
        bound = MAX_CHECKPOINT
    else:
        checkpoint = _checkpoint(value, state, payload, authorities, adopted=adopted)
        _, anchor_raw, message = _anchor(state, identity, authorities, checkpoint, adopted=adopted)
        check()
        signature = signing_key.sign(message)
        public.verify(signature, message)
        result = {"apiVersion": SIGNATURE_API, "signer": name, "anchorPayloadSha256": p.sha(anchor_raw),
            "keyId": selected["keyId"], "keySpkiSha256": selected["keySpkiSha256"], "signatureBase64": p.encoded(signature)}
        bound = MAX_SIGNATURE
    raw = generation.canonical(result)
    p.require(len(raw) <= bound)
    check()
    return raw, deadline


def assemble(*, input_original: bytes, adopted=False) -> tuple[bytes, int]:
    """Keyless assembly; verify all supplied signatures before wrapper output."""
    value, state, identity, payload, authorities, public_keys, deadline, check = _context("assemble", input_original, adopted=adopted)
    checkpoint = _checkpoint(value, state, payload, authorities, adopted=adopted)
    anchor, anchor_raw, message = _anchor(state, identity, authorities, checkpoint, adopted=adopted)
    signatures = p.fields(value["anchorSignatures"], KEY_NAMES)
    for name, field in zip(KEY_NAMES, ANCHOR_SIGNATURE_FIELDS, strict=True):
        _, record = _original(signatures[name], MAX_SIGNATURE)
        p.fields(record, SIGNATURE_FIELDS)
        p.require(record["apiVersion"] == SIGNATURE_API and record["signer"] == name
            and record["anchorPayloadSha256"] == p.sha(anchor_raw)
            and record["keyId"] == authorities[name]["keyId"]
            and record["keySpkiSha256"] == authorities[name]["keySpkiSha256"])
        public_keys[name].verify(p.decoded(record["signatureBase64"], size=64), message)
        anchor[field] = record["signatureBase64"]
    anchor["retainedAnchorSha256"] = p.framed(history_authority.ANCHOR_DIGEST_DOMAIN,
        (anchor_raw, *(anchor[name].encode("ascii") for name in ANCHOR_SIGNATURE_FIELDS)))
    retention = {"oldestRetainedEpochSequence": 1, "currentEpochSequence": 1,
        "oldestRetainedCheckpointSequence": 1, "currentCheckpointSequence": 1,
        "oldestReplayableRecordSequence": 0, "currentRecordSequence": 0,
        "oldestRetainedCompactionSequence": 0, "currentCompactionSequence": 0,
        "maximumRetainedEpochs": 1, "maximumCompactionAnchors": 1, "maximumReplayTombstones": 1}
    for first, last, source in (
            ("oldestRetainedEndpointGeneration", "currentEndpointGeneration", "endpointGeneration"),
            ("oldestRetainedServiceGeneration", "currentServiceGeneration", "serviceGeneration"),
            ("oldestRetainedOperationGeneration", "currentOperationGeneration", "operationGeneration"),
            ("oldestRetainedDurableEpoch", "currentDurableEpoch", "durableEpoch")):
        retention[first] = retention[last] = state[source]
    history = {"apiVersion": history_authority.HISTORY_API,
        "authorityRole": {"authorityKind": "isolated-service", "role": state["serviceRole"]},
        "rootAuthority": authorities["root"], "retention": retention, "firstRetainedEpoch": anchor,
        "adjacentTransitions": [], "compactionAnchors": [], "replayTombstones": []}
    history["manifestSha256"] = p.framed(history_authority.HISTORY_DOMAIN,
        (generation.canonical([history[name] for name in generation.HISTORY[:-1]]),))
    check()
    wrapper_api = initial.ADOPTED_WRAPPER_API if adopted and state["serviceRole"] in initial.ADOPTED_ROLES else WRAPPER_API
    raw = generation.canonical({"apiVersion": wrapper_api, "initialState": state,
        "initialCheckpoint": checkpoint, "history": history})
    p.require(len(raw) <= MAX_OUTPUT)
    admitted = initial.manifest(raw, role=state["serviceRole"],
        root_pin={name: authorities["root"][name] for name in ("keyId", "keySpkiSha256")}, adopted=adopted)
    _same(admitted, history)
    check()
    return raw, deadline
