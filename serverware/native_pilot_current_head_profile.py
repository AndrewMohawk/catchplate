"""Existing current-head wire and an explicit, separately approved decision.

Historical signatures do not prove currentness. ``currentness`` is a fresh
checkpoint-authority DECISION for one genuine retained trust request, supplied
under independent complete-input approval. These pure helpers verify its exact
joins, not approval, live-request provenance, empty resources or absence of a
newer checkpoint. No decision/request/cursor is automatically composed here.
The later service handshake has a different digest and includes this signature;
its final digest must never be substituted for the earlier trust-request hash.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_authority as history_authority
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_driver_bootstrap as driver

p = g.p
API = "serverware.nativePilotCurrentHeadAuthorityInput/v1"
PROTOCOL_API = "serverware.policyCustodyProtocol/v3"
CURRENTNESS_PROFILE = "initial-checkpoint-current-for-exact-request-v1"
DOMAIN = b"serverware.policyCustodyTrustedHostCurrentHeadAttestation/v3"
REQUEST_DOMAIN = b"serverware.policyCustodyEndpointRequest/v3"
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = MAX_REQUEST = 65536
INPUT_FIELDS = ("apiVersion", "serviceRole", "driverConfigurationOriginal", "driverWindowOriginal",
    "launchOriginal", "configurationOriginal", "preparationOriginal", "resourcesOriginal",
    "initialHistoryOriginal", "rootAuthority", "requestOriginal", "currentness")
CURRENTNESS_FIELDS = ("profile", "initialHistorySha256", "checkpointSha256", "requestSha256",
    "requestNonceSha256", "issuedAtBoottimeNanos")
REQUEST_FIELDS = ("apiVersion", "endpointRole", "requestNonceSha256", "requestEntropyBase64",
    "requestedAtBoottimeNanos", "deadline", "operation")
STATEMENT_FIELDS = ("apiVersion", "endpointRole", "requestNonceSha256", "requestSha256",
    "checkpointSequence", "checkpointSha256", "endpointGeneration", "revocationGenerationHighWater",
    "revocationRootSha256", "issuedAtBoottimeNanos", "deadline")
ENVELOPE_FIELDS = ("statement", "authorityKeyId", "authorityKeySpkiSha256",
    "authoritySignatureBase64", "attestationSha256")


def _original(value, maximum):
    return history_authority._original(value, maximum)


def request(raw: bytes) -> dict:
    """Only the existing current-endpoint-trust request; no live-owner claim."""
    value = p.fields(p.document(raw, MAX_REQUEST), REQUEST_FIELDS)
    p.require(value["apiVersion"] == PROTOCOL_API and value["endpointRole"] in key.ENDPOINT_ROLES)
    p.decoded(value["requestEntropyBase64"], size=32)
    p.digest(value["requestNonceSha256"])
    issued = key._uint(value["requestedAtBoottimeNanos"])
    deadline = key._deadline(value["deadline"])
    p.require(issued < deadline["absoluteBoottimeNanos"])
    operation = p.fields(value["operation"], ("operation", "body"))
    p.require(operation["operation"] == "current-endpoint-trust")
    # Serde's enum rename_all changes variant names, not their named fields.
    body = p.fields(operation["body"], ("accepted_floor",))
    floor = p.fields(body["accepted_floor"], ("checkpointSequence", "checkpointSha256", "consumeCursor"))
    key._uint(floor["checkpointSequence"]); p.digest(floor["checkpointSha256"])
    cursor = p.fields(floor["consumeCursor"],
        ("sequenceHighWater", "expectedNextSequence", "expectedPredecessorReceiptSha256"))
    high = key._uint(cursor["sequenceHighWater"], minimum=0)
    p.require(key._uint(cursor["expectedNextSequence"]) == high + 1)
    p.digest(cursor["expectedPredecessorReceiptSha256"])
    nonce_raw = p.canonical([value[name] for name in ("apiVersion", "endpointRole", "requestEntropyBase64",
        "requestedAtBoottimeNanos", "deadline", "operation")])
    p.require(value["requestNonceSha256"] == p.sha(nonce_raw))
    return copy.deepcopy(value)


def request_sha256(raw: bytes) -> str:
    request(raw)
    return p.framed(REQUEST_DOMAIN, (raw,))


def validate_statement(value: dict) -> dict:
    p.fields(value, STATEMENT_FIELDS)
    p.require(value["apiVersion"] == PROTOCOL_API and value["endpointRole"] in key.ENDPOINT_ROLES)
    for name in ("requestNonceSha256", "requestSha256", "checkpointSha256", "revocationRootSha256"):
        p.digest(value[name])
    for name in ("checkpointSequence", "endpointGeneration", "revocationGenerationHighWater", "issuedAtBoottimeNanos"):
        key._uint(value[name])
    deadline = key._deadline(value["deadline"])
    p.require(value["issuedAtBoottimeNanos"] < deadline["absoluteBoottimeNanos"])
    # Native shape fields are u64; native canonical_json_bytes separately
    # rejects values above i64::MAX when making the signed transcript.
    p.require(len(g.canonical(value)) <= MAX_OUTPUT)
    return copy.deepcopy(value)


def _signature_payload(statement, authority_key_id, authority_key_spki_sha256):
    return p.canonical([validate_statement(statement), p.digest(authority_key_id), p.digest(authority_key_spki_sha256)])


def signature_preimage(statement, authority_key_id, authority_key_spki_sha256) -> bytes:
    raw = _signature_payload(statement, authority_key_id, authority_key_spki_sha256)
    return (b"serverware-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN
        + len(raw).to_bytes(8, "big") + raw)


def envelope(statement, authority_key_id, authority_key_spki_sha256, signature_base64) -> dict:
    """Encode a supplied signature, never create one or assert verification."""
    raw = _signature_payload(statement, authority_key_id, authority_key_spki_sha256)
    p.decoded(signature_base64, size=64)
    return {"statement": copy.deepcopy(statement), "authorityKeyId": authority_key_id,
        "authorityKeySpkiSha256": authority_key_spki_sha256, "authoritySignatureBase64": signature_base64,
        "attestationSha256": p.framed(DOMAIN, (raw, signature_base64.encode("ascii")))}


def validate_envelope(value: dict) -> dict:
    p.fields(value, ENVELOPE_FIELDS)
    expected = envelope(value["statement"], value["authorityKeyId"], value["authorityKeySpkiSha256"],
        value["authoritySignatureBase64"])
    p.require(value == expected and len(p.canonical(value)) <= MAX_OUTPUT)
    return copy.deepcopy(value)


def binding(value: dict) -> dict:
    """Existing ServiceCurrentHeadBindingV3 shape/hash, not an authentication."""
    checked = validate_envelope(value)
    return {"signedCurrentHead": checked, "exactAttestationSha256": p.sha(p.canonical(checked))}


def prepare_input(input_original: bytes, *, boot: tuple, now_boottime_ns: int) -> dict:
    """Check independently approved exact originals; never decide currentness."""
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    role = value["serviceRole"]
    p.require(value["apiVersion"] == API and role in g.ROLES)
    now = key._uint(now_boottime_ns)
    configuration_raw, _ = _original(value["driverConfigurationOriginal"], 65536)
    configuration = window_authority.validate_configuration(configuration_raw)
    _, signed_window = _original(value["driverWindowOriginal"], 32768)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(configuration["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=now)
    launch_raw, _ = _original(value["launchOriginal"], 65536)
    launch, startup, lifetime = service._launch(launch_raw, boot, now)
    p.require(startup == p.ns(window["startupDeadlineBoottimeNs"])
        and lifetime == p.ns(window["lifetimeDeadlineBoottimeNs"])
        and launch["invocationId"] == window["invocationId"])
    cold_raw, _ = _original(value["configurationOriginal"], 65536)
    cold = g.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
    preparation_raw, _ = _original(value["preparationOriginal"], key.MAX_PREPARATION)
    resources_raw, _ = _original(value["resourcesOriginal"], initial.MAX_STATE)
    history_raw, wrapper = _original(value["initialHistoryOriginal"], g.MAX_BYTES)
    p.fields(wrapper, initial.WRAPPER_FIELDS)
    p.require(wrapper["apiVersion"] == initial.WRAPPER_API)
    root = p.fields(value["rootAuthority"], ("keyId", "keySpkiSha256"))
    history = initial.manifest(history_raw, role=role, root_pin=root)
    epoch = history["firstRetainedEpoch"]["retainedEpoch"]
    state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
    payload = checkpoint["payload"]
    identity = initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
        launch_raw=launch_raw, configuration=cold, window=window, endpoint_role=payload["endpointRole"], now=now)
    key.validate_payload(payload, identity=identity, window=window, now=now)
    excluded = (cold["authority"], configuration["bootstrapAuthority"], configuration["phaseTwoAuthority"],
        configuration["lifecycle"]["constructedAdmissionAuthority"])
    for selected in (history["rootAuthority"], epoch["checkpointAuthority"], epoch["serviceSigningKey"]):
        public = history_authority._key(selected)
        for other in excluded:
            p.require(selected["keyId"] != other["keyId"]
                and history_authority._raw_key(public) != p.decoded(other["publicKeyBase64url"], size=32))
    request_raw, _ = _original(value["requestOriginal"], MAX_REQUEST)
    pending = request(request_raw)
    floor = pending["operation"]["body"]["accepted_floor"]
    p.require(pending["endpointRole"] == payload["endpointRole"]
        and floor["checkpointSequence"] == payload["checkpointSequence"]
        and floor["checkpointSha256"] == checkpoint["checkpointSha256"])
    decision = p.fields(value["currentness"], CURRENTNESS_FIELDS)
    p.require(decision["profile"] == CURRENTNESS_PROFILE
        and p.digest(decision["initialHistorySha256"]) == p.sha(history_raw)
        and p.digest(decision["checkpointSha256"]) == checkpoint["checkpointSha256"]
        and p.digest(decision["requestSha256"]) == request_sha256(request_raw)
        and p.digest(decision["requestNonceSha256"]) == pending["requestNonceSha256"])
    issued = key._uint(decision["issuedAtBoottimeNanos"])
    deadline = pending["deadline"]["absoluteBoottimeNanos"]
    p.require(pending["deadline"]["domain"] == key._boot(window)
        and p.ns(state["issuedAtBoottimeNs"]) <= pending["requestedAtBoottimeNanos"] <= issued <= now < deadline
        and payload["validFromBoottime"]["absoluteBoottimeNanos"] <= issued
        and deadline <= min(startup, lifetime, payload["validUntilBoottime"]["absoluteBoottimeNanos"]))
    statement = {"apiVersion": PROTOCOL_API, "endpointRole": payload["endpointRole"],
        "requestNonceSha256": pending["requestNonceSha256"], "requestSha256": decision["requestSha256"],
        "checkpointSequence": payload["checkpointSequence"], "checkpointSha256": checkpoint["checkpointSha256"],
        "endpointGeneration": payload["exactEndpointGeneration"],
        "revocationGenerationHighWater": payload["revocationGenerationHighWater"],
        "revocationRootSha256": payload["revocationRootSha256"], "issuedAtBoottimeNanos": issued,
        "deadline": copy.deepcopy(pending["deadline"])}
    return {"statement": validate_statement(statement), "authority": copy.deepcopy(epoch["checkpointAuthority"]),
        "window": copy.deepcopy(window), "deadline": deadline}


def checked_result(input_original: bytes, result: dict, *, boot: tuple, now_boottime_ns: int) -> bytes:
    prepared = prepare_input(input_original, boot=boot, now_boottime_ns=now_boottime_ns)
    p.fields(result, ("original", "sha256"))
    raw, value = _original(result["original"], MAX_OUTPUT)
    checked = validate_envelope(value)
    selected = prepared["authority"]
    p.require(p.digest(result["sha256"]) == p.sha(raw) and checked["statement"] == prepared["statement"]
        and checked["authorityKeyId"] == selected["keyId"]
        and checked["authorityKeySpkiSha256"] == selected["keySpkiSha256"])
    history_authority._key(selected).verify(p.decoded(checked["authoritySignatureBase64"], size=64),
        signature_preimage(checked["statement"], selected["keyId"], selected["keySpkiSha256"]))
    return raw
