"""Closed framing around the native adoption validator, never its semantics.

These pure checks cannot authorize a signature. Only the retained process
owner may admit a result after the pinned native validator completes, stdout
reaches EOF, and the same actual child is successfully consumed with waitid.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_publication_cold_binding as cold

p = g.p
CONTROL_API = "catchplate.nativePublicationAdoptionAuthorityControl/v1"
MAX_INPUT, MAX_RESULT, MAX_AUTHORIZATION = 32 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024
INPUT_FIELDS = ("apiVersion", "payloadOriginal", "currentTrustOriginal", "currentTrustSha256",
    "currentAssignmentOriginal", "currentClosureSetOriginal", "currentConfigurationBindingSha256",
    "currentProofScopeOriginal", "targetHistories")
PAYLOAD_FIELDS = ("apiVersion", "purpose", "adoptionIdSha256", "coldConfigurationOriginal", "coldBundleOriginal",
    "coldNativeGrantOriginal", "coldRetrievalGrantOriginal", "priorSupervisor", "assignmentPayloadSha256",
    "assignmentRevision", "productionConfigurationBindingSha256", "proofScopeOriginal", "retrievalNamespaceSha256",
    "native", "retrieval", "targetHistories", "authority", "trustCheckpointId", "revocationGeneration",
    "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
RESULT_FIELDS = ("apiVersion", "inputSha256", "payloadOriginal", "payloadSha256", "signingKeyId",
    "signingKeySpkiSha256", "publicKeyBase64url", "deadlineBoottimeNanos", "expiresAtUnixNanos")
HISTORY_FIELDS = ("serviceRole", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
CONFIGURATION_FIELDS = ("apiVersion", "scope", "durableGrantOriginal", "currentGrantOriginal", "histories",
    "serviceSessions", "nativeEndpoints", "resultPeer")
PROFILES = {"catchplate.nativePublicationAdoptionValidationInput/v" + str(version): (
    "catchplate.nativePublicationAdoptionValidation/v" + str(version),
    "catchplate.nativePublicationAdoptionAuthorization/v" + str(version),
    "catchplate.nativePublicationAdoptionAuthorization.signature/v" + str(version),
    "catchplate.nativePublicationGenesisCoordinatorRuntime/v" + str(version)) for version in (1, 2)}


def control(raw, expected_input_sha256):
    value = p.fields(p.document(raw, 4096), ("apiVersion", "validatorExecutableSha256", "inputSha256"))
    p.require(value["apiVersion"] == CONTROL_API and value["inputSha256"] == p.digest(expected_input_sha256))
    p.digest(value["validatorExecutableSha256"])
    return value


def original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    return value.encode("ascii")


def authority(value):
    p.fields(value, ("keyId", "keySpkiSha256", "publicKeyBase64url"))
    raw = p.decoded(value["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32) and value["keyId"] == value["keySpkiSha256"]
        == p.sha(bytes.fromhex("302a300506032b6570032100") + raw))
    return Ed25519PublicKey.from_public_bytes(raw)


def prepare_input(raw, *, expected_input_sha256, boot, now_boottime_ns, now_unix_ns):
    """Structural association/clock bounds only; native validation is mandatory."""
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT
        and p.sha(raw) == p.digest(expected_input_sha256))
    # Outer numbers live only inside literal originals; target history rows
    # contain strings. The payload's separate codec preserves native u64 data.
    value = p.fields(p.document(raw, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] in PROFILES)
    result_api, payload_api, domain, configuration_api = PROFILES[value["apiVersion"]]
    payload_raw = original(value["payloadOriginal"], MAX_AUTHORIZATION)
    payload = p.fields(g.document(payload_raw, MAX_AUTHORIZATION), PAYLOAD_FIELDS)
    p.require(payload["apiVersion"] == payload_api and payload["purpose"] == "cold-publication-to-operational"
        and len(payload_raw) + len(b'{"payload":,"signature":""}') + 86 <= MAX_AUTHORIZATION)
    authority(payload["authority"])
    for name in ("adoptionIdSha256", "assignmentPayloadSha256", "productionConfigurationBindingSha256",
            "retrievalNamespaceSha256", "trustCheckpointId", "revocationRootSha256"):
        p.digest(payload[name])
    for name in ("assignmentRevision", "revocationGeneration"):
        p.integer(payload[name], maximum=p.MAX_U64)
    for name in ("issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
        p.integer(payload[name], maximum=p.MAX_U64)
    for name in ("issuedAtUnixNanos", "expiresAtUnixNanos"):
        p.integer(payload[name])
    configuration = p.fields(g.document(original(payload["coldConfigurationOriginal"], MAX_AUTHORIZATION),
        MAX_AUTHORIZATION), CONFIGURATION_FIELDS)
    p.require(configuration["apiVersion"] == configuration_api)
    scope = p.fields(configuration["scope"], cold.GENESIS_FIELDS)
    p.require(scope["apiVersion"] == cold.GENESIS_API
        and (scope["bootIdBase64url"], scope["timeNamespaceDevice"], scope["timeNamespaceInode"]) == boot)
    p.decoded(scope["bootIdBase64url"], size=16)
    for name in ("timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
        p.integer(scope[name], maximum=p.MAX_U64)
    p.require(scope["issuedAtBoottimeNanos"] <= payload["issuedAtBoottimeNanos"] <= now_boottime_ns
        < payload["expiresAtBoottimeNanos"] <= scope["expiresAtBoottimeNanos"]
        and payload["issuedAtUnixNanos"] <= now_unix_ns < payload["expiresAtUnixNanos"])
    for name, maximum in (("currentTrustOriginal", 1024 * 1024), ("currentAssignmentOriginal", 1024 * 1024),
            ("currentClosureSetOriginal", MAX_INPUT), ("currentProofScopeOriginal", 65536)):
        original(value[name], maximum)
    p.require(p.sha(value["currentTrustOriginal"].encode("ascii")) == p.digest(value["currentTrustSha256"])
        and value["currentConfigurationBindingSha256"] == payload["productionConfigurationBindingSha256"]
        and value["currentProofScopeOriginal"] == payload["proofScopeOriginal"])
    p.require(type(value["targetHistories"]) is list and len(value["targetHistories"]) == 2)
    roles = set()
    for row in value["targetHistories"]:
        p.fields(row, HISTORY_FIELDS); p.require(row["serviceRole"] not in roles); roles.add(row["serviceRole"])
        for name in ("runtimeOriginal", "historyOriginal"): original(row[name], 1024 * 1024)
        for name in ("rootKeyId", "rootKeySpkiSha256"): p.digest(row[name])
    p.require(roles == {"durable-recovery-store", "current-signature-authority"})
    return {"inputSha256": expected_input_sha256, "payload": payload, "payloadOriginal": payload_raw,
        "resultApi": result_api, "domain": domain, "boot": boot,
        "issued": payload["issuedAtBoottimeNanos"], "deadline": payload["expiresAtBoottimeNanos"],
        "epochIssued": payload["issuedAtUnixNanos"], "epochLimit": payload["expiresAtUnixNanos"]}


def result(raw, context):
    """Compare a packet to retained originals; this does not mint validation."""
    value = p.fields(g.document(raw, MAX_RESULT), RESULT_FIELDS)
    payload, key = context["payload"], context["payload"]["authority"]
    p.require(value == {"apiVersion": context["resultApi"], "inputSha256": context["inputSha256"],
        "payloadOriginal": context["payloadOriginal"].decode("ascii"), "payloadSha256": p.sha(context["payloadOriginal"]),
        "signingKeyId": key["keyId"], "signingKeySpkiSha256": key["keySpkiSha256"],
        "publicKeyBase64url": key["publicKeyBase64url"], "deadlineBoottimeNanos": payload["expiresAtBoottimeNanos"],
        "expiresAtUnixNanos": payload["expiresAtUnixNanos"]})
    return value


def message(context):
    return (b"catchplate.signedEnvelope/v1\0" + context["domain"].encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + context["payloadOriginal"])


def successful_reap(result, pid):
    """Fact comparison used only after actual consuming waitid by the owner."""
    p.require(result is not None and result.si_pid == pid and result.si_code == os.CLD_EXITED and result.si_status == 0)
