"""Native handshake framing from an authenticated, separately approved head.

The request owner supplies genuine originals. These pure functions neither
sample entropy/clocks nor transmit or create readiness. Deterministic IDs use
distinct domains over the original trust request and exact head/client pins;
the later request digest includes the signed head, not the other way round.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_current_head_profile as head

p = head.p
API = "catchplate.policyCustodyTrustedHostService/v4"
DOMAIN = b"catchplate.policyCustodyTrustedHostServiceHandshakeRequest/v3"
ID_DOMAIN = b"catchplate.nativePilotServiceHandshake.requestId/v1"
NONCE_DOMAIN = b"catchplate.nativePilotServiceHandshake.nonce/v1"
FIELDS = ("apiVersion", "serviceRole", "requestIdSha256", "handshakeNonceSha256",
    "clientProcessIdentitySha256", "clientConfigurationGenerationSha256", "deadline",
    "expectedCurrentHead", "requestRightsCount", "replyRightsCount", "requestSha256")
RIGHTS = {"durable-recovery-store": (0, 0), "cleanup-authorization-consumer": (0, 0),
    "recovery-target-provider": (6, 2), "current-signature-authority": (0, 0),
    "bounded-cleanup-helper": (2, 0)}
MAX_BYTES = 65536


def _digest(value):
    p.digest(value)
    p.require(value != "sha256:" + "0" * 64)
    return value


def shape(raw, *, service_role, endpoint_role, client_process_identity_sha256,
          client_configuration_generation_sha256):
    """Exact native request shape/framing and selected pins, not a signature check."""
    value = p.fields(p.document(raw, MAX_BYTES), FIELDS)
    p.require(service_role in RIGHTS and value["apiVersion"] == API and value["serviceRole"] == service_role)
    for name in ("requestIdSha256", "handshakeNonceSha256", "clientProcessIdentitySha256",
            "clientConfigurationGenerationSha256", "requestSha256"):
        _digest(value[name])
    p.require(value["clientProcessIdentitySha256"] == _digest(client_process_identity_sha256)
        and value["clientConfigurationGenerationSha256"] == _digest(client_configuration_generation_sha256))
    head.key._deadline(value["deadline"])
    binding = p.fields(value["expectedCurrentHead"], ("signedCurrentHead", "exactAttestationSha256"))
    p.require(binding == head.binding(binding["signedCurrentHead"]))
    statement = binding["signedCurrentHead"]["statement"]
    p.require(statement["endpointRole"] == endpoint_role and statement["deadline"] == value["deadline"])
    counts = tuple(value[name] for name in ("requestRightsCount", "replyRightsCount"))
    p.require(all(type(count) is int for count in counts) and counts == RIGHTS[service_role])
    p.require(value["requestSha256"] == p.framed(DOMAIN, (p.canonical([value[name] for name in FIELDS[:-1]]),)))
    return copy.deepcopy(value)


def frame(*, service_role, trust_request_original, signed_current_head,
          client_process_identity_sha256, client_configuration_generation_sha256):
    """Public framing only; use build() for authenticated complete authority inputs."""
    p.require(service_role in RIGHTS)
    pending = head.request(trust_request_original)
    checked = head.validate_envelope(signed_current_head)
    statement = checked["statement"]
    p.require(statement["endpointRole"] == pending["endpointRole"]
        and statement["requestNonceSha256"] == pending["requestNonceSha256"]
        and statement["requestSha256"] == head.request_sha256(trust_request_original)
        and statement["checkpointSha256"] == pending["operation"]["body"]["accepted_floor"]["checkpointSha256"]
        and pending["requestedAtBoottimeNanos"] <= statement["issuedAtBoottimeNanos"]
        and statement["deadline"] == pending["deadline"])
    pins = p.canonical([service_role, pending["endpointRole"], _digest(client_process_identity_sha256),
        _digest(client_configuration_generation_sha256)])
    exact_head = p.canonical(checked)
    request_count, reply_count = RIGHTS[service_role]
    value = {"apiVersion": API, "serviceRole": service_role,
        "requestIdSha256": p.framed(ID_DOMAIN, (trust_request_original, exact_head, pins)),
        "handshakeNonceSha256": p.framed(NONCE_DOMAIN, (trust_request_original, exact_head, pins)),
        "clientProcessIdentitySha256": client_process_identity_sha256,
        "clientConfigurationGenerationSha256": client_configuration_generation_sha256,
        "deadline": copy.deepcopy(pending["deadline"]), "expectedCurrentHead": head.binding(checked),
        "requestRightsCount": request_count, "replyRightsCount": reply_count}
    value["requestSha256"] = p.framed(DOMAIN, (p.canonical([value[name] for name in FIELDS[:-1]]),))
    raw = p.canonical(value)
    shape(raw, service_role=service_role, endpoint_role=pending["endpointRole"],
        client_process_identity_sha256=client_process_identity_sha256,
        client_configuration_generation_sha256=client_configuration_generation_sha256)
    return raw


def build(input_original, result, *, boot, now_boottime_ns, client_process_identity_sha256,
          client_configuration_generation_sha256):
    """Verify the actual current-head result before framing its later handshake."""
    exact_head = head.checked_result(input_original, result, boot=boot, now_boottime_ns=now_boottime_ns)
    value = p.document(input_original, head.MAX_INPUT)
    pending = value["requestOriginal"].encode("ascii")
    return frame(service_role=value["serviceRole"], trust_request_original=pending,
        signed_current_head=p.document(exact_head, head.MAX_OUTPUT),
        client_process_identity_sha256=client_process_identity_sha256,
        client_configuration_generation_sha256=client_configuration_generation_sha256)
