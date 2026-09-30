"""Verify the actual separately assigned native publication receipt original."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_policy_canary as p
from serverware import authority_policy_native_activation as profile
from serverware import authority_policy_canary_native_opening as custody


def verify(original, *, prepared, request_sha256, assignment, policy):
    envelope = profile.canonical_original(original, 32768)
    p.require(type(envelope) is dict and set(envelope) == {"payload", "signature"})
    value = envelope["payload"]
    p.require(type(value) is dict and set(value) == profile.PUBLICATION_FIELDS
        and value["apiVersion"] == profile.PUBLICATION and value["purpose"] == profile.PUBLICATION_PURPOSE)
    for name in ("activationId", "replayId", "assignmentPayloadSha256", "generationId", "generationPublicationEnvelopeSha256",
            "publicationBefore", "trustCheckpoint", "expiresAtUnixNanos"):
        p.require(value[name] == prepared[name])
    p.require(value["requestSha256"] == p.digest(request_sha256) and value["preparedSha256"] == p.sha256(p.canonical(prepared))
        and value["publicationAfter"] == {**prepared["publicationAfter"], "revision": prepared["publicationBefore"]["revision"] + 1})
    p.digest(value["durableStateSha256"])
    interval = value["observedAtUnixNanos"]
    p.require(type(interval) is dict and set(interval) == {"earliest", "latest"}
        and prepared["issuedAtUnixNanos"] <= p.epoch(interval["earliest"]) <= p.epoch(interval["latest"]) < prepared["expiresAtUnixNanos"])
    key, _ = custody._keys(assignment, "custody-activation-publication")
    p.require(value["signingKeyId"] == key["keyId"] and value["signingKeySpkiSha256"] == key["keySpkiSha256"])
    selected = [item for item in profile.validate_policy(policy)["publicationKeys"] if item["keyId"] == key["keyId"]]
    p.require(len(selected) == 1 and policy["issuedAtEpochNs"] <= prepared["issuedAtUnixNanos"]
        and prepared["expiresAtUnixNanos"] <= policy["expiresAtEpochNs"])
    raw = p.decoded(selected[0]["publicKeyBase64Url"], 32, length=32)
    public = Ed25519PublicKey.from_public_bytes(raw)
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(p.sha256(spki) == key["keySpkiSha256"] and custody.framed("serverware.policyAuthorityPublicKeyMaterial/v1",
        key["keyAlgorithm"].encode("ascii"), spki) == key["keyMaterialSha256"])
    preimage = b"serverware.signedEnvelope/v1\0" + profile.PUBLICATION_DOMAIN.encode("ascii") + b"\0serverware.canonicalJson/ascii-integer-v1\0" + p.canonical(value)
    public.verify(p.decoded(envelope["signature"], 64, length=64), preimage)
    return value
