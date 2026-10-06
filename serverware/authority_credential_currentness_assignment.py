"""Independent postboot holder selection, never a native liveness verdict."""
import json
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_credential_currentness as profile
from serverware import authority_request_commitment as commitment

SCHEMA = "serverware.credentialCurrentnessAssignment/v1"
SIGNED_SCHEMA = "serverware.signedCredentialCurrentnessAssignment/v1"
MAX_ORIGINAL_BYTES = 16 * 1024
MAX_INTERVAL_NS = 86_400_000_000_000
DYNAMIC_FIELDS = frozenset({"holderId", "bootId", "keyId", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256", "expectedModuleId"})
AUTHORIZER_FIELDS = frozenset({"publicKeyPem", "publicKeyPemSha256", "publicKeySpkiSha256"})
PAYLOAD_FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest", "deploymentId",
    "targetId", "assignment", "issuedAtEpochNs", "expiresAtEpochNs"})


def target_id(value):
    profile.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)
    return value


def target(value):
    from serverware import authority_credential_currentness_policy as native
    fields = native.ASSIGNMENT_FIELDS - DYNAMIC_FIELDS
    profile.require(type(value) is dict and set(value) == fields | {"targetId"})
    target_id(value["targetId"])
    for name in ("controlPlaneResponseSigningKeyId", "releaseRecordSha256", "policyHash", "expectedBinaryDigest"):
        profile.digest(value[name])
    pcrs = value["expectedPcrs"]
    profile.require(type(pcrs) is dict and 3 <= len(pcrs) <= 32 and {"PCR0", "PCR1", "PCR2"} <= set(pcrs))
    for name, pin in pcrs.items():
        profile.require(type(name) is str and re.fullmatch(r"PCR(?:[0-9]|[12][0-9]|3[01])", name) is not None)
        native.nitro.require_sha384(pin, name)
        if name in {"PCR0", "PCR1", "PCR2"}:
            profile.require(pin != "sha384:" + "0" * 96)
    native.nitro.require_sha384(value["expectedEif"], "currentness assignment EIF")
    profile.require(value["expectedEif"] == pcrs["PCR0"]
        and type(value["maxAgeSeconds"]) is int and 1 <= value["maxAgeSeconds"] <= 300
        and type(value["futureSkewSeconds"]) is int and 0 <= value["futureSkewSeconds"] <= 30)
    return value


def excluded_keys(payload, root_key):
    result = set()
    if root_key is not None:
        profile.require(isinstance(root_key, Ed25519PublicKey))
        result.add(profile.sha256(root_key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in payload["roles"].values():
        result.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    return result


def authorizer(value, *, payload, root_key, targets):
    profile.require(type(value) is dict and set(value) == AUTHORIZER_FIELDS
        and type(value["publicKeyPem"]) is str and 0 < len(value["publicKeyPem"]) <= 4096)
    raw = value["publicKeyPem"].encode("ascii")
    key = serialization.load_pem_public_key(raw)
    profile.require(isinstance(key, Ed25519PublicKey)
        and key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.digest(value["publicKeyPemSha256"]); profile.digest(value["publicKeySpkiSha256"])
    profile.require(profile.sha256(raw) == value["publicKeyPemSha256"]
        and profile.sha256(spki) == value["publicKeySpkiSha256"]
        and value["publicKeySpkiSha256"] not in excluded_keys(payload, root_key)
            | {item["controlPlaneResponseSigningKeyId"] for item in targets},
        "Currentness assignment authorizer is not independently purpose-separated")
    return key


def original(value):
    """Bounded canonical original only; no cryptographic admission here."""
    from serverware import authority_credential_currentness_policy as native
    profile.require(type(value) is str and value.isascii() and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    def pairs(items):
        result = {}
        for name, item in items:
            profile.require(name not in result)
            result[name] = item
        return result
    envelope = json.loads(value, object_pairs_hook=pairs, parse_constant=lambda _: profile.require(False))
    pending, count = [(envelope, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        profile.require(depth <= 8 and count <= 4096 and type(item) in {dict, str, int})
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
    profile.require(profile.canonical(envelope).decode("ascii") == value
        and set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED_SCHEMA)
    payload = envelope["payload"]
    profile.require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS and payload["schema"] == SCHEMA)
    profile.digest(payload["controlPlaneConfigurationDigest"])
    target_id(payload["deploymentId"]); target_id(payload["targetId"])
    native._assignment(payload["assignment"])
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    profile.require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1 and expires - issued <= MAX_INTERVAL_NS)
    profile.encoded(envelope["signature"], 64)
    return envelope


def verify_original(value, *, configuration_payload, root_key, now_epoch_ns):
    from serverware import authority_credential_currentness_policy as native
    from serverware.authority_policy_canary_policy import full_configuration_digest
    profile.require(isinstance(root_key, Ed25519PublicKey))
    policy = native.validate_policy(configuration_payload.get(native.FIELD), payload=configuration_payload, root_key=root_key)
    profile.require(policy is not None and policy["schema"] in native.POSTBOOT_SCHEMAS)
    envelope = original(value); payload = envelope["payload"]; item = payload["assignment"]
    targets = [entry for entry in policy["targets"] if entry["targetId"] == payload["targetId"]]
    profile.require(len(targets) == 1 and type(now_epoch_ns) is int
        and payload["issuedAtEpochNs"] <= now_epoch_ns < payload["expiresAtEpochNs"]
        and payload["controlPlaneConfigurationDigest"] == full_configuration_digest(configuration_payload)
        and payload["deploymentId"] == policy["deploymentId"]
        and profile.canonical({"targetId": payload["targetId"], **{
            name: item[name] for name in native.ASSIGNMENT_FIELDS - DYNAMIC_FIELDS}}) == profile.canonical(targets[0]),
        "Currentness assignment differs from its full configuration, fixed target or original interval")
    key = authorizer(policy["assignmentAuthorizer"], payload=configuration_payload,
        root_key=root_key, targets=policy["targets"])
    profile.require(item["keyId"] not in excluded_keys(configuration_payload, root_key)
        | {entry["controlPlaneResponseSigningKeyId"] for entry in policy["targets"]}
        | {policy["assignmentAuthorizer"]["publicKeySpkiSha256"]},
        "Native holder cannot supply its own assignment or another authority purpose")
    key.verify(profile.encoded(envelope["signature"], 64),
        commitment.framed_digest(SIGNED_SCHEMA, profile.canonical(payload)).encode("ascii"))
    return payload
