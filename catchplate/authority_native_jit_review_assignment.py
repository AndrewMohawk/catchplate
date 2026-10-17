"""Independent postboot selection for native compound JIT review custody.

This purpose neither borrows static/currentness assignment authority nor
grants native liveness, review disclosure or SQL permission. The enclosing
configuration must already belong to the actual measured caller. Fresh native
proof is verified separately against this literal, independently signed choice.
"""
from __future__ import annotations

import base64
from functools import wraps
import json
import math
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from catchplate import authority_credential_currentness as codec
from catchplate import authority_credential_currentness_policy as native
from catchplate import authority_request_commitment as commitment

FIELD = "nativeJitReviewCustodyPolicy"
SCHEMA = "catchplate.nativeJitReviewAssignment/v1"
SIGNED_SCHEMA = "catchplate.signedNativeJitReviewAssignment/v1"
MAX_ORIGINAL_BYTES = 64 * 1024
MAX_INTERVAL_NS = 86_400_000_000_000
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {"instanceId", "secretKekId"}
DYNAMIC_FIELDS = frozenset({"holderId", "bootId", "keyId", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256", "expectedModuleId"})
TARGET_FIELDS = ASSIGNMENT_FIELDS - DYNAMIC_FIELDS
PAYLOAD_FIELDS = frozenset({"schema", "sourceContractDigest", "controlPlaneConfigurationDigest",
    "deploymentId", "assignment", "issuedAtEpochNs", "expiresAtEpochNs"})
AUTHORIZER_FIELDS = frozenset({"publicKeyPem", "publicKeyPemSha256", "publicKeySpkiSha256"})
canonical, sha256 = codec.canonical, codec.sha256


class AdmissionError(ValueError):
    def __init__(self):
        super().__init__("native JIT review custody is unavailable")


def require(value):
    if not value:
        raise AdmissionError()


def checked(function):
    @wraps(function)
    def bounded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise AdmissionError() from None
    return bounded


def integer(value, minimum=1, maximum=2**63 - 1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and value == value.strip() and not any(ord(char) < 33 or ord(char) == 127 for char in value))
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
        and value != "sha256:" + "0" * 64)
    return value


def deployment(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)
    return value


def kek(value):
    require(type(value) is str and re.fullmatch(r"attested-memory-kek:[0-9a-f]{24}", value) is not None)
    return value


def decoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) <= maximum and (exact is None or len(raw) == exact)
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def document(value, maximum):
    """Own one bounded duplicate-free canonical original; no authentication."""
    require(type(value) is str and 0 < len(value) <= maximum and value.isascii())
    def pairs(items):
        result = {}
        for name, item in items:
            require(name not in result)
            result[name] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    pending, count = [(result, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(depth <= 32 and count <= 131072)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            require(item is None or type(item) in {str, int, bool}
                or type(item) is float and math.isfinite(item))
    require(type(result) is dict and canonical(result).decode("ascii") == value)
    return result


def target(value):
    require(type(value) is dict and set(value) == TARGET_FIELDS)
    for name in ("controlPlaneResponseSigningKeyId", "releaseRecordSha256", "policyHash", "expectedBinaryDigest"):
        digest(value[name])
    pcrs = value["expectedPcrs"]
    require(type(pcrs) is dict and 3 <= len(pcrs) <= 32 and {"PCR0", "PCR1", "PCR2"} <= set(pcrs))
    for name, pin in pcrs.items():
        require(type(name) is str and re.fullmatch(r"PCR(?:[0-9]|[12][0-9]|3[01])", name) is not None)
        nitro.require_sha384(pin, name)
        if name in {"PCR0", "PCR1", "PCR2"}:
            require(pin != "sha384:" + "0" * 96)
    nitro.require_sha384(value["expectedEif"], "JIT assignment EIF")
    require(value["expectedEif"] == pcrs["PCR0"])
    integer(value["maxAgeSeconds"], maximum=300)
    integer(value["futureSkewSeconds"], minimum=0, maximum=30)
    require(text(value["instanceId"], 4096).startswith("spiffe://"))
    kek(value["secretKekId"])
    return value


def excluded_keys(payload, root_key):
    require(isinstance(root_key, Ed25519PublicKey) and type(payload) is dict
        and type(payload.get("roles")) is dict)
    excluded = {sha256(root_key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))}
    for role in payload["roles"].values():
        require(type(role) is dict)
        excluded.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    return excluded


def authorizer(value, *, payload, root_key, response_key_id):
    require(type(value) is dict and set(value) == AUTHORIZER_FIELDS
        and type(value["publicKeyPem"]) is str and 0 < len(value["publicKeyPem"]) <= 4096)
    raw = value["publicKeyPem"].encode("ascii")
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey)
        and key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(digest(value["publicKeyPemSha256"]) == sha256(raw)
        and digest(value["publicKeySpkiSha256"]) == sha256(spki)
        and value["publicKeySpkiSha256"] not in excluded_keys(payload, root_key) | {response_key_id})
    return key


@checked
def original(value):
    envelope = document(value, MAX_ORIGINAL_BYTES)
    require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED_SCHEMA)
    payload = envelope["payload"]
    require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS and payload["schema"] == SCHEMA)
    digest(payload["sourceContractDigest"]); digest(payload["controlPlaneConfigurationDigest"])
    deployment(payload["deploymentId"])
    item = payload["assignment"]
    require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
    native._assignment({name: item[name] for name in native.ASSIGNMENT_FIELDS})
    target({name: item[name] for name in TARGET_FIELDS})
    issued, expires = integer(payload["issuedAtEpochNs"]), integer(payload["expiresAtEpochNs"])
    require(issued < expires and expires - issued <= MAX_INTERVAL_NS)
    decoded(envelope["signature"], 64, 64)
    return envelope


@checked
def verify_original(value, *, configuration_payload, root_key, now_epoch_ns):
    """Verify selection, not native liveness or permission to persist/open."""
    from catchplate import authority_native_jit_review_custody as custody
    from catchplate.authority_policy_canary_policy import full_configuration_digest

    policy = custody.validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(policy is not None)
    envelope = original(value)
    payload, item = envelope["payload"], envelope["payload"]["assignment"]
    require(payload["issuedAtEpochNs"] <= integer(now_epoch_ns) < payload["expiresAtEpochNs"]
        and payload["sourceContractDigest"] == policy["sourceContractDigest"]
        and payload["controlPlaneConfigurationDigest"] == full_configuration_digest(configuration_payload)
        and payload["deploymentId"] == policy["deploymentId"]
        and canonical({name: item[name] for name in TARGET_FIELDS}) == canonical(policy["target"]))
    key = authorizer(policy["assignmentAuthorizer"], payload=configuration_payload, root_key=root_key,
        response_key_id=item["controlPlaneResponseSigningKeyId"])
    require(item["keyId"] not in excluded_keys(configuration_payload, root_key)
        | {item["controlPlaneResponseSigningKeyId"], policy["assignmentAuthorizer"]["publicKeySpkiSha256"]})
    key.verify(decoded(envelope["signature"], 64, 64),
        commitment.framed_digest(SIGNED_SCHEMA, canonical(payload)).encode("ascii"))
    return payload
