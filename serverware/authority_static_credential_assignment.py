"""Purpose-fixed postboot selection outside both immutable configuration hashes.

An independently signed assignment selects actual public runtime identities;
it is not a Nitro verdict, a generated identity, SQL permission or a renewable
lease. The custody verifier must still authenticate the current native proof.
No private key, issuer, storage lookup or runtime action belongs here.
"""
import base64
import json
import re
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness_policy as native
from serverware import authority_request_commitment as commitment
from serverware import authority_static_credential_create as profile

SCHEMA = "serverware.staticCredentialAssignment/v1"
SIGNED_SCHEMA = "serverware.signedStaticCredentialAssignment/v1"
MAX_ORIGINAL_BYTES = 64 * 1024
MAX_INTERVAL_NS = 86_400_000_000_000
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {
    "instanceId", "secretKekId", "intakeOrigin", "portalOrigin"}
DYNAMIC_FIELDS = frozenset({"holderId", "bootId", "keyId", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256", "expectedModuleId"})
TARGET_FIELDS = ASSIGNMENT_FIELDS - DYNAMIC_FIELDS
AUTHORIZER_FIELDS = frozenset({"publicKeyPem", "publicKeyPemSha256", "publicKeySpkiSha256"})
PAYLOAD_FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest", "deploymentId",
    "assignment", "issuedAtEpochNs", "expiresAtEpochNs"})
canonical, require, digest = profile.canonical, profile.require, profile.digest


def _text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def origin(value):
    _text(value, 2048)
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and parsed.username is None
        and parsed.password is None and parsed.path == "" and parsed.query == ""
        and parsed.fragment == "" and parsed.netloc == parsed.netloc.lower()
        and parsed.port is None and not parsed.netloc.endswith(":443"))
    return value


def target(value):
    """Validate fixed preboot restrictions without inventing dynamic identities."""
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
    nitro.require_sha384(value["expectedEif"], "static assignment EIF")
    require(value["expectedEif"] == pcrs["PCR0"])
    require(type(value["maxAgeSeconds"]) is int and 1 <= value["maxAgeSeconds"] <= 300
        and type(value["futureSkewSeconds"]) is int and 0 <= value["futureSkewSeconds"] <= 30)
    require(_text(value["instanceId"], 4096).startswith("spiffe://"))
    profile._kek_id(value["secretKekId"])
    origin(value["intakeOrigin"]); origin(value["portalOrigin"])
    require(value["intakeOrigin"] != value["portalOrigin"])
    return value


def excluded_keys(configuration_payload, root_key):
    excluded = set()
    if root_key is not None:
        require(isinstance(root_key, Ed25519PublicKey))
        excluded.add(profile.sha256(root_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in configuration_payload["roles"].values():
        excluded.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    return excluded


def authorizer(value, *, configuration_payload, root_key, response_key_id):
    require(type(value) is dict and set(value) == AUTHORIZER_FIELDS
        and type(value["publicKeyPem"]) is str and 0 < len(value["publicKeyPem"]) <= 4096)
    raw = value["publicKeyPem"].encode("ascii")
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey)
        and key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest(value["publicKeyPemSha256"]); digest(value["publicKeySpkiSha256"])
    require(profile.sha256(raw) == value["publicKeyPemSha256"]
        and profile.sha256(spki) == value["publicKeySpkiSha256"]
        and value["publicKeySpkiSha256"] not in excluded_keys(configuration_payload, root_key) | {response_key_id},
        "Static assignment authorizer must be independently selected and purpose-separated")
    return key


def _signature(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{86}", value) is not None)
    raw = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    require(len(raw) == 64 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def original(value):
    """Canonical closed original only; this function does not verify a signature."""
    require(type(value) is str and 0 < len(value) <= MAX_ORIGINAL_BYTES and value.isascii())
    def pairs(items):
        result = {}
        for name, item in items:
            require(name not in result)
            result[name] = item
        return result
    envelope = json.loads(value, object_pairs_hook=pairs,
        parse_constant=lambda _: require(False))
    pending, count = [(envelope, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(depth <= 8 and count <= 4096 and type(item) in {dict, str, int})
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
    require(canonical(envelope).decode("ascii") == value and set(envelope) == {"schema", "payload", "signature"}
        and envelope["schema"] == SIGNED_SCHEMA)
    payload = envelope["payload"]
    require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS and payload["schema"] == SCHEMA)
    digest(payload["controlPlaneConfigurationDigest"])
    require(type(payload["deploymentId"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", payload["deploymentId"]) is not None)
    item = payload["assignment"]
    require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
    native._assignment({name: item[name] for name in native.ASSIGNMENT_FIELDS})
    target({name: item[name] for name in TARGET_FIELDS})
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1 and expires - issued <= MAX_INTERVAL_NS)
    _signature(envelope["signature"])
    return envelope


def verify_original(value, *, configuration_payload, root_key, now_epoch_ns):
    """Verify the independent selection and return parsed payload, not native authority.

    The caller must have authenticated the complete enclosing configuration and
    retain its own original clock/deadline. This never advances a checkpoint or
    claims that the selected boot/key is still live; fresh native proof follows.
    """
    from serverware import authority_static_credential_custody as custody
    from serverware.authority_policy_canary_policy import full_configuration_digest

    require(isinstance(root_key, Ed25519PublicKey))
    selected = custody.validate_policy(configuration_payload.get(custody.FIELD),
        payload=configuration_payload, root_key=root_key)
    require(selected is not None)
    envelope = original(value)
    payload, item = envelope["payload"], envelope["payload"]["assignment"]
    require(type(now_epoch_ns) is int and payload["issuedAtEpochNs"] <= now_epoch_ns < payload["expiresAtEpochNs"]
        and payload["controlPlaneConfigurationDigest"] == full_configuration_digest(configuration_payload)
        and payload["deploymentId"] == selected["deploymentId"]
        and canonical({name: item[name] for name in TARGET_FIELDS}) == canonical(selected["target"]),
        "Static assignment differs from the admitted full configuration, fixed target or original interval")
    key = authorizer(selected["assignmentAuthorizer"], configuration_payload=configuration_payload,
        root_key=root_key, response_key_id=selected["target"]["controlPlaneResponseSigningKeyId"])
    require(item["keyId"] not in excluded_keys(configuration_payload, root_key)
        | {item["controlPlaneResponseSigningKeyId"], selected["assignmentAuthorizer"]["publicKeySpkiSha256"]},
        "Static native key cannot supply its own assignment or another authority purpose")
    key.verify(_signature(envelope["signature"]),
        commitment.framed_digest(SIGNED_SCHEMA, canonical(payload)).encode("ascii"))
    return payload
