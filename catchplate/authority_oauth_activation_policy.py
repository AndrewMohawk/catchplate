"""OAuth enrollment verification under the actual signed measured configuration.

An HTTP caller supplies only the original enrollment, never its trust root.
Both verifier and planner invoke this over their own admitted configuration.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_oauth_activation as profile

FIELD = "oauthActivationPolicy"
SCHEMA = "catchplate.oauthActivationAuthorityPolicy/v1"
ENVELOPE_SCHEMA = "catchplate.signedOAuthApplicationEnrollment/v1"
ENROLLMENT_SCHEMA = "catchplate.oauthApplicationEnrollment/v1"
ASSOCIATION_SCHEMA = "catchplate.oauthApplicationAssociation/v1"
FIELDS = frozenset({"schema", "enrollmentRootPublicKeyBase64Url", "enrollmentRootSpkiSha256", "controlPlaneConfigurationDigest", "deploymentId"})
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "deploymentId", "applicationId", "providerId", "providerFamilyNamespace", "providerFamilyGeneration", "clientId", "redirectUri", "clientMaterialSha256", "providerConfigurationSha256", "issuedAtEpochNs", "expiresAtEpochNs"})


def _b64(value, size):
    profile.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    profile.require(len(raw) == size and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def _identifier(value):
    profile.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)


def _spki(key):
    return "sha256:" + hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "OAuth activation operations require their dedicated enrollment root")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    _identifier(value["deploymentId"])
    profile.digest(value["controlPlaneConfigurationDigest"])
    profile.digest(value["enrollmentRootSpkiSha256"])
    key = Ed25519PublicKey.from_public_bytes(_b64(value["enrollmentRootPublicKeyBase64Url"], 32))
    pin = _spki(key)
    profile.require(pin == value["enrollmentRootSpkiSha256"])
    if root_key is not None:
        profile.require(pin != _spki(root_key), "OAuth enrollment root must differ from authority configuration root")
    for role in payload["roles"].values():
        for name, item in role.items():
            if name.endswith("SpkiDigest") or name.endswith("SpkiSha256"):
                profile.require(pin != item, "OAuth enrollment root must differ from role keys")
    # Other purpose-specific public keys never inherit enrollment authority.
    for name in ("webauthnEnrollmentAuthorization", "webauthnEvidenceAdmission", "webauthnTransitions"):
        other = payload.get(name)
        if type(other) is dict:
            profile.require(pin not in other.values(), "OAuth enrollment root must be purpose-separated")
    return key


def enrollment_document(raw):
    profile.require(type(raw) is bytes and 2 <= len(raw) <= profile.MAX_ENROLLMENT_BYTES)
    def pairs(items):
        result = {}
        for key, value in items:
            profile.require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite enrollment")))
    profile.require(type(value) is dict and set(value) == {"schema", "payload", "signatureBase64Url"}
        and value["schema"] == ENVELOPE_SCHEMA and profile.canonical(value) == raw)
    payload = value["payload"]
    profile.require(type(payload) is dict and set(payload) == ENROLLMENT_FIELDS and payload["schema"] == ENROLLMENT_SCHEMA)
    for field in ("deploymentId", "applicationId", "providerFamilyNamespace"):
        _identifier(payload[field])
    for field in ("configurationDigest", "clientMaterialSha256", "providerConfigurationSha256"):
        profile.digest(payload[field])
        profile.require(payload[field] != "sha256:" + "0" * 64)
    for field, bound in (("sourceRevision", 128), ("clientId", 2048), ("redirectUri", 4096)):
        item = payload[field]
        profile.require(type(item) is str and item == item.strip() and 1 <= len(item.encode("utf-8")) <= bound
            and not any(ord(c) < 32 or ord(c) == 127 for c in item))
    uri = urlsplit(payload["redirectUri"])
    profile.require(uri.scheme == "https" and uri.hostname and not uri.username and not uri.password and not uri.fragment)
    profile.require(payload["providerId"] in ("google", "x"))
    for field in ("providerFamilyGeneration", "issuedAtEpochNs", "expiresAtEpochNs"):
        profile.require(type(payload[field]) is int and 1 <= payload[field] <= 9_223_372_036_854_775_807)
    profile.require(payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"])
    _b64(value["signatureBase64Url"], 64)
    return value


def association(raw):
    value = enrollment_document(raw)["payload"]
    return {"schema": ASSOCIATION_SCHEMA, "enrollmentSha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        **{name: value[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
            "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    """Reverify original signature/time/scope; return no reusable success object."""
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(key is not None, "OAuth activation enrollment authority is disabled")
    raw = profile.enrollment_bytes(values["enrollment_original"])
    envelope = enrollment_document(raw)
    payload = envelope["payload"]
    profile.require(type(now_epoch_ns) is int and payload["issuedAtEpochNs"] <= now_epoch_ns < payload["expiresAtEpochNs"]
        and payload["sourceRevision"] == configuration_payload["sourceRevision"]
        and payload["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and payload["deploymentId"] == policy["deploymentId"], "OAuth activation enrollment scope or original interval differs")
    key.verify(_b64(envelope["signatureBase64Url"], 64), ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(payload))
