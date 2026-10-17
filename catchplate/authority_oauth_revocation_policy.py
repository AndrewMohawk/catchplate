"""Current cleanup authority authenticates history without reviving consent."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_oauth_revocation as profile

FIELD = "oauthRevocationPolicy"
SCHEMA = "catchplate.oauthRevocationAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256", "controlPlaneConfigurationDigest", "deploymentId"})


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "OAuth revocation requires separately admitted current grant authority")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    enrollment._identifier(value["deploymentId"])
    profile.digest(value["controlPlaneConfigurationDigest"])
    profile.digest(value["grantRootSpkiSha256"])
    raw = profile.unb64(value["grantRootPublicKeyBase64Url"], 32)
    profile.require(len(raw) == 32)
    key = Ed25519PublicKey.from_public_bytes(raw)
    pin = enrollment._spki(key)
    profile.require(pin == value["grantRootSpkiSha256"])
    if root_key is not None:
        profile.require(pin != enrollment._spki(root_key))
    for role in payload["roles"].values():
        for name, item in role.items():
            if name.endswith("SpkiDigest") or name.endswith("SpkiSha256"):
                profile.require(pin != item)
    for name in ("oauthActivationPolicy", "oauthExchangePolicy", "webauthnEnrollmentAuthorization", "webauthnEvidenceAdmission", "webauthnTransitions"):
        other = payload.get(name)
        if type(other) is dict:
            profile.require(pin not in other.values(), "cleanup root must be separate from other purpose roots")
    return key


def verify_originals(values, *, grant_root, configuration_digest, source_revision, deployment_id, now_epoch_ns):
    raw = profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES)
    signed = profile.grant_document(raw)
    grant = signed["payload"]
    profile.require(isinstance(grant_root, Ed25519PublicKey) and grant["sourceRevision"] == source_revision
        and grant["configurationDigest"] == configuration_digest and grant["deploymentId"] == deployment_id
        and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"])
    grant_root.verify(profile.unb64(signed["signatureBase64Url"], 64),
        profile.GRANT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(grant))
    historical_raw = profile.unb64(values["historical_root_original"], 4096)
    historical = serialization.load_pem_public_key(historical_raw)
    profile.require(isinstance(historical, Ed25519PublicKey)
        and historical.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == historical_raw
        and enrollment._spki(historical) == grant["historicalEnrollmentRootSpkiSha256"]
        and enrollment._spki(historical) != enrollment._spki(grant_root))
    original = profile.exchange.enrollment_bytes(values["enrollment_original"])
    historical_envelope = enrollment.enrollment_document(original)
    payload = historical_envelope["payload"]
    profile.require(profile.sha256(original) == grant["enrollmentSha256"]
        and payload["deploymentId"] == grant["deploymentId"] and payload["providerId"] == grant["providerId"]
        and payload["clientId"] == grant["clientId"] and payload["clientMaterialSha256"] == grant["clientMaterialSha256"]
        and payload["providerConfigurationSha256"] == profile.sha256(profile.canonical(grant["providerConfiguration"])))
    historical.verify(profile.unb64(historical_envelope["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(payload))
    # Deliberately no old-interval-now test: this authenticates retained history,
    # not a new application/consent owner. The kernel joins its original creation
    # time to that historical interval; the current grant bounds cleanup alone.


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(key is not None)
    verify_originals(values, grant_root=key, configuration_digest=policy["controlPlaneConfigurationDigest"],
        source_revision=configuration_payload["sourceRevision"], deployment_id=policy["deploymentId"], now_epoch_ns=now_epoch_ns)
