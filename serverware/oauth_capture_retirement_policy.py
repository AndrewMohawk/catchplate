"""Portable capture-retirement policy and grant signature checks, not a phase grant."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_oauth_capture_retirement as profile
from serverware import native_oauth_refresh as material
from serverware import oauth_retirement_policy_values as portable

FIELD = "oauthMeasuredCaptureRetirementPolicy"
SCHEMA = "serverware.oauthMeasuredCaptureRetirementAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256", "controlPlaneConfigurationDigest",
    "deploymentId", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = portable.APPLICATION_ASSIGNMENT_FIELDS | {"exchangeIds", "recoveryAuthorizationSha256s"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "capture retirement requires its independent assignment and family authority")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    portable.identifier(value["deploymentId"]); profile.digest(value["controlPlaneConfigurationDigest"])
    raw = profile.unb64(value["grantRootPublicKeyBase64Url"], 32); profile.require(len(raw) == 32)
    key = Ed25519PublicKey.from_public_bytes(raw)
    pin = portable.spki(key); profile.require(pin == value["grantRootSpkiSha256"])
    forbidden = {pin}
    if root_key is not None:
        profile.require(pin != portable.spki(root_key)); forbidden.add(portable.spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items() if type(item) is str
            and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
        profile.require(pin not in role.values())
    for name, other in payload.items():
        if name != FIELD and type(other) is dict:
            profile.require(pin not in other.values(), "capture retirement root cannot substitute another purpose root")
    portable.trust_roots(value["trustRoots"])
    entries = value["assignments"]
    profile.require(type(entries) is list and 1 <= len(entries) <= 32)
    identities = []
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        portable.native_assignment({name: entry[name] for name in portable.NATIVE_ASSIGNMENT_FIELDS})
        profile.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in {"google", "x"})
        from urllib.parse import urlsplit
        uri = urlsplit(material.text(entry["instanceId"], 4096))
        profile.require(uri.scheme == "spiffe" and uri.hostname and not uri.username and not uri.password
            and uri.port is None and uri.path.startswith("/") and not uri.query and not uri.fragment)
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            profile.digest(entry[name])
        ids = entry["exchangeIds"]
        profile.require(type(ids) is list and 1 <= len(ids) <= 64 and ids == sorted(set(ids)))
        for identifier in ids:
            profile.identifier(identifier)
        recovery = entry["recoveryAuthorizationSha256s"]
        profile.require(type(recovery) is list and len(recovery) <= 16 and recovery == sorted(set(recovery)))
        for original in recovery:
            profile.digest(original)
        key_id = entry["secretKekId"]
        profile.require(type(key_id) is str and key_id.startswith("attested-memory-kek:") and len(key_id) == 44
            and all(char in "0123456789abcdef" for char in key_id[-24:]))
        identities.append((entry["holderId"], entry["enrollmentSha256"]))
    profile.require(identities == sorted(set(identities)) and len(profile.canonical(value)) <= 1024 * 1024)
    return key


def assignment(policy, statement):
    found = [item for item in policy["assignments"] if item["holderId"] == statement["holderId"]
        and item["enrollmentSha256"] == statement["enrollmentSha256"]]
    profile.require(len(found) == 1, "capture retirement has no independent helper assignment")
    return found[0]


def verify_grant(values, *, key, configuration_digest, source_revision, deployment_id, now_epoch_ns, historical=False):
    raw = profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES)
    signed = profile.grant_document(raw); grant = signed["payload"]
    profile.require(grant["deploymentId"] == deployment_id)
    if not historical:
        profile.require(grant["sourceRevision"] == source_revision and grant["configurationDigest"] == configuration_digest
            and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"])
    key.verify(profile.unb64(signed["signatureBase64Url"], 64), profile.GRANT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(grant))
    historical_raw = profile.unb64(values["historical_root_original"], 4096)
    historical = serialization.load_pem_public_key(historical_raw)
    profile.require(isinstance(historical, Ed25519PublicKey)
        and historical.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == historical_raw
        and portable.spki(historical) == grant["historicalEnrollmentRootSpkiSha256"]
        and portable.spki(historical) != portable.spki(key))
    original = portable.enrollment_document(profile.unb64(values["enrollment_original"], 32768))
    application = original["payload"]
    profile.require(application["deploymentId"] == grant["deploymentId"] and application["providerId"] == grant["providerId"]
        and application["clientId"] == grant["clientId"] and application["clientMaterialSha256"] == grant["clientMaterialSha256"]
        and application["providerConfigurationSha256"] == profile.sha256(profile.canonical(grant["providerConfiguration"])))
    historical.verify(profile.unb64(original["signatureBase64Url"], 64),
        portable.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(application))
    return grant, application
