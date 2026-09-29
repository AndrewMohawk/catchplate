"""Portable staged-pending retirement policy and grant signature checks.

The strict CP predicates also govern the native receipt consumer; no weaker
helper policy, enrollment decoder or translated signature purpose is accepted.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import oauth_pending_retirement_values as grant_values
from serverware import oauth_retirement_policy_values as portable

OPERATIONS = frozenset({"oauth.measured-pending-retirement." + phase for phase in
    ("inspect", "claim", "contact", "finish", "recover")})

FIELD = "oauthMeasuredPendingRetirementPolicy"
SCHEMA = "serverware.oauthMeasuredPendingRetirementAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256", "controlPlaneConfigurationDigest",
    "deploymentId", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = portable.APPLICATION_ASSIGNMENT_FIELDS | {"pendingIds", "recoveryAuthorizationSha256s"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values())
    if value is None:
        portable.require(not enabled, "pending retirement requires its independent assignment and family authority")
        return None
    portable.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    portable.identifier(value["deploymentId"]); portable.digest(value["controlPlaneConfigurationDigest"])
    raw = portable.unb64(value["grantRootPublicKeyBase64Url"], 32); portable.require(len(raw) == 32)
    key = Ed25519PublicKey.from_public_bytes(raw)
    pin = portable.spki(key); portable.require(pin == value["grantRootSpkiSha256"])
    forbidden = {pin}
    if root_key is not None:
        portable.require(pin != portable.spki(root_key)); forbidden.add(portable.spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items() if type(item) is str
            and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
        portable.require(pin not in role.values())
    for name, other in payload.items():
        if name != FIELD and type(other) is dict:
            portable.require(pin not in other.values(), "pending retirement root cannot substitute another purpose root")
    portable.trust_roots(value["trustRoots"])
    entries = value["assignments"]
    portable.require(type(entries) is list and 1 <= len(entries) <= 32)
    identities = []
    for entry in entries:
        portable.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        portable.native_assignment({name: entry[name] for name in portable.NATIVE_ASSIGNMENT_FIELDS})
        portable.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in {"google", "x"})
        from urllib.parse import urlsplit
        uri = urlsplit(portable.text(entry["instanceId"], 4096))
        portable.require(uri.scheme == "spiffe" and uri.hostname and not uri.username and not uri.password
            and uri.port is None and uri.path.startswith("/") and not uri.query and not uri.fragment)
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            portable.digest(entry[name])
        ids = entry["pendingIds"]
        portable.require(type(ids) is list and 1 <= len(ids) <= 64 and ids == sorted(set(ids)))
        for identifier in ids:
            portable.uuid_value(identifier)
        recovery = entry["recoveryAuthorizationSha256s"]
        portable.require(type(recovery) is list and len(recovery) <= 16 and recovery == sorted(set(recovery)))
        for original in recovery:
            portable.digest(original)
        key_id = entry["secretKekId"]
        portable.require(type(key_id) is str and key_id.startswith("attested-memory-kek:") and len(key_id) == 44
            and all(char in "0123456789abcdef" for char in key_id[-24:]))
        identities.append((entry["holderId"], entry["enrollmentSha256"]))
    portable.require(identities == sorted(set(identities)) and len(portable.canonical(value)) <= 1024 * 1024)
    return key


def assignment(policy, statement):
    found = [item for item in policy["assignments"] if item["holderId"] == statement["holderId"]
        and item["enrollmentSha256"] == statement["enrollmentSha256"]]
    portable.require(len(found) == 1, "pending retirement has no independent helper assignment")
    return found[0]


def verify_grant(values, *, key, configuration_digest, source_revision, deployment_id, now_epoch_ns, historical=False):
    raw = portable.unb64(values["authorization_original"], grant_values.MAX_GRANT_BYTES)
    signed = grant_values.grant_document(raw); grant = signed["payload"]
    portable.require(grant["deploymentId"] == deployment_id)
    if not historical:
        portable.require(grant["sourceRevision"] == source_revision and grant["configurationDigest"] == configuration_digest
            and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"])
    key.verify(portable.unb64(signed["signatureBase64Url"], 64), grant_values.GRANT_SCHEMA.encode("ascii") + b"\0" + portable.canonical(grant))
    historical_raw = portable.unb64(values["historical_root_original"], 4096)
    historical = serialization.load_pem_public_key(historical_raw)
    portable.require(isinstance(historical, Ed25519PublicKey)
        and historical.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == historical_raw
        and portable.spki(historical) == grant["historicalEnrollmentRootSpkiSha256"]
        and portable.spki(historical) != portable.spki(key))
    enrollment_raw = portable.unb64(values["enrollment_original"], portable.MAX_ENROLLMENT_BYTES)
    portable.require(portable.sha256(enrollment_raw) == grant["enrollmentSha256"])
    original = portable.enrollment_document(enrollment_raw)
    application = original["payload"]
    portable.require(application["deploymentId"] == grant["deploymentId"] and application["providerId"] == grant["providerId"]
        and application["clientId"] == grant["clientId"] and application["clientMaterialSha256"] == grant["clientMaterialSha256"]
        and application["providerConfigurationSha256"] == portable.sha256(portable.canonical(grant["providerConfiguration"])))
    historical.verify(portable.unb64(original["signatureBase64Url"], 64),
        portable.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + portable.canonical(application))
    return grant, application
