"""Independent measured issuance permission, not audit or holder membership.

Both actual verifier and planner re-admit the original NSM document, signature,
current signed purpose configuration and exact application assignment.
"""
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_measured_refresh as profile
from serverware import authority_oauth_refresh as refresh

FIELD = "oauthMeasuredRefreshPolicy"
SCHEMA = "serverware.oauthMeasuredRefreshAuthorityPolicy/v1"
FIELDS = enrollment.FIELDS | {"dueWithinSeconds", "operationMaxSeconds", "revocationCapacity",
    "recoveryMaxSeconds", "trustRoots", "assignments"}
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {"instanceId", "providerId", "enrollmentSha256",
    "applicationMaterialSha256", "secretKekId", "providerTlsRootSha256", "credentialIds"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "measured refresh requires its own explicit signed issuance purpose")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    view = {name: value[name] for name in enrollment.FIELDS}
    view["schema"] = enrollment.SCHEMA
    key = enrollment.validate_policy(view, payload=payload, root_key=root_key)
    refresh.limits({name: value[name] for name in ("dueWithinSeconds", "operationMaxSeconds", "revocationCapacity")})
    profile.require(type(value["recoveryMaxSeconds"]) is int and 1 <= value["recoveryMaxSeconds"] <= 30)
    # The root-certificate format/verifier is shared, never its assignment or
    # currentness permission. These originals occur in this signed purpose.
    native._trust(value["trustRoots"])
    entries = value["assignments"]
    profile.require(type(entries) is list and 1 <= len(entries) <= 32)
    identities = []
    forbidden = {enrollment._spki(key)}
    if root_key is not None:
        forbidden.add(enrollment._spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items() if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        native._assignment({name: entry[name] for name in native.ASSIGNMENT_FIELDS})
        profile.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in profile.material.ENDPOINTS)
        from urllib.parse import urlsplit
        uri = urlsplit(profile.material.text(entry["instanceId"], 4096))
        profile.require(uri.scheme == "spiffe" and uri.hostname and not uri.username and not uri.password
            and uri.port is None and uri.path.startswith("/") and not uri.query and not uri.fragment)
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            profile.digest(entry[name])
        credentials = entry["credentialIds"]
        profile.require(type(credentials) is list and 1 <= len(credentials) <= 64 and credentials == sorted(set(credentials)))
        for item in credentials:
            refresh._uuid(item)
        key_id = entry["secretKekId"]
        profile.require(type(key_id) is str and key_id.startswith("attested-memory-kek:")
            and len(key_id) == 44 and all(char in "0123456789abcdef" for char in key_id[-24:]))
        identities.append((entry["holderId"], entry["enrollmentSha256"]))
    profile.require(identities == sorted(set(identities)) and len(profile.canonical(value)) <= 1024 * 1024)
    return key


def assignment(policy, statement):
    entries = [entry for entry in policy["assignments"] if entry["holderId"] == statement["holderId"]
        and entry["enrollmentSha256"] == statement["enrollmentSha256"]]
    profile.require(len(entries) == 1, "measured refresh has no independent issuance assignment")
    return entries[0]


def owns_enrollment(policy, raw):
    """Purpose-selection check only; never a substitute for verify_original."""
    return type(policy) is dict and any(entry.get("enrollmentSha256") == profile.sha256(raw)
        for entry in policy.get("assignments", ()))


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    enrollment_key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(enrollment_key is not None and type(now_epoch_ns) is int and now_epoch_ns > 0
        and values["control_plane_configuration_digest"] == policy["controlPlaneConfigurationDigest"])
    raw = refresh.enrollment_bytes(values["enrollment_original"])
    original = enrollment.enrollment_document(raw)
    application = original["payload"]
    enrollment_key.verify(enrollment._b64(original["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(application))
    profile.require(application["sourceRevision"] == configuration_payload["sourceRevision"]
        and application["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and application["deploymentId"] == policy["deploymentId"])
    request = values["request"]
    # Recovery authenticates an archived enrollment; its fresh configuration
    # grants only retained-capture processing, never another provider contact.
    historical = (operation == profile.OP_RECOVER or operation == profile.OP_INSPECT and request["recoveryVersion"] is not None
        or operation == profile.OP_COMMIT and request["recoveryRequestDigest"] is not None)
    if not historical:
        profile.require(application["issuedAtEpochNs"] <= now_epoch_ns < application["expiresAtEpochNs"])
    profile.require(request["limits"] == {name: policy[name] for name in ("dueWithinSeconds", "operationMaxSeconds", "revocationCapacity")})
    proof = values["evidence"]
    statement = proof["statement"]
    expected = assignment(policy, statement)
    if operation != profile.OP_INSPECT:
        profile.require(values["assignment_original"] == expected)
    profile.require(values["credential_id"] in expected["credentialIds"]
        and statement["providerId"] == expected["providerId"] == application["providerId"]
        and statement["deploymentId"] == policy["deploymentId"]
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"]
        <= statement["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    if operation in {profile.OP_INSPECT, profile.OP_CLAIM}:
        profile.require(request["applicationMaterialSha256"] == expected["applicationMaterialSha256"])
    if operation in {profile.OP_INSPECT, profile.OP_RECOVER}:
        maximum = policy["recoveryMaxSeconds"] if historical else policy["operationMaxSeconds"]
        profile.require(request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + maximum * 1_000_000_000)
    if operation == profile.OP_CLAIM:
        profile.require(application["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now_epoch_ns < request["contactExpiresAtEpochNs"]
            and request["retentionExpiresAtEpochNs"] <= application["expiresAtEpochNs"])
    raw_key = profile.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    profile.require(enrollment._spki(key) == expected["keyId"])
    signature = profile.decoded(proof["signature"][8:], 64, 64)
    statement_raw = profile.canonical(statement)
    key.verify(signature, profile.SIGNATURE_DOMAIN + statement_raw)
    nonce = hashlib.sha256(profile.ATTESTATION_DOMAIN + profile.decoded(statement["challenge"], 32, 32)
        + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + profile.decoded(expected["bootId"], 32, 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    document = profile.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificates,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
