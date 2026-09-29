"""Independent native pending-retirement assignment and fresh family grant."""
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_measured_refresh_policy as issuance
from serverware import authority_oauth_measured_pending_retirement as profile

FIELD = "oauthMeasuredPendingRetirementPolicy"
SCHEMA = "serverware.oauthMeasuredPendingRetirementAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256", "controlPlaneConfigurationDigest",
    "deploymentId", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = (issuance.ASSIGNMENT_FIELDS - {"credentialIds"}) | {"pendingIds", "recoveryAuthorizationSha256s"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "pending retirement requires its independent assignment and family authority")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    enrollment._identifier(value["deploymentId"]); profile.digest(value["controlPlaneConfigurationDigest"])
    raw = profile.unb64(value["grantRootPublicKeyBase64Url"], 32); profile.require(len(raw) == 32)
    key = Ed25519PublicKey.from_public_bytes(raw)
    pin = enrollment._spki(key); profile.require(pin == value["grantRootSpkiSha256"])
    forbidden = {pin}
    if root_key is not None:
        profile.require(pin != enrollment._spki(root_key)); forbidden.add(enrollment._spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items() if type(item) is str
            and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
        profile.require(pin not in role.values())
    for name, other in payload.items():
        if name != FIELD and type(other) is dict:
            profile.require(pin not in other.values(), "pending retirement root cannot substitute another purpose root")
    native._trust(value["trustRoots"])
    entries = value["assignments"]
    profile.require(type(entries) is list and 1 <= len(entries) <= 32)
    identities = []
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        native._assignment({name: entry[name] for name in native.ASSIGNMENT_FIELDS})
        profile.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in {"google", "x"})
        from urllib.parse import urlsplit
        uri = urlsplit(profile.retained.text(entry["instanceId"], 4096))
        profile.require(uri.scheme == "spiffe" and uri.hostname and not uri.username and not uri.password
            and uri.port is None and uri.path.startswith("/") and not uri.query and not uri.fragment)
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            profile.digest(entry[name])
        ids = entry["pendingIds"]
        profile.require(type(ids) is list and 1 <= len(ids) <= 64 and ids == sorted(set(ids)))
        for identifier in ids:
            profile._uuid(identifier)
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
    profile.require(len(found) == 1, "pending retirement has no independent helper assignment")
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
        and enrollment._spki(historical) == grant["historicalEnrollmentRootSpkiSha256"]
        and enrollment._spki(historical) != enrollment._spki(key))
    original = enrollment.enrollment_document(profile.refresh.enrollment_bytes(values["enrollment_original"]))
    application = original["payload"]
    profile.require(application["deploymentId"] == grant["deploymentId"] and application["providerId"] == grant["providerId"]
        and application["clientId"] == grant["clientId"] and application["clientMaterialSha256"] == grant["clientMaterialSha256"]
        and application["providerConfigurationSha256"] == profile.sha256(profile.canonical(grant["providerConfiguration"])))
    historical.verify(profile.unb64(original["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(application))
    return grant, application


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(key is not None)
    grant, application = verify_grant(values, key=key, configuration_digest=policy["controlPlaneConfigurationDigest"],
        source_revision=configuration_payload["sourceRevision"], deployment_id=policy["deploymentId"], now_epoch_ns=now_epoch_ns,
        historical=operation == profile.OP_RECOVER)
    proof = values["evidence"]; statement = proof["statement"]; expected = assignment(policy, statement)
    profile.require(operation in {profile.OP_INSPECT, profile.OP_RECOVER} or values["assignment_original"] == expected)
    profile.require(values["control_plane_configuration_digest"] == policy["controlPlaneConfigurationDigest"]
        and grant["pendingId"] in expected["pendingIds"]
        and grant["providerId"] == expected["providerId"] == application["providerId"]
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"])
    if operation == profile.OP_RECOVER:
        profile.require(statement["authorizationSha256"] in expected["recoveryAuthorizationSha256s"])
    else:
        profile.require(grant["holderId"] == expected["holderId"])
    for name in ("applicationMaterialSha256", "providerTlsRootSha256", "enrollmentSha256"):
        profile.require(grant[name] == expected[name])
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    raw_key = profile.unb64(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32)
    native_key = Ed25519PublicKey.from_public_bytes(raw_key)
    profile.require(enrollment._spki(native_key) == expected["keyId"])
    signature = profile.unb64(proof["signature"][8:], 64); original = profile.canonical(statement)
    native_key.verify(signature, profile.SIGNATURE_DOMAIN + original)
    nonce = hashlib.sha256(profile.ATTESTATION_DOMAIN + profile.unb64(statement["challenge"], 32)
        + hashlib.sha256(original).digest() + signature).digest()
    boot = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + profile.unb64(expected["bootId"], 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot
    roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(
        profile.unb64(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024), claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now_epoch_ns // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
