"""Independent enrolled application, family replacement and native permissions."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_measured_exchange_policy as scalar
from serverware import authority_oauth_reconnect as profile
from serverware import native_oauth_exchange as material

FIELD = "oauthMeasuredReconnectPolicy"
SCHEMA = "serverware.oauthMeasuredReconnectAuthorityPolicy/v1"
FIELDS = scalar.FIELDS | {"familyReplacementRootPublicKeyBase64Url", "familyReplacementRootSpkiSha256",
    "affectedLineageCapacity", "historyCapacity", "authorizationMaxSeconds"}
ASSIGNMENT_FIELDS = scalar.ASSIGNMENT_FIELDS


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "reconnect requires its independently selected purpose policy")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    view = {name: value[name] for name in enrollment.FIELDS}; view["schema"] = enrollment.SCHEMA
    enrollment_key = enrollment.validate_policy(view, payload=payload, root_key=root_key)
    profile.issuance.limits({name: value[name] for name in ("pendingCapacity", "revocationCapacity")})
    for name, maximum in (("contactMaxSeconds", 600), ("retentionMaxSeconds", 600), ("pendingMaxSeconds", 3600),
            ("operationMaxSeconds", 30), ("recoveryMaxSeconds", 30), ("authorizationMaxSeconds", 3600)):
        profile.require(type(value[name]) is int and 1 <= value[name] <= maximum)
    profile.require(type(value["affectedLineageCapacity"]) is int and value["affectedLineageCapacity"] == profile.MAX_AFFECTED_LINEAGES
        and type(value["historyCapacity"]) is int and value["historyCapacity"] == profile.MAX_HISTORY_ROWS)
    replacement_key = Ed25519PublicKey.from_public_bytes(enrollment._b64(value["familyReplacementRootPublicKeyBase64Url"], 32))
    replacement_pin = enrollment._spki(replacement_key)
    profile.require(replacement_pin == value["familyReplacementRootSpkiSha256"])
    forbidden = {enrollment._spki(enrollment_key)}
    if root_key is not None:
        forbidden.add(enrollment._spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    # The replacement root has no enrollment, cleanup, configuration or role
    # permission. Require its independence from every configured purpose root.
    for name, other in payload.items():
        if name != FIELD and type(other) is dict:
            forbidden.update(item for key, item in other.items()
                if (key.endswith("SpkiDigest") or key.endswith("SpkiSha256")) and type(item) is str)
    profile.require(replacement_pin not in forbidden)
    forbidden.add(replacement_pin)
    native._trust(value["trustRoots"])
    entries, identities = value["assignments"], []
    profile.require(type(entries) is list and 1 <= len(entries) <= 32)
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        native._assignment({name: entry[name] for name in native.ASSIGNMENT_FIELDS})
        profile.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in material.AUTHORIZATION)
        material.text(entry["instanceId"], 4096); profile.require(entry["instanceId"].startswith("spiffe://"))
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            profile.digest(entry[name])
        material.origin(entry["portalOrigin"]); material.origin(entry["callbackOrigin"])
        profile.require(entry["portalOrigin"] != entry["callbackOrigin"])
        kek = entry["secretKekId"]
        profile.require(type(kek) is str and kek.startswith("attested-memory-kek:") and len(kek) == 44
            and all(char in "0123456789abcdef" for char in kek[-24:]))
        identities.append((entry["holderId"], entry["enrollmentSha256"]))
    profile.require(identities == sorted(set(identities)))
    previous = payload.get(enrollment.FIELD)
    if previous is not None:
        profile.require(all(value[name] == previous[name] for name in enrollment.FIELDS - {"schema"}))
    return enrollment_key, replacement_key


def assignment(policy, statement):
    entries = [entry for entry in policy["assignments"] if entry["holderId"] == statement["holderId"]
        and entry["enrollmentSha256"] == statement["enrollmentSha256"]]
    profile.require(len(entries) == 1)
    return entries[0]


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    keys = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(keys is not None and type(now_epoch_ns) is int and now_epoch_ns > 0)
    enrollment_key, replacement_key = keys
    grant_raw = profile.decoded(values["authorization_original"], profile.MAX_GRANT_BYTES)
    signed = profile.grant_document(grant_raw); grant = signed["payload"]
    replacement_key.verify(enrollment._b64(signed["signatureBase64Url"], 64),
        profile.GRANT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(grant))
    raw = profile.activation.enrollment_bytes(values["enrollment_original"])
    envelope = enrollment.enrollment_document(raw); application = envelope["payload"]
    enrollment_key.verify(enrollment._b64(envelope["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(application))
    profile.require(grant["sourceRevision"] == application["sourceRevision"] == configuration_payload["sourceRevision"]
        and grant["configurationDigest"] == application["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and grant["deploymentId"] == application["deploymentId"] == policy["deploymentId"]
        and grant["providerId"] == application["providerId"] and grant["clientId"] == application["clientId"]
        and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"]
        and application["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] < grant["expiresAtEpochNs"] <= application["expiresAtEpochNs"]
        and grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= policy["authorizationMaxSeconds"] * 1_000_000_000
        and any(entry["enrollmentSha256"] == profile.sha256(raw) for entry in policy["assignments"]))
    issued, contact, retained, pending = (grant[name] for name in
        ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"))
    profile.require(contact - issued <= policy["contactMaxSeconds"] * 1_000_000_000
        and retained - contact <= policy["retentionMaxSeconds"] * 1_000_000_000
        and pending - contact <= policy["pendingMaxSeconds"] * 1_000_000_000)
    if operation in {profile.OP_AUTHORIZE, profile.OP_FENCE}:
        profile.require(now_epoch_ns < contact)
    if operation not in profile.NATIVE_OPERATIONS:
        return
    request, proof = values["request"], values["native_evidence"]
    statement = proof["statement"]; expected = assignment(policy, statement)
    profile.require(values["assignment_original"] == expected
        and request["limits"] == {name: policy[name] for name in ("pendingCapacity", "revocationCapacity")}
        and statement["providerId"] == expected["providerId"] == application["providerId"]
        and statement["deploymentId"] == policy["deploymentId"]
        and application["redirectUri"] == material.callback_uri(expected["callbackOrigin"], expected["providerId"])
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"]
        <= statement["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId", "callbackOrigin", "portalOrigin"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    if operation == profile.OP_PREPARE:
        profile.require(issued <= request["issuedAtEpochNs"] <= now_epoch_ns < contact
            and now_epoch_ns - request["issuedAtEpochNs"] <= 30_000_000_000
            and all(request[name]["secret_kek_id"] == expected["secretKekId"] for name in ("stateEnvelope", "reservedEnvelope")))
    if operation == profile.OP_RECOVER:
        profile.require(request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + policy["recoveryMaxSeconds"] * 1_000_000_000
            and request["expiresAtEpochNs"] <= pending)
    for name in ("callbackEnvelope", "rawResponseEnvelope", "issuedMaterialEnvelope", "tokenEnvelope", "identityRawEnvelope"):
        if request.get(name) is not None:
            profile.require(request[name]["secret_kek_id"] == expected["secretKekId"])
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
    original = profile.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12288)
    roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(original, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificates,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
