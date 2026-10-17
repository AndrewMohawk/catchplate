"""Independent signed permission for measured Setup issuance and activation."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_credential_currentness_policy as native
from catchplate import authority_oauth_measured_exchange_policy as scalar
from catchplate import authority_oauth_measured_setup as profile
from catchplate import authority_oauth_setup as setup
from catchplate import native_oauth_exchange as material

FIELD = "oauthMeasuredSetupPolicy"
SCHEMA = "catchplate.oauthMeasuredSetupAuthorityPolicy/v1"
FIELDS = scalar.FIELDS | {"setupCapacity", "setupMaxSeconds"}
ASSIGNMENT_FIELDS = scalar.ASSIGNMENT_FIELDS
OPERATIONS = profile.OPERATIONS | setup.OPERATIONS


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "Setup operations require independently signed Setup permission")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    # Share enrollment key/scalar checks, never another effect's signed bytes.
    enrollment_view = {name: value[name] for name in enrollment.FIELDS}
    enrollment_view["schema"] = enrollment.SCHEMA
    key = enrollment.validate_policy(enrollment_view, payload=payload, root_key=root_key)
    profile.limits({name: value[name] for name in ("pendingCapacity", "revocationCapacity")})
    for name, maximum in (("contactMaxSeconds", 600), ("retentionMaxSeconds", 600), ("pendingMaxSeconds", 3600),
            ("operationMaxSeconds", 30), ("recoveryMaxSeconds", 30), ("setupCapacity", 64), ("setupMaxSeconds", 604800)):
        profile.require(type(value[name]) is int and 1 <= value[name] <= maximum)
    profile.require(value["setupMaxSeconds"] >= 300)
    profile.require(value["setupCapacity"] == 64, "the source complete-Setup population profile is exactly64")
    native._trust(value["trustRoots"])
    entries = value["assignments"]
    profile.require(type(entries) is list and 1 <= len(entries) <= 32)
    forbidden = {enrollment._spki(key)}
    if root_key is not None:
        forbidden.add(enrollment._spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    identities = []
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        native._assignment({name: entry[name] for name in native.ASSIGNMENT_FIELDS})
        profile.require(entry["keyId"] not in forbidden and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["providerId"] in material.AUTHORIZATION)
        material.text(entry["instanceId"], 4096)
        profile.require(entry["instanceId"].startswith("spiffe://"))
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
    return key


def assignment(policy, statement):
    entries = [entry for entry in policy["assignments"] if entry["holderId"] == statement["holderId"]
        and entry["enrollmentSha256"] == statement["enrollmentSha256"]]
    profile.require(len(entries) == 1)
    return entries[0]


def owns_enrollment(policy, raw):
    return type(policy) is dict and any(entry.get("enrollmentSha256") == profile.sha256(raw)
        for entry in policy.get("assignments", ()) if type(entry) is dict)


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    profile.require(operation in OPERATIONS and type(now_epoch_ns) is int and now_epoch_ns > 0)
    contract = profile if operation in profile.OPERATIONS else setup
    values = contract.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    enrollment_key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(enrollment_key is not None)
    if operation == setup.OP_SETTLE:
        # Only factual completion of the exact retained protected outbox may
        # settle. The kernel supplies no session/effect or approval permission.
        return
    raw = profile.activation.enrollment_bytes(values["enrollment_original"])
    envelope = enrollment.enrollment_document(raw)
    application = envelope["payload"]
    enrollment_key.verify(enrollment._b64(envelope["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(application))
    profile.require(application["sourceRevision"] == configuration_payload["sourceRevision"]
        and application["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and application["deploymentId"] == policy["deploymentId"] and owns_enrollment(policy, raw))
    request = values["request"]
    historical = operation == profile.OP_RECOVER or operation == profile.OP_STAGE and request["recoveryRequestDigest"] is not None
    if not historical:
        profile.require(application["issuedAtEpochNs"] <= now_epoch_ns < application["expiresAtEpochNs"])
    if operation in setup.ASSERTION_OPERATIONS:
        if operation == setup.OP_CREATE:
            profile.require(request["providerId"] == application["providerId"]
                and request["issuedAtEpochNs"] <= now_epoch_ns < request["issuedAtEpochNs"] + 30_000_000_000
                and request["expiresAtEpochNs"] <= request["issuedAtEpochNs"] + policy["setupMaxSeconds"] * 1_000_000_000
                and request["expiresAtEpochNs"] <= application["expiresAtEpochNs"])
        else:
            profile.require(now_epoch_ns < request["setupBinding"]["expiresAtEpochNs"])
        return
    profile.require(values["control_plane_configuration_digest"] == policy["controlPlaneConfigurationDigest"]
        and request["limits"] == {name: policy[name] for name in ("pendingCapacity", "revocationCapacity")})
    proof = values["native_evidence"]; statement = proof["statement"]
    expected = assignment(policy, statement)
    if operation != profile.OP_PREPARE:
        profile.require(values["assignment_original"] == expected)
    profile.require(statement["providerId"] == expected["providerId"] == application["providerId"]
        and statement["deploymentId"] == policy["deploymentId"]
        and application["redirectUri"] == material.callback_uri(expected["callbackOrigin"], expected["providerId"])
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"]
        <= statement["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000
        and statement["expiresAtEpochNs"] <= request["setupBinding"]["expiresAtEpochNs"])
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId", "callbackOrigin", "portalOrigin"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    if operation == profile.OP_PREPARE:
        issued, contact, retention, pending = (request[name] for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"))
        profile.require(application["issuedAtEpochNs"] <= issued <= now_epoch_ns < contact <= issued + policy["contactMaxSeconds"] * 1_000_000_000
            and retention <= contact + policy["retentionMaxSeconds"] * 1_000_000_000
            and pending <= contact + policy["pendingMaxSeconds"] * 1_000_000_000
            and pending <= application["expiresAtEpochNs"] and now_epoch_ns - issued <= 30_000_000_000)
        profile.require(all(request[name]["secret_kek_id"] == expected["secretKekId"] for name in ("stateEnvelope", "reservedEnvelope")))
    if operation == profile.OP_RECOVER:
        profile.require(request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + policy["recoveryMaxSeconds"] * 1_000_000_000
            and request["expiresAtEpochNs"] <= request["setupBinding"]["expiresAtEpochNs"])
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
    boot_binding = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + profile.decoded(expected["bootId"], 32, 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    original = profile.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12288)
    roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(original, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificates,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
