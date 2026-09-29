"""Independent succession root, historical enrollment and native assignment.

No active-family reconnect signature or old retirement grant authorizes this
purpose. Original closed statements are verified without relabeling them.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_measured_exchange_policy as scalar

FIELD = "oauthRetiredScopeSuccessionPolicy"
SCHEMA = "serverware.oauthRetiredScopeSuccessionAuthorityPolicy/v1"
FIELDS = scalar.FIELDS | {"successionRootPublicKeyBase64Url", "successionRootSpkiSha256", "historicalEnrollmentRoots",
    "materialCapacity", "affectedLineageCapacity", "populationCapacity", "historyCapacity", "authorizationMaxSeconds"}
ASSIGNMENT_FIELDS = scalar.ASSIGNMENT_FIELDS | {"enrollmentRootSpkiSha256"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & p.OPERATIONS for role in payload["roles"].values())
    if value is None:
        p.require(not enabled, "succession operations require their independently selected policy")
        return None
    p.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    view = {name: value[name] for name in enrollment.FIELDS}; view["schema"] = enrollment.SCHEMA
    target_root = enrollment.validate_policy(view, payload=payload, root_key=root_key)
    p.issuance.limits({name: value[name] for name in ("pendingCapacity", "revocationCapacity")})
    p.require(all(type(value[name]) is int and value[name] == expected for name, expected in p.LIMITS.items()))
    for name, maximum in (("contactMaxSeconds", 600), ("retentionMaxSeconds", 600), ("pendingMaxSeconds", 3600),
            ("operationMaxSeconds", 30), ("recoveryMaxSeconds", 30)):
        p.require(type(value[name]) is int and 1 <= value[name] <= maximum)
    key = Ed25519PublicKey.from_public_bytes(enrollment._b64(value["successionRootPublicKeyBase64Url"], 32))
    pin = enrollment._spki(key); p.require(pin == value["successionRootSpkiSha256"])
    forbidden = {enrollment._spki(target_root)}
    if root_key is not None:
        forbidden.add(enrollment._spki(root_key))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items() if type(item) is str
            and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
    for name, other in payload.items():
        if name != FIELD and type(other) is dict:
            forbidden.update(item for field, item in other.items() if type(item) is str
                and (field.endswith("SpkiDigest") or field.endswith("SpkiSha256")))
    p.require(pin not in forbidden, "succession effect root must be independent")
    roots, order = {enrollment._spki(target_root): target_root}, []
    p.require(type(value["historicalEnrollmentRoots"]) is list and len(value["historicalEnrollmentRoots"]) <= p.MAX_MATERIALS)
    for historical in value["historicalEnrollmentRoots"]:
        p.require(type(historical) is dict and set(historical) == {"publicKeyBase64Url", "spkiSha256"})
        actual = Ed25519PublicKey.from_public_bytes(enrollment._b64(historical["publicKeyBase64Url"], 32))
        actual_pin = enrollment._spki(actual)
        p.require(actual_pin == historical["spkiSha256"] and actual_pin != pin and actual_pin not in roots)
        roots[actual_pin] = actual; order.append(actual_pin)
    p.require(order == sorted(set(order)))
    native._trust(value["trustRoots"])
    assignments, identities = value["assignments"], []
    p.require(type(assignments) is list and 1 <= len(assignments) <= 32)
    for entry in assignments:
        p.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        native._assignment({name: entry[name] for name in native.ASSIGNMENT_FIELDS})
        p.require(entry["keyId"] not in forbidden | {pin} and entry["keyId"] != entry["controlPlaneResponseSigningKeyId"]
            and entry["enrollmentRootSpkiSha256"] in roots and entry["providerId"] in p.material.AUTHORIZATION)
        p.material.text(entry["instanceId"], 4096); p.require(entry["instanceId"].startswith("spiffe://"))
        for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
            p.digest(entry[name])
        p.material.origin(entry["portalOrigin"]); p.material.origin(entry["callbackOrigin"])
        p.require(entry["portalOrigin"] != entry["callbackOrigin"])
        kek = entry["secretKekId"]
        p.require(type(kek) is str and kek.startswith("attested-memory-kek:") and len(kek) == 44
            and all(char in "0123456789abcdef" for char in kek[-24:]))
        identities.append((entry["holderId"], entry["enrollmentSha256"]))
    p.require(identities == sorted(set(identities)))
    prior = payload.get(enrollment.FIELD)
    if prior is not None:
        p.require(all(value[name] == prior[name] for name in enrollment.FIELDS - {"schema"}))
    return target_root, key, roots


def assignment(policy, statement):
    entries = [entry for entry in policy["assignments"] if entry["holderId"] == statement["holderId"]
        and entry["enrollmentSha256"] == statement["enrollmentSha256"]]
    p.require(len(entries) == 1)
    return entries[0]


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = p.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    keys = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    p.require(keys is not None and type(now_epoch_ns) is int and now_epoch_ns > 0)
    target_root, successor_root, roots = keys
    raw = p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES)
    signed = p.grant_document(raw); grant = signed["payload"]
    successor_root.verify(enrollment._b64(signed["signatureBase64Url"], 64), p.GRANT_SCHEMA.encode("ascii") + b"\0" + p.canonical(grant))
    p.require(grant["sourceRevision"] == configuration_payload["sourceRevision"]
        and grant["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and grant["deploymentId"] == policy["deploymentId"]
        and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"]
        and grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= policy["authorizationMaxSeconds"] * 1_000_000_000)
    enrollment_raw = p.activation.enrollment_bytes(values["enrollment_original"])
    envelope = enrollment.enrollment_document(enrollment_raw); application = envelope["payload"]
    historical = operation in p.MATERIAL_OPERATIONS | {p.OP_RECOVER} and values["request"]["materialId"] is not None
    proof = values["native_evidence"] if operation in p.NATIVE_OPERATIONS else None
    expected = assignment(policy, proof["statement"]) if proof is not None else None
    admitted_root = roots[expected["enrollmentRootSpkiSha256"]] if historical else target_root
    admitted_root.verify(enrollment._b64(envelope["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + p.canonical(application))
    p.require(application["providerId"] == grant["providerId"] and application["deploymentId"] == grant["deploymentId"])
    if not historical:
        p.require(application["sourceRevision"] == grant["sourceRevision"]
            and application["configurationDigest"] == grant["configurationDigest"]
            and application["clientId"] == grant["clientId"] and p.sha256(enrollment_raw) == grant["enrollmentSha256"]
            and application["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] < grant["expiresAtEpochNs"] <= application["expiresAtEpochNs"])
    # A historical enrollment authenticates retained material only. Its expired
    # issuance interval never supplies the new cleanup effect permission.
    if operation not in p.NATIVE_OPERATIONS:
        return
    statement = proof["statement"]
    p.require(values["assignment_original"] == expected and statement["providerId"] == expected["providerId"]
        and statement["deploymentId"] == policy["deploymentId"]
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"]
        <= statement["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId", "callbackOrigin", "portalOrigin"):
        p.require(statement[name] == expected[name])
    p.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    if operation in p.FRESH_OPERATIONS:
        p.require(application["redirectUri"] == p.material.callback_uri(expected["callbackOrigin"], expected["providerId"])
            and values["request"]["limits"] == {name: policy[name] for name in ("pendingCapacity", "revocationCapacity")})
    request = values["request"]
    for name in ("stateEnvelope", "reservedEnvelope", "callbackEnvelope", "rawResponseEnvelope", "issuedMaterialEnvelope", "tokenEnvelope", "identityRawEnvelope"):
        if request.get(name) is not None:
            p.require(request[name]["secret_kek_id"] == expected["secretKekId"])
    if operation == p.OP_FINISH:
        transport = p.document(p.decoded(request["transportOriginal"], p.MAX_TRANSPORT_BYTES), p.MAX_TRANSPORT_BYTES)
        p.require(transport["rawResponseEnvelope"]["secret_kek_id"] == expected["secretKekId"])
    raw_key = p.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key); p.require(enrollment._spki(key) == expected["keyId"])
    signature = p.decoded(proof["signature"][8:], 64, 64); statement_raw = p.canonical(statement)
    key.verify(signature, p.SIGNATURE_DOMAIN + statement_raw)
    nonce = hashlib.sha256(p.ATTESTATION_DOMAIN + p.decoded(statement["challenge"], 32, 32)
        + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + p.decoded(expected["bootId"], 32, 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    original = p.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12288)
    trust_roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(original, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=trust_roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now_epoch_ns // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    p.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
