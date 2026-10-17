"""Independent native pending-retirement assignment and fresh family grant."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_credential_currentness_policy as native
from catchplate import authority_oauth_measured_pending_retirement as profile
from catchplate.oauth_pending_retirement_policy import (
    FIELD, SCHEMA, FIELDS, ASSIGNMENT_FIELDS, validate_policy, assignment, verify_grant,
)


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
    boot = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + profile.unb64(expected["bootId"], 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot
    roots, crls, certificates = native._trust(policy["trustRoots"])
    verified, _, _, _, _ = native.nitro._verify_nitro_document_common(
        profile.unb64(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024), claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now_epoch_ns // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
