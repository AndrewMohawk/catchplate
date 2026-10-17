"""Fresh purpose-fixed native N+1 evidence; historical provenance is not a live grant."""
import base64
from datetime import datetime, timezone
import hashlib
import re
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from catchplate import authority_credential_currentness as current
from catchplate import authority_credential_currentness_policy as native
from catchplate import authority_static_credential_rotate as profile
from catchplate import authority_static_credential_assignment as assignment
from catchplate import static_credential_provenance_values as values
from catchplate import authority_static_credential_custody as runtime

canonical, sha256, digest, require = profile.canonical, profile.sha256, profile.digest, profile.require
FIELD = "staticCredentialCustodyPolicy"
SCHEMA = "catchplate.staticCredentialCustodyAuthorityPolicy/v2"
TRUST_SCHEMA = "catchplate.staticCredentialNativeTrustRoots/v1"
STATEMENT_SCHEMA = values.ROTATION_STATEMENT_SCHEMA
SIGN_OPERATION = "nativeStaticCredentialRotation.sign/v1"
SIGNATURE_DOMAIN = STATEMENT_SCHEMA.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"catchplate/native-static-credential-rotation-attestation/v1\0"
MAX_EVIDENCE_BYTES = values.MAX_EVIDENCE_BYTES
MAX_AUTHORITY_EVIDENCE_BYTES = MAX_EVIDENCE_BYTES + 2 * assignment.MAX_ORIGINAL_BYTES + 256
MAX_POLICY_BYTES = 512 * 1024
POLICY_FIELDS = frozenset({"schema", "deploymentId",
    "operationMaxSeconds", "trustRoots", "assignmentAuthorizer", "target"})
ASSIGNMENT_FIELDS = assignment.ASSIGNMENT_FIELDS
STATEMENT_FIELDS = values.ROTATION_STATEMENT_FIELDS
_SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")


def _integer(value):
    require(type(value) is int and 0 < value <= 2**63 - 1)
    return value


def _text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def origin(value):
    _text(value, 2048)
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and parsed.username is None
        and parsed.password is None and parsed.path == "" and parsed.query == ""
        and parsed.fragment == "" and parsed.netloc == parsed.netloc.lower()
        and parsed.port is None and not parsed.netloc.endswith(":443"))
    return value


def decoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) <= maximum and (exact is None or len(raw) == exact)
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def _evidence(value):
    """Compatibility parser only; cryptographic admission remains below."""
    return values.rotation_evidence(value)


evidence = _evidence


def authority_evidence(value):
    """Closed original transport; neither signature is verified by this parser."""
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence", "assignmentOriginal"})
    _evidence({name: value[name] for name in ("statement", "signature", "nativeKeyEvidence")})
    assignment.original(value["assignmentOriginal"])
    require(len(canonical(value)) <= MAX_AUTHORITY_EVIDENCE_BYTES)
    return value


def input_sha256(arguments):
    values = profile.arguments(profile.OPERATION, arguments, typed="businessIntent" in arguments)
    return sha256(canonical(values))


def _bind(values, proof, now_epoch_ns):
    _integer(now_epoch_ns)
    item, request = proof["statement"], values["request"]
    selected = assignment.original(proof["assignmentOriginal"])["payload"]
    require(selected["controlPlaneConfigurationDigest"] == values["control_plane_configuration_digest"]
        and selected["deploymentId"] == item["deploymentId"]
        and selected["assignment"]["holderId"] == item["holderId"]
        and selected["issuedAtEpochNs"] <= item["issuedAtEpochNs"]
        < item["expiresAtEpochNs"] <= selected["expiresAtEpochNs"])
    original = request["nativeGenerationOriginal"].encode("ascii")
    generation = profile.generation(request["nativeGenerationOriginal"])
    stamp = datetime.fromisoformat(generation["envelope"]["secret_updated_at"])
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    generation_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    require(item["inputSha256"] == sha256(canonical(values))
        and item["generationSha256"] == sha256(original)
        and item["intentSha256"] == generation["intentSha256"]
        and item["actorId"] == values["actor_id"]
        and item["controlPlaneConfigurationDigest"] == values["control_plane_configuration_digest"]
        and item["credentialId"] == request["credentialId"]
        and item["credentialVersion"] == request["credentialVersion"]
        and item["previousCredentialVersion"] == request["previousCredentialVersion"]
        and item["previousCredentialSha256"] == request["previousCredentialSha256"]
        and item["previousCurrentnessOriginRequestDigest"] == request["previousCurrentnessOriginRequestDigest"]
        and item["previousProvenanceSha256"] == sha256(request["previousProvenanceOriginal"].encode("ascii"))
        and item["predecessorBarrierSha256"] == request["predecessorBarrierSha256"]
        and item["predecessorCurrentnessRootSha256"] == request["predecessorCurrentnessRootSha256"]
        and item["secretKekId"] == generation["envelope"]["secret_kek_id"]
        and item["generationCreatedAtEpochNs"] == generation_ns
        and request["executionIssuedAtEpochNs"] <= item["issuedAtEpochNs"] <= now_epoch_ns
        < item["expiresAtEpochNs"] <= request["executionExpiresAtEpochNs"],
        "Static native proof differs from its literal generation or current execution")


def bind_originals(*, arguments, evidence, now_epoch_ns):
    """Kernel rejoin for independently verified literal evidence, not a verdict.

    Calling this on caller-supplied evidence is insufficient. The actual
    authority service must run verify_original on those same originals before
    issuing capability and clip its original deadline to the statement expiry.
    """
    values = profile.arguments(profile.OPERATION, arguments, typed="businessIntent" in arguments)
    _bind(values, authority_evidence(evidence), now_epoch_ns)


_trust = runtime._trust
validate_policy = runtime.validate_policy


def verify_original(operation, arguments, *, evidence, configuration_payload, root_key, now_epoch_ns):
    """Verify original native bytes; no admission DTO or authority escapes.

    The caller owns signed configuration admission and the original cumulative
    request deadline. It must check that deadline after verification and before
    capability issuance; neither old generation time nor a quote renews it.
    """
    from catchplate.authority_policy_canary_policy import full_configuration_digest

    require(operation == profile.OPERATION and root_key is not None)
    configuration_digest = full_configuration_digest(configuration_payload)
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None)
    profile.verify_request_context(operation, values, selected_policy=configuration_payload[profile.FIELD],
        expected_configuration_digest=configuration_digest, now_epoch_ns=now_epoch_ns)
    proof = authority_evidence(evidence)
    selected_assignment = assignment.verify_original(proof["assignmentOriginal"],
        configuration_payload=configuration_payload, root_key=root_key, now_epoch_ns=now_epoch_ns)
    _bind(values, proof, now_epoch_ns)
    item = proof["statement"]
    expected = selected_assignment["assignment"]
    require(expected["holderId"] == item["holderId"], "Static producer differs from its signed postboot assignment")
    require(item["deploymentId"] == selected["deploymentId"]
        and item["controlPlaneConfigurationDigest"] == configuration_digest
        and item["expiresAtEpochNs"] <= item["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId",
            "secretKekId", "intakeOrigin", "portalOrigin"):
        require(item[name] == expected[name])
    require(item["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    # Leaf digests are measured BrowserTls owner output signed below, not a
    # certificate or TLS identity accepted independently from an HTTP caller.
    raw_key = decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = decoded(proof["signature"][8:], 64, 64)
    statement_raw = canonical(item)
    key.verify(signature, SIGNATURE_DOMAIN + statement_raw)
    nonce = hashlib.sha256(ATTESTATION_DOMAIN + decoded(item["challenge"], 32, 32)
        + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0"
        + current.encoded(expected["bootId"], 32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(expected[name][7:]) for name in _SCOPE_DIGESTS) + hashlib.sha256(raw_key).digest() + boot_binding
    document = decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    roots, crls, certificate_profile = _trust(selected["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificate_profile,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
