"""Purpose-only native canary authorship under the actual signed configuration.

The outer proof authenticates a sender, not any inner canary assertion. The
transaction independently verifies every historical/current signed original.
"""
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness_policy as native
from serverware import authority_policy_canary as profile
from serverware import authority_request_commitment as commitment

FIELD = "policyCanaryIntakePolicy"
SCHEMA = "serverware.policyCanaryIntakeAuthorityPolicy/v2"
CONFIGURATION_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
TRUST_SCHEMA = "serverware.policyCanaryNativeTrustRoots/v1"
FIELDS = frozenset({"schema", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs",
    "operationMaxSeconds", "limits", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {"instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId", "workloadCaCertificatePem"}


def full_configuration_digest(payload):
    """Hash the full independently admitted payload, without exclusions.

    An embedded purpose cannot contain its own enclosing configuration digest.
    Runtime/cold pins are made only after the complete signed original exists.
    """
    profile.require(type(payload) is dict and payload.get("schema") == CONFIGURATION_SCHEMA)
    return commitment.framed_digest(CONFIGURATION_SCHEMA, profile.canonical(payload))


def trust(value):
    profile.require(type(value) is dict and value.get("apiVersion") == TRUST_SCHEMA)
    # Only certificate parsing is shared. Neither the old profile nor any old
    # currentness/audit assignment authorizes this purpose.
    return native._trust({**value, "apiVersion": native.TRUST_SCHEMA})


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "native canary intake requires its separately admitted policy")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    profile.component(value["deploymentId"])
    issued, expires = profile.epoch(value["issuedAtEpochNs"]), profile.epoch(value["expiresAtEpochNs"])
    profile.require(0 < expires - issued <= 86_400_000_000_000 and type(value["operationMaxSeconds"]) is int
        and 1 <= value["operationMaxSeconds"] <= 30 and value["limits"] == profile.LIMITS
        and all(type(value["limits"][name]) is int for name in profile.LIMITS))
    trust(value["trustRoots"])
    assignments = value["assignments"]
    profile.require(type(assignments) is list and 1 <= len(assignments) <= 32)
    excluded = set()
    if root_key is not None:
        excluded.add(profile.sha256(root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in payload["roles"].values():
        for name, item in role.items():
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str:
                excluded.add(item)
    identities = []
    for item in assignments:
        profile.require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
        expected = native._assignment({name: item[name] for name in native.ASSIGNMENT_FIELDS})
        profile.component(item["instanceId"]); profile.text(item["canaryId"], 256)
        profile.digest(item["canaryAssignmentSha256"]); profile.digest(item["canaryBootId"])
        profile.require(expected["keyId"] not in excluded and expected["keyId"] != expected["controlPlaneResponseSigningKeyId"])
        pem = item["workloadCaCertificatePem"]
        profile.require(type(pem) is str and 0 < len(pem) <= 65536)
        ca = x509.load_pem_x509_certificate(pem.encode("ascii"))
        profile.require(ca.public_bytes(serialization.Encoding.PEM) == pem.encode("ascii")
            and nitro.basic_constraints(ca, "canary workload CA").ca
            and isinstance(ca.public_key(), ec.EllipticCurvePublicKey)
            and profile.sha256(ca.public_bytes(serialization.Encoding.DER)) == expected["caCertificateSha256"]
            and profile.sha256(ca.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["caPublicKeySpkiSha256"])
        identities.append((item["canaryId"], item["instanceId"], item["holderId"]))
    profile.require(identities == sorted(set(identities)) and len(profile.canonical(value)) <= 2 * 1024 * 1024)
    return value


def _certificate(envelope, assignment, now, peer_der):
    statement = envelope["statement"]
    original = profile.decoded(envelope["clientCertificateDerBase64Url"], 16 * 1024)
    if peer_der is not None:
        profile.require(type(peer_der) is bytes and original == peer_der, "signed canary sender differs from actual TLS peer")
    leaf = x509.load_der_x509_certificate(original)
    ca = x509.load_pem_x509_certificate(assignment["workloadCaCertificatePem"].encode("ascii"))
    profile.require(leaf.public_bytes(serialization.Encoding.DER) == original and leaf.issuer == ca.subject
        and not nitro.basic_constraints(leaf, "canary TLS leaf").ca)
    ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    for cert in (leaf, ca):
        profile.require(int(cert.not_valid_before_utc.timestamp()) * 1_000_000_000 <= now
            < int(cert.not_valid_after_utc.timestamp()) * 1_000_000_000)
    profile.require(list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        and list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
            == [x509.UniformResourceIdentifier(statement["workloadUri"])]
        and profile.sha256(leaf.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)) == statement["clientSpkiSha256"])


def verify_evidence(operation, batch_original, evidence, configuration_digest, *, configuration_payload, root_key,
        now_epoch_ns, peer_der=None):
    original = profile.batch(batch_original)
    envelope = profile.evidence(evidence); statement = envelope["statement"]
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    profile.require(selected is not None and operation in {profile.OP_INTAKE, profile.OP_INSPECT}
        and statement["operation"] == operation and statement["requestId"] == original["requestId"]
        and statement["canaryId"] == original["canaryId"]
        and statement["batchSha256"] == profile.sha256(batch_original.encode("ascii"))
        and configuration_digest == full_configuration_digest(configuration_payload)
        and statement["deploymentId"] == selected["deploymentId"]
        and selected["issuedAtEpochNs"] <= now_epoch_ns < selected["expiresAtEpochNs"]
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"] <= selected["expiresAtEpochNs"]
        and statement["expiresAtEpochNs"] <= statement["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
    matches = [item for item in selected["assignments"]
        if profile.sha256(profile.canonical(item)) == statement["purposeAssignmentSha256"]]
    profile.require(len(matches) == 1, "canary sender has no exact independently admitted purpose assignment")
    expected = matches[0]
    for name in ("instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId", "holderId", "bootId", "keyId",
            "controlPlaneResponseSigningKeyId", "policyHash"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    _certificate(envelope, expected, now_epoch_ns, peer_der)
    raw_key = profile.decoded(envelope["nativeKeyEvidence"]["responseProofPublicKey"], 32, length=32)
    profile.require(raw_key != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    profile.require(profile.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = profile.decoded(envelope["signature"][8:], 64, length=64)
    key.verify(signature, profile.STATEMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(statement))
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0"
        + profile.decoded(expected["bootId"], 32, length=32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    roots, crls, certificates = trust(selected["trustRoots"])
    quote = profile.decoded(envelope["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    verified, _, _, _, _ = nitro._verify_nitro_document_common(quote, claims=None, expected_user_data_bytes=user_data,
        challenge=profile.attestation_nonce(envelope), expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now_epoch_ns // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(verified["public_key"] == raw_key)
    # No transferable success DTO escapes. Callers retain/recheck originals.


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    verify_evidence(operation, values["batch_original"], values["native_evidence"], values["control_plane_configuration_digest"],
        configuration_payload=configuration_payload, root_key=root_key, now_epoch_ns=now_epoch_ns)
