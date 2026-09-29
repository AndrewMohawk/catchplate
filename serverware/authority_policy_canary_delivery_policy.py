"""Independent delivery permission and historical-to-current observation scope.

The genuine measured configuration is retained in-process by the planner. No
HTTP value, verified flag or exported admission token supplies that source.
"""
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness_policy as native
from serverware import authority_policy_canary as intake
from serverware import authority_policy_canary_policy as intake_policy
from serverware import authority_policy_canary_delivery as profile

FIELD = "policyCanaryDeliveryPolicy"
SCHEMA = "serverware.policyCanaryDeliveryAuthorityPolicy/v1"
TRUST_SCHEMA = "serverware.policyCanaryDeliveryTrustRoots/v1"
FIELDS = frozenset({"schema", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs",
    "operationMaxSeconds", "limits", "trustRoots", "assignments", "historicalTrustRoots", "historicalAssignments", "recoveryAssociations"})
ASSIGNMENT_FIELDS = intake_policy.ASSIGNMENT_FIELDS | {"intakePurposeAssignmentSha256"}
RECOVERY_FIELDS = frozenset({"historicalAssignmentSha256", "currentAssignmentSha256", "canaryId", "instanceId",
    "issuedAtEpochNs", "expiresAtEpochNs"})


def trust(value):
    profile.require(type(value) is dict and value.get("apiVersion") == TRUST_SCHEMA)
    # Certificate decoding is shared, never another purpose's permission.
    return native._trust({**value, "apiVersion": native.TRUST_SCHEMA})


def _assignment(item, excluded):
    profile.require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
    expected = native._assignment({name: item[name] for name in native.ASSIGNMENT_FIELDS})
    profile.component(item["instanceId"]); intake.text(item["canaryId"], 256)
    for name in ("canaryAssignmentSha256", "canaryBootId", "intakePurposeAssignmentSha256"): profile.digest(item[name])
    profile.require(expected["keyId"] not in excluded and expected["keyId"] != expected["controlPlaneResponseSigningKeyId"])
    pem = item["workloadCaCertificatePem"]
    profile.require(type(pem) is str and 0 < len(pem) <= 65536)
    ca = x509.load_pem_x509_certificate(pem.encode("ascii"))
    profile.require(ca.public_bytes(serialization.Encoding.PEM) == pem.encode("ascii")
        and nitro.basic_constraints(ca, "delivery workload CA").ca and isinstance(ca.public_key(), ec.EllipticCurvePublicKey)
        and profile.sha256(ca.public_bytes(serialization.Encoding.DER)) == expected["caCertificateSha256"]
        and profile.sha256(ca.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["caPublicKeySpkiSha256"])


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "canary delivery requires its independent current policy")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    profile.component(value["deploymentId"])
    issued, expires = profile.epoch(value["issuedAtEpochNs"]), profile.epoch(value["expiresAtEpochNs"])
    profile.require(0 < expires - issued <= 86_400_000_000_000 and type(value["operationMaxSeconds"]) is int
        and 1 <= value["operationMaxSeconds"] <= 30 and value["limits"] == profile.LIMITS
        and all(type(value["limits"][name]) is int for name in profile.LIMITS))
    trust(value["trustRoots"]); trust(value["historicalTrustRoots"])
    excluded = set()
    if root_key is not None:
        excluded.add(profile.sha256(root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in payload["roles"].values():
        for name, item in role.items():
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str: excluded.add(item)
    inventories = {}
    for field in ("assignments", "historicalAssignments"):
        entries = value[field]
        profile.require(type(entries) is list and (1 if field == "assignments" else 0) <= len(entries) <= 32)
        identities, by_digest = [], {}
        for item in entries:
            _assignment(item, excluded)
            identities.append((item["canaryId"], item["instanceId"], item["holderId"]))
            by_digest[profile.sha256(profile.canonical(item))] = item
        profile.require(identities == sorted(set(identities)))
        inventories[field] = by_digest
    associations, identities = value["recoveryAssociations"], []
    profile.require(type(associations) is list and len(associations) <= 32)
    for item in associations:
        profile.require(type(item) is dict and set(item) == RECOVERY_FIELDS)
        old, new = item["historicalAssignmentSha256"], item["currentAssignmentSha256"]
        profile.digest(old); profile.digest(new)
        profile.require(old in inventories["historicalAssignments"] and new in inventories["assignments"]
            and issued <= profile.epoch(item["issuedAtEpochNs"]) < profile.epoch(item["expiresAtEpochNs"]) <= expires)
        profile.require(all(item[name] == inventories["historicalAssignments"][old][name] == inventories["assignments"][new][name]
            for name in ("canaryId", "instanceId")))
        identities.append((old, new))
    profile.require(identities == sorted(set(identities)) and len(profile.canonical(value)) <= 2 * 1024 * 1024)
    return value


def _verify_native(envelope, expected, trust_roots, now, peer_der=None):
    signed = envelope["statement"]
    for name in ("instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId", "holderId", "bootId", "keyId",
            "controlPlaneResponseSigningKeyId", "policyHash"):
        profile.require(signed[name] == expected[name])
    profile.require(signed["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    # Exact actual peer/certificate validation is identical scalar TLS
    # ownership, not an intake permission or intake signature verification.
    intake_policy._certificate(envelope, expected, now, peer_der)
    raw_key = profile.decoded(envelope["nativeKeyEvidence"]["responseProofPublicKey"], 32, length=32)
    profile.require(raw_key != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    profile.require(profile.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = profile.decoded(envelope["signature"][8:], 64, length=64)
    key.verify(signature, profile.signature_domain(signed["operation"]) + profile.canonical(signed))
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0"
        + profile.decoded(expected["bootId"], 32, length=32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    roots, crls, certificates = trust(trust_roots)
    quote = profile.decoded(envelope["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    verified, _, _, _, _ = nitro._verify_nitro_document_common(quote, claims=None, expected_user_data_bytes=user_data,
        challenge=profile.attestation_nonce(envelope), expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(verified["public_key"] == raw_key)


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns, peer_der=None):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    proof = values["native_evidence"]; signed = proof["statement"]
    profile.require(selected is not None and intake_policy.full_configuration_digest(configuration_payload) == values["control_plane_configuration_digest"]
        and selected["deploymentId"] == signed["deploymentId"] and selected["issuedAtEpochNs"] <= now_epoch_ns < selected["expiresAtEpochNs"]
        and signed["issuedAtEpochNs"] <= now_epoch_ns < signed["expiresAtEpochNs"] <= selected["expiresAtEpochNs"]
        and signed["expiresAtEpochNs"] <= signed["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
    matches = [item for item in selected["assignments"] if profile.sha256(profile.canonical(item)) == signed["purposeAssignmentSha256"]]
    profile.require(len(matches) == 1)
    expected = matches[0]
    _verify_native(proof, expected, selected["trustRoots"], now_epoch_ns, peer_der)
    if operation == profile.OP_PREPARE:
        original = profile.http_original(values["request"]["httpOriginal"])
        profile.require(original["nativeEvidence"]["statement"]["purposeAssignmentSha256"] == expected["intakePurposeAssignmentSha256"])
        intake_policy.verify_evidence(intake.OP_INTAKE, original["batchOriginal"], original["nativeEvidence"],
            values["control_plane_configuration_digest"], configuration_payload=configuration_payload, root_key=root_key,
            now_epoch_ns=now_epoch_ns, peer_der=peer_der)


class _Admission:
    """Retain only the actual authority process's measured configuration."""
    __slots__ = ("_configuration", "_original", "_digest")

    def __init__(self, configuration):
        from serverware import authority_service as service
        profile.require(type(configuration) is service.MeasuredConfiguration)
        self._configuration = configuration
        self._original, self._digest = configuration.original_bytes, configuration.digest
        self.check()

    def check(self):
        from serverware import authority_service as service
        configured = self._configuration
        profile.require(type(configured) is service.MeasuredConfiguration and configured.original_bytes is self._original
            and configured.digest == self._digest and service._sha256(self._original) == configured.file_digest
            and service._domain_digest(service.CONFIG_SCHEMA, service._canonical(configured.payload)) == self._digest)
        envelope = profile.document(self._original, service.MAX_CONFIG_BYTES, exact=False)
        profile.require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == service.SIGNED_CONFIG_SCHEMA
            and envelope["payload"] == configured.payload)
        configured.root_key.verify(profile.decoded(envelope["signature"], 64, length=64),
            service._domain_digest(service.SIGNED_CONFIG_SCHEMA, profile.canonical(envelope["payload"])).encode("ascii"))
        selected = validate_policy(configured.payload.get(FIELD), payload=configured.payload, root_key=configured.root_key)
        profile.require(selected is not None)
        return selected

    def verify(self, operation, arguments, now):
        self.check()
        verify_original(operation, arguments, configuration_payload=self._configuration.payload,
            root_key=self._configuration.root_key, now_epoch_ns=now)

    def require_slot_reader(self, slot, signed, now):
        selected = self.check()
        profile.require(selected["issuedAtEpochNs"] <= now < selected["expiresAtEpochNs"]
            and slot["deployment_id"] == signed["deploymentId"] and slot["canary_id"] == signed["canaryId"]
            and slot["instance_id"] == signed["instanceId"])
        same = slot["delivery_assignment_digest"] == signed["purposeAssignmentSha256"]
        if same:
            profile.require(slot["holder_id"] == signed["holderId"] and slot["native_boot_id"] == signed["bootId"] and slot["key_id"] == signed["keyId"])
            return
        profile.require(signed["operation"] == profile.OP_RECOVER, "historical observation never transfers claim authority")
        matches = [item for item in selected["recoveryAssociations"]
            if item["historicalAssignmentSha256"] == slot["delivery_assignment_digest"]
            and item["currentAssignmentSha256"] == signed["purposeAssignmentSha256"]
            and item["canaryId"] == slot["canary_id"] and item["instanceId"] == slot["instance_id"]
            and item["issuedAtEpochNs"] <= now < item["expiresAtEpochNs"]]
        profile.require(len(matches) == 1, "new boot has no independent historical/current observation association")
        historical = [item for item in selected["historicalAssignments"]
            if profile.sha256(profile.canonical(item)) == slot["delivery_assignment_digest"]]
        profile.require(len(historical) == 1 and historical[0]["intakePurposeAssignmentSha256"] == slot["intake_assignment_digest"])
        proof = profile.evidence(profile.document(slot["prepare_evidence_original"].encode("ascii"), 128 * 1024))
        profile.require(proof["statement"]["operation"] == profile.OP_PREPARE
            and proof["statement"]["slotId"] == slot["id"] and proof["statement"]["httpSha256"] == slot["http_sha256"]
            and proof["statement"]["purposeAssignmentSha256"] == slot["delivery_assignment_digest"])
        _verify_native(proof, historical[0], selected["historicalTrustRoots"], proof["statement"]["issuedAtEpochNs"])
