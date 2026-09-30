"""Independent native heartbeat authority; never Fleet or intake permission."""
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness_policy as native
from serverware import authority_policy_canary as p

FIELD = "policyCanaryFinalizationPolicy"
SCHEMA = "serverware.policyCanaryFinalizationAuthorityPolicy/v1"
TRUST_SCHEMA = "serverware.policyCanaryFinalizationTrustRoots/v1"
RECORD = "serverware.nativePolicyShadowHeartbeat/v2"
STATEMENT = "serverware.nativePolicyShadowHeartbeatStatement/v2"
PURPOSE = "native-policy-shadow-finalization"
FIELDS = frozenset({"schema", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs", "operationMaxSeconds",
    "maximumGapNanos", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {"instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId"}
RECORD_FIELDS = frozenset({"apiVersion", "canary_id", "instance_id", "boot_id", "assignment_envelope_digest",
    "assignment_payload_digest", "load_receipt_envelope_digest", "publication_envelope_digest", "evidence"})
STATEMENT_FIELDS = frozenset({"apiVersion", "purpose", "deploymentId", "instanceId", "holderId", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256", "purposeAssignmentSha256", "canaryId",
    "canaryAssignmentSha256", "canaryBootId", "assignmentPayloadSha256", "loadReceiptSha256", "publicationSha256",
    "generationId", "runtimeIdentitySha256", "heartbeatSequence", "previousHeartbeatSha256", "baselineEventOrdinal",
    "baselineHeadSha256", "eventOrdinal", "headSha256", "originalCount", "lastIngressSequence", "openingReceiptSha256",
    "observedAtUnixNanos", "issuedAtEpochNs", "expiresAtEpochNs", "nonce", "seal"})


def trust(value):
    p.require(type(value) is dict and value.get("apiVersion") == TRUST_SCHEMA)
    return native._trust({**value, "apiVersion": native.TRUST_SCHEMA})


def validate_policy(value, *, payload, root_key=None):
    if value is None:
        return None
    p.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    p.component(value["deploymentId"])
    issued, expires = p.epoch(value["issuedAtEpochNs"]), p.epoch(value["expiresAtEpochNs"])
    p.require(0 < expires - issued <= 86_400_000_000_000
        and type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumGapNanos"]) is int and 1_000_000_000 <= value["maximumGapNanos"] <= 60_000_000_000)
    trust(value["trustRoots"])
    assignments = value["assignments"]
    p.require(type(assignments) is list and 1 <= len(assignments) <= 32)
    excluded = {item for role in payload["roles"].values() for name, item in role.items()
        if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str}
    if root_key is not None:
        excluded.add(p.sha256(root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    identities = []
    for item in assignments:
        p.require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
        native._assignment({name: item[name] for name in native.ASSIGNMENT_FIELDS})
        p.component(item["instanceId"]); p.text(item["canaryId"], 256)
        p.digest(item["canaryAssignmentSha256"]); p.digest(item["canaryBootId"])
        p.require(item["keyId"] not in excluded and item["keyId"] != item["controlPlaneResponseSigningKeyId"])
        identities.append((item["canaryId"], item["instanceId"], item["holderId"]))
    p.require(identities == sorted(set(identities)) and len(p.canonical(value)) <= 2 * 1024 * 1024)
    return value


def record(value):
    p.require(type(value) is dict and set(value) == RECORD_FIELDS and value["apiVersion"] == RECORD
        and len(p.canonical(value)) <= 65536)
    proof = value["evidence"]
    p.require(type(proof) is dict and set(proof) == {"statement", "signature", "nativeKeyEvidence"})
    s = proof["statement"]
    p.require(type(s) is dict and set(s) == STATEMENT_FIELDS and s["apiVersion"] == STATEMENT and s["purpose"] == PURPOSE)
    for key in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256",
            "purposeAssignmentSha256", "canaryAssignmentSha256", "canaryBootId", "assignmentPayloadSha256", "loadReceiptSha256",
            "publicationSha256", "generationId", "runtimeIdentitySha256", "previousHeartbeatSha256", "baselineHeadSha256", "headSha256"):
        p.digest(s[key])
    for key in ("deploymentId", "instanceId"):
        p.component(s[key])
    p.text(s["canaryId"], 256)
    p.decoded(s["bootId"], 32, length=32); p.decoded(s["nonce"], 32, length=32)
    for key in ("heartbeatSequence", "observedAtUnixNanos", "issuedAtEpochNs", "expiresAtEpochNs"):
        p.epoch(s[key])
    for key in ("baselineEventOrdinal", "eventOrdinal", "originalCount"):
        p.require(type(s[key]) is int and 0 <= s[key] <= 9_223_372_036_854_775_807)
    p.require(1 <= s["heartbeatSequence"] <= 32 and s["observedAtUnixNanos"] == s["issuedAtEpochNs"]
        and 0 < s["expiresAtEpochNs"] - s["issuedAtEpochNs"] <= 30_000_000_000
        and 0 <= s["eventOrdinal"] - s["baselineEventOrdinal"] == s["originalCount"] <= 64)
    if s["lastIngressSequence"] is None:
        p.require(s["openingReceiptSha256"] is None)
    else:
        p.require(p.epoch(s["lastIngressSequence"]) > 0); p.digest(s["openingReceiptSha256"])
    for outer, inner in (("canary_id", "canaryId"), ("instance_id", "instanceId"), ("boot_id", "canaryBootId"),
            ("assignment_envelope_digest", "canaryAssignmentSha256"), ("assignment_payload_digest", "assignmentPayloadSha256"),
            ("load_receipt_envelope_digest", "loadReceiptSha256"), ("publication_envelope_digest", "publicationSha256")):
        p.require(value[outer] == s[inner])
    p.require(type(proof["signature"]) is str and proof["signature"].startswith("ed25519:"))
    p.decoded(proof["signature"][8:], 64, length=64)
    key = proof["nativeKeyEvidence"]
    p.require(type(key) is dict and set(key) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and key["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    p.decoded(key["responseProofPublicKey"], 32, length=32); p.decoded(key["attestationDocumentB64"], 12288)
    seal(s)
    return s


def verify_record(value, configuration_payload, root_key, now_epoch_ns):
    s = record(value); proof = value["evidence"]
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    p.require(policy is not None and policy["deploymentId"] == s["deploymentId"]
        and policy["issuedAtEpochNs"] <= s["issuedAtEpochNs"] <= now_epoch_ns < s["expiresAtEpochNs"] <= policy["expiresAtEpochNs"]
        and s["expiresAtEpochNs"] - s["issuedAtEpochNs"] <= policy["operationMaxSeconds"] * 1_000_000_000)
    matches = [item for item in policy["assignments"] if p.sha256(p.canonical(item)) == s["purposeAssignmentSha256"]]
    p.require(len(matches) == 1); expected = matches[0]
    for name in ("instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId", "holderId", "bootId", "keyId",
            "controlPlaneResponseSigningKeyId", "policyHash"):
        p.require(s[name] == expected[name])
    p.require(s["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    raw = p.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, length=32)
    p.require(raw != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw)
    p.require(p.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = p.decoded(proof["signature"][8:], 64, length=64)
    key.verify(signature, STATEMENT.encode("ascii") + b"\0" + p.canonical(s))
    boot = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + p.decoded(expected["bootId"], 32, length=32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw).digest() + boot
    nonce = hashlib.sha256(b"serverware/native-policy-shadow-finalization-attestation/v1\0"
        + p.decoded(s["nonce"], 32, length=32) + hashlib.sha256(p.canonical(s)).digest() + signature).digest()
    roots, crls, certificates = trust(policy["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(p.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12288),
        claims=None, expected_user_data_bytes=user, challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=roots, crls=crls, certificate_profile=certificates, expected_module_id=expected["expectedModuleId"],
        now=now_epoch_ns // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    p.require(verified["public_key"] == raw)


def verify_batch(batch_original, *, configuration_payload, root_key, now_epoch_ns, before_original):
    batch = p.batch(batch_original)
    for event in batch["events"]:
        item = event["record"]
        if event["kind"] == "custody" and item.get("apiVersion") == RECORD:
            p.require(len(batch["events"]) == 1)
            verify_record(item, configuration_payload, root_key, now_epoch_ns)
            # These before rows are later matched against complete protected
            # roots by the planner and again inside the same transition.
            before = p.document(before_original.encode("ascii"), p.MAX_ARGUMENT)
            current = item["evidence"]["statement"]
            observed = []
            for row in before[p.TABLE]:
                for event_before in p.batch(row["batch_original"])["events"]:
                    prior = event_before["record"]
                    if event_before["kind"] == "custody" and prior.get("apiVersion") == RECORD:
                        previous = record(prior)
                        if previous["generationId"] == current["generationId"]:
                            observed.append(previous["observedAtUnixNanos"])
            if not observed:
                loads = [row for row in before["policy_canary_load_receipts"]
                    if all(row[name] == item[name] for name in ("canary_id", "instance_id", "boot_id"))]
                p.require(len(loads) == 1)
                load = p.document(loads[0]["load_receipt_payload_json"].encode("ascii"), p.MAX_ORIGINAL)
                assignments = [row for row in before["policy_canary_assignments"] if row["canary_id"] == item["canary_id"]]
                p.require(len(assignments) == 1)
                assignment = p.document(assignments[0]["assignment_payload_json"].encode("ascii"), p.MAX_ORIGINAL)
                observed.append(max(load["issuedAtUnixNanos"], load["loadedAtUnixNanos"], assignment["observationWindow"]["startsAtUnixNanos"]))
            p.require(0 <= current["observedAtUnixNanos"] - max(observed)
                <= configuration_payload[FIELD]["maximumGapNanos"])
        elif event["kind"] == "checkpoint" and item.get("apiVersion") == "serverware.nativeCumulativeCheckpoint/v2":
            p.require(len(batch["events"]) == 1)
            verify_record(item["heartbeat"], configuration_payload, root_key, now_epoch_ns)

def seal(statement):
    value = statement["seal"]
    if value is None:
        return
    p.require(type(value) is dict and set(value) == {"apiVersion", "generationId", "windowEndsAtUnixNanos",
        "sealDeadlineUnixNanos", "admissionClosedAtUnixNanos", "drainedAtUnixNanos", "admissionAttempts",
        "pendingAdmissions", "liveLifecycles", "unfinishedLifecycles", "lifecycles", "coverageStartedAtUnixNanos"})
    p.require(value["apiVersion"] == "serverware.nativePolicyShadowDrain/v1"
        and value["generationId"] == statement["generationId"])
    for name in ("coverageStartedAtUnixNanos", "windowEndsAtUnixNanos", "sealDeadlineUnixNanos", "admissionClosedAtUnixNanos", "drainedAtUnixNanos"):
        p.epoch(value[name])
    p.require(value["coverageStartedAtUnixNanos"] <= value["admissionClosedAtUnixNanos"]
        and value["windowEndsAtUnixNanos"] <= value["admissionClosedAtUnixNanos"] <= value["drainedAtUnixNanos"]
        <= statement["observedAtUnixNanos"] < statement["expiresAtEpochNs"] <= value["sealDeadlineUnixNanos"])
    for name in ("pendingAdmissions", "liveLifecycles", "unfinishedLifecycles"):
        p.require(type(value[name]) is int and value[name] == 0)
    p.require(type(value["admissionAttempts"]) is int and 0 <= value["admissionAttempts"] <= 64
        and type(value["lifecycles"]) is list and len(value["lifecycles"]) <= value["admissionAttempts"])
    previous = 0
    for row in value["lifecycles"]:
        p.require(type(row) is dict and set(row) == {"ingressSequence", "requestBindingSha256", "requestCommitmentSha256",
            "dispatchAuthorized", "observations"} and type(row["dispatchAuthorized"]) is bool)
        p.require(p.epoch(row["ingressSequence"]) > previous)
        previous = row["ingressSequence"]
        p.digest(row["requestBindingSha256"]); p.digest(row["requestCommitmentSha256"])
        observed = row["observations"]
        p.require(type(observed) is dict and set(observed) == {"openingReceiptSha256", "terminalReceiptSha256",
            "candidateReceiptSha256", "responseReceiptSha256"})
        for name in ("openingReceiptSha256", "terminalReceiptSha256", "candidateReceiptSha256"):
            p.digest(observed[name])
        if row["dispatchAuthorized"]:
            p.digest(observed["responseReceiptSha256"])
        else:
            p.require(observed["responseReceiptSha256"] is None)
