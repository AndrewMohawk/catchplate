"""Exact native IngressOpen original, not terminal canary coverage.

The native exporter retains a completed production admission. This receiver
checks its dedicated custody signature against the independently protected
assignment and publication. Persistence/retrieval digests remain the original
receipt's commitments, not independent physical-storage proof manufactured here.
"""
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_policy_canary as profile
from catchplate.policy_shadow_assignment_fields import LEGACY_FIELDS, NATIVE_FIELDS

SCHEMA = "catchplate.nativeCustodyOpening/v1"
EARLY_SCHEMA = "catchplate.nativeCustodyOpening/v2"
EARLY_EVENT = "catchplate.nativeShadowIngressAdmissionEvent/v1"
SCHEMAS = frozenset({SCHEMA, EARLY_SCHEMA})
MAX_RECORD = 64 * 1024
FIELDS = frozenset({"apiVersion", "canary_id", "instance_id", "boot_id", "assignment_envelope_digest",
    "assignment_payload_digest", "load_receipt_envelope_digest", "publication_envelope_digest",
    "opening_receipt", "signing_public_key_base64url"})
RECEIPT_FIELDS = frozenset({"generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256",
    "event_ordinal", "event_phase", "disposition", "event_sha256", "canonical_event_bytes", "predecessor_event_ordinal",
    "predecessor_head_sha256", "resulting_head_sha256", "trusted_observed_at_unix_nanos", "trusted_time_checkpoint_sha256",
    "persistence_receipt_sha256", "retrieval_id_sha256", "retrieval_proof_sha256", "signing_key_id", "signing_key_spki_sha256",
    "signature", "signed_receipt_sha256"})
# The Rust enum's declaration order, also BTreeMap order. Not lexical order.
ROLES = tuple("custody-" + name for name in ("ingress-admission", "unavailable-ingress", "dispatch-barrier", "terminal-append",
    "ledger-append", "spool-compaction", "active-effect-barrier", "active-effect-commit", "publication-reconciliation",
    "activation-publication", "result-envelope", "store-response", "signer-response", "retrieval-response",
    "trusted-time-response", "provider-response", "attestation-verifier", "supervisor-capability"))
ALL_ROLES = ("compiler-analysis", "activation-readiness", "activation-approval", "fleet-tee-attestation",
    "fleet-ingress", "fleet-active-decision", "fleet-shadow") + ROLES


def framed(domain, *parts):
    return profile.sha256(domain.encode("ascii") + b"\0" + b"".join(len(part).to_bytes(8, "big") + part for part in parts))


def material(domain, value):
    return framed(domain, profile.canonical(value))


def assignment_fields(value, *, version=1):
    """Exact explicit-version shapes; legacy callers never infer v2 admission."""
    old = frozenset(LEGACY_FIELDS)
    native = frozenset(NATIVE_FIELDS)
    profile.require(type(version) is int and version in (1, 2))
    shapes = (old, native) if version == 1 else (native | {"nativeClosureSet"},)
    profile.require(type(value) is dict and set(value) in shapes,
        "assignment is neither the exact legacy nor actual native custody original")
    if version == 2:
        binding = value["nativeClosureSet"]
        profile.require(type(binding) is dict and set(binding) == {"setRootSha256", "seccompSetRootSha256"})
        profile.digest(binding["setRootSha256"]); profile.digest(binding["seccompSetRootSha256"])
    return frozenset(value)


def assignment_payload(value, *, version=1):
    assignment_fields(value, version=version)
    return value


def _keys(assignment, selected_role="custody-ingress-admission"):
    authority = assignment["authorityKeyIndependence"]
    profile.require(type(authority) is dict and set(authority) == {"bindings", "keyIdSetRootSha256", "spkiSetRootSha256",
        "keyMaterialSetRootSha256", "independenceRootSha256"} and type(authority["bindings"]) is list
        and 25 <= len(authority["bindings"]) <= 256)
    result = {}
    order, identities = [], {name: set() for name in ("keyId", "keySpkiSha256", "keyMaterialSha256")}
    for value in authority["bindings"]:
        profile.require(type(value) is dict and set(value) == {"role", "scopeSha256", "keyAlgorithm", "keyId", "keySpkiSha256", "keyMaterialSha256"})
        profile.require(value["role"] in ALL_ROLES and type(value["keyAlgorithm"]) is str and value["keyAlgorithm"].lower() == "ed25519")
        profile.digest(value["scopeSha256"])
        order.append((ALL_ROLES.index(value["role"]), value["scopeSha256"], value["keyAlgorithm"], value["keyId"],
            value["keySpkiSha256"], value["keyMaterialSha256"]))
        for name in identities:
            profile.digest(value[name]); profile.require(value[name] not in identities[name]); identities[name].add(value[name])
        if value["role"] in ROLES and value["scopeSha256"] == assignment["assignmentId"]:
            profile.require(value["role"] not in result)
            result[value["role"]] = value
    profile.require(set(result) == set(ROLES) and order == sorted(set(order)))
    for name, root in (("keyId", "keyIdSetRootSha256"), ("keySpkiSha256", "spkiSetRootSha256"), ("keyMaterialSha256", "keyMaterialSetRootSha256")):
        profile.require(_merkle(sorted(identities[name])) == authority[root])
    profile.require(authority["independenceRootSha256"] == material("catchplate.policyAuthorityKeyIndependence/v1",
        [authority["bindings"], authority["keyIdSetRootSha256"], authority["spkiSetRootSha256"], authority["keyMaterialSetRootSha256"]]))
    custody = assignment["custodyAuthority"]
    prefixes = [role.removeprefix("custody-").split("-") for role in ROLES]
    prefixes = [parts[0] + "".join(part.title() for part in parts[1:]) for parts in prefixes]
    fields = {"authorityId", "storageRealmSha256", "retrievalNamespaceSha256", "executionClosureManifestSha256",
        "structurallyVerifiedSeccompPolicySha256", "attestationMode"}
    fields |= {prefix + suffix for prefix in prefixes for suffix in ("KeyId", "KeySpkiSha256")}
    profile.require(type(custody) is dict and set(custody) == fields)
    for name in fields - {"attestationMode"}:
        profile.digest(custody[name])
    mode = custody["attestationMode"]
    profile.require(type(mode) is dict and set(mode) == {"mode", "platform", "expectedMeasurementSha256", "endorsementRootSha256",
        "collateralPolicySha256", "revocationSourceSha256"} and mode["mode"] == "tee" and mode["platform"] == "aws-nitro-enclave")
    for name in set(mode) - {"mode", "platform"}:
        profile.digest(mode[name])
    leaves = []
    for ordinal, role in enumerate(ROLES, 1):
        key = result[role]
        prefix = prefixes[ordinal - 1]
        profile.require(key["keyId"] == custody[prefix + "KeyId"] and key["keySpkiSha256"] == custody[prefix + "KeySpkiSha256"])
        digest = material("catchplate.policyShadowCustodyAssertedKey/v1", [role, key["keyId"], key["keySpkiSha256"], key["keyMaterialSha256"]])
        leaves.append(digest)
    profile.require(selected_role in ROLES)
    return result[selected_role], _merkle(leaves)


def _merkle(values):
    leaves = [hashlib.sha256(b"catchplate.policyShadowMerkleLeaf/v1\0" + ordinal.to_bytes(8, "big") + bytes.fromhex(digest[7:])).digest()
        for ordinal, digest in enumerate(values, 1)]
    profile.require(bool(leaves))
    while len(leaves) > 1:
        leaves = [leaves[index] if index + 1 == len(leaves) else hashlib.sha256(
            b"catchplate.policyShadowMerkleNode/v1\1" + leaves[index] + leaves[index + 1]).digest() for index in range(0, len(leaves), 2)]
    return "sha256:" + leaves[0].hex()


def _generation(assignment, load, context, publication):
    window = assignment["observationWindow"]
    result = {"generationId": publication["generation_id_digest"], "minimumGenerationTombstoneEpoch": assignment["minimumGenerationTombstoneEpoch"],
        "assignmentRevision": assignment["assignmentRevision"], "assignmentSha256": context["assignment_envelope_digest"],
        "assignmentPayloadSha256": context["assignment_payload_digest"], "loadReceiptSha256": context["load_receipt_envelope_digest"],
        "loadReceiptPayloadSha256": context["load_receipt_payload_digest"], "runtimeBootIdSha256": context["boot_id"],
        "assignmentStartsAtUnixNanos": window["startsAtUnixNanos"], "assignmentEndsAtUnixNanos": window["endsAtUnixNanos"],
        "samplingBasisPoints": window["samplingBasisPoints"], "requestCommitmentKeyId": window["requestCommitmentKeyId"],
        "requestCommitmentKeyEpoch": window["requestCommitmentKeyEpoch"],
        "requestFactsSchemaSha256": assignment["expectedLoadedSnapshots"]["requestFactsSchemaSha256"]}
    for name in ("generationEpoch", "generationTombstoneEpoch", "ingressRangeStartSequence", "ingressRangePredecessorHeadSha256",
            "observationIntervalSha256", "responseValidationObligationsRootSha256", "publicationReconciliationReceiptSha256",
            "publicationRevision", "authoritativeLedgerEventOrdinal", "authoritativeLedgerHeadSha256", "authoritativeSpoolRootSha256"):
        result[name] = load[name]
    for side in ("active", "candidate"):
        for target, source in (("PolicySha256", "policySha256"), ("PolicySequence", "policySequence"),
                ("RollbackEpoch", "rollbackEpoch"), ("CompiledSnapshotSha256", "compiledSnapshotSha256")):
            result[side + target] = load["loadedSnapshots"][side][source]
    return result


def early_sampling(event, receipt, generation):
    """Verify the explicit early context. This is NOT ProtectedRequestFacts."""
    profile.require(type(event) is list and len(event) == 4 and event[0] == EARLY_EVENT
        and profile.canonical(event[1]) == profile.canonical(generation)
        and event[2] == receipt["trusted_observed_at_unix_nanos"] and receipt["event_phase"] == "ingress-open")
    sample = event[3]
    profile.require(type(sample) is dict and set(sample) == {"context", "commitment"})
    expected = {"apiVersion": "catchplate.nativeIngressSamplingContext/v1",
        "assignmentPayloadSha256": generation["assignmentPayloadSha256"], "assignmentRevision": generation["assignmentRevision"],
        "runtimeBootIdSha256": generation["runtimeBootIdSha256"], "generationId": generation["generationId"],
        "requestBindingSha256": receipt["request_binding_sha256"], "ingressSequence": receipt["ingress_sequence"],
        "samplingBasisPoints": generation["samplingBasisPoints"], "keyId": generation["requestCommitmentKeyId"],
        "keyEpoch": generation["requestCommitmentKeyEpoch"], "observedAtUnixNanos": event[2]}
    profile.require(profile.canonical(sample["context"]) == profile.canonical(expected)
        and profile.sha256(profile.canonical(sample)) == receipt["request_commitment_sha256"])
    tag = sample["commitment"]
    profile.require(type(tag) is str and tag.startswith("hmac-sha256:") and len(tag) == 76
        and all(v in "0123456789abcdef" for v in tag[12:]))
    basis = expected["samplingBasisPoints"]
    profile.require(type(basis) is int and 1 <= basis <= 10000)
    bucket = int.from_bytes(bytes.fromhex(tag[12:])[:8], "big") % 10000
    return "included" if bucket < basis else "excluded-by-assignment"


def verify(value, *, assignment, load, context, publication, now):
    from catchplate import db
    profile.require(type(value) is dict and set(value) == FIELDS and value["apiVersion"] in SCHEMAS
        and len(profile.canonical(value)) <= MAX_RECORD)
    successor = "nativeClosureSet" in assignment
    profile.require(assignment_fields(assignment, version=2 if successor else 1)
        == db._POLICY_SHADOW_DIRECT_PAYLOAD_FIELDS["canary_assignment"]
        | {"custodyAuthority", "authorityKeyIndependence"} | ({"nativeClosureSet"} if successor else set()),
        "opening requires the actual custody-bearing assignment")
    receipt = value["opening_receipt"]
    profile.require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS
        and receipt["event_phase"] == "ingress-open" and receipt["disposition"] == "appended")
    for name in RECEIPT_FIELDS - {"ingress_sequence", "event_ordinal", "predecessor_event_ordinal", "event_phase", "disposition",
            "canonical_event_bytes", "trusted_observed_at_unix_nanos", "signature"}:
        profile.digest(receipt[name])
    for name in ("ingress_sequence", "event_ordinal", "trusted_observed_at_unix_nanos"):
        profile.epoch(receipt[name])
    profile.require(type(receipt["predecessor_event_ordinal"]) is int
        and 0 <= receipt["predecessor_event_ordinal"] < receipt["event_ordinal"]
        and receipt["ingress_sequence"] > 0 and receipt["event_ordinal"] == receipt["predecessor_event_ordinal"] + 1)
    raw = receipt["canonical_event_bytes"]
    profile.require(type(raw) is list and 0 < len(raw) <= 16 * 1024 and all(type(v) is int and 0 <= v <= 255 for v in raw))
    raw = bytes(raw)
    event = profile.document(raw, 16 * 1024)
    early = value["apiVersion"] == EARLY_SCHEMA
    profile.require(profile.canonical(event) == raw and profile.sha256(raw) == receipt["event_sha256"]
        and type(event) is list and len(event) == 4 and event[0] == (EARLY_EVENT if early else "catchplate.policyShadowIngressAdmissionEvent/v1")
        and profile.canonical(event[1]) == profile.canonical(_generation(assignment, load, context, publication))
        and event[2] == receipt["trusted_observed_at_unix_nanos"])
    sample = event[3]
    window = assignment["observationWindow"]
    if early:
        decision = early_sampling(event, receipt, _generation(assignment, load, context, publication))
        # Only the old validation projection below is shared. The signed event
        # and record remain exact v2 originals and are never rewritten as v1.
        sample = {"generationId": receipt["generation_id"], "requestBindingSha256": receipt["request_binding_sha256"],
            "ingressSequence": receipt["ingress_sequence"], "samplingBasisPoints": window["samplingBasisPoints"],
            "requestCommitmentSha256": receipt["request_commitment_sha256"], "decision": decision}
    profile.require(type(sample) is dict and set(sample) == {"generationId", "requestBindingSha256", "ingressSequence",
        "samplingBasisPoints", "requestCommitmentSha256", "decision"})
    expected_sample = {"generationId": receipt["generation_id"], "requestBindingSha256": receipt["request_binding_sha256"],
        "ingressSequence": receipt["ingress_sequence"], "samplingBasisPoints": window["samplingBasisPoints"],
        "requestCommitmentSha256": receipt["request_commitment_sha256"], "decision": sample["decision"]}
    profile.require(profile.canonical(sample) == profile.canonical(expected_sample)
        and sample["decision"] in {"included", "excluded-by-assignment"}
        and receipt["generation_id"] == publication["generation_id_digest"]
        and receipt["ingress_sequence"] >= load["ingressRangeStartSequence"]
        and window["startsAtUnixNanos"] <= event[2] < window["endsAtUnixNanos"]
        and 0 <= now - event[2] <= window["maximumEvidenceAgeNanos"]
        and now < min(assignment["expiresAtUnixNanos"], window["endsAtUnixNanos"]))
    message = verify_receipt_signature(value, receipt, assignment=assignment, context=context,
        publication=publication, role="ingress-admission")
    return {"apiVersion": value["apiVersion"], "generationId": receipt["generation_id"], "ingressSequence": receipt["ingress_sequence"],
        "openingReceiptSha256": receipt["signed_receipt_sha256"], "signatureMessageSha256": profile.sha256(message),
        "recordSha256": profile.sha256(profile.canonical(value)), "coverage": "opening-only"}


def receipt_authority_payload(*, assignment, assignment_payload_sha256, configuration_binding_sha256,
                              key_root, role, receipt_payload):
    """Exact shared transcript for an already authenticated native assignment.

    The caller owns assignment signature admission; this arithmetic does not
    turn the additional roots or a stored observation into authority.
    """
    successor = "nativeClosureSet" in assignment
    assignment_payload(assignment, version=2 if successor else 1)
    authority = assignment["custodyAuthority"]
    values = [assignment["assignmentId"], assignment_payload_sha256, assignment["assignmentRevision"],
        authority["authorityId"], authority["storageRealmSha256"], authority["retrievalNamespaceSha256"],
        assignment["authorityKeyIndependence"]["independenceRootSha256"], configuration_binding_sha256, key_root,
        authority["executionClosureManifestSha256"], authority["structurallyVerifiedSeccompPolicySha256"]]
    roots = [assignment["nativeClosureSet"][name] for name in ("setRootSha256", "seccompSetRootSha256")] if successor else []
    version = "2" if successor else "1"
    scope = material("catchplate.policyShadowProductionCustodyProofScope/v" + version, values + roots)
    return ["catchplate.policyShadowAssignmentBoundCustodyReceipt/v" + version, scope,
        authority["executionClosureManifestSha256"], authority["structurallyVerifiedSeccompPolicySha256"],
        *roots, role, profile.sha256(receipt_payload)]


def verify_receipt_signature(value, receipt, *, assignment, context, publication, role):
    """Source-fixed role selected only after a closed event/phase admission."""
    from catchplate import db
    domains = {"ingress-admission": b"catchplate.policyShadowIngressAdmission/v1",
        "terminal-append": b"catchplate.policyShadowTerminalAppend/v1", "ledger-append": b"catchplate.policyShadowLedgerAppend/v1",
        "dispatch-barrier": b"catchplate.policyShadowDispatchBarrier/v1"}
    profile.require(role in domains)
    key, key_root = _keys(assignment, "custody-" + role)
    public = profile.decoded(value["signing_public_key_base64url"], 32, length=32)
    verifier = Ed25519PublicKey.from_public_bytes(public)
    der = verifier.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.require(receipt["signing_key_id"] == key["keyId"] and receipt["signing_key_spki_sha256"] == key["keySpkiSha256"] == profile.sha256(der)
        and key["keyMaterialSha256"] == framed("catchplate.policyAuthorityPublicKeyMaterial/v1", b"ed25519", der))
    record = material("catchplate.policyShadowSpoolRecord/v1", [receipt[name] for name in (
        "generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256", "event_phase", "disposition",
        "event_sha256", "canonical_event_bytes", "event_ordinal", "predecessor_event_ordinal", "predecessor_head_sha256",
        "trusted_observed_at_unix_nanos", "trusted_time_checkpoint_sha256", "persistence_receipt_sha256", "retrieval_id_sha256", "retrieval_proof_sha256")])
    profile.require(receipt["resulting_head_sha256"] == material("catchplate.policyShadowSpoolHead/v1",
        [receipt["predecessor_event_ordinal"], receipt["predecessor_head_sha256"], receipt["event_ordinal"], record])
        and receipt["signed_receipt_sha256"] == material("catchplate.policyShadowSpillReceipt/v1",
            [record, receipt["resulting_head_sha256"], receipt["signing_key_id"], receipt["signing_key_spki_sha256"], receipt["signature"]]))
    payload = [receipt[name] for name in ("generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256",
        "event_ordinal", "event_phase", "disposition", "event_sha256", "canonical_event_bytes", "predecessor_event_ordinal",
        "predecessor_head_sha256", "resulting_head_sha256", "trusted_observed_at_unix_nanos", "trusted_time_checkpoint_sha256",
        "persistence_receipt_sha256", "retrieval_id_sha256", "retrieval_proof_sha256")]
    payload += [role, receipt["signing_key_id"], receipt["signing_key_spki_sha256"]]
    evidence = db.loads(publication["generation_evidence_json"], None)
    bound = receipt_authority_payload(assignment=assignment, assignment_payload_sha256=context["assignment_payload_digest"],
        configuration_binding_sha256=evidence["custody"]["custodyConfigurationSha256"], key_root=key_root,
        role=role, receipt_payload=profile.canonical(payload))
    message = b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domains[role],
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), profile.canonical(bound)))
    verifier.verify(profile.decoded(receipt["signature"], 64, length=64), message)
    return message
