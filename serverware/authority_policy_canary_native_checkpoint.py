"""Exact completed native compaction originals; interval coverage only."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_native_opening as opening

SCHEMA = "serverware.nativeCustodyCheckpointObservation/v1"
MAX_RECORD = 32 * 1024
PREFIX = 8
FIELDS = opening.FIELDS - {"opening_receipt"} | {"receipt", "ordered_range"}
RECEIPT_ORDER = ("generation_id", "old_spool_head_sha256", "compacted_first_event_ordinal",
    "compacted_last_event_ordinal", "compacted_ordered_range_root_sha256", "compacted_record_count",
    "compacted_through_spill_receipt_sha256", "retained_successor_event_ordinal", "retained_successor_head_sha256",
    "new_spool_root_sha256", "trusted_observed_at_unix_nanos", "trusted_time_checkpoint_sha256",
    "persistence_receipt_sha256", "retrieval_id_sha256", "retrieval_proof_sha256")
RECEIPT_FIELDS = frozenset(RECEIPT_ORDER) | {"signing_key_id", "signing_key_spki_sha256", "signature", "signed_receipt_sha256"}
RANGE_FIELDS = frozenset({"domain", "generationId", "firstEventOrdinal", "lastEventOrdinal", "recordCount", "receipts"})
REFERENCE_FIELDS = frozenset({"eventOrdinal", "eventSha256", "canonicalEventLength", "canonicalEventSha256",
    "predecessorEventOrdinal", "predecessorHeadSha256", "resultingHeadSha256", "signedReceiptSha256",
    "retrievalIdSha256", "retrievalProofSha256"})


def verify(value, *, assignment, context, publication, now):
    from serverware import db
    profile.require(type(value) is dict and set(value) == FIELDS and value["apiVersion"] == SCHEMA
        and len(profile.canonical(value)) <= MAX_RECORD)
    receipt, covered = value["receipt"], value["ordered_range"]
    profile.require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS)
    integer_fields = {"compacted_first_event_ordinal", "compacted_last_event_ordinal", "compacted_record_count",
        "retained_successor_event_ordinal", "trusted_observed_at_unix_nanos"}
    for name in RECEIPT_FIELDS - integer_fields - {"retained_successor_head_sha256", "signature"}:
        profile.digest(receipt[name])
    for name in integer_fields - {"retained_successor_event_ordinal"}:
        profile.require(profile.epoch(receipt[name]) > 0)
    first, last = receipt["compacted_first_event_ordinal"], receipt["compacted_last_event_ordinal"]
    profile.require(receipt["compacted_record_count"] == PREFIX and last - first + 1 == PREFIX
        and (receipt["retained_successor_event_ordinal"] is None) == (receipt["retained_successor_head_sha256"] is None))
    if receipt["retained_successor_event_ordinal"] is not None:
        profile.require(profile.epoch(receipt["retained_successor_event_ordinal"]) == last + 1)
        profile.digest(receipt["retained_successor_head_sha256"])
    profile.require(type(covered) is dict and set(covered) == RANGE_FIELDS
        and covered["domain"] == "serverware.policyShadowSpoolCompactedOrderedRange/v1"
        and covered["generationId"] == receipt["generation_id"]
        and type(covered["firstEventOrdinal"]) is int and covered["firstEventOrdinal"] == first
        and type(covered["lastEventOrdinal"]) is int and covered["lastEventOrdinal"] == last
        and type(covered["recordCount"]) is int and covered["recordCount"] == PREFIX
        and type(covered["receipts"]) is list and len(covered["receipts"]) == PREFIX)
    previous = None
    for ordinal, reference in enumerate(covered["receipts"], first):
        profile.require(type(reference) is dict and set(reference) == REFERENCE_FIELDS
            and profile.epoch(reference["eventOrdinal"]) == ordinal
            and type(reference["predecessorEventOrdinal"]) is int and reference["predecessorEventOrdinal"] == ordinal - 1
            and 0 < profile.epoch(reference["canonicalEventLength"]) <= 256 * 1024)
        for name in REFERENCE_FIELDS - {"eventOrdinal", "predecessorEventOrdinal", "canonicalEventLength"}:
            profile.digest(reference[name])
        profile.require(reference["eventSha256"] == reference["canonicalEventSha256"])
        if previous is not None:
            profile.require(reference["predecessorHeadSha256"] == previous["resultingHeadSha256"])
        previous = reference
    profile.require(previous["signedReceiptSha256"] == receipt["compacted_through_spill_receipt_sha256"]
        and profile.sha256(profile.canonical(covered)) == receipt["compacted_ordered_range_root_sha256"])
    if receipt["retained_successor_event_ordinal"] is None:
        profile.require(receipt["old_spool_head_sha256"] == previous["resultingHeadSha256"])
    root = {"domain": "serverware.policyShadowCompactedSpoolRoot/v1", "generationId": receipt["generation_id"],
        "oldSpoolHeadSha256": receipt["old_spool_head_sha256"],
        "compactedOrderedRangeRootSha256": receipt["compacted_ordered_range_root_sha256"], "compactedRecordCount": PREFIX,
        "retainedSuccessorEventOrdinal": receipt["retained_successor_event_ordinal"],
        "retainedSuccessorHeadSha256": receipt["retained_successor_head_sha256"]}
    profile.require(profile.sha256(profile.canonical(root)) == receipt["new_spool_root_sha256"])
    window, observed = assignment["observationWindow"], receipt["trusted_observed_at_unix_nanos"]
    profile.require(receipt["generation_id"] == publication["generation_id_digest"]
        and window["startsAtUnixNanos"] <= observed < window["endsAtUnixNanos"]
        and 0 <= now - observed <= window["maximumEvidenceAgeNanos"]
        and now < min(assignment["expiresAtUnixNanos"], window["endsAtUnixNanos"]))
    key, key_root = opening._keys(assignment, "custody-spool-compaction")
    public = profile.decoded(value["signing_public_key_base64url"], 32, length=32)
    verifier = Ed25519PublicKey.from_public_bytes(public)
    der = verifier.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.require(receipt["signing_key_id"] == key["keyId"]
        and receipt["signing_key_spki_sha256"] == key["keySpkiSha256"] == profile.sha256(der)
        and key["keyMaterialSha256"] == opening.framed("serverware.policyAuthorityPublicKeyMaterial/v1", b"ed25519", der))
    original = [receipt[name] for name in RECEIPT_ORDER]
    profile.require(receipt["signed_receipt_sha256"] == opening.material("serverware.policyShadowSpoolCompactionReceipt/v1",
        original + [receipt["signing_key_id"], receipt["signing_key_spki_sha256"], receipt["signature"]]))
    payload = original + ["spool-compaction", receipt["signing_key_id"], receipt["signing_key_spki_sha256"]]
    authority = assignment["custodyAuthority"]
    evidence = db.loads(publication["generation_evidence_json"], None)
    scope = opening.material("serverware.policyShadowProductionCustodyProofScope/v1", [assignment["assignmentId"],
        context["assignment_payload_digest"], assignment["assignmentRevision"], authority["authorityId"], authority["storageRealmSha256"],
        authority["retrievalNamespaceSha256"], assignment["authorityKeyIndependence"]["independenceRootSha256"],
        evidence["custody"]["custodyConfigurationSha256"], key_root, authority["executionClosureManifestSha256"],
        authority["structurallyVerifiedSeccompPolicySha256"]])
    bound = ["serverware.policyShadowAssignmentBoundCustodyReceipt/v1", scope, authority["executionClosureManifestSha256"],
        authority["structurallyVerifiedSeccompPolicySha256"], "spool-compaction", profile.sha256(profile.canonical(payload))]
    message = b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, b"serverware.policyShadowSpoolCompaction/v1",
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), profile.canonical(bound)))
    verifier.verify(profile.decoded(receipt["signature"], 64, length=64), message)
    return {"apiVersion": SCHEMA, "generationId": receipt["generation_id"], "firstEventOrdinal": first,
        "lastEventOrdinal": last, "orderedRangeRootSha256": receipt["compacted_ordered_range_root_sha256"],
        "receiptSha256": receipt["signed_receipt_sha256"], "signatureMessageSha256": profile.sha256(message),
        "recordSha256": profile.sha256(profile.canonical(value)), "coverage": "contiguous-spool-interval"}
