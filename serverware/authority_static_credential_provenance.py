"""Historical static creation joined to authenticated current rows.

The caller's original is acquisition data. Only the exact protected creation
outbox/root join establishes its provenance. The old quote is never replayed
as fresh Nitro evidence, nor does this authorize rotation or a secret lease.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_credential_currentness as currentness
from serverware import authority_oauth_setup as codec
from serverware import authority_setup_bind_credential as timestamps
from serverware import authority_static_credential_create as creation
from serverware import authority_static_credential_custody as custody
from serverware import authority_transition_quota as shared
from serverware import credential_currentness_rows

SCHEMA = "serverware.staticCredentialCreationProvenance/v1"
MAX_ORIGINAL_BYTES = 40 * 1024
FIELDS = frozenset({"apiVersion", "creationRequestDigest", "nativeEvidenceOriginal"})
AUDIT_FIELDS = frozenset({"schema", "operation", "requestDigest", "credentialId",
    "credentialVersion", "candidateSha256", "intentSha256", "nativeGenerationSha256",
    "custodyStatementSha256", "approvalId"})
ROTATION_SCHEMA = "serverware.staticCredentialRotationProvenance/v1"
ROTATION_FIELDS = frozenset({"apiVersion", "rotationRequestDigest", "nativeEvidenceOriginal"})
ROTATION_AUDIT_SCHEMA = "serverware.staticCredentialRotationAudit/v1"
ROTATION_AUDIT_FIELDS = AUDIT_FIELDS | {"previousCredentialVersion", "previousCredentialSha256",
    "previousCurrentnessOriginRequestDigest", "previousProvenanceSha256", "predecessorBarrierSha256",
    "predecessorCurrentnessRootSha256", "credentialPostSha256"}


def original(value):
    """Closed literal native evidence acquired from the original measured plan."""
    creation.require(type(value) is str and value.isascii()
        and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    parsed = codec.document(value.encode("ascii"), MAX_ORIGINAL_BYTES)
    creation.require(set(parsed) == FIELDS and parsed["apiVersion"] == SCHEMA)
    creation.digest(parsed["creationRequestDigest"])
    evidence = parsed["nativeEvidenceOriginal"]
    creation.require(type(evidence) is str and evidence.isascii()
        and 0 < len(evidence) <= custody.MAX_EVIDENCE_BYTES)
    custody.evidence(codec.document(evidence.encode("ascii"), custody.MAX_EVIDENCE_BYTES))
    return parsed


def evidence(value):
    parsed = original(value)
    return custody.evidence(codec.document(parsed["nativeEvidenceOriginal"].encode("ascii"),
        custody.MAX_EVIDENCE_BYTES))


def outbox_id(value):
    return shared._audit_identity(creation.OPERATION, original(value)["creationRequestDigest"])


def verify_native_signature(value):
    """Integrity only: this key becomes historical authority solely via SQL proof."""
    proof = evidence(value)
    statement = proof["statement"]
    key = Ed25519PublicKey.from_public_bytes(custody.decoded(
        proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32))
    creation.require(creation.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == statement["keyId"])
    key.verify(custody.decoded(proof["signature"][8:], 64, 64),
        custody.SIGNATURE_DOMAIN + creation.canonical(statement))
    return statement


def verify_rows(value, *, credential, generation, root, outbox,
        configuration_digest, now_epoch_ns):
    """Join exact selected rows; callers must supply genuine authenticated rows.

    The HTTP owner uses this for consistency only. The transition kernel repeats
    it over independently proven rows before any challenge/membership effect.
    No historical expiry is renewed or compared to present time as a live grant.
    """
    parsed = original(value)
    statement = verify_native_signature(value)
    creation.require(type(now_epoch_ns) is int and now_epoch_ns > 0)
    credential_currentness_rows.credential_original(credential)
    currentness.refresh.generation_original(generation)
    currentness.root_original(root)
    creation.require(credential["kind"] in creation.KINDS
        and credential["credential_version"] == generation["last_version"] == 1
        and type(generation["last_version"]) is int
        and credential["id"] == generation["credential_id"] == root["credential_id"] == statement["credentialId"]
        and credential["lifecycle_status"] == "active"
        and credential["revocation_error"] is None and credential["revocation_requested_at"] is None
        and root["id"] == currentness.root_id(credential["id"], 1)
        and root["profile"] == currentness.ROOT_SCHEMA and root["epoch"] == root["credential_version"] == 1
        and root["predecessor_barrier_sha256"] is None
        and root["origin_request_digest"] == parsed["creationRequestDigest"]
        and statement["controlPlaneConfigurationDigest"] == configuration_digest)
    created = credential["created_at"]
    creation.require(created == credential["updated_at"] == generation["updated_at"]
        == root["created_at"] == outbox["created_at"]
        and statement["issuedAtEpochNs"] <= timestamps.epoch(created) < statement["expiresAtEpochNs"])
    creation.require(outbox["id"] == outbox_id(value) and outbox["event_type"] == creation.OPERATION
        and outbox["actor_type"] == "admin" and outbox["actor_id"] == statement["actorId"]
        and outbox["status"] == "audited" and outbox["audited_at"] is not None
        and outbox["audit_event_hash"] is not None and outbox["claim_id"] is None
        and outbox["claimed_at"] is None and outbox["last_error"] is None
        and timestamps.epoch(created) <= timestamps.epoch(outbox["audited_at"]) <= now_epoch_ns)
    creation.digest(outbox["audit_event_hash"])
    event = codec.document(outbox["event_json"].encode("ascii"), 8192)
    creation.require(set(event) == AUDIT_FIELDS
        and event["schema"] == "serverware.staticCredentialCreationAudit/v1"
        and event["operation"] == creation.OPERATION
        and event["requestDigest"] == parsed["creationRequestDigest"]
        and event["credentialId"] == credential["id"]
        and type(event["credentialVersion"]) is int and event["credentialVersion"] == 1
        and event["custodyStatementSha256"] == creation.sha256(creation.canonical(statement))
        and event["intentSha256"] == statement["intentSha256"]
        and outbox["event_digest"] == shared.core.framed_digest(
            "serverware.metadataAuditOutboxEvent/v1", outbox["event_json"].encode("ascii")))
    creation.digest(event["candidateSha256"])
    if event["approvalId"] is not None:
        creation.identifier(event["approvalId"])
    # Reconstruct only the existing canonical generation from the actual row.
    # The matching committed hash proves these bytes; no input ciphertext is
    # adopted and no secret is decrypted or hashed.
    native = {"apiVersion": creation.GENERATION_SCHEMA, "purpose": creation.OPERATION,
        "actorId": statement["actorId"], "controlPlaneConfigurationDigest": configuration_digest,
        "intentSha256": statement["intentSha256"], "credentialId": credential["id"],
        "credentialVersion": 1,
        "envelope": {name: credential[name] for name in creation.material.ENVELOPE_FIELDS}}
    raw = creation.canonical(native)
    creation.generation(raw.decode("ascii"))
    creation.require(creation.sha256(raw) == statement["generationSha256"] == event["nativeGenerationSha256"]
        and native["envelope"]["secret_kek_id"] == statement["secretKekId"]
        and timestamps.epoch(native["envelope"]["secret_updated_at"]) == statement["generationCreatedAtEpochNs"])
    return statement["deploymentId"]


def generation_original(value):
    """Explicit creation/rotation provenance dispatch, never a fresh verdict."""
    creation.require(type(value) is str and value.isascii() and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    parsed = codec.document(value.encode("ascii"), MAX_ORIGINAL_BYTES)
    if parsed.get("apiVersion") == SCHEMA:
        return original(value)
    from serverware import authority_static_credential_rotation_custody as rotation_custody
    creation.require(set(parsed) == ROTATION_FIELDS and parsed["apiVersion"] == ROTATION_SCHEMA)
    creation.digest(parsed["rotationRequestDigest"])
    native = parsed["nativeEvidenceOriginal"]
    creation.require(type(native) is str and native.isascii() and 0 < len(native) <= rotation_custody.MAX_EVIDENCE_BYTES)
    rotation_custody.evidence(codec.document(native.encode("ascii"), rotation_custody.MAX_EVIDENCE_BYTES))
    return parsed


def request_digest(parsed):
    return parsed["creationRequestDigest"] if parsed["apiVersion"] == SCHEMA else parsed["rotationRequestDigest"]


def generation_evidence(value):
    parsed = generation_original(value)
    if parsed["apiVersion"] == SCHEMA:
        return evidence(value)
    from serverware import authority_static_credential_rotation_custody as rotation_custody
    return rotation_custody.evidence(codec.document(parsed["nativeEvidenceOriginal"].encode("ascii"),
        rotation_custody.MAX_EVIDENCE_BYTES))


def generation_outbox_id(value):
    parsed = generation_original(value)
    operation = creation.OPERATION if parsed["apiVersion"] == SCHEMA else "credential.static.rotate"
    return shared._audit_identity(operation, request_digest(parsed))


def verify_generation_signature(value):
    if generation_original(value)["apiVersion"] == SCHEMA:
        return verify_native_signature(value)
    from serverware import authority_static_credential_rotation_custody as rotation_custody
    proof = generation_evidence(value)
    statement = proof["statement"]
    key = Ed25519PublicKey.from_public_bytes(custody.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32))
    creation.require(creation.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == statement["keyId"])
    key.verify(custody.decoded(proof["signature"][8:], 64, 64),
        rotation_custody.SIGNATURE_DOMAIN + creation.canonical(statement))
    return statement


def verify_generation_rows(value, *, credential, generation, root, outbox, configuration_digest, now_epoch_ns):
    """Latest committed provenance and actual current envelope/root, not a chain DTO.

    Earlier barriers were consumed by the original protected transition. This
    proves its exact completed audit and successor rather than replaying an old
    quote, trusting caller history, or recursively expanding prior generations.
    """
    parsed = generation_original(value)
    if parsed["apiVersion"] == SCHEMA:
        return verify_rows(value, credential=credential, generation=generation, root=root, outbox=outbox,
            configuration_digest=configuration_digest, now_epoch_ns=now_epoch_ns)
    from serverware import authority_static_credential_rotate as rotation
    statement = verify_generation_signature(value)
    creation.require(type(now_epoch_ns) is int and now_epoch_ns > 0)
    row_raw = credential_currentness_rows.credential_original(credential)
    currentness.refresh.generation_original(generation); currentness.root_original(root)
    version = statement["credentialVersion"]
    creation.require(credential["kind"] in creation.KINDS
        and type(generation["last_version"]) is int and credential["credential_version"] == generation["last_version"] == version
        and credential["id"] == generation["credential_id"] == root["credential_id"] == statement["credentialId"]
        and credential["lifecycle_status"] == "active" and credential["revocation_error"] is None
        and credential["revocation_requested_at"] is None
        and root["id"] == currentness.root_id(credential["id"], version)
        and root["profile"] == currentness.ROOT_SCHEMA and root["epoch"] == root["credential_version"] == version
        and root["predecessor_barrier_sha256"] == statement["predecessorBarrierSha256"]
        and root["origin_request_digest"] == parsed["rotationRequestDigest"]
        and statement["controlPlaneConfigurationDigest"] == configuration_digest)
    stamp = credential["updated_at"]
    creation.require(stamp == generation["updated_at"] == root["created_at"] == outbox["created_at"]
        and timestamps.epoch(credential["created_at"]) <= timestamps.epoch(stamp)
        and statement["issuedAtEpochNs"] <= timestamps.epoch(stamp) < statement["expiresAtEpochNs"]
        and outbox["id"] == generation_outbox_id(value) and outbox["event_type"] == rotation.OPERATION
        and outbox["actor_type"] == "admin" and outbox["actor_id"] == statement["actorId"]
        and outbox["status"] == "audited" and outbox["audited_at"] is not None
        and outbox["audit_event_hash"] is not None and outbox["claim_id"] is None
        and outbox["claimed_at"] is None and outbox["last_error"] is None
        and timestamps.epoch(stamp) <= timestamps.epoch(outbox["audited_at"]) <= now_epoch_ns)
    creation.digest(outbox["audit_event_hash"])
    event = codec.document(outbox["event_json"].encode("ascii"), 8192)
    creation.require(set(event) == ROTATION_AUDIT_FIELDS and event["schema"] == ROTATION_AUDIT_SCHEMA
        and event["operation"] == rotation.OPERATION and event["requestDigest"] == parsed["rotationRequestDigest"]
        and event["credentialId"] == credential["id"] and type(event["credentialVersion"]) is int
        and event["credentialVersion"] == version and event["credentialPostSha256"] == creation.sha256(row_raw)
        and event["custodyStatementSha256"] == creation.sha256(creation.canonical(statement))
        and event["intentSha256"] == statement["intentSha256"]
        and outbox["event_digest"] == shared.core.framed_digest(
            "serverware.metadataAuditOutboxEvent/v1", outbox["event_json"].encode("ascii")))
    for name in ("previousCredentialVersion", "previousCredentialSha256", "previousCurrentnessOriginRequestDigest",
            "previousProvenanceSha256", "predecessorBarrierSha256", "predecessorCurrentnessRootSha256"):
        creation.require(event[name] == statement[name])
    creation.digest(event["candidateSha256"])
    if event["approvalId"] is not None:
        creation.identifier(event["approvalId"])
    native = {"apiVersion": rotation.GENERATION_SCHEMA, "purpose": rotation.OPERATION,
        "actorId": statement["actorId"], "controlPlaneConfigurationDigest": configuration_digest,
        "intentSha256": statement["intentSha256"], "credentialId": credential["id"], "credentialVersion": version,
        "envelope": {name: credential[name] for name in rotation.material.ENVELOPE_FIELDS}}
    raw = creation.canonical(native)
    rotation.generation(raw.decode("ascii"))
    creation.require(creation.sha256(raw) == statement["generationSha256"] == event["nativeGenerationSha256"]
        and native["envelope"]["secret_kek_id"] == statement["secretKekId"]
        and timestamps.epoch(native["envelope"]["secret_updated_at"]) == statement["generationCreatedAtEpochNs"])
    return statement["deploymentId"]
