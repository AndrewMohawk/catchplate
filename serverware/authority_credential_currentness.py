"""Closed measured-holder originals for irreversible credential-version drains."""
from __future__ import annotations

import base64
import re
import uuid
from collections.abc import Mapping

from serverware import authority_oauth_refresh as refresh

canonical, sha256, require = refresh.canonical, refresh.sha256, refresh.require
OP_CHALLENGE = "credential.currentness.challenge"
OP_REGISTER = "credential.currentness.register"
OP_QUIESCE = "credential.currentness.quiesce"
OP_ACK = "credential.currentness.ack"
OP_ADMIT = "credential.currentness.admit"
OPERATIONS = frozenset({OP_CHALLENGE, OP_REGISTER, OP_QUIESCE, OP_ACK, OP_ADMIT})
ROOT_TABLE = "credential_currentness_roots"
HOLDER_TABLE = "credential_currentness_holders"
CHALLENGE_TABLE = "credential_currentness_challenges"
BARRIER_TABLE = "credential_currentness_barriers"
TABLES = (ROOT_TABLE, HOLDER_TABLE, CHALLENGE_TABLE, BARRIER_TABLE)
ROOT_SCHEMA = "serverware.credentialCurrentnessRoot/v1"
BARRIER_SCHEMA = "serverware.credentialCurrentnessBarrier/v1"
STATEMENT_SCHEMA = "serverware.nativeCredentialCurrentnessStatement/v1"
SIGNATURE_DOMAIN = STATEMENT_SCHEMA.encode("ascii") + b"\0"
HOLDER_DOMAIN = b"serverware/credential-currentness-holder/v1\0"
ATTESTATION_DOMAIN = b"serverware/credential-currentness-attestation/v1\0"
MAX_ROWS = 64
MAX_ARGUMENT_BYTES = 64 * 1024
ROOT_FIELDS = frozenset({"id", "credential_id", "credential_version", "epoch", "profile", "status", "origin_request_digest", "predecessor_barrier_sha256", "barrier_id", "created_at", "updated_at"})
HOLDER_FIELDS = frozenset({"id", "root_id", "credential_id", "credential_version", "epoch", "holder_id", "boot_id", "key_id", "control_plane_response_signing_key_id", "control_plane_configuration_digest", "registration_sha256", "registration_original_json", "acknowledgement_sha256", "acknowledgement_original_json", "status", "created_at", "updated_at"})
CHALLENGE_FIELDS = frozenset({"id", "root_id", "credential_id", "credential_version", "epoch", "holder_id", "phase", "challenge", "barrier_id", "barrier_sha256", "issued_at_epoch_ns", "expires_at_epoch_ns", "status", "request_digest", "consumed_request_digest", "created_at", "updated_at"})
BARRIER_FIELDS = frozenset({"id", "root_id", "credential_id", "credential_version", "epoch", "original_json", "original_sha256", "status", "quiesce_request_digest", "admit_request_digest", "consume_request_digest", "created_at", "updated_at"})
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "deploymentId", "credentialId", "credentialVersion", "epoch", "challengeId", "challenge", "barrierId", "barrierSha256", "policyHash", "dataPlaneBinarySha256", "issuedAtEpochNs", "expiresAtEpochNs"})
CHALLENGE_REQUEST_FIELDS = frozenset({"phase", "holderId", "challengeId", "challenge", "barrierId", "barrierSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
BARRIER_ORIGINAL_FIELDS = frozenset({"apiVersion", "barrierId", "credentialId", "credentialVersion", "epoch", "holders", "issuedAtEpochNs", "expiresAtEpochNs"})
FROZEN_HOLDER_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "registrationSha256"})


def digest(value):
    refresh.digest(value)
    require(value != "sha256:" + "0" * 64)
    return value


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def version(value):
    require(type(value) is int and 1 <= value <= 2**63 - 1)
    return value


def encoded(value, size):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(len(raw) == size and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value
        and (size != 32 or raw != bytes(32)))
    return raw


def holder_id(boot_id, key_id):
    digest(key_id)
    return sha256(HOLDER_DOMAIN + encoded(boot_id, 32) + bytes.fromhex(key_id[7:]))


def root_id(credential_id, credential_version):
    identifier(credential_id)
    version(credential_version)
    return str(uuid.uuid5(uuid.UUID(credential_id), "serverware.credentialCurrentness/v1:" + str(credential_version)))


def holder_record_id(root, holder):
    identifier(root)
    digest(holder)
    return str(uuid.uuid5(uuid.UUID(root), "serverware.credentialCurrentnessHolder/v1:" + holder))


def _interval(value):
    version(value["issuedAtEpochNs"])
    version(value["expiresAtEpochNs"])
    require(value["issuedAtEpochNs"] < value["expiresAtEpochNs"] <= value["issuedAtEpochNs"] + 30_000_000_000)


def challenge_request(value):
    require(type(value) is dict and set(value) == CHALLENGE_REQUEST_FIELDS and value["phase"] in {"register", "ack"})
    digest(value["holderId"])
    identifier(value["challengeId"])
    encoded(value["challenge"], 32)
    _interval(value)
    if value["phase"] == "register":
        require(value["barrierId"] is None and value["barrierSha256"] is None)
    else:
        identifier(value["barrierId"])
        digest(value["barrierSha256"])
    return dict(value)


def evidence(value):
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    item = value["statement"]
    require(type(item) is dict and set(item) == STATEMENT_FIELDS and item["apiVersion"] == STATEMENT_SCHEMA)
    challenge_request({name: item[name] for name in CHALLENGE_REQUEST_FIELDS})
    identifier(item["credentialId"])
    version(item["credentialVersion"])
    require(type(item["epoch"]) is int and item["epoch"] == item["credentialVersion"])
    encoded(item["bootId"], 32)
    for name in ("keyId", "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256"):
        digest(item[name])
    require(item["holderId"] == holder_id(item["bootId"], item["keyId"]))
    require(type(item["deploymentId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item["deploymentId"]) is not None)
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    encoded(value["signature"][8:], 64)
    native = value["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"}
        and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    encoded(native["responseProofPublicKey"], 32)
    require(type(native["attestationDocumentB64"]) is str and 1 <= len(native["attestationDocumentB64"]) <= 16 * 1024)
    require(len(canonical(value)) <= 32 * 1024)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == {"credential_id", "credential_version", "control_plane_configuration_digest", "request"} | ({"businessIntent"} if typed else set()))
    identifier(value["credential_id"])
    version(value["credential_version"])
    digest(value["control_plane_configuration_digest"])
    request = value["request"]
    require(type(request) is dict)
    if operation == OP_CHALLENGE:
        challenge_request(request)
    elif operation in {OP_REGISTER, OP_ACK}:
        require(set(request) == {"evidence"})
        original = evidence(request["evidence"])["statement"]
        require(original["credentialId"] == value["credential_id"] and original["credentialVersion"] == value["credential_version"]
            and original["phase"] == ("register" if operation == OP_REGISTER else "ack"))
    elif operation == OP_QUIESCE:
        require(set(request) == {"barrierId", "issuedAtEpochNs", "expiresAtEpochNs"})
        identifier(request["barrierId"])
        _interval(request)
    else:
        require(set(request) == {"barrierId", "barrierSha256"})
        identifier(request["barrierId"])
        digest(request["barrierSha256"])
    result = {name: value[name] for name in ("credential_id", "credential_version", "control_plane_configuration_digest", "request")}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def _row_original(row, fields, nullable, integers):
    value = dict(row)
    require(set(value) == fields)
    for name, item in value.items():
        if item is None:
            require(name in nullable)
        elif name in integers:
            version(item)
        else:
            require(type(item) is str)
    original = canonical(value)
    require(len(original) <= 128 * 1024)
    return original


def root_original(row):
    return _row_original(row, ROOT_FIELDS, {"predecessor_barrier_sha256", "barrier_id"}, {"credential_version", "epoch"})


def root_digest(row):
    return sha256(root_original(row))


def holder_original(row):
    return _row_original(row, HOLDER_FIELDS, {"acknowledgement_sha256", "acknowledgement_original_json"}, {"credential_version", "epoch"})


def barrier_original(value):
    require(type(value) is dict and set(value) == BARRIER_ORIGINAL_FIELDS and value["apiVersion"] == BARRIER_SCHEMA)
    identifier(value["barrierId"])
    identifier(value["credentialId"])
    version(value["credentialVersion"])
    require(type(value["epoch"]) is int and value["epoch"] == value["credentialVersion"])
    _interval(value)
    holders = value["holders"]
    require(type(holders) is list and len(holders) <= MAX_ROWS)
    ids = []
    for holder in holders:
        require(type(holder) is dict and set(holder) == FROZEN_HOLDER_FIELDS)
        for name in FROZEN_HOLDER_FIELDS - {"bootId"}:
            digest(holder[name])
        require(holder["holderId"] == holder_id(holder["bootId"], holder["keyId"]))
        ids.append(holder["holderId"])
    require(ids == sorted(set(ids)))
    return canonical(value)


def barrier_digest(value):
    return sha256(barrier_original(value))


def public_root(row):
    root_original(row)
    return {"apiVersion": ROOT_SCHEMA, "credentialId": row["credential_id"], "credentialVersion": row["credential_version"],
        "epoch": row["epoch"], "status": row["status"], "rootSha256": root_digest(row), "barrierId": row["barrier_id"],
        "predecessorBarrierSha256": row["predecessor_barrier_sha256"], "originRequestDigest": row["origin_request_digest"]}


def public_holder(row):
    holder_original(row)
    return {"holderId": row["holder_id"], "bootId": row["boot_id"], "keyId": row["key_id"], "epoch": row["epoch"],
        "registrationSha256": row["registration_sha256"], "acknowledgementSha256": row["acknowledgement_sha256"], "status": row["status"]}


def registration_evidence(row):
    holder_original(row)
    digest(row["control_plane_configuration_digest"])
    original = evidence(refresh.document(row["registration_original_json"].encode("ascii"), 32 * 1024))
    statement = original["statement"]
    require(sha256(canonical(original)) == row["registration_sha256"] and statement["phase"] == "register"
        and statement["credentialId"] == row["credential_id"] and statement["credentialVersion"] == row["credential_version"]
        and statement["epoch"] == row["epoch"] and statement["holderId"] == row["holder_id"]
        and statement["bootId"] == row["boot_id"] and statement["keyId"] == row["key_id"]
        and statement["controlPlaneResponseSigningKeyId"] == row["control_plane_response_signing_key_id"])
    return original


def public_barrier(row):
    value = refresh.document(row["original_json"].encode("ascii"), 64 * 1024)
    require(barrier_digest(value) == row["original_sha256"])
    return {"original": value, "sha256": row["original_sha256"], "status": row["status"]}


def new_root(credential_id, credential_version, request_digest, now, predecessor=None):
    digest(request_digest)
    if predecessor is not None:
        digest(predecessor)
    value = {"id": root_id(credential_id, credential_version), "credential_id": credential_id,
        "credential_version": credential_version, "epoch": credential_version, "profile": ROOT_SCHEMA, "status": "open",
        "origin_request_digest": request_digest, "predecessor_barrier_sha256": predecessor, "barrier_id": None,
        "created_at": now, "updated_at": now}
    root_original(value)
    return value


def result(operation, value):
    """Closed data validation only; caller must verify its actual signed reply."""
    require(operation in OPERATIONS and type(value) is dict and set(value) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "currentness"}
        and value["ok"] is True and value["idempotentReplay"] is False and value["operation"] == operation)
    digest(value["requestDigest"])
    digest(value["auditEventDigest"])
    item = value["currentness"]
    require(type(item) is dict and set(item) == {"root", "challenge", "holder", "barrier"})
    root = item["root"]
    require(type(root) is dict and set(root) == {"apiVersion", "credentialId", "credentialVersion", "epoch", "status", "rootSha256", "barrierId", "predecessorBarrierSha256", "originRequestDigest"}
        and root["apiVersion"] == ROOT_SCHEMA and root["status"] in {"open", "quiescing", "admitted", "consumed"})
    identifier(root["credentialId"])
    version(root["credentialVersion"])
    require(type(root["epoch"]) is int and root["epoch"] == root["credentialVersion"])
    digest(root["rootSha256"])
    digest(root["originRequestDigest"])
    if root["predecessorBarrierSha256"] is not None:
        digest(root["predecessorBarrierSha256"])
    require((root["barrierId"] is None) == (root["status"] == "open"))
    if root["barrierId"] is not None:
        identifier(root["barrierId"])
    if item["challenge"] is not None:
        challenge_request(item["challenge"])
    if item["holder"] is not None:
        holder = item["holder"]
        require(type(holder) is dict and set(holder) == {"holderId", "bootId", "keyId", "epoch", "registrationSha256", "acknowledgementSha256", "status"}
            and holder["status"] in {"registered", "acked"} and type(holder["epoch"]) is int and holder["epoch"] == root["epoch"]
            and holder["holderId"] == holder_id(holder["bootId"], holder["keyId"]))
        digest(holder["registrationSha256"])
        require((holder["acknowledgementSha256"] is None) == (holder["status"] == "registered"))
        if holder["acknowledgementSha256"] is not None:
            digest(holder["acknowledgementSha256"])
    if item["barrier"] is not None:
        barrier = item["barrier"]
        require(type(barrier) is dict and set(barrier) == {"original", "sha256", "status"}
            and barrier["status"] in {"quiescing", "admitted", "consumed"}
            and barrier_digest(barrier["original"]) == barrier["sha256"])
        original = barrier["original"]
        require(original["credentialId"] == root["credentialId"] and original["credentialVersion"] == root["credentialVersion"]
            and original["epoch"] == root["epoch"] and original["barrierId"] == root["barrierId"])
    require((item["challenge"] is not None) == (operation in {OP_CHALLENGE, OP_REGISTER, OP_ACK})
        and (item["holder"] is not None) == (operation in {OP_REGISTER, OP_ACK})
        and (item["barrier"] is not None) == (root["status"] != "open")
        and len(canonical(value)) <= 64 * 1024)
    return value


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.credential_currentness_request_digest(operation, value)
