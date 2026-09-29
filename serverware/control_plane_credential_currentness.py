"""Actual cold custody clients for measured-holder registration and drains.

SQL here is SELECT-only. Only the admitted fixed writer can mutate roots,
membership, challenges or barriers. A poll observation is not a send permit.
"""
from __future__ import annotations

import os
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request

from serverware import authority_contract, db
from serverware import authority_credential_currentness as profile
from serverware import authority_oauth_refresh as refresh
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware.control_plane_approval_verification import _request_pin

REQUEST_SCHEMA = "serverware.credentialCurrentnessRequest/v1"
OBSERVATION_SCHEMA = "serverware.credentialCurrentnessObservation/v1"
LEASE_DOMAIN = b"serverware.nativeCurrentCredentialLeaseBinding/v1\0"
_PUBLIC = {"challenge": profile.OP_CHALLENGE, "register": profile.OP_REGISTER, "ack": profile.OP_ACK}


def selected():
    # Reuse the genuinely admitted startup owner; never lazily create a client
    # or fall back after configured startup failure. No separate trust service.
    return startup.require_started() is not None


def _rows(credential_id, version):
    profile.identifier(credential_id)
    profile.version(version)
    with db.connect() as connection:
        credential = connection.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        generation = connection.execute("SELECT * FROM credential_generations WHERE credential_id = ?", (credential_id,)).fetchone()
        root = connection.execute("SELECT * FROM credential_currentness_roots WHERE id = ?",
            (profile.root_id(credential_id, version),)).fetchone()
    profile.require(credential is not None and generation is not None and root is not None)
    credential, generation, root = dict(credential), dict(generation), dict(root)
    refresh.credential_original(credential)
    refresh.generation_original(generation)
    profile.root_original(root)
    profile.require(credential["lifecycle_status"] == "active" and credential["credential_version"] == version
        and generation["last_version"] == version and root["credential_id"] == credential_id
        and root["credential_version"] == version and root["epoch"] == version
        and root["profile"] == profile.ROOT_SCHEMA)
    return credential, generation, root


def _holder(root, holder_id, configuration_digest):
    profile.digest(holder_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM credential_currentness_holders WHERE id = ?",
            (profile.holder_record_id(root["id"], holder_id),)).fetchone()
    if row is None:
        return None
    value = dict(row)
    profile.holder_original(value)
    profile.registration_evidence(value)
    profile.require(value["root_id"] == root["id"] and value["credential_id"] == root["credential_id"]
        and value["credential_version"] == root["credential_version"] and value["epoch"] == root["epoch"]
        and value["control_plane_configuration_digest"] == configuration_digest)
    return value


def _barrier(root):
    if root["barrier_id"] is None:
        return None
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM credential_currentness_barriers WHERE id = ?", (root["barrier_id"],)).fetchone()
    profile.require(row is not None)
    row = dict(row)
    profile.require(set(row) == profile.BARRIER_FIELDS and row["root_id"] == root["id"]
        and row["credential_id"] == root["credential_id"] and row["credential_version"] == root["credential_version"]
        and row["epoch"] == root["epoch"])
    observed = profile.public_barrier(row)
    profile.require(observed["original"]["barrierId"] == row["id"])
    return row


def _projection(root, configuration_digest, holder_id=None, challenge=None):
    holder = None if holder_id is None else _holder(root, holder_id, configuration_digest)
    barrier = _barrier(root)
    return {"root": profile.public_root(root), "challenge": challenge,
        "holder": None if holder is None else profile.public_holder(holder),
        "barrier": None if barrier is None else profile.public_barrier(barrier)}


class _Owner:
    def __init__(self, *, deadline=None, expires=None):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline = min(self.mono + 30_000_000_000, deadline or 2**63 - 1)
        self.expires = min(self.epoch + 30_000_000_000, expires or 2**63 - 1)
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.custody = startup.require_started()
        profile.require(self.custody is not None)
        self.binding = custody_client._snapshot(self.custody)
        self.configuration_digest = self.binding.configuration_digest
        profile.digest(self.configuration_digest)
        self.poisoned, self.attempts = False, set()

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and startup.require_started() is self.custody
                and custody_client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.configuration_digest)
            self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def __copy__(self):
        raise ValueError("currentness owner cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("currentness owner cannot be copied")

    def dispatch(self, operation, credential_id, version, request):
        self.check()
        arguments = profile.arguments(operation, {"credential_id": credential_id,
            "credential_version": version, "control_plane_configuration_digest": self.configuration_digest,
            "request": request})
        if operation == profile.OP_ACK or (operation == profile.OP_CHALLENGE and request["phase"] == "ack"):
            statement = request["evidence"]["statement"] if operation == profile.OP_ACK else request
            _, _, root = _rows(credential_id, version)
            profile.require(_holder(root, statement["holderId"], self.configuration_digest) is not None)
        original, digest = profile.canonical(arguments), profile.request_digest(operation, arguments)
        profile.require(digest not in self.attempts)
        self.attempts.add(digest)  # An uncertain actual writer call never retries.
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments},
            deadline_ns=self.deadline)
        self.check()
        profile.require(profile.canonical(arguments) == original and type(result) is dict
            and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "currentness"}
            and result["ok"] is True and result["operation"] == operation and result["requestDigest"] == digest
            and result["idempotentReplay"] is False)
        profile.digest(result["auditEventDigest"])
        _, _, root = _rows(credential_id, version)
        holder_id, challenge = None, None
        if operation == profile.OP_CHALLENGE:
            challenge = request
        elif operation in {profile.OP_REGISTER, profile.OP_ACK}:
            statement = request["evidence"]["statement"]
            holder_id = statement["holderId"]
            challenge = {name: statement[name] for name in profile.CHALLENGE_REQUEST_FIELDS}
        profile.require(result["currentness"] == _projection(root, self.configuration_digest, holder_id, challenge))
        self.check()
        return result


def on_request(request, payload):
    """Root route authenticates its existing DP token and signs this response."""
    profile.require(type(request) is Request and request.method == "POST"
        and request.url.path == "/api/data-plane/credential-currentness" and not request.url.query
        and type(payload) is dict and set(payload) == {"apiVersion", "credentialId", "credentialVersion", "request"}
        and payload["apiVersion"] == REQUEST_SCHEMA)
    owner, scope, pin, original = _Owner(), request.scope, _request_pin(request), profile.canonical(payload)
    profile.require(len(original) <= 64 * 1024)
    item = payload["request"]
    profile.require(type(item) is dict and set(item) == {"phase", "arguments"})
    credential_id, version = payload["credentialId"], payload["credentialVersion"]
    _rows(credential_id, version)
    phase, arguments = item["phase"], item["arguments"]
    if phase == "poll":
        profile.require(type(arguments) is dict and set(arguments) == {"holderId"})
        _, _, root = _rows(credential_id, version)
        result = {"apiVersion": OBSERVATION_SCHEMA,
            "currentness": _projection(root, owner.configuration_digest, arguments["holderId"])}
    else:
        profile.require(phase in _PUBLIC)
        if phase == "challenge":
            profile.challenge_request(arguments)
            owner.expires = min(owner.expires, arguments["expiresAtEpochNs"])
        else:
            profile.require(type(arguments) is dict and set(arguments) == {"evidence"})
            statement = profile.evidence(arguments["evidence"])["statement"]
            owner.expires = min(owner.expires, statement["expiresAtEpochNs"])
        owner.deadline = min(owner.deadline, owner.mono + owner.expires - owner.epoch)
        result = owner.dispatch(_PUBLIC[phase], credential_id, version, arguments)
    owner.check()
    profile.require(request.scope is scope and _request_pin(request) == pin and profile.canonical(payload) == original)
    return result


class LeaseOpening(_Owner):
    """One exact outer HTTP request retained through inner lease finalization."""

    def __init__(self, request, inner_request, currentness):
        super().__init__()
        profile.require(type(request) is Request and request.method == "POST"
            and request.url.path == "/api/data-plane/credential-leases" and not request.url.query
            and type(inner_request) is dict)
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.inner, self.currentness = inner_request, currentness
        self.original = profile.canonical({"leaseRequest": inner_request, "currentness": currentness})
        self.version, self.credential, self.generation = None, None, None
        authority = inner_request.get("requestAuthority")
        if authority is not None:
            profile.require(type(authority) is dict and type(authority.get("reservationExpiresAtEpochMs")) is int)
            self.expires = min(self.expires, authority["reservationExpiresAtEpochMs"] * 1_000_000)
            self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()

    def check(self):
        try:
            super().check()
            profile.require(self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical({"leaseRequest": self.inner, "currentness": self.currentness}) == self.original)
            if self.version is not None:
                credential, generation, root = _rows(self.inner["credentialId"], self.version)
                profile.require(credential == self.credential and generation == self.generation
                    and root["status"] == "open" and root["barrier_id"] is None)
                if self.currentness is not None:
                    holder = _holder(root, self.currentness["holderId"], self.configuration_digest)
                    profile.require(holder is not None and holder["status"] == "registered"
                        and holder["registration_sha256"] == self.currentness["registrationSha256"])
            super().check()
        except BaseException:
            self.poisoned = True
            raise

    def metadata(self, version):
        self.check()
        profile.require(self.currentness is None and self.inner["purpose"] == "generationMetadata")
        credential, generation, root = _rows(self.inner["credentialId"], version)
        profile.require(root["status"] == "open" and root["barrier_id"] is None)
        self.version, self.credential, self.generation = version, credential, generation
        self.check()
        return {"credentialVersion": version, "epoch": root["epoch"], "rootSha256": profile.root_digest(root)}

    def require_dispatch(self, version):
        self.check()
        pin = self.currentness
        profile.require(type(pin) is dict and set(pin) == {"holderId", "epoch", "registrationSha256", "signature"}
            and self.inner["purpose"] == "dispatchSecret" and self.inner["expectedCredentialVersion"] == version
            and type(pin["epoch"]) is int and pin["epoch"] == version)
        credential, generation, root = _rows(self.inner["credentialId"], version)
        profile.require(root["status"] == "open" and root["barrier_id"] is None)
        holder = _holder(root, pin["holderId"], self.configuration_digest)
        profile.require(holder is not None and holder["status"] == "registered"
            and holder["registration_sha256"] == pin["registrationSha256"])
        evidence = profile.registration_evidence(holder)
        profile.require(evidence["statement"]["policyHash"] == self.inner["policyHash"]
            and evidence["statement"]["dataPlaneBinarySha256"] == self.inner["dataPlaneBinaryDigest"]
            and type(pin["signature"]) is str and pin["signature"].startswith("ed25519:"))
        key = Ed25519PublicKey.from_public_bytes(profile.encoded(evidence["nativeKeyEvidence"]["responseProofPublicKey"], 32))
        key.verify(profile.encoded(pin["signature"][8:], 64), LEASE_DOMAIN + profile.canonical({
            "holderId": pin["holderId"], "epoch": version, "registrationSha256": pin["registrationSha256"],
            "leaseRequest": self.inner}))
        self.version, self.credential, self.generation = version, credential, generation
        self.check()


def _all_acknowledged(root, barrier, configuration_digest):
    original = profile.public_barrier(barrier)["original"]
    with db.connect() as connection:
        rows = connection.execute("SELECT * FROM credential_currentness_holders WHERE root_id = ? ORDER BY holder_id LIMIT 65",
            (root["id"],)).fetchall()
    profile.require(len(rows) <= profile.MAX_ROWS)
    values = [dict(row) for row in rows]
    profile.require([row["holder_id"] for row in values] == [item["holderId"] for item in original["holders"]])
    for row, frozen in zip(values, original["holders"]):
        profile.registration_evidence(row)
        profile.require(row["registration_sha256"] == frozen["registrationSha256"]
            and row["control_plane_configuration_digest"] == configuration_digest)
        if row["status"] != "acked":
            return False
        evidence = profile.evidence(refresh.document(row["acknowledgement_original_json"].encode("ascii"), 32768))
        statement = evidence["statement"]
        profile.require(profile.sha256(profile.canonical(evidence)) == row["acknowledgement_sha256"]
            and statement["phase"] == "ack" and statement["holderId"] == row["holder_id"]
            and statement["barrierId"] == barrier["id"] and statement["barrierSha256"] == barrier["original_sha256"])
    return True


def _coordinate(owner, credential, generation, parent):
    parent.check()
    owner.check()
    credential_id, version = credential["id"], credential["credential_version"]
    current, head, root = _rows(credential_id, version)
    profile.require(current == credential and head == generation and root["status"] == "open" and root["barrier_id"] is None)
    issued = time.time_ns()
    result = owner.dispatch(profile.OP_QUIESCE, credential_id, version, {
        "barrierId": str(uuid.uuid4()), "issuedAtEpochNs": issued, "expiresAtEpochNs": owner.expires})
    frozen = result["currentness"]["barrier"]
    profile.require(frozen is not None and frozen["status"] == "quiescing")
    while True:
        parent.check()
        owner.check()
        current, head, root = _rows(credential_id, version)
        profile.require(current == credential and head == generation and root["status"] == "quiescing")
        barrier = _barrier(root)
        profile.require(barrier is not None and profile.public_barrier(barrier) == frozen)
        if _all_acknowledged(root, barrier, owner.configuration_digest):
            break
        # Waiting is observation, never proof. The original deadline is not
        # renewed and an unreachable holder leaves this one-shot root blocked.
        time.sleep(min(0.025, max(0, owner.deadline - time.monotonic_ns()) / 1_000_000_000))
    result = owner.dispatch(profile.OP_ADMIT, credential_id, version,
        {"barrierId": barrier["id"], "barrierSha256": barrier["original_sha256"]})
    profile.require(result["currentness"]["root"]["status"] == "admitted"
        and result["currentness"]["barrier"]["sha256"] == frozen["sha256"])
    parent.check()
    owner.check()
    return frozen["sha256"]


def admit_refresh_barrier(opening, credential_row, generation_row):
    from serverware.control_plane_oauth_refresh import LeaseOpening as RefreshOpening
    profile.require(type(opening) is RefreshOpening)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.operation is not None and opening.operation.custody_owner() is owner.custody)
    return _coordinate(owner, credential_row, generation_row, opening)


def admit_cleanup_barrier(operation):
    from serverware.control_plane_oauth_refresh_cleanup import _Operation
    profile.require(type(operation) is _Operation)
    operation.check()
    owner = _Owner(deadline=operation.deadline, expires=operation.expires)
    profile.require(operation.owner.custody is owner.custody)
    credential, generation, root = _rows(operation.credential["id"], operation.credential["credential_version"])
    profile.require(credential == operation.credential and generation == operation.generation)
    if root["status"] == "consumed":
        barrier = _barrier(root)
        profile.require(barrier is not None and barrier["status"] == "consumed"
            and barrier["original_sha256"] == operation.historical_barrier_sha256
            and barrier["consume_request_digest"] == operation.refresh["claim_request_digest"]
            and operation.refresh["credential_id"] == credential["id"]
            and operation.refresh["credential_version"] == credential["credential_version"])
        operation.check()
        owner.check()
        return barrier["original_sha256"]
    return _coordinate(owner, credential, generation, operation)
