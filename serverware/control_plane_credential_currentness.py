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
from serverware import credential_currentness_rows
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware import control_plane_credential_currentness_assignment as assignment_startup
from serverware.control_plane_approval_verification import _request_pin

REQUEST_SCHEMA = "serverware.credentialCurrentnessRequest/v1"
STATIC_REQUEST_SCHEMA = "serverware.credentialCurrentnessRequest/v2"
ROTATION_REQUEST_SCHEMA = "serverware.credentialCurrentnessRequest/v3"
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
    credential_currentness_rows.credential_original(credential)
    refresh.generation_original(generation)
    profile.root_original(root)
    profile.require(credential["lifecycle_status"] == "active" and credential["credential_version"] == version
        and generation["last_version"] == version and root["credential_id"] == credential_id
        and root["credential_version"] == version and root["epoch"] == version
        and root["profile"] == profile.ROOT_SCHEMA)
    return credential, generation, root


def _static_rows(original, credential_id, version, configuration_digest, now):
    from serverware import authority_static_credential_provenance as provenance
    credential, generation, root = _rows(credential_id, version)
    with db.connect() as connection:
        outbox = connection.execute("SELECT * FROM metadata_audit_outbox WHERE id = ?",
            (provenance.generation_outbox_id(original),)).fetchone()
    profile.require(outbox is not None)
    return provenance.verify_generation_rows(original, credential=credential, generation=generation,
        root=root, outbox=dict(outbox), configuration_digest=configuration_digest, now_epoch_ns=now)


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
        self.assignment = None
        self.poisoned, self.attempts = False, set()

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and startup.require_started() is self.custody
                and custody_client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.configuration_digest)
            if self.assignment is not None:
                profile.require(assignment_startup.require_selected() is self.assignment
                    and self.assignment.binding is self.binding
                    and self.assignment.configuration_digest == self.configuration_digest)
                self.assignment.check()
            self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def __copy__(self):
        raise ValueError("currentness owner cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("currentness owner cannot be copied")

    def dispatch(self, operation, credential_id, version, request, *, static_provenance_original=None):
        self.check()
        values = {"credential_id": credential_id,
            "credential_version": version, "control_plane_configuration_digest": self.configuration_digest,
            "request": request}
        if static_provenance_original is not None:
            from serverware import authority_credential_currentness_policy as policy
            self.assignment = assignment_startup.require_selected()
            profile.require(self.assignment.binding is self.binding
                and self.assignment.policy["schema"] in ({policy.STATIC_POSTBOOT_SCHEMA, policy.ROTATION_POSTBOOT_SCHEMA}
                    if version == 1 else {policy.ROTATION_POSTBOOT_SCHEMA}))
            deployment = _static_rows(static_provenance_original, credential_id, version,
                self.configuration_digest, self.epoch)
            profile.require(deployment == self.assignment.policy["deploymentId"])
            values["static_creation_provenance_original" if version == 1 else "static_generation_provenance_original"] = static_provenance_original
            self.check()
        if operation in profile.ASSIGNMENT_OPERATIONS and assignment_startup.selected():
            self.assignment = assignment_startup.require_selected()
            statement = request if operation == profile.OP_CHALLENGE else request["evidence"]["statement"]
            profile.require(self.assignment.binding is self.binding
                and self.assignment.configuration_digest == self.configuration_digest
                and self.assignment.payload["assignment"]["holderId"] == statement["holderId"])
            self.expires = min(self.expires, self.assignment.expires)
            self.deadline = min(self.deadline, self.assignment.deadline, self.mono + self.expires - self.epoch)
            values["assignment_original"] = self.assignment.assignment_original
            self.check()
        arguments = profile.arguments(operation, values)
        if static_provenance_original is not None:
            profile.arguments(operation, {**arguments,
                "businessIntent": authority_contract.synthesize_business_intent(operation, arguments)}, typed=True)
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
        if static_provenance_original is not None:
            _static_rows(static_provenance_original, credential_id, version, self.configuration_digest, self.epoch)
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
    static = type(payload) is dict and payload.get("apiVersion") in {STATIC_REQUEST_SCHEMA, ROTATION_REQUEST_SCHEMA}
    successor = type(payload) is dict and payload.get("apiVersion") == ROTATION_REQUEST_SCHEMA
    provenance_field = "staticGenerationProvenanceOriginal" if successor else "staticCreationProvenanceOriginal"
    profile.require(type(request) is Request and request.method == "POST"
        and request.url.path == "/api/data-plane/credential-currentness" and not request.url.query
        and type(payload) is dict and set(payload) == {"apiVersion", "credentialId", "credentialVersion", "request"}
            | ({provenance_field} if static else set())
        and payload["apiVersion"] == (ROTATION_REQUEST_SCHEMA if successor else STATIC_REQUEST_SCHEMA if static else REQUEST_SCHEMA))
    owner, scope, pin, original = _Owner(), request.scope, _request_pin(request), profile.canonical(payload)
    profile.require(len(original) <= (profile.MAX_STATIC_ARGUMENT_BYTES if static else 64 * 1024))
    item = payload["request"]
    profile.require(type(item) is dict and set(item) == {"phase", "arguments"})
    credential_id, version = payload["credentialId"], payload["credentialVersion"]
    _rows(credential_id, version)
    provenance_original = payload[provenance_field] if static else None
    if static:
        from serverware import authority_credential_currentness_policy as policy
        profile.require(type(version) is int and (2 <= version <= 2**63 - 1 if successor else version == 1))
        owner.assignment = assignment_startup.require_selected()
        profile.require(owner.assignment.binding is owner.binding
            and owner.assignment.policy["schema"] in ({policy.ROTATION_POSTBOOT_SCHEMA} if successor
                else {policy.STATIC_POSTBOOT_SCHEMA, policy.ROTATION_POSTBOOT_SCHEMA}))
        deployment = _static_rows(provenance_original, credential_id, version, owner.configuration_digest, owner.epoch)
        profile.require(deployment == owner.assignment.policy["deploymentId"])
        owner.check()
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
        result = owner.dispatch(_PUBLIC[phase], credential_id, version, arguments,
            static_provenance_original=provenance_original)
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


def _coordinate(owner, credential, generation, parent, *, static_provenance_original=None):
    parent.check()
    owner.check()
    credential_id, version = credential["id"], credential["credential_version"]
    current, head, root = _rows(credential_id, version)
    profile.require(current == credential and head == generation and root["status"] == "open" and root["barrier_id"] is None)
    issued = time.time_ns()
    result = owner.dispatch(profile.OP_QUIESCE, credential_id, version, {
        "barrierId": str(uuid.uuid4()), "issuedAtEpochNs": issued, "expiresAtEpochNs": owner.expires},
        static_provenance_original=static_provenance_original)
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
    parent.check()
    result = owner.dispatch(profile.OP_ADMIT, credential_id, version,
        {"barrierId": barrier["id"], "barrierSha256": barrier["original_sha256"]},
        static_provenance_original=static_provenance_original)
    profile.require(result["currentness"]["root"]["status"] == "admitted"
        and result["currentness"]["barrier"]["sha256"] == frozen["sha256"])
    parent.check()
    owner.check()
    return frozen["sha256"]


def admit_static_rotation_barrier(opening, credential_row, generation_row):
    """One source-owned drain; returned hashes are observations, not permission.

    The final rotation kernel independently proves/consumes the retained rows.
    This never adopts an old quiescing/admitted root or retries an uncertain
    attempt. Fresh execution must fit the original barrier expiry returned here.
    """
    from serverware import control_plane_static_credential_rotation as http
    from serverware import authority_static_credential_rotate as rotation
    from serverware import authority_credential_currentness_policy as policy

    profile.require(type(opening) is http._Owner and opening.drain_started is True
        and opening.dispatched is False and type(opening.drain_original) is bytes
        and type(opening.drain_values) is dict
        and rotation.canonical(opening.drain_values) == opening.drain_original)
    opening.check()
    values = http._candidate(opening, opening.drain_original.decode("ascii"))
    profile.require(rotation.canonical(values) == opening.drain_original)
    values = rotation.arguments(rotation.OPERATION, values, candidate=True)
    request = values["request"]
    owner = _Owner(deadline=opening.deadline, expires=min(opening.expires, request["expiresAtEpochNs"]))
    profile.require(opening.cold.custody is owner.custody and opening.cold.binding is owner.binding
        and values["control_plane_configuration_digest"] == owner.configuration_digest)
    owner.assignment = assignment_startup.require_selected()
    profile.require(owner.assignment.binding is owner.binding
        and owner.assignment.policy["schema"] == policy.ROTATION_POSTBOOT_SCHEMA)
    owner.check()
    item_id, version = request["credentialId"], request["previousCredentialVersion"]
    credential, generation, root = _rows(item_id, version)
    profile.require(credential == credential_row and generation == generation_row
        and rotation.sha256(credential_currentness_rows.credential_original(credential)) == request["previousCredentialSha256"]
        and root["origin_request_digest"] == request["previousCurrentnessOriginRequestDigest"]
        and root["status"] == "open" and root["barrier_id"] is None)
    original = request["previousProvenanceOriginal"]
    profile.require(_static_rows(original, item_id, version, owner.configuration_digest, owner.epoch)
        == owner.assignment.policy["deploymentId"])
    barrier_sha = _coordinate(owner, credential, generation, opening, static_provenance_original=original)
    current, head, admitted = _rows(item_id, version)
    barrier = _barrier(admitted)
    profile.require(current == credential and head == generation and admitted["status"] == "admitted"
        and admitted["origin_request_digest"] == root["origin_request_digest"]
        and barrier is not None and barrier["status"] == "admitted"
        and barrier["original_sha256"] == barrier_sha)
    interval = profile.public_barrier(barrier)["original"]
    opening.check(); owner.check()
    return {"barrierSha256": barrier_sha, "currentnessRootSha256": profile.root_digest(admitted),
        "issuedAtEpochNs": interval["issuedAtEpochNs"], "expiresAtEpochNs": interval["expiresAtEpochNs"]}


def admit_refresh_barrier(opening, credential_row, generation_row):
    from serverware.control_plane_oauth_refresh import LeaseOpening as RefreshOpening
    profile.require(type(opening) is RefreshOpening)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.operation is not None and opening.operation.custody_owner() is owner.custody)
    return _coordinate(owner, credential_row, generation_row, opening)


def admit_measured_refresh_barrier(opening, credential_row, generation_row):
    from serverware.control_plane_oauth_measured_refresh import Opening
    from serverware.authority_oauth_measured_refresh import OP_INSPECT
    profile.require(type(opening) is Opening and opening.dispatched and opening.operation == OP_INSPECT
        and opening.arguments["request"]["recoveryVersion"] is None)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.custody is owner.custody and opening.binding is owner.binding)
    return _coordinate(owner, credential_row, generation_row, opening)


def admit_measured_cleanup_barrier(opening, credential_row, generation_row, history):
    from serverware.control_plane_oauth_measured_cleanup import Opening
    from serverware import authority_oauth_measured_cleanup as cleanup
    profile.require(type(opening) is Opening and opening.dispatched and opening.operation == cleanup.OP_INSPECT)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.custody is owner.custody and opening.binding is owner.binding)
    grant = cleanup.grant_document(cleanup.unb64(opening.arguments["authorization_original"], cleanup.MAX_GRANT_BYTES))["payload"]
    credential, generation, root = _rows(grant["credentialId"], grant["credentialVersion"])
    profile.require(credential == credential_row and generation == generation_row
        and cleanup.sha256(refresh.row_original(history)) == grant["refreshRowSha256"])
    if root["status"] == "consumed":
        barrier = _barrier(root)
        profile.require(barrier is not None and barrier["status"] == "consumed"
            and barrier["original_sha256"] == grant["historicalBarrierSha256"]
            and barrier["consume_request_digest"] == history["claim_request_digest"]
            and history["credential_id"] == credential["id"] and history["credential_version"] == credential["credential_version"])
        opening.check(); owner.check()
        return barrier["original_sha256"]
    return _coordinate(owner, credential, generation, opening)


def admit_pending_retirement_barriers(opening, affected_originals):
    from serverware.control_plane_oauth_measured_pending_retirement import Opening
    from serverware import authority_oauth_measured_pending_retirement as pending
    profile.require(type(opening) is Opening and opening.dispatched and opening.operation == pending.OP_INSPECT)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.custody is owner.custody and opening.binding is owner.binding)
    grant = pending.grant_document(pending.unb64(opening.arguments["authorization_original"], pending.MAX_GRANT_BYTES))["payload"]
    profile.require(type(affected_originals) is list and len(affected_originals) == len(grant["affectedLineages"]))
    result = []
    for original, pin in zip(affected_originals, grant["affectedLineages"]):
        opening.check(); owner.check()
        profile.require(type(original) is dict and set(original) == pending.AFFECTED_ORIGINAL_FIELDS)
        credential = pending.document(original["credentialOriginal"].encode("ascii"), 512 * 1024)
        generation = pending.document(original["generationOriginal"].encode("ascii"), 8192)
        profile.require(pending.sha256(refresh.credential_original(credential)) == pin["credentialRowSha256"]
            and pending.sha256(refresh.generation_original(generation)) == pin["generationRowSha256"])
        actual, head, root = _rows(pin["credentialId"], pin["credentialVersion"])
        profile.require(actual == credential and head == generation and root["status"] == "open"
            and root["barrier_id"] is None)
        digest = _coordinate(owner, credential, generation, opening)
        result.append({"credentialId": pin["credentialId"], "credentialVersion": pin["credentialVersion"], "barrierSha256": digest})
    opening.check(); owner.check()
    return pending.barriers(result, grant["affectedLineages"])


def admit_capture_retirement_barriers(opening, affected_originals):
    from serverware.control_plane_oauth_measured_capture_retirement import Opening
    from serverware import authority_oauth_measured_capture_retirement as pending
    profile.require(type(opening) is Opening and opening.dispatched and opening.operation == pending.OP_INSPECT)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.custody is owner.custody and opening.binding is owner.binding)
    grant = pending.grant_document(pending.unb64(opening.arguments["authorization_original"], pending.MAX_GRANT_BYTES))["payload"]
    profile.require(type(affected_originals) is list and len(affected_originals) == len(grant["affectedLineages"]))
    result = []
    for original, pin in zip(affected_originals, grant["affectedLineages"]):
        opening.check(); owner.check()
        profile.require(type(original) is dict and set(original) == {"credentialOriginal", "generationOriginal"})
        credential = pending.document(original["credentialOriginal"].encode("ascii"), 512 * 1024)
        generation = pending.document(original["generationOriginal"].encode("ascii"), 8192)
        profile.require(pending.sha256(refresh.credential_original(credential)) == pin["credentialRowSha256"]
            and pending.sha256(refresh.generation_original(generation)) == pin["generationRowSha256"])
        actual, head, root = _rows(pin["credentialId"], pin["credentialVersion"])
        profile.require(actual == credential and head == generation and root["status"] == "open"
            and root["barrier_id"] is None)
        digest = _coordinate(owner, credential, generation, opening)
        result.append({"credentialId": pin["credentialId"], "credentialVersion": pin["credentialVersion"], "barrierSha256": digest})
    opening.check(); owner.check()
    return pending.barriers(result, grant["affectedLineages"])

def admit_reconnect_barriers(opening):
    from serverware.control_plane_oauth_reconnect import _Authorization
    from serverware import authority_oauth_reconnect as reconnect
    from serverware import authority_transition_oauth_reconnect_rows as reconnect_rows
    profile.require(type(opening) is _Authorization and opening.sent and opening.authorized and not opening.fenced)
    opening.check()
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(opening.custody is owner.custody and opening.binding is owner.binding)
    members = reconnect_rows.affected(opening.journal, opening.grant)
    result = []
    for (credential, generation), pin in zip(members, opening.grant["affectedLineages"]):
        opening.check(); owner.check()
        digest = _coordinate(owner, credential, generation, opening)
        result.append({"credentialId": pin["credentialId"], "credentialVersion": pin["credentialVersion"], "barrierSha256": digest})
    opening.check(); owner.check()
    return reconnect.barriers(result, opening.grant["affectedLineages"])


def admit_succession_barriers(opening):
    from serverware.control_plane_oauth_succession_ceremony import _Fence
    from serverware import authority_oauth_retirement_succession as succession
    from serverware import authority_oauth_measured_pending_retirement as scalars
    profile.require(type(opening) is _Fence and not opening.sent and not opening.drain_attempted)
    opening.check(); opening.drain_attempted = True
    owner = _Owner(deadline=opening.deadline, expires=opening.expires)
    profile.require(owner.custody is opening.custody and owner.binding is opening.binding)
    active = [pin for pin in opening.grant["affectedLineages"] if pin["predecessorKind"] == "active"]
    result = []
    for pin in active:
        opening.check(); owner.check()
        credential, generation, _ = _rows(pin["credentialId"], pin["credentialVersion"])
        profile.require(succession.sha256(refresh.credential_original(credential)) == pin["credentialRowSha256"]
            and succession.sha256(refresh.generation_original(generation)) == pin["generationRowSha256"])
        digest = _coordinate(owner, credential, generation, opening)
        result.append({"credentialId": pin["credentialId"], "credentialVersion": pin["credentialVersion"], "barrierSha256": digest})
    opening.check(); owner.check()
    # Historical consumed roots are independently re-admitted by FENCE. They
    # never enter this fresh coordination or reopen because a new grant exists.
    return scalars.barriers(result, [{name: pin[name] for name in scalars.LINEAGE_FIELDS} for pin in active])


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
