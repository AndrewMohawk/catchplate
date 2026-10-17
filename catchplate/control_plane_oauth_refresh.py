"""Retained cold client for one due-only refresh before generation admission.

Every mutation is a purpose-fixed controlled writer operation. Local SELECTs
observe its fence; they are not retrospective revocation of dispatched effects.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time

from fastapi import Request

from catchplate import authority_contract, crypto, db, oauth, runtime
from catchplate import authority_oauth_refresh as profile
from catchplate import oauth_application_owner as applications
from catchplate import oauth_refresh_material as material
from catchplate.control_plane_approval_verification import _request_pin

_PUBLIC_FIELDS = frozenset({"id", "credentialId", "expectedVersion", "status", "rowSha256",
    "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs"})
_CREDENTIAL_PUBLIC_FIELDS = frozenset({"id", "name", "kind", "secret_kek_id", "credential_version",
    "secret_updated_at", "metadata", "lifecycle_status", "revocation_error",
    "revocation_requested_at", "created_at", "updated_at"})
_STATUS = {profile.OP_CLAIM: "claimed", profile.OP_RETAIN: "retained", profile.OP_COMMIT: "committed"}


def _limits():
    # These source-selected bounds must also equal independently signed current
    # oauthRefreshPolicy values at every controlled transition.
    return profile.limits({"dueWithinSeconds": oauth.OAUTH_REFRESH_SKEW_SECONDS,
        "operationMaxSeconds": 30, "revocationCapacity": 64})


def _row(refresh_id):
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM oauth_refresh_reservations WHERE id = ?", (refresh_id,)).fetchone()
    profile.require(value is not None)
    value = dict(value)
    profile.row_original(value)
    return value


def _credential_rows(credential_id):
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        head = connection.execute("SELECT * FROM credential_generations WHERE credential_id = ?", (credential_id,)).fetchone()
    return (None if value is None else dict(value), None if head is None else dict(head))


def _unfenced(credential_id):
    with db.connect() as connection:
        row = connection.execute(
            "SELECT id FROM oauth_refresh_reservations WHERE credential_id = ? AND status <> 'committed' LIMIT 1",
            (credential_id,),
        ).fetchone()
    profile.require(row is None)


def _public(row):
    return {"id": row["id"], "credentialId": row["credential_id"], "expectedVersion": row["credential_version"],
        "status": row["status"], "rowSha256": profile.row_digest(row),
        "contactExpiresAtEpochNs": row["contact_expires_at_epoch_ns"],
        "retentionExpiresAtEpochNs": row["retention_expires_at_epoch_ns"]}


def _decrypted(item_id, envelope, version):
    profile.envelope(envelope, version)
    return crypto.decrypt_secret_envelope({"id": item_id, **envelope}).encode("utf-8")


def _encrypted(item_id, original, version=1):
    profile.require(type(original) is bytes)
    envelope = profile.envelope(db._envelope_values(item_id, original.decode("utf-8"), version), version)
    profile.require(_decrypted(item_id, envelope, version) == original)
    return envelope


class LeaseOpening:
    """Same actual HTTP opening and cold owner retained through lease output."""

    def __init__(self, request, payload):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.epoch, self.mono = time.time_ns(), time.monotonic_ns()
        self.expires, self.deadline = self.epoch + 30_000_000_000, self.mono + 30_000_000_000
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.payload = payload
        self.payload_original = profile.canonical(payload.model_dump(by_alias=True, exclude_unset=True))
        profile.require(type(request) is Request and request.method == "POST"
            and request.url.path == "/api/data-plane/credential-leases" and not request.url.query)
        self.cold = applications.require_started()
        profile.require(self.cold is not None)
        self.operation, self.observed, self.head = None, None, None
        self.authority, self.authority_original = None, None
        self.poisoned = False
        self.check()

    def __copy__(self):
        raise ValueError("OAuth lease opening cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("OAuth lease opening cannot be copied")

    def check(self):
        try:
            epoch, mono = time.time_ns(), time.monotonic_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical(self.payload.model_dump(by_alias=True, exclude_unset=True)) == self.payload_original
                and applications.require_started() is self.cold)
            self.cold.check()
            if self.authority_original is not None:
                profile.require(profile.canonical(self.authority) == self.authority_original)
            if self.operation is not None:
                self.operation.check()
            closing_epoch, closing_mono = time.time_ns(), time.monotonic_ns()
            profile.require(epoch <= closing_epoch < self.expires and mono <= closing_mono < self.deadline)
            self.epoch, self.mono = closing_epoch, closing_mono
        except BaseException:
            self.poisoned = True
            raise

    def bind_authority(self, authority):
        self.check()
        profile.require(self.authority_original is None)
        if authority is not None:
            profile.require(type(authority) is dict and type(authority.get("reservationExpiresAtEpochMs")) is int)
            expiry = authority["reservationExpiresAtEpochMs"] * 1_000_000
            self.expires = min(self.expires, expiry)
            self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
            self.authority, self.authority_original = authority, profile.canonical(authority)
        self.check()

    def _read(self, *, ciphertext_only=False):
        self.check()
        profile.require(type(ciphertext_only) is bool)
        row, head = _credential_rows(self.payload.credential_id)
        profile.require(row is not None and row["lifecycle_status"] == "active")
        if row["kind"] != "oauth2":
            return row, head, None, None
        profile.require(head is not None)
        profile.credential_original(row)
        profile.generation_original(head)
        profile.require(head["credential_id"] == row["id"] and head["last_version"] == row["credential_version"])
        _unfenced(row["id"])
        metadata = material.json_object(row["metadata"].encode("utf-8"), 32 * 1024)
        if self.operation is None:
            self.operation = oauth.require_application_metadata(metadata)
            profile.require(self.operation is not None and self.operation.owner is self.cold)
            self.expires = min(self.expires, self.operation.expires_ns)
            self.deadline = min(self.deadline, self.operation.deadline_ns)
        else:
            profile.require(oauth.require_application_metadata(metadata, self.operation) is self.operation)
        self.check()
        if ciphertext_only:
            # Do not materialize refresh/access tokens in this HTTP process.
            # Token-to-metadata checks must run inside the measured recipient;
            # here retain only genuine enrolled identity and ciphertext scope.
            from catchplate import credential_ciphertext
            credential_ciphertext.row_projection(row)
            db.validate_managed_oauth_account_identity(metadata)
            profile.require(metadata.get("oauth") is True and metadata.get("refreshable") is True)
            material._epoch(metadata.get("expires_at_epoch_ms"))
            token = None
        else:
            self.operation.require_parent_material()
            token, admitted_metadata = material.current(row)
            profile.require(admitted_metadata == metadata)
        self.check()
        return row, head, token, metadata

    def generation_metadata(self, *, ciphertext_only=False):
        profile.require(self.payload.purpose == "generationMetadata")
        row, head, token, metadata = self._read(ciphertext_only=ciphertext_only)
        if metadata is not None and metadata["expires_at_epoch_ms"] <= time.time_ns() // 1_000_000 + _limits()["dueWithinSeconds"] * 1000:
            if ciphertext_only:
                # The measured refresh producer is a separate required join.
                # Never silently downgrade to the parent-held KEK path.
                raise ValueError("broker OAuth refresh requires measured provider custody")
            row, head = _Refresh(self, row, head, token, metadata).execute()
        self.observed, self.head = row, head
        self.require_current()

    def dispatch_credential(self, *, ciphertext_only=False):
        profile.require(self.payload.purpose == "dispatchSecret")
        row, head, _, metadata = self._read(ciphertext_only=ciphertext_only)
        if metadata is not None:
            profile.require(row["credential_version"] == self.payload.expected_credential_version
                and metadata["expires_at_epoch_ms"] > time.time_ns() // 1_000_000 + _limits()["dueWithinSeconds"] * 1000)
        self.observed, self.head = row, head
        self.require_current()
        return db.row_to_credential(row, include_secret=not ciphertext_only)

    def require_current(self, credential=None):
        self.check()
        if self.observed is None:
            return
        row, head = _credential_rows(self.observed["id"])
        profile.require(row == self.observed and head == self.head)
        if row["kind"] == "oauth2":
            _unfenced(row["id"])
            profile.require(self.operation is not None)
            metadata = material.json_object(row["metadata"].encode("utf-8"), 32 * 1024)
            self.operation.require_association(metadata[applications.ASSOCIATION_KEY])
            profile.require(metadata["expires_at_epoch_ms"] > time.time_ns() // 1_000_000 + _limits()["dueWithinSeconds"] * 1000)
        if credential is not None:
            profile.require(credential["id"] == row["id"] and credential["credential_version"] == row["credential_version"]
                and credential["metadata"] == material.json_object(row["metadata"].encode("utf-8"), 32 * 1024))
        self.check()


class _Refresh:
    def __init__(self, opening, row, head, token, metadata):
        opening.operation.require_parent_material()
        self.opening, self.row, self.head, self.token, self.metadata = opening, row, head, token, metadata
        self.operation, self.provider = opening.operation, opening.operation.provider
        self.version, self.credential_id = row["credential_version"], row["id"]
        self.refresh_id = profile.refresh_id(self.credential_id, self.version)
        self.enrollment = self.operation.enrollment_original()
        self.encoded_enrollment = base64.urlsafe_b64encode(self.enrollment).rstrip(b"=").decode("ascii")
        self.custody = self.operation.custody_owner()
        self.bounds, self.attempts, self.claim_original = _limits(), set(), None
        self.nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        self.contact_attempted = False
        self.check()

    def check(self):
        self.opening.check()
        profile.require(self.operation.enrollment_original() == self.enrollment
            and self.operation.custody_owner() is self.custody and _limits() == self.bounds)
        self.operation.require_association(self.metadata[applications.ASSOCIATION_KEY])

    def _arguments(self, operation, request):
        return profile.arguments(operation, {"credential_id": self.credential_id,
            "enrollment_original": self.encoded_enrollment, "request": request})

    def dispatch(self, operation, request, row=None):
        self.check()
        profile.require(operation not in self.attempts)
        if row is not None:
            profile.require(profile.row_original(_row(self.refresh_id)) == profile.row_original(row))
        arguments = self._arguments(operation, request)
        original, digest = profile.canonical(arguments), profile.request_digest(operation, arguments)
        self.attempts.add(operation)
        from catchplate.control_plane_custody_client import ControlPlaneCustodyClient
        result = ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments},
            deadline_ns=self.opening.deadline)
        self.check()
        fields = {"ok", "refresh", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}
        if operation == profile.OP_COMMIT:
            fields.add("credential")
        profile.require(profile.canonical(arguments) == original and type(result) is dict and set(result) == fields
            and result["ok"] is True and result["operation"] == operation and result["requestDigest"] == digest
            and result["idempotentReplay"] is False and type(result["refresh"]) is dict
            and set(result["refresh"]) == _PUBLIC_FIELDS)
        profile.digest(result["auditEventDigest"])
        if operation == profile.OP_COMMIT:
            profile.require(type(result["credential"]) is dict and set(result["credential"]) == _CREDENTIAL_PUBLIC_FIELDS)
        current = _row(self.refresh_id)
        profile.require(_public(current) == result["refresh"] and current["status"] == _STATUS[operation]
            and current["credential_id"] == self.credential_id and current["credential_version"] == self.version
            and current["enrollment_original"] == self.encoded_enrollment
            and current["credential_original_json"].encode("ascii") == profile.credential_original(self.row)
            and current["generation_original_json"].encode("ascii") == profile.generation_original(self.head))
        self.check()
        if operation == profile.OP_CLAIM:
            profile.require(current["claim_request_digest"] == digest)
            self.claim_original = profile.row_original(current)
        return current, result

    def execute(self):
        self.check()
        profile.require(self.row["lifecycle_status"] == "active")
        refresh_expiry = self.token.get("refresh_token_expires_at_epoch_ms")
        profile.require(refresh_expiry is None or refresh_expiry > time.time_ns() // 1_000_000)
        request, contact_digest = material.token_request(self.provider, self.token)
        issued = time.time_ns()
        retention = min(self.opening.expires, issued + self.bounds["operationMaxSeconds"] * 1_000_000_000)
        contact = min(retention, issued + 20_000_000_000)
        from catchplate.control_plane_credential_currentness import admit_refresh_barrier
        # Drain the genuine registered holders before the irreversible claim.
        # Waiting spends these original bounds; it does not start a fresh
        # contact or retention allowance when the final holder acknowledges.
        barrier_sha256 = admit_refresh_barrier(self.opening, self.row, self.head)
        self.check()
        profile.require(time.time_ns() < contact)
        common = {"expectedVersion": self.version, "limits": self.bounds}
        def reserved(purpose):
            return _encrypted(profile.artifact_id(self.refresh_id, purpose), profile.canonical({
                "schema": "catchplate.oauthRefreshReservedMaterial/v1", "refreshId": self.refresh_id, "purpose": purpose}))
        row, _ = self.dispatch(profile.OP_CLAIM, {**common,
            "credentialRowSha256": profile.sha256(profile.credential_original(self.row)),
            "generationRowSha256": profile.sha256(profile.generation_original(self.head)),
            "currentnessBarrierSha256": barrier_sha256,
            "ownerNonceSha256": profile.sha256(base64.urlsafe_b64decode(self.nonce + "=")),
            "issuedAtEpochNs": issued, "contactExpiresAtEpochNs": contact, "retentionExpiresAtEpochNs": retention,
            "contactRequestSha256": contact_digest, "reservedIssuedEnvelope": reserved("issued"),
            "reservedSupersededEnvelope": reserved("superseded") if self.provider.id == "x" else None})
        runtime.invalidate_secret_leases(self.credential_id)
        self.check()
        profile.require(not self.contact_attempted and self.claim_original == profile.row_original(row)
            and self.claim_original == profile.row_original(_row(self.refresh_id))
            and row["contact_request_sha256"] == contact_digest and time.time_ns() < contact
            and (refresh_expiry is None or refresh_expiry > time.time_ns() // 1_000_000))
        actual_rows = _credential_rows(self.credential_id)
        profile.require(actual_rows == (self.row, self.head))
        rebuilt, rebuilt_digest = material.token_request(self.provider, self.token)
        profile.require(rebuilt_digest == contact_digest and rebuilt.data == request.data)
        deadline = min(self.opening.deadline, time.monotonic_ns() + contact - time.time_ns())
        self.check()
        self.contact_attempted = True
        response, raw, received = material.contact(rebuilt, self.operation, deadline_ns=deadline)
        issued_original = material.issued_original(response, self.metadata[applications.ASSOCIATION_KEY])
        raw_envelope = _encrypted(profile.artifact_id(self.refresh_id, "response"), raw)
        try:
            issued_envelope = None if issued_original is None else _encrypted(profile.artifact_id(self.refresh_id, "issued"), issued_original)
        except (TypeError, ValueError, UnicodeError):
            issued_original, issued_envelope = None, None
        def possession(current):
            return {**common, "refreshRowSha256": profile.row_digest(current), "ownerNonce": self.nonce}
        row, _ = self.dispatch(profile.OP_RETAIN, {**possession(row), "receivedAtEpochNs": received,
            "rawResponseSha256": profile.sha256(raw), "rawResponseEnvelope": raw_envelope,
            "issuedMaterialSha256": None if issued_original is None else profile.sha256(issued_original),
            "issuedMaterialEnvelope": issued_envelope}, row)
        stored_raw = profile.document(row["raw_response_envelope_json"].encode("ascii"), profile.MAX_ENVELOPE_BYTES)
        profile.require(stored_raw == raw_envelope
            and _decrypted(profile.artifact_id(self.refresh_id, "response"), stored_raw, 1) == raw
            and row["raw_response_sha256"] == profile.sha256(raw) and row["received_at_epoch_ns"] == received
            and issued_original is not None)
        stored_issued = profile.document(row["issued_material_envelope_json"].encode("ascii"), profile.MAX_ENVELOPE_BYTES)
        profile.require(stored_issued == issued_envelope
            and _decrypted(profile.artifact_id(self.refresh_id, "issued"), stored_issued, 1) == issued_original
            and row["issued_material_sha256"] == profile.sha256(issued_original))
        self.check()
        replacement, metadata, superseded = material.replacement(response, received, self.provider, self.token, self.metadata)
        next_envelope = _encrypted(self.credential_id, replacement, self.version + 1)
        superseded_envelope = None if superseded is None else _encrypted(profile.artifact_id(self.refresh_id, "superseded"), superseded)
        row, result = self.dispatch(profile.OP_COMMIT, {**possession(row),
            "replacementSecretSha256": profile.sha256(replacement), "replacementEnvelope": next_envelope,
            "replacementMetadata": metadata, "supersededMaterialSha256": None if superseded is None else profile.sha256(superseded),
            "supersededEnvelope": superseded_envelope}, row)
        current, head = _credential_rows(self.credential_id)
        profile.require(current is not None and head is not None
            and profile.generation_original(head)
            and head["credential_id"] == self.credential_id
            and current["credential_version"] == self.version + 1 and head["last_version"] == self.version + 1
            and row["replacement_credential_sha256"] == profile.sha256(profile.credential_original(current))
            and row["replacement_secret_sha256"] == profile.sha256(replacement)
            and row["superseded_material_sha256"] == (None if superseded is None else profile.sha256(superseded))
            and material.json_object(current["metadata"].encode("utf-8"), 32 * 1024) == metadata
            and {field: current[field] for field in profile.ENVELOPE_FIELDS} == next_envelope
            and _decrypted(self.credential_id, {field: current[field] for field in profile.ENVELOPE_FIELDS}, self.version + 1) == replacement
            and db.row_to_credential(current) == result["credential"])
        _unfenced(self.credential_id)
        self.check()
        runtime.invalidate_secret_leases(self.credential_id)
        return current, head
