"""Fresh-authorized terminal observation of one intact publication interruption.

This owner cannot generate, return, rename, unlink or retry a token. Its only
effects are one-use approval/audit transactions and append-only journal records.
"""
from __future__ import annotations

import fcntl
import os
import threading
import time

from fastapi import HTTPException, Request

from serverware import control_plane_admin_token_publication as publication
from serverware import db
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

ACTION = "control_plane.token.publication.resolve"
PATH = "/api/control-plane/tokens/admin/publication/resolve"


def binding(payload):
    return {"token": "admin", "publicationId": payload.publication_id,
        "intentSha256": payload.intent_sha256, "outcome": payload.outcome,
        "reason": payload.reason}


class _Resolution:
    def __init__(self, request, payload):
        self.epoch, self.mono = time.time_ns(), time.monotonic_ns()
        self.expires = self.epoch + 30_000_000_000
        self.deadline = self.mono + 30_000_000_000
        self.pid, self.tid = os.getpid(), threading.get_ident()
        self.request, self.scope, self.payload = request, request.scope, payload
        self.request_pin = _request_pin(request)
        publication._require(type(request) is Request and request.method == "POST"
            and request.url.path == PATH and not request.url.query)
        self.bound = binding(payload)
        self.bound_original = publication._json(self.bound)
        self.mfa_original = publication._json(payload.mfa)
        from serverware import app as application
        self.payload_digest = application._control_plane_payload_digest(self.bound)
        self.policy = self._policy()
        self.identity = self._identity()
        self.parent = self.directory = None
        self.pins = []
        self.history = None
        self.credential = None
        self.attempt = payload.publication_id
        self.executing = self.claimed = self.authorized = False

    def _policy(self):
        from serverware import app as application
        publication._require(application._control_plane_two_person_required(ACTION))
        return publication._json({"mfa": True, "twoPerson": True,
            "authn": application._control_plane_mutation_authn_policy()})

    def _identity(self):
        from serverware import auth
        current = Request(self.scope)
        identity = auth.require_admin(current,
            x_serverware_admin_token=current.headers.get("X-Serverware-Admin-Token"))
        auth.validate_csrf_request(current)
        publication._require(type(identity) is auth.AdminIdentity and identity.has_any_role({"admin"}))
        return identity

    def check(self):
        epoch, mono = time.time_ns(), time.monotonic_ns()
        publication._require((os.getpid(), threading.get_ident()) == (self.pid, self.tid)
            and self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline
            and self.request.scope is self.scope and _request_pin(self.request) == self.request_pin
            and publication._json(binding(self.payload)) == self.bound_original
            and publication._json(self.payload.mfa) == self.mfa_original
            and self._policy() == self.policy and self._identity() == self.identity)
        self.epoch, self.mono = epoch, mono
        if self.credential is not None:
            from serverware import app as application, webauthn
            current = db.get_webauthn_credential_by_record_id(self.credential[0])
            publication._require(type(current) is dict and current.get("revoked_at") is None
                and tuple(current.get(key) for key in ("id", "user_id", "credential_id", "public_key_cose"))
                    == self.credential)
            webauthn._allowed_authenticator(current, application._control_plane_mutation_authn_policy())
        if self.parent is not None:
            publication._recheck_secure_parent_directory(self.path, label="generated admin token",
                expected=self.parent_identity, mutation_target=True)
            held, named = os.fstat(self.directory), os.stat(publication._JOURNAL,
                dir_fd=self.parent, follow_symlinks=False)
            publication._require((held.st_dev, held.st_ino, held.st_uid, held.st_gid, held.st_mode)
                == self.journal_identity
                == (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode))
            for directory, name, descriptor, original, identity in self.pins:
                raw, value = publication._read(directory, name,
                    256 if directory == self.parent or name.endswith((".old", ".new")) else publication._MAX_RECORD)
                publication._require(raw == original and publication._file_identity(value) == identity
                    == publication._file_identity(os.fstat(descriptor)))
            if self.history is not None:
                publication._require(publication._records(self.directory) == self.history)
        epoch, mono = time.time_ns(), time.monotonic_ns()
        publication._require(self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline)
        self.epoch, self.mono = epoch, mono

    def _pin(self, directory, name, maximum):
        original, value = publication._read(directory, name, maximum)
        descriptor = os.open(name, publication._READ_FLAGS, dir_fd=directory)
        try:
            identity = publication._file_identity(value)
            publication._require(publication._file_identity(os.fstat(descriptor)) == identity)
            self.pins.append((directory, name, descriptor, original, identity))
        except BaseException:
            os.close(descriptor)
            raise
        return original, identity

    def _record(self, phase, value):
        self.check()
        raw = publication._json(value)
        publication._exclusive(self.directory, self.attempt + "." + phase, raw)
        retained, _ = self._pin(self.directory, self.attempt + "." + phase, publication._MAX_RECORD)
        publication._require(retained == raw)
        self.history[self.attempt][phase] = value
        self.history[self.attempt][phase + "Sha256"] = publication._sha(raw)
        self.check()
        return publication._sha(raw)

    def _verify(self):
        from serverware import app as application, webauthn
        self.check()
        supplied = self.payload.mfa if type(self.payload.mfa) is dict else {}
        assertion = supplied.get("assertion")
        challenge = None
        if type(assertion) is dict and type(assertion.get("response")) is dict:
            client_data, _ = webauthn._parse_client_data(
                assertion["response"].get("clientDataJSON"), "webauthn.get")
            challenge = db.get_unused_webauthn_challenge(client_data["challenge"],
                challenge_type="control-plane-mutation", user_id=self.identity.user_id)
            publication._require(challenge is not None)
            self.expires = min(self.expires, _epoch_ns(challenge["expires_at"]))
            self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
            self.check()
        # Only the actual verifier is allowed here, never the authority metadata
        # shortcut. The helper's action-specific gate remains mandatory even
        # when unrelated mutations use the optional-MFA policy.
        self.mfa = application._require_control_plane_mutation_mfa(action=ACTION,
            resource_id=publication._RESOURCE, payload_digest=self.payload_digest,
            mfa={"assertion": supplied.get("assertion")}, identity=self.identity)
        publication._require(type(self.mfa) is dict and self.mfa.get("method") == "webauthn"
            and self.mfa.get("user_id") == self.identity.user_id
            and self.mfa.get("user_present") is True and self.mfa.get("user_verified") is True
            and challenge is not None and self.mfa.get("challenge_id") == challenge["id"])
        for hint, field in (("authorityChallengeId", "challenge_id"),
                ("credentialRecordId", "credential_record_id")):
            publication._require(hint not in supplied or supplied[hint] == self.mfa.get(field))
        value = db.get_webauthn_credential_by_record_id(self.mfa["credential_record_id"])
        publication._require(type(value) is dict and value.get("revoked_at") is None
            and value.get("user_id") == self.identity.user_id)
        self.credential = tuple(value[key] for key in ("id", "user_id", "credential_id", "public_key_cose"))
        self.check()
        if not application._control_plane_approval_id(self.payload.mfa):
            application._require_control_plane_two_person(action=ACTION, resource_id=publication._RESOURCE,
                payload_digest=self.payload_digest, mfa=self.payload.mfa, identity=self.identity,
                request=self.bound)
            raise publication.PublicationError("required resolution approval did not negotiate")

    def _open(self):
        self.path, self.basename, parent, self.parent_identity = publication._parent()
        try:
            # Same lock order as the actual publisher. The journal lock also
            # excludes a publisher that began before the parent-lock addition.
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            directory, identity, _ = publication._journal(parent, create=False)
        except BaseException:
            os.close(parent)
            raise
        self.parent, self.directory, self.journal_identity = parent, directory, identity
        self.check()
        attempts, incomplete, _ = publication._history(directory, self.path)
        item = attempts.get(self.attempt)
        publication._require(item is not None and incomplete is item
            and item["intentSha256"] == self.payload.intent_sha256
            and not any(key.startswith("resolution-") for key in item),
            "resolution requires an intact unresolved tail with no prior resolution claim")
        # Retain all selected original descriptors; no caller observation is
        # accepted as proof of the current token or staged publication state.
        for phase in ("intent", "authorized", "claimed", "complete", "old", "new"):
            if phase in item:
                self._pin(directory, self.attempt + "." + phase,
                    256 if phase in {"old", "new"} else publication._MAX_RECORD)
        current, current_identity = self._pin(parent, self.basename, 256)
        intent = item["intent"]
        publication._require(publication._TOKEN.fullmatch(current) is not None)
        if self.payload.outcome == "finalize-installed":
            publication._require("claimed" in item and "new" not in item
                and publication._sha(current) == intent["newFileSha256"]
                and publication._sha(current[:-1]) == intent["newTokenSha256"]
                and current_identity[:8] == intent["newFileIdentity"][:8])
            if "complete" in item:
                publication._require(current_identity == item["complete"]["fileIdentity"])
        else:
            publication._require(self.payload.outcome == "abandon-uninstalled"
                and "complete" not in item and "new" in item
                and publication._sha(current) == intent["previousFileSha256"]
                and publication._sha(current[:-1]) == intent["previousTokenSha256"]
                and current_identity == intent["previousFileIdentity"])
            staged = next(pin for pin in self.pins if pin[1] == self.attempt + ".new")
            publication._require(staged[4] == intent["newFileIdentity"])
        self.history = attempts
        self.file_sha, self.file_identity = publication._sha(current), current_identity
        self.prior_completion = item.get("completeSha256")
        self.check()

    def execute(self):
        from serverware import app as application
        publication._require(not self.executing)
        self.executing = True
        self._verify()
        self._open()
        audit = {**self.bound, "payloadDigest": self.payload_digest,
            "actorId": self.identity.user_id, "fileSha256": self.file_sha,
            "fileIdentity": self.file_identity, "control_plane_mfa": self.mfa}
        with publication._durable_connection() as connection:
            approval = application._require_control_plane_two_person(action=ACTION,
                resource_id=publication._RESOURCE, payload_digest=self.payload_digest,
                mfa=self.payload.mfa, identity=self.identity, request=self.bound, connection=connection)
            publication._require(type(approval) is dict)
            row = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?",
                (approval["approval_id"],)).fetchone()
            publication._require(row is not None and row["status"] == "consumed"
                and row["consumed_by"] == row["requester_id"] == self.identity.user_id
                and row["action"] == ACTION and row["resource_id"] == publication._RESOURCE
                and row["payload_digest"] == self.payload_digest
                and row["approved_by"] not in {None, "", self.identity.user_id}
                and row["approver_webauthn_credential_id"] is not None)
            self.check()
            self.expires = min(self.expires, _epoch_ns(row["expires_at"]))
            self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
            self.check()
            audit["control_plane_approval"] = approval
            db.append_audit_event(connection, event_type="control_plane.token_publication_resolution.authorized",
                actor_type="admin", actor_id=self.identity.user_id, event=audit,
                idempotency_key="admin-token-resolution-intent:" + self.attempt)
            # A crash or uncertain transaction after this durable one-shot
            # guard burns resolution. The claim is NOT committed-approval proof.
            self.claimed = True
            claim_sha = self._record("resolution-claimed", {
                "schema": "serverware.adminTokenPublicationResolutionClaim/v1",
                "attemptId": self.attempt, "intentSha256": self.payload.intent_sha256,
                "outcome": self.payload.outcome, "actorId": self.identity.user_id,
                "payloadDigest": self.payload_digest, "approvalId": approval["approval_id"],
                "reason": self.payload.reason, "fileSha256": self.file_sha,
                "fileIdentity": self.file_identity, "priorCompletionSha256": self.prior_completion,
                "auditId": "admin-token-resolution-intent:" + self.attempt})
        # Only a definitely returned owned commit reaches terminal publication.
        self.authorized = True
        self.check()
        publication._require(self.claimed and self.authorized)
        # An installed rename may have been interrupted before its original
        # directory flush. Flush the held originals and both held directories;
        # do not repeat the rename or change any token bytes.
        for _, _, descriptor, _, _ in self.pins:
            os.fsync(descriptor)
        os.fsync(self.parent)
        os.fsync(self.directory)
        self.check()
        completion_sha = self._record("resolution-complete", {
            "schema": "serverware.adminTokenPublicationResolutionComplete/v1",
            "attemptId": self.attempt, "intentSha256": self.payload.intent_sha256,
            "resolutionClaimSha256": claim_sha, "outcome": self.payload.outcome,
            "fileSha256": self.file_sha, "fileIdentity": self.file_identity})
        with publication._durable_connection() as connection:
            db.append_audit_event(connection, event_type="control_plane.token_publication_resolved",
                actor_type="admin", actor_id=self.identity.user_id,
                event={**audit, "resolutionCompletionSha256": completion_sha},
                idempotency_key="admin-token-resolution-complete:" + self.attempt)
            self.check()
        self._record("resolution-settled", {
            "schema": "serverware.adminTokenPublicationResolutionSettled/v1",
            "attemptId": self.attempt, "resolutionCompletionSha256": completion_sha,
            "auditId": "admin-token-resolution-complete:" + self.attempt})
        attempts, incomplete, terminal = publication._history(self.directory, self.path)
        publication._require(attempts == self.history and incomplete is None and terminal == completion_sha)
        self.check()
        return {"schema": "serverware.adminTokenPublicationResolution/v1", "ok": True,
            "publicationId": self.attempt, "intentSha256": self.payload.intent_sha256,
            "outcome": self.payload.outcome, "resolutionCompletionSha256": completion_sha,
            "automaticRetryAllowed": False}

    def close(self):
        while self.pins:
            os.close(self.pins.pop()[2])
        for name in ("directory", "parent"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                os.close(descriptor)


def resolve_on_request(request, payload):
    owner = None
    try:
        owner = _Resolution(request, payload)
        return owner.execute()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=409, detail={
            "error": "admin_token_publication_resolution_uncertain" if owner is not None and owner.claimed
                else "admin_token_publication_resolution_refused",
            "publicationId": owner.attempt if owner is not None else None,
            "automaticRetryAllowed": False,
            "inspectionEndpoint": "/api/control-plane/tokens/admin/publication"}) from exc
    finally:
        if owner is not None:
            owner.close()
