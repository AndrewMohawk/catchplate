"""One-shot generated-admin-token publication, not a general effect runner.

The live HTTP request and existing approval gate own authorization. Local
originals and an irreversible journal retain uncertainty across interruption;
neither a journal projection nor a returned approval dictionary grants a retry.
"""
from __future__ import annotations

import fcntl
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time

from fastapi import HTTPException, Request

from serverware import config, db
from serverware.policy_bundle import (
    _open_secure_parent_directory,
    _recheck_secure_parent_directory, _secure_stat_components,
    _validate_secure_file_stat,
)

_ACTION = "control_plane.token.rotate"
_RESOURCE = "admin-token"
_JOURNAL = ".serverware-admin-token-publications"
_MAX_ATTEMPTS = 64
_MAX_RECORD = 16 * 1024
_NAME = re.compile(r"([0-9a-f]{32})\.(intent|authorized|claimed|complete|settled|old|new|resolution-claimed|resolution-complete|resolution-settled)")
_TOKEN = re.compile(rb"[A-Za-z0-9_-]{43}\n")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_INTENT_FIELDS = {"schema", "attemptId", "actorId", "payloadDigest", "approvalId",
    "reason", "tokenPath", "previousTokenSha256", "newTokenSha256",
    "previousFileSha256", "newFileSha256", "previousFileIdentity", "newFileIdentity",
    "previousCompletionSha256"}


class PublicationError(RuntimeError):
    pass


def _require(condition, message="admin token publication state is unavailable or uncertain"):
    if not condition:
        raise PublicationError(message)


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")
    _require(0 < len(raw) <= _MAX_RECORD)
    return raw


def _file_identity(value):
    return list(_secure_stat_components(value))


@contextmanager
def _durable_connection():
    # The effect cannot mistake a borrowed/no-commit migration facade for a
    # committed transaction. Require local flush, not an off-host witness claim.
    connection = db.connect()
    try:
        with connection:
            if type(connection) is sqlite3.Connection:
                _require(not connection.in_transaction)
                connection.execute("PRAGMA synchronous=FULL")
                _require(connection.execute("PRAGMA synchronous").fetchone()[0] == 2
                    and connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
            elif type(connection) is db.PostgresMetadataConnection:
                connection.execute("SET LOCAL synchronous_commit = on")
                settings = connection.execute("SELECT current_setting('fsync') AS fsync, "
                    "current_setting('full_page_writes') AS full_page_writes, "
                    "current_setting('synchronous_commit') AS synchronous_commit").fetchone()
                _require(settings["fsync"] == "on" and settings["full_page_writes"] == "on"
                    and settings["synchronous_commit"] == "on")
            else:
                raise PublicationError("admin publication requires an owned durable transaction")
            yield connection
    finally:
        if type(connection) is sqlite3.Connection:
            connection.close()


def _read(parent, name, maximum):
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        _validate_secure_file_stat(before, label="admin token publication original",
            expected_mode=0o600, maximum_size=maximum)
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        _require(0 < len(raw) <= maximum
            and _file_identity(os.fstat(descriptor)) == _file_identity(before)
            and _file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                == _file_identity(before))
        return bytes(raw), before
    finally:
        os.close(descriptor)


def _exclusive(parent, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            _require(written > 0)
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent)
    observed, identity = _read(parent, name, max(len(raw), 1))
    _require(observed == raw)
    return identity


def _parent():
    _require(not config.ADMIN_TOKEN,
        "externally provided admin token cannot be rotated at runtime")
    return _open_secure_parent_directory(config.ADMIN_TOKEN_PATH,
        label="generated admin token", mutation_target=True)


def _journal(parent, *, create):
    created = False
    if create:
        try:
            os.mkdir(_JOURNAL, 0o700, dir_fd=parent)
            os.fsync(parent)
            created = True
        except FileExistsError:
            pass
    descriptor = os.open(_JOURNAL, _READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
    try:
        value = os.fstat(descriptor)
        _require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
            and stat.S_IMODE(value.st_mode) == 0o700 and value.st_nlink >= 2
            and value.st_dev == os.fstat(parent).st_dev)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor, (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode), created
    except BaseException:
        os.close(descriptor)
        raise


def _records(directory):
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            _require(len(names) < _MAX_ATTEMPTS * 10 and _NAME.fullmatch(entry.name) is not None)
            names.append(entry.name)
    attempts = {}
    for name in sorted(names):
        match = _NAME.fullmatch(name)
        identifier, phase = match.groups()
        item = attempts.setdefault(identifier, {})
        _require(len(attempts) <= _MAX_ATTEMPTS)
        raw, _ = _read(directory, name, 256 if phase in {"old", "new"} else _MAX_RECORD)
        if phase in {"old", "new"}:
            _require(_TOKEN.fullmatch(raw) is not None)
            item[phase] = _sha(raw)
            item[phase + "TokenSha256"] = _sha(raw[:-1])
        else:
            value = json.loads(raw)
            _require(type(value) is dict and _json(value) == raw
                and value.get("attemptId") == identifier)
            item[phase] = value
            item[phase + "Sha256"] = _sha(raw)
    return attempts


def _resolution_history(identifier, item):
    """Validate new terminal evidence without relabeling an old publication."""
    claim = item.get("resolution-claimed")
    complete = item.get("resolution-complete")
    settled = item.get("resolution-settled")
    if claim is None:
        _require(complete is None and settled is None)
        return
    intent = item["intent"]
    _require("settled" not in item and set(claim) == {"schema", "attemptId",
        "intentSha256", "outcome", "actorId", "payloadDigest", "approvalId",
        "reason", "fileSha256", "fileIdentity", "priorCompletionSha256", "auditId"}
        and claim["schema"] == "serverware.adminTokenPublicationResolutionClaim/v1"
        and claim["intentSha256"] == item["intentSha256"]
        and claim["outcome"] in {"finalize-installed", "abandon-uninstalled"}
        and type(claim["actorId"]) is str and 0 < len(claim["actorId"]) <= 4096
        and type(claim["approvalId"]) is str and 0 < len(claim["approvalId"]) <= 128
        and type(claim["payloadDigest"]) is str and _DIGEST.fullmatch(claim["payloadDigest"])
        and (claim["reason"] is None or type(claim["reason"]) is str and len(claim["reason"]) <= 500)
        and type(claim["fileIdentity"]) is list and len(claim["fileIdentity"]) == 9
        and all(type(part) is int for part in claim["fileIdentity"])
        and claim["priorCompletionSha256"] == item.get("completeSha256")
        and claim["auditId"] == "admin-token-resolution-intent:" + identifier)
    _require(claim["payloadDigest"] == _sha(_json({"token": "admin", "publicationId": identifier,
        "intentSha256": item["intentSha256"], "outcome": claim["outcome"], "reason": claim["reason"]})))
    if claim["outcome"] == "finalize-installed":
        _require("claimed" in item and "new" not in item
            and claim["fileSha256"] == intent["newFileSha256"]
            and claim["fileIdentity"][:8] == intent["newFileIdentity"][:8])
        if "complete" in item:
            _require(claim["fileIdentity"] == item["complete"]["fileIdentity"])
    else:
        _require("complete" not in item and "new" in item
            and claim["fileSha256"] == intent["previousFileSha256"]
            and claim["fileIdentity"] == intent["previousFileIdentity"])
    if complete is not None:
        _require(complete == {"schema": "serverware.adminTokenPublicationResolutionComplete/v1",
            "attemptId": identifier, "intentSha256": item["intentSha256"],
            "resolutionClaimSha256": item["resolution-claimedSha256"],
            "outcome": claim["outcome"], "fileSha256": claim["fileSha256"],
            "fileIdentity": claim["fileIdentity"]})
    if settled is not None:
        _require(complete is not None and settled == {
            "schema": "serverware.adminTokenPublicationResolutionSettled/v1",
            "attemptId": identifier, "resolutionCompletionSha256": item["resolution-completeSha256"],
            "auditId": "admin-token-resolution-complete:" + identifier})


def _terminal(item):
    if "resolution-settled" in item:
        return item["resolution-completeSha256"], item["resolution-complete"]
    if "settled" in item:
        return item["completeSha256"], item["complete"]
    return None, None


def _history(directory, token_path):
    attempts = _records(directory)
    for identifier, item in attempts.items():
        intent = item.get("intent")
        _require(type(intent) is dict and set(intent) == _INTENT_FIELDS
            and intent.get("tokenPath") == str(token_path)
            and intent.get("schema") == "serverware.adminTokenPublicationIntent/v1")
        for key in ("previousFileSha256", "newFileSha256", "previousTokenSha256", "newTokenSha256"):
            _require(type(intent.get(key)) is str and _DIGEST.fullmatch(intent[key]) is not None)
        _require(item.get("old") == intent["previousFileSha256"]
            and item.get("oldTokenSha256") == intent["previousTokenSha256"])
        for key in ("previousFileIdentity", "newFileIdentity"):
            _require(type(intent[key]) is list and len(intent[key]) == 9
                and all(type(part) is int for part in intent[key]))
        authorized, claimed, complete = (item.get(key) for key in ("authorized", "claimed", "complete"))
        if authorized is not None:
            _require(authorized == {"schema": "serverware.adminTokenPublicationAuthorized/v1",
                "attemptId": identifier, "intentSha256": item["intentSha256"],
                "auditId": "admin-token-intent:" + identifier})
        if claimed is not None:
            _require(authorized is not None and claimed == {
                "schema": "serverware.adminTokenPublicationClaim/v1", "attemptId": identifier,
                "authorizedSha256": item["authorizedSha256"], "intentSha256": item["intentSha256"]})
        if complete is not None:
            _require(claimed is not None and set(complete) == {"schema", "attemptId",
                "intentSha256", "claimSha256", "fileSha256", "fileIdentity"}
                and complete["schema"] == "serverware.adminTokenPublicationComplete/v1"
                and complete["intentSha256"] == item["intentSha256"]
                and complete["claimSha256"] == item["claimedSha256"]
                and complete["fileSha256"] == intent["newFileSha256"]
                and type(complete["fileIdentity"]) is list and len(complete["fileIdentity"]) == 9
                and all(type(part) is int for part in complete["fileIdentity"])
                and "new" not in item)
        elif "new" in item:
            _require(item["new"] == intent["newFileSha256"]
                and item["newTokenSha256"] == intent["newTokenSha256"])
        if "settled" in item:
            _require(complete is not None and item["settled"] == {
                "schema": "serverware.adminTokenPublicationSettled/v1", "attemptId": identifier,
                "completionSha256": item["completeSha256"],
                "auditId": "admin-token-complete:" + identifier})
        _resolution_history(identifier, item)
    # A single append-only predecessor chain; no counter reset or journal repair.
    predecessor = None
    previous_complete = None
    visited = set()
    while True:
        children = [(identifier, item) for identifier, item in attempts.items()
            if item["intent"].get("previousCompletionSha256") == predecessor]
        _require(len(children) <= 1)
        if not children:
            break
        identifier, item = children[0]
        _require(identifier not in visited)
        if previous_complete is not None:
            _require(item["intent"]["previousFileSha256"] == previous_complete["fileSha256"]
                and item["intent"]["previousFileIdentity"] == previous_complete["fileIdentity"])
        visited.add(identifier)
        terminal_sha, terminal = _terminal(item)
        if terminal is None:
            _require(len(visited) == len(attempts))
            return attempts, item, None
        predecessor, previous_complete = terminal_sha, terminal
    _require(len(visited) == len(attempts))
    return attempts, None, predecessor


def _read_generated_token():
    """Every generated-token authentication observes the current exact file."""
    config.ensure_data_dirs()
    path, basename, parent, identity = _parent()
    try:
        try:
            raw, _ = _read(parent, basename, 256)
        except FileNotFoundError:
            # Preserve first boot, but never regenerate a missing published token.
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.stat(_JOURNAL, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise PublicationError("published admin token is missing; automatic regeneration is forbidden")
            try:
                raw, _ = _read(parent, basename, 256)
            except FileNotFoundError:
                raw = (secrets.token_urlsafe(32) + "\n").encode("ascii")
                _exclusive(parent, basename, raw)
        _require(_TOKEN.fullmatch(raw) is not None)
        _recheck_secure_parent_directory(path, label="generated admin token",
            expected=identity, mutation_target=True)
        return raw[:-1].decode("ascii")
    finally:
        os.close(parent)


class _Publication:
    def __init__(self, request, payload):
        # Sample before configuration/file/verification reads; never renewed.
        self.epoch, self.mono = time.time_ns(), time.monotonic_ns()
        self.expires = self.epoch + 30_000_000_000
        self.deadline = self.mono + 30_000_000_000
        self.pid, self.tid = os.getpid(), threading.get_ident()
        self.request, self.scope = request, request.scope
        self.payload = payload
        self.parent = self.directory = None
        self.original_descriptor = self.staged_descriptor = None
        self.attempt = None
        self.executing = False
        self.started = False
        self.authorized = False
        from serverware import app as application
        from serverware.control_plane_approval_verification import _request_pin
        self.request_pin = _request_pin(request)
        _require(request.method == "POST" and request.url.path == "/api/control-plane/tokens/admin/rotate"
            and not request.url.query)
        self.payload_original = _json({"token": "admin", "reason": payload.reason})
        self.payload_digest = application._admin_token_rotation_payload_digest(payload)
        self.policy = self._policy()
        self.identity = self._identity()
        self.mfa = None
        self.approval = None
        self.credential = None

    def _policy(self):
        from serverware import app as application
        return _json({"mfa": application.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
            "twoPerson": application._control_plane_two_person_required(_ACTION),
            "authn": application._control_plane_mutation_authn_policy()})

    def _identity(self):
        from serverware import auth
        current = Request(self.scope)
        identity = auth.require_admin(current,
            x_serverware_admin_token=current.headers.get("X-Serverware-Admin-Token"))
        auth.validate_csrf_request(current)
        _require(type(identity) is auth.AdminIdentity and identity.has_any_role({"admin"}))
        return identity

    def check(self, *, authentication=False):
        from serverware.control_plane_approval_verification import _request_pin
        epoch, mono = time.time_ns(), time.monotonic_ns()
        _require((os.getpid(), threading.get_ident()) == (self.pid, self.tid)
            and self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline
            and self.request.scope is self.scope and _request_pin(self.request) == self.request_pin
            and self._policy() == self.policy
            and _json({"token": "admin", "reason": self.payload.reason}) == self.payload_original)
        self.epoch, self.mono = epoch, mono
        if authentication:
            _require(self._identity() == self.identity)
            if self.credential is not None:
                from serverware import app as application, webauthn
                current = db.get_webauthn_credential_by_record_id(self.credential[0])
                _require(type(current) is dict and current.get("revoked_at") is None
                    and tuple(current.get(key) for key in ("id", "user_id", "credential_id", "public_key_cose"))
                        == self.credential)
                webauthn._allowed_authenticator(current, application._control_plane_mutation_authn_policy())
        if self.parent is not None:
            _recheck_secure_parent_directory(self.path, label="generated admin token",
                expected=self.parent_identity, mutation_target=True)
            value = os.stat(_JOURNAL, dir_fd=self.parent, follow_symlinks=False)
            held = os.fstat(self.directory)
            _require((value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode)
                == self.journal_identity
                == (held.st_dev, held.st_ino, held.st_uid, held.st_gid, held.st_mode))
        # Closing sample covers time spent in the current authentication/path
        # reads. This is still not preemption of a blocked dependency.
        epoch, mono = time.time_ns(), time.monotonic_ns()
        _require(self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline)
        self.epoch, self.mono = epoch, mono

    def _record(self, phase, value):
        self.check()
        raw = _json(value)
        _exclusive(self.directory, self.attempt + "." + phase, raw)
        self.check()
        return _sha(raw)

    def _verify(self):
        from serverware import app as application
        self.check(authentication=True)
        # This fixed effect has no authority-transaction downstream. Strip the
        # shared helper's raw-only authority shortcut; only its genuine verifier
        # may supply audit evidence. Optional MFA remains optional.
        supplied = self.payload.mfa if isinstance(self.payload.mfa, dict) else {}
        self.mfa = application._require_control_plane_mutation_mfa(action=_ACTION,
            resource_id=_RESOURCE, payload_digest=self.payload_digest,
            mfa={"assertion": supplied.get("assertion")}, identity=self.identity)
        if application.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED:
            _require(type(self.mfa) is dict and self.mfa.get("method") == "webauthn")
            for hint, field in (("authorityChallengeId", "challenge_id"),
                    ("credentialRecordId", "credential_record_id")):
                _require(hint not in supplied or supplied[hint] == self.mfa.get(field))
            value = db.get_webauthn_credential_by_record_id(self.mfa["credential_record_id"])
            _require(type(value) is dict and value.get("revoked_at") is None)
            self.credential = tuple(value[key] for key in ("id", "user_id", "credential_id", "public_key_cose"))
        self.check(authentication=True)
        # Ordinary negotiation remains outside the irreversible publication lane.
        if (application._control_plane_two_person_required(_ACTION)
                and not application._control_plane_approval_id(self.payload.mfa)):
            application._require_control_plane_two_person(action=_ACTION, resource_id=_RESOURCE,
                payload_digest=self.payload_digest, mfa=self.payload.mfa, identity=self.identity,
                request={"token": "admin", "reason": self.payload.reason})
            raise PublicationError("required approval gate did not negotiate")

    def execute(self):
        from serverware import app as application
        _require(not self.executing)
        self.executing = True
        self._verify()
        self.path, self.basename, self.parent, self.parent_identity = _parent()
        fcntl.flock(self.parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.directory, self.journal_identity, created = _journal(self.parent, create=True)
        if created:
            # Our mkdir may add one parent link (some filesystems do not count
            # directory links); it may not substitute this held directory.
            _, _, reopened, identity = _parent()
            try:
                _require(identity.stat_components[:-1] == self.parent_identity.stat_components[:-1]
                    and identity.nlink in {self.parent_identity.nlink, self.parent_identity.nlink + 1})
                self.parent_identity = identity
            finally:
                os.close(reopened)
        self.check(authentication=True)
        attempts, incomplete, predecessor = _history(self.directory, self.path)
        _require(incomplete is None, "an interrupted admin token publication blocks rotation; inspect without retry")
        _require(len(attempts) < _MAX_ATTEMPTS, "admin token publication journal is full; no automatic pruning")
        old, old_identity = _read(self.parent, self.basename, 256)
        _require(_TOKEN.fullmatch(old) is not None)
        self.original_descriptor = os.open(self.basename, _READ_FLAGS, dir_fd=self.parent)
        _require(_file_identity(os.fstat(self.original_descriptor)) == _file_identity(old_identity))
        if predecessor is not None:
            latest = next(_terminal(item)[1] for item in attempts.values() if _terminal(item)[0] == predecessor)
            _require(_sha(old) == latest["fileSha256"]
                and _file_identity(old_identity) == latest["fileIdentity"])
        self.attempt = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        new = (token + "\n").encode("ascii")
        self.check(authentication=True)
        # The existing gate consumes the actual row and retains all its role,
        # WebAuthn, expiry and distinct-approver checks in this same transaction.
        with _durable_connection() as connection:
            self.approval = application._require_control_plane_two_person(action=_ACTION,
                resource_id=_RESOURCE, payload_digest=self.payload_digest, mfa=self.payload.mfa,
                identity=self.identity, request={"token": "admin", "reason": self.payload.reason},
                connection=connection)
            if self.approval is not None:
                row = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?",
                    (self.approval["approval_id"],)).fetchone()
                _require(row is not None and row["status"] == "consumed"
                    and row["consumed_by"] == self.identity.user_id
                    and row["requester_id"] == self.identity.user_id
                    and row["action"] == _ACTION and row["resource_id"] == _RESOURCE
                    and row["payload_digest"] == self.payload_digest)
                expires = datetime.fromisoformat(row["expires_at"])
                _require(expires.tzinfo is not None)
                delta = expires.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
                expires_ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
                self.check()
                self.expires = min(self.expires, expires_ns)
                self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
            self.check()
            _exclusive(self.directory, self.attempt + ".old", old)
            new_identity = _exclusive(self.directory, self.attempt + ".new", new)
            self.staged_descriptor = os.open(self.attempt + ".new", _READ_FLAGS, dir_fd=self.directory)
            _require(_file_identity(os.fstat(self.staged_descriptor)) == _file_identity(new_identity))
            intent = {"schema": "serverware.adminTokenPublicationIntent/v1", "attemptId": self.attempt,
                "actorId": self.identity.user_id, "payloadDigest": self.payload_digest,
                "approvalId": self.approval["approval_id"] if self.approval is not None else None,
                "reason": self.payload.reason, "tokenPath": str(self.path),
                "previousTokenSha256": _sha(old[:-1]), "newTokenSha256": _sha(new[:-1]),
                "previousFileSha256": _sha(old), "newFileSha256": _sha(new),
                "previousFileIdentity": _file_identity(old_identity),
                "newFileIdentity": _file_identity(new_identity),
                "previousCompletionSha256": predecessor}
            intent_sha = self._record("intent", intent)
            audit = {"publication_id": self.attempt, "intent_sha256": intent_sha,
                "token": "admin", "token_path": str(self.path),
                "previous_token_sha256": _sha(old[:-1]), "new_token_sha256": _sha(new[:-1]),
                "reason": self.payload.reason, "control_plane_mfa": self.mfa,
                "control_plane_approval": self.approval, "payload_digest": self.payload_digest}
            db.append_audit_event(connection, event_type="control_plane.token_publication.authorized",
                actor_type="admin", actor_id=self.identity.user_id, event=audit,
                idempotency_key="admin-token-intent:" + self.attempt)
            self.check()
        # A thrown/uncertain commit never reaches this assignment or the effect.
        self.authorized = True
        authorized_sha = self._record("authorized", {
            "schema": "serverware.adminTokenPublicationAuthorized/v1", "attemptId": self.attempt,
            "intentSha256": intent_sha, "auditId": "admin-token-intent:" + self.attempt})
        self.check(authentication=True)
        current, current_identity = _read(self.parent, self.basename, 256)
        staged, staged_identity = _read(self.directory, self.attempt + ".new", 256)
        _require(current == old and _file_identity(current_identity) == _file_identity(old_identity)
            and staged == new and _file_identity(staged_identity) == _file_identity(new_identity))
        claim_sha = self._record("claimed", {"schema": "serverware.adminTokenPublicationClaim/v1",
            "attemptId": self.attempt, "intentSha256": intent_sha, "authorizedSha256": authorized_sha})
        self.check(authentication=True)
        _require(self.authorized and not self.started)
        current, current_identity = _read(self.parent, self.basename, 256)
        staged, staged_identity = _read(self.directory, self.attempt + ".new", 256)
        _require(current == old and staged == new
            and _file_identity(current_identity) == _file_identity(old_identity)
                == _file_identity(os.fstat(self.original_descriptor))
            and _file_identity(staged_identity) == _file_identity(new_identity)
                == _file_identity(os.fstat(self.staged_descriptor)))
        self.check()
        self.started = True
        os.replace(self.attempt + ".new", self.basename,
            src_dir_fd=self.directory, dst_dir_fd=self.parent)
        os.fsync(self.parent)
        os.fsync(self.directory)
        installed, installed_identity = _read(self.parent, self.basename, 256)
        # Rename may change ctime, but may not substitute the held staged inode.
        _require(installed == new and _file_identity(installed_identity)[:8]
            == _file_identity(new_identity)[:8]
            and _file_identity(installed_identity) == _file_identity(os.fstat(self.staged_descriptor)))
        self.check()
        completed_sha = self._record("complete", {
            "schema": "serverware.adminTokenPublicationComplete/v1", "attemptId": self.attempt,
            "intentSha256": intent_sha, "claimSha256": claim_sha,
            "fileSha256": _sha(installed), "fileIdentity": _file_identity(installed_identity)})
        # Retain the outcome in the metadata transaction/outbox as well. A failed
        # audit commit leaves a complete local original, never a new mutation.
        with _durable_connection() as connection:
            db.append_audit_event(connection, event_type="control_plane.token_rotated",
                actor_type="admin", actor_id=self.identity.user_id,
                event={**audit, "completion_sha256": completed_sha},
                idempotency_key="admin-token-complete:" + self.attempt)
            self.check()
        self._record("settled", {"schema": "serverware.adminTokenPublicationSettled/v1",
            "attemptId": self.attempt, "completionSha256": completed_sha,
            "auditId": "admin-token-complete:" + self.attempt})
        self.check()
        closing, closing_identity = _read(self.parent, self.basename, 256)
        _require(closing == installed and _file_identity(closing_identity) == _file_identity(installed_identity))
        self.check()
        return {"ok": True, "token": token, "tokenSha256": _sha(new[:-1]),
            "tokenPath": str(self.path), "publicationId": self.attempt}

    def close(self):
        for name in ("staged_descriptor", "original_descriptor", "directory", "parent"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                os.close(descriptor)


def rotate_on_request(request, payload):
    owner = None
    try:
        owner = _Publication(request, payload)
        return owner.execute()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=409, detail={
            "error": "admin_token_publication_uncertain" if owner is not None and owner.attempt else "admin_token_publication_refused",
            "publicationId": owner.attempt if owner is not None else None, "automaticRetryAllowed": False,
            "inspectionEndpoint": "/api/control-plane/tokens/admin/publication",
        }) from exc
    finally:
        if owner is not None:
            owner.close()


def inspect_publication():
    """Read-only bounded observations; never returns old/new token plaintext."""
    path, basename, parent, identity = _parent()
    directory = None
    try:
        current, current_identity = _read(parent, basename, 256)
        _require(_TOKEN.fullmatch(current) is not None)
        try:
            directory, _, _ = _journal(parent, create=False)
        except FileNotFoundError:
            return {"schema": "serverware.adminTokenPublicationObservation/v1",
                "state": "no-journal", "automaticRetryAllowed": False, "attempts": []}
        attempts, incomplete, _ = _history(directory, path)
        rows = []
        for identifier, item in sorted(attempts.items()):
            intent = item["intent"]
            observed = "different"
            if _sha(current) == intent["newFileSha256"]:
                observed = "new-original"
            elif _sha(current) == intent["previousFileSha256"]:
                observed = "previous-original"
            rows.append({"publicationId": identifier, "intentSha256": item["intentSha256"],
                "state": next((phase for phase in ("resolution-settled", "resolution-complete", "resolution-claimed",
                    "settled", "complete", "claimed", "authorized") if phase in item), "intent"),
                "resolutionOutcome": item.get("resolution-claimed", {}).get("outcome"),
                "currentFileMatches": observed, "approvalId": intent.get("approvalId")})
        closing, closing_identity = _read(parent, basename, 256)
        _require(closing == current and _file_identity(closing_identity) == _file_identity(current_identity))
        _recheck_secure_parent_directory(path, label="generated admin token", expected=identity,
            mutation_target=True)
        return {"schema": "serverware.adminTokenPublicationObservation/v1",
            "state": "interrupted" if incomplete is not None else "completed-history",
            "automaticRetryAllowed": False, "attempts": rows}
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)
