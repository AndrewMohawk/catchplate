"""One-shot materialization of already committed policy originals.

No signing, activation, authority advance, retry or journal reconstruction.
The actual HTTP/approval owner and retained metadata lock authorize the sole
rename; journal observations and loader checks are never effect permissions.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

from fastapi import HTTPException, Request

from serverware import policy_bundle as bundles
from serverware import authority_policy_file_approval as profile
from serverware import control_plane_publication_authorization as ceremonies
from serverware import control_plane_admin_token_publication as files
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

PATH = "/api/policy/file-publication"
JOURNAL = ".serverware-policy-file-publications"
MAX_RECORD = 16 * 1024
MAX_SLOTS = 16
PHASES = {"old", "new", "stage", "intent", "claimed", "complete", "settled",
    "resolution-claimed", "resolution-complete", "resolution-settled"}
NAME = re.compile(r"([0-9a-f]{32})\.([a-z-]+)\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _require(value):
    profile.require(value, "policy file publication is unavailable or uncertain; no automatic retry")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(value, *, absent=False):
    _require(absent and value is None or type(value) is list and len(value) == 9
        and all(type(part) is int and part >= 0 for part in value))
    return value


def _renamed_identity(actual, staged):
    # rename changes ctime, but not the held inode, bytes or other metadata.
    return actual is not None and staged is not None and actual[:8] == staged[:8]


def _json(value):
    raw = profile.canonical(value)
    _require(0 < len(raw) <= MAX_RECORD)
    return raw


def _original(value):
    _require(type(value) is str and 1 <= len(value) <= (bundles.MAX_POLICY_BUNDLE_BYTES * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    _require(0 < len(raw) <= bundles.MAX_POLICY_BUNDLE_BYTES
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def _signed(raw):
    value = bundles._decode_raw_policy(Path("policy.json"), raw)
    trust = bundles._load_policy_signing_trust()
    snapshot = bundles.compile_policy_bundle(value, verify_signature=True, validate_schema=True, signing_trust=trust)
    policy_id, sequence, rollback, policy_hash = bundles._policy_snapshot_authority(snapshot)
    from serverware import app
    return snapshot, trust.identity, {"policyOriginalSha256": _sha(raw), "policyId": policy_id,
        "sequence": sequence, "rollbackEpoch": rollback, "policyHash": policy_hash,
        "policyBundleSha256": app._policy_canary_bundle_digest(value)}


def _directory(parent, *, create):
    created = False
    if create:
        try:
            os.mkdir(JOURNAL, 0o700, dir_fd=parent)
            os.fsync(parent)
            created = True
        except FileExistsError:
            pass
    descriptor = os.open(JOURNAL, files._READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
    value = os.fstat(descriptor)
    try:
        _require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
            and stat.S_IMODE(value.st_mode) == 0o700 and value.st_dev == os.fstat(parent).st_dev)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor, files._file_identity(value), created
    except BaseException:
        os.close(descriptor)
        raise


def _audit(phase, digest):
    from serverware.authority_transition_quota import _audit_identity
    return _audit_identity(profile.PREFIX + phase, digest)


def _history(directory):
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            match = NAME.fullmatch(entry.name)
            _require(len(names) < MAX_SLOTS * len(PHASES) and match is not None and match[2] in PHASES)
            names.append(entry.name)
    items = {}
    for name in sorted(names):
        identifier, phase = NAME.fullmatch(name).groups()
        item = items.setdefault(identifier, {})
        _require(len(items) <= MAX_SLOTS)
        raw, identity = files._read(directory, name,
            bundles.MAX_POLICY_BUNDLE_BYTES if phase in {"old", "new", "stage"} else MAX_RECORD)
        item[phase + "Sha256"] = _sha(raw)
        item[phase + "Identity"] = files._file_identity(identity)
        if phase not in {"old", "new", "stage"}:
            value = json.loads(raw)
            _require(type(value) is dict and _json(value) == raw and value.get("publicationId") == identifier)
            item[phase] = value
    by_previous = {}
    for identifier, item in items.items():
        intent = item.get("intent")
        _require(type(intent) is dict and set(intent) == {"schema", "publicationId", "binding", "actorId",
            "approvalId", "previousTerminalSha256", "oldIdentity", "stageIdentity"}
            and intent["schema"] == "serverware.policyFilePublicationIntent/v1")
        bound = profile.request_binding(intent["binding"])
        _require(bound["kind"] in {"materialize", "genesis-materialize"} and bound["publicationId"] == identifier
            and item.get("newSha256") == bound["policyOriginalSha256"]
            and item.get("oldSha256") == bound["expectedFileSha256"])
        _identity(intent["oldIdentity"], absent=True)
        _identity(intent["stageIdentity"])
        _require((intent["oldIdentity"] is None) == (bound["expectedFileSha256"] is None)
            and type(intent["actorId"]) is str and intent["actorId"].startswith("oidc:")
            and type(intent["approvalId"]) is str and re.fullmatch(r"[0-9a-f-]{36}", intent["approvalId"]) is not None)
        if "stageSha256" in item:
            _require(item["stageSha256"] == item["newSha256"] and item["stageIdentity"] == intent["stageIdentity"])
        previous = intent["previousTerminalSha256"]
        _require(bound["kind"] != "genesis-materialize" or (previous is None
            and intent["oldIdentity"] is None and bound["expectedFileSha256"] is None))
        _require(previous not in by_previous and (previous is None or SHA.fullmatch(previous) is not None))
        by_previous[previous] = identifier
        claim = item.get("claimed")
        if claim is not None:
            _require(set(claim) == {"schema", "publicationId", "intentSha256", "authorityRequestDigest", "auditId"}
                and claim["schema"] == "serverware.policyFilePublicationClaim/v1"
                and claim["intentSha256"] == item["intentSha256"]
                and claim["auditId"] == _audit("consume", profile.digest(claim["authorityRequestDigest"])))
        complete = item.get("complete")
        if complete is not None:
            _identity(complete.get("fileIdentity"))
            _require(claim is not None and "stageSha256" not in item and complete == {
                "schema": "serverware.policyFilePublicationComplete/v1", "publicationId": identifier,
                "intentSha256": item["intentSha256"], "claimSha256": item["claimedSha256"],
                "fileSha256": item["newSha256"], "fileIdentity": complete["fileIdentity"]}
                and _renamed_identity(complete["fileIdentity"], intent["stageIdentity"]))
        for prefix in ("", "resolution-"):
            settled = item.get(prefix + "settled")
            if settled is not None:
                _require(prefix + "complete" in item and set(settled) == {
                    "schema", "publicationId", "completionSha256", "authorityRequestDigest", "auditId"}
                    and settled["schema"] == "serverware.policyFilePublicationSettlement/v1"
                    and settled["completionSha256"] == item[prefix + "completeSha256"]
                    and settled["auditId"] == _audit("settle", profile.digest(settled["authorityRequestDigest"])))
        resolving = item.get("resolution-claimed")
        if resolving is not None:
            _require("settled" not in item and set(resolving) == {"schema", "publicationId", "binding",
                "actorId", "approvalId", "authorityRequestDigest", "auditId", "fileSha256", "fileIdentity"}
                and resolving["schema"] == "serverware.policyFileResolutionClaim/v1")
            request = profile.request_binding(resolving["binding"])
            _require(request["kind"] == "resolve" and request["publicationId"] == identifier
                and request["intentSha256"] == item["intentSha256"]
                and resolving["auditId"] == _audit("consume", profile.digest(resolving["authorityRequestDigest"])))
            installed = request["outcome"] == "finalize-installed"
            _identity(resolving["fileIdentity"], absent=True)
            _require((installed and claim is not None and "stageSha256" not in item
                and resolving["fileSha256"] == item["newSha256"]
                and _renamed_identity(resolving["fileIdentity"], intent["stageIdentity"])
                and (complete is None or resolving["fileIdentity"] == complete["fileIdentity"]))
                or (not installed and complete is None and "stageSha256" in item
                and resolving["fileSha256"] == bound["expectedFileSha256"]
                and resolving["fileIdentity"] == intent["oldIdentity"]))
            if "resolution-complete" in item:
                _require(item["resolution-complete"] == {"schema": "serverware.policyFileResolutionComplete/v1",
                    "publicationId": identifier, "intentSha256": item["intentSha256"],
                    "claimSha256": item["resolution-claimedSha256"], "outcome": request["outcome"],
                    "fileSha256": resolving["fileSha256"], "fileIdentity": resolving["fileIdentity"]})
        else:
            _require("resolution-complete" not in item and "resolution-settled" not in item)
    previous = None
    visited = set()
    incomplete = None
    terminal = None
    while previous in by_previous:
        identifier = by_previous[previous]
        _require(identifier not in visited and incomplete is None)
        visited.add(identifier)
        item = items[identifier]
        if terminal is not None:
            _require(item["intent"]["binding"]["expectedFileSha256"] == terminal["fileSha256"]
                and item["intent"]["oldIdentity"] == terminal["fileIdentity"])
        phase = "resolution-complete" if "resolution-settled" in item else "complete" if "settled" in item else None
        if phase is None:
            incomplete = identifier
            break
        terminal = item[phase]
        previous = item[phase + "Sha256"]
    _require(len(visited) == len(items))
    return items, incomplete, previous, terminal


class PolicyFilePublication:
    def __init__(self, request, payload, *, resolving=False, genesis=False):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline, self.expires = self.mono + 30_000_000_000, self.epoch + 30_000_000_000
        self.request, self.pin, self.payload = request, _request_pin(request), payload
        _require(type(genesis) is bool and not (resolving and genesis)
            and type(request) is Request and request.url.path == PATH + (
                "/resolve" if resolving else "/genesis-materialize" if genesis else "/materialize"))
        self.resolving, self.genesis = resolving, genesis
        self.parent = self.directory = self.authority = None
        self.pins = []
        self.history = None
        self.attempt = payload.publication_id
        self.approval = ceremonies._Ceremony(request, purpose="policy-file", deadline_ns=self.deadline, expires_epoch_ns=self.expires)
        self.deadline, self.expires = min(self.deadline, self.approval.deadline), min(self.expires, self.approval.expires)
        self.assertion = self.approval.capture_assertion(payload.mfa)
        self.mfa_original = profile.canonical(payload.mfa)
        self.raw = None if resolving else _original(payload.policy_original)
        if resolving:
            self.bound = {"kind": "resolve", "publicationId": self.attempt, "intentSha256": payload.intent_sha256,
                "outcome": payload.outcome, "reason": payload.reason}
        else:
            self.snapshot, self.trust, original = _signed(self.raw)
            self.bound = {"kind": "genesis-materialize" if genesis else "materialize",
                "publicationId": self.attempt, **original, "expectedFileSha256": payload.expected_file_sha256,
                "reason": payload.reason}
            self.bound.update({"genesisPreparationDigest": payload.genesis_preparation_digest,
                "genesisFinalizationDigest": payload.genesis_finalization_digest} if genesis else
                {"artifactEnvelopeSha256": payload.artifact_sha256})
        self.bound = profile.request_binding(self.bound)
        self.bound_original = profile.canonical(self.bound)
        self.payload_digest = _sha(self.bound_original)
        self.consumed = None
        self.settlement_attempted = False
        self.executing = False
        self.target_installed = False

    def check(self):
        from serverware import control_plane_policy_genesis_maintenance as genesis_maintenance
        genesis_maintenance.require_binding(self.bound, publication=self)
        mono, epoch = time.monotonic_ns(), time.time_ns()
        _require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
            and _request_pin(self.request) == self.pin and profile.canonical(self.bound) == self.bound_original
            and profile.canonical(self.payload.mfa) == self.mfa_original)
        self.approval.check()
        if self.parent is not None:
            bundles._recheck_secure_parent_directory(self.path, label="policy materialization",
                expected=self.parent_identity, mutation_target=True)
            _require(files._file_identity(os.fstat(self.directory))[:5] == self.directory_identity[:5]
                and files._file_identity(os.stat(JOURNAL, dir_fd=self.parent, follow_symlinks=False))[:5] == self.directory_identity[:5])
            for directory, name, descriptor, original, identity in self.pins:
                raw, value = files._read(directory, name, max(len(original), 1))
                _require(raw == original and files._file_identity(value) == identity
                    == files._file_identity(os.fstat(descriptor)))
            if hasattr(self, "file_identity") and self.file_identity is None and not self.target_installed:
                try:
                    os.stat(self.basename, dir_fd=self.parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    _require(False)
            if self.history is not None:
                _require(_history(self.directory)[0] == self.history)
        closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
        _require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
        self.mono, self.epoch = closing_mono, closing_epoch

    def _arguments(self, phase):
        return ceremonies._arguments(phase, self.approval.identity, self.bound, self.approval.policy,
            getattr(self, "approval_id", None), purpose="policy-file", publication=self)

    def negotiate(self):
        from serverware import app
        identifier = app._control_plane_approval_id(self.payload.mfa)
        if identifier is None:
            result = self.approval.dispatch("request", self._arguments("request"), self.assertion)["approval"]
            raise HTTPException(status_code=428, detail={"error": "control_plane_approval_required", "approvalId": result["id"],
                "status": result["status"], "action": result["action"], "resourceId": profile.RESOURCE,
                "payloadDigest": result["payload_digest"], "expiresAt": result["expires_at"], "retry": {"mfa.approvalId": result["id"]}})
        row = ceremonies._approval(identifier, "policy-file")
        _require(row["status"] == "approved" and row["requester_id"] == self.approval.identity.user_id
            and row["action"] == profile.action(self.bound) and row["resource_id"] == profile.RESOURCE
            and row["request_json"] == self.bound_original.decode("ascii") and row["payload_digest"] == self.payload_digest)
        self.approval_id = identifier
        self.expires = min(self.expires, _epoch_ns(row["expires_at"]), self.approval.expires)
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch, self.approval.deadline)
        self.check()

    def _pin(self, directory, name, maximum):
        raw, value = files._read(directory, name, maximum)
        descriptor = os.open(name, files._READ_FLAGS, dir_fd=directory)
        identity = files._file_identity(value)
        try:
            _require(files._file_identity(os.fstat(descriptor)) == identity)
        except BaseException:
            os.close(descriptor)
            raise
        self.pins.append((directory, name, descriptor, raw, identity))
        return raw, identity

    def _record(self, phase, value):
        self.check()
        previous = self.history
        raw = _json(value)
        files._exclusive(self.directory, self.attempt + "." + phase, raw)
        self._pin(self.directory, self.attempt + "." + phase, MAX_RECORD)
        self.history = _history(self.directory)[0]
        _require(set(self.history) == set(previous) and all(
            all(self.history[identifier].get(key) == value for key, value in item.items())
            for identifier, item in previous.items()))
        self.check()
        return _sha(raw)

    def _open(self):
        _require(bundles._policy_path_protections_are_production())
        self.path, self.basename, self.parent, self.parent_identity = bundles._open_secure_parent_directory(
            bundles.POLICY_BUNDLE_PATH, label="policy materialization", mutation_target=True)
        fcntl.flock(self.parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.directory, self.directory_identity, created = _directory(self.parent, create=not self.resolving)
        if created:
            _, _, reopened, identity = bundles._open_secure_parent_directory(
                self.path, label="policy materialization", mutation_target=True)
            try:
                _require(identity.stat_components[:-1] == self.parent_identity.stat_components[:-1]
                    and identity.nlink in {self.parent_identity.nlink, self.parent_identity.nlink + 1})
                self.parent_identity = identity
            finally:
                os.close(reopened)
        items, incomplete, previous, terminal = _history(self.directory)
        self.history = items
        try:
            old, identity = self._pin(self.parent, self.basename, bundles.MAX_POLICY_BUNDLE_BYTES)
        except FileNotFoundError:
            old = identity = None
        self.file_sha, self.file_identity = _sha(old) if old is not None else None, identity
        if self.resolving:
            _require(incomplete == self.attempt and self.attempt in items)
            item = items[self.attempt]
            _require(item["intentSha256"] == self.bound["intentSha256"] and "resolution-claimed" not in item)
            for phase in PHASES:
                if phase in {"old", "new", "stage"} and phase + "Sha256" in item or phase in item:
                    self._pin(self.directory, self.attempt + "." + phase,
                        bundles.MAX_POLICY_BUNDLE_BYTES if phase in {"old", "new", "stage"} else MAX_RECORD)
            installed = self.bound["outcome"] == "finalize-installed"
            expected = item["intent"]
            _require((installed and "claimed" in item and "stageSha256" not in item
                and self.file_sha == item["newSha256"] and _renamed_identity(identity, expected["stageIdentity"])
                and ("complete" not in item or identity == item["complete"]["fileIdentity"]))
                or (not installed and "complete" not in item and "stageSha256" in item
                and self.file_sha == expected["binding"]["expectedFileSha256"] and identity == expected["oldIdentity"]))
            self.raw = files._read(self.directory, self.attempt + ".new", bundles.MAX_POLICY_BUNDLE_BYTES)[0]
            self.snapshot, self.trust, original = _signed(self.raw)
            _require(all(expected["binding"][key] == value for key, value in original.items()))
            self.material_binding = expected["binding"]
        else:
            _require(incomplete is None and self.attempt not in items and len(items) < MAX_SLOTS
                and self.file_sha == self.bound["expectedFileSha256"])
            # Local absence is necessary, never positive genesis authority.
            _require(not self.genesis or (not items and previous is None and terminal is None
                and old is None and identity is None))
            if terminal is not None:
                _require(self.file_sha == terminal["fileSha256"] and identity == terminal["fileIdentity"])
            # Originals and the single staged inode precede the irreversible
            # claim. Orphans from interruption here are deliberately not repaired.
            self.check()
            previous_history = self.history
            self.history = None
            if old is not None:
                files._exclusive(self.directory, self.attempt + ".old", old)
                self.check()
            files._exclusive(self.directory, self.attempt + ".new", self.raw)
            self.check()
            stage = files._exclusive(self.directory, self.attempt + ".stage", self.raw)
            self.check()
            intent = {"schema": "serverware.policyFilePublicationIntent/v1", "publicationId": self.attempt,
                "binding": self.bound, "actorId": self.approval.identity.user_id, "approvalId": self.approval_id,
                "previousTerminalSha256": previous, "oldIdentity": identity, "stageIdentity": files._file_identity(stage)}
            files._exclusive(self.directory, self.attempt + ".intent", _json(intent))
            self.history = _history(self.directory)[0]
            _require(set(self.history) == set(previous_history) | {self.attempt}
                and all(self.history[identifier] == item for identifier, item in previous_history.items()))
            for phase in ("old", "new", "stage", "intent"):
                if phase == "old" and old is None:
                    continue
                self._pin(self.directory, self.attempt + "." + phase,
                    MAX_RECORD if phase == "intent" else bundles.MAX_POLICY_BUNDLE_BYTES)
            self.material_binding = self.bound
        self.check()

    def _consume(self):
        values = self._arguments("consume")
        digest = profile.request_digest(profile.PREFIX + "consume", values)
        item = self.history[self.attempt]
        claim = {"schema": "serverware.policyFilePublicationClaim/v1", "publicationId": self.attempt,
            "intentSha256": item["intentSha256"], "authorityRequestDigest": digest, "auditId": _audit("consume", digest)}
        if self.resolving:
            claim = {"schema": "serverware.policyFileResolutionClaim/v1", "publicationId": self.attempt,
                "binding": self.bound, "actorId": self.approval.identity.user_id, "approvalId": self.approval_id,
                "authorityRequestDigest": digest, "auditId": _audit("consume", digest),
                "fileSha256": self.file_sha, "fileIdentity": self.file_identity}
        self.claim_sha = self._record("resolution-claimed" if self.resolving else "claimed", claim)
        self.consumed = self.approval.dispatch("consume", values, self.assertion)
        _require(self.consumed["approval"]["status"] == "consumed")
        self.check()

    def execute(self):
        _require(not self.executing)
        self.executing = True
        self.negotiate()
        self._open()
        self._consume()
        from serverware.control_plane_policy_file_authority import CurrentPolicyAuthority
        from serverware.control_plane_policy_file_genesis import GenesisPolicyAuthority
        # This connection is separate from definite approval/audit commits.
        # Never call the controlled writer while its conflicting fence is held.
        authority = GenesisPolicyAuthority if self.material_binding["kind"] == "genesis-materialize" else CurrentPolicyAuthority
        self.authority = authority.open(self)
        try:
            self.authority.check()
            if not self.resolving:
                stage_name = self.attempt + ".stage"
                self.check()
                self.authority.check()
                replaced_pins = [pin for pin in self.pins
                    if (pin[0], pin[1]) in {(self.directory, stage_name), (self.parent, self.basename)}]
                staged = next(pin for pin in replaced_pins if pin[0] == self.directory)
                os.rename(stage_name, self.basename, src_dir_fd=self.directory, dst_dir_fd=self.parent)
                self.target_installed = True
                previous = self.history
                self.history = _history(self.directory)[0]
                _require(set(self.history) == set(previous) and all(
                    self.history[identifier] == ({key: value for key, value in item.items()
                        if key not in {"stageSha256", "stageIdentity"}} if identifier == self.attempt else item)
                    for identifier, item in previous.items()))
                actual, identity = self._pin(self.parent, self.basename, bundles.MAX_POLICY_BUNDLE_BYTES)
                _require(actual == self.raw and _renamed_identity(identity, staged[4])
                    and identity == files._file_identity(os.fstat(staged[2])))
                for pin in replaced_pins:
                    self.pins.remove(pin)
                    os.close(pin[2])
                self.file_sha, self.file_identity = _sha(actual), identity
            for _, _, descriptor, _, _ in self.pins:
                os.fsync(descriptor)
            os.fsync(self.parent)
            os.fsync(self.directory)
            self.authority.check()
            self.check()
            prefix = "resolution-" if self.resolving else ""
            completion = {"schema": "serverware.policyFileResolutionComplete/v1" if self.resolving else
                "serverware.policyFilePublicationComplete/v1", "publicationId": self.attempt,
                "intentSha256": self.history[self.attempt]["intentSha256"], "claimSha256": self.claim_sha,
                "fileSha256": self.file_sha, "fileIdentity": self.file_identity}
            if self.resolving:
                completion["outcome"] = self.bound["outcome"]
            complete_sha = self._record(prefix + "complete", completion)
            self.authority.check()
        finally:
            self.authority.close()
            self.authority = None
        self.check()
        _require(not self.settlement_attempted)
        self.settlement_attempted = True
        settling = ceremonies._Ceremony(self.request, purpose="policy-file", deadline_ns=self.deadline, expires_epoch_ns=self.expires)
        values = self._arguments("consume")
        values.pop("credential_policy")
        values.update(consumption_request_digest=self.consumed["requestDigest"], completion_sha256=complete_sha)
        result = settling.dispatch("settle", values)
        self._record(prefix + "settled", {"schema": "serverware.policyFilePublicationSettlement/v1", "publicationId": self.attempt,
            "completionSha256": complete_sha, "authorityRequestDigest": result["requestDigest"],
            "auditId": _audit("settle", result["requestDigest"])})
        self.check()
        return {"schema": "serverware.policyFilePublicationResult/v1", "ok": True, "publicationId": self.attempt,
            "completionSha256": complete_sha, "outcome": self.bound.get("outcome", "materialized"), "automaticRetryAllowed": False}

    def close(self):
        try:
            if self.authority is not None:
                self.authority.close()
        finally:
            for _, _, descriptor, _, _ in self.pins:
                os.close(descriptor)
            self.pins = []
            for descriptor in (self.directory, self.parent):
                if descriptor is not None:
                    os.close(descriptor)


def execute(request, payload, *, resolving=False, genesis=False):
    owner = None
    try:
        owner = PolicyFilePublication(request, payload, resolving=resolving, genesis=genesis)
        return owner.execute()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=409, detail={"error": "policy_file_publication_unavailable_or_uncertain",
            "automaticRetryAllowed": False, "inspectionEndpoint": PATH}) from None
    finally:
        if owner is not None:
            owner.close()


def inspect_publication(*, expected_identity=None):
    path, basename, parent, identity = bundles._open_secure_parent_directory(
        bundles.POLICY_BUNDLE_PATH, label="policy file observation", mutation_target=True)
    directory = None
    try:
        fcntl.flock(parent, fcntl.LOCK_SH | fcntl.LOCK_NB)
        try:
            directory, _, _ = _directory(parent, create=False)
        except FileNotFoundError:
            items, incomplete, terminal_sha, terminal = {}, None, None, None
        else:
            items, incomplete, terminal_sha, terminal = _history(directory)
        try:
            raw, value = files._read(parent, basename, bundles.MAX_POLICY_BUNDLE_BYTES)
            current, current_identity = _sha(raw), files._file_identity(value)
        except FileNotFoundError:
            current = current_identity = None
        if expected_identity is not None:
            _require(type(expected_identity) is bundles.PolicyFileIdentity
                and current == expected_identity.file_sha256
                and current_identity == list(expected_identity.stat_components))
        bundles._recheck_secure_parent_directory(path, label="policy file observation", expected=identity, mutation_target=True)
        return {"schema": "serverware.policyFilePublicationObservation/v1", "fileSha256": current,
            "automaticRetryAllowed": False, "incompletePublicationId": incomplete, "terminalSha256": terminal_sha,
            "attempts": [{"publicationId": identifier, "intentSha256": item["intentSha256"],
                "binding": item["intent"]["binding"], "resolutionClaimed": "resolution-claimed" in item}
                for identifier, item in sorted(items.items())],
            "terminalMatches": terminal is None or current == terminal["fileSha256"] and current_identity == terminal["fileIdentity"]}
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def require_loadable(path, *, expected_identity=None):
    _require(Path(path) == bundles.POLICY_BUNDLE_PATH)
    observed = inspect_publication(expected_identity=expected_identity)
    _require(observed["incompletePublicationId"] is None and observed["terminalMatches"])
