"""Actual retained control-plane loader/journal observation, never permission.

The fixed-path reader holds the real publication lock and file descriptors. It
does not claim that the native gate loaded this snapshot, sign a receipt, clear
an uncertain publication, or perform any database/filesystem mutation.
"""
import fcntl
import os
import threading
import time

from catchplate import db, policy_bundle as bundles
from catchplate import authority_setup_policy as profile
from catchplate import authority_policy_file_approval as approval_profile
from catchplate import authority_transition_publication_approval as approval_kernel
from catchplate import authority_transition_core as core
from catchplate import control_plane_admin_token_publication as files
from catchplate import control_plane_policy_file_publication as publication

MAX_OBSERVATION = 128 * 1024


def _row(table, identifier):
    profile.require(table in {"control_plane_approvals", "metadata_audit_outbox"})
    with db.connect() as connection:
        result = connection.execute("SELECT * FROM " + table + " WHERE id = ?", (identifier,)).fetchone()
    profile.require(result is not None, "settled publication metadata is unavailable")
    return dict(result)


class LoadedPublication:
    def __init__(self, *, continuation, deadline_ns, check_owner):
        self.continuation = dict(continuation)
        self.continuation_original = profile.row_original(self.continuation)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.deadline, self.check_owner = deadline_ns, check_owner
        self.parent = self.directory = None
        self.pins = []
        self.history = self.approval = self.audit = None
        self.started = self.last = time.monotonic_ns()
        self.started_epoch = time.time_ns()
        profile.require(type(deadline_ns) is int and self.started < deadline_ns <= self.started + 30_000_000_000)

    def _pin(self, directory, name, maximum):
        raw, stat = files._read(directory, name, maximum)
        identity = files._file_identity(stat)
        descriptor = os.open(name, files._READ_FLAGS, dir_fd=directory)
        try:
            profile.require(files._file_identity(os.fstat(descriptor)) == identity)
        except BaseException:
            os.close(descriptor)
            raise
        self.pins.append((directory, name, descriptor, raw, identity))
        return raw, identity

    def open(self):
        self.check()
        self.path, self.basename, self.parent, self.parent_identity = bundles._open_secure_parent_directory(
            bundles.POLICY_BUNDLE_PATH, label="Setup loaded policy observation", mutation_target=True)
        fcntl.flock(self.parent, fcntl.LOCK_SH | fcntl.LOCK_NB)
        self.directory, _, _ = publication._directory(self.parent, create=False, shared=True)
        self.directory_identity = files._file_identity(os.fstat(self.directory))
        self.history, incomplete, self.terminal_sha, terminal = publication._history(self.directory)
        profile.require(incomplete is None and terminal is not None and self.terminal_sha is not None,
            "Setup needs an actual terminal materializer journal, not an absent journal")
        self.publication_id = terminal["publicationId"]
        self.item = self.history[self.publication_id]
        self.prefix = "resolution-" if "resolution-settled" in self.item else ""
        profile.require(not self.prefix or terminal["outcome"] == "finalize-installed",
            "abandoned publication cannot establish installed policy")
        self.intent = self.item["intent"]
        self.binding = self.intent["binding"]
        profile.require(self.binding["kind"] == "materialize"
            and self.binding["artifactEnvelopeSha256"] == self.continuation["artifact_envelope_digest"]
            and self.binding["policyHash"] == self.continuation["policy_hash"])
        self.raw, self.file_identity = self._pin(self.parent, self.basename, bundles.MAX_POLICY_BUNDLE_BYTES)
        profile.require(publication._sha(self.raw) == terminal["fileSha256"] == self.binding["policyOriginalSha256"]
            and self.file_identity == terminal["fileIdentity"])
        self.originals = {}
        phases = ("intent", "claimed", self.prefix + "complete", self.prefix + "settled")
        if self.prefix:
            phases += ("resolution-claimed",)
        for phase in phases:
            raw, _ = self._pin(self.directory, self.publication_id + "." + phase, publication.MAX_RECORD)
            profile.require(publication._sha(raw) == self.item[phase + "Sha256"])
            self.originals[phase] = raw.decode("ascii")
        self._load()
        self._settlement()
        self.check()
        return self

    def _load(self):
        # The actual process-global loader owns this cache. A supplied snapshot,
        # equal-looking PolicyFileIdentity or HTTP-loaded flag is not admitted.
        with bundles._SNAPSHOT_CACHE_LOCK:
            snapshot = bundles.get_policy_snapshot()
            loader = bundles._POLICY_BUNDLE_LOADER
            cache = loader.cache
            profile.require(snapshot is not None and loader.path == bundles.POLICY_BUNDLE_PATH
                and type(cache) is tuple and len(cache) == 3)
            identity, retained, trust_identity = cache
            profile.require(type(identity) is bundles.PolicyFileIdentity and retained is not None and trust_identity is not None
                and list(identity.stat_components) == self.file_identity
                and identity.file_sha256 == publication._sha(self.raw)
                and snapshot.hash == retained.hash == self.continuation["policy_hash"]
                and profile.canonical(snapshot.raw) == profile.canonical(retained.raw)
                and profile.sha256(profile.canonical(snapshot.raw)) == self.binding["policyBundleSha256"])
            signed, signed_trust, original = publication._signed(self.raw)
            profile.require(signed_trust == trust_identity and signed.hash == snapshot.hash
                and all(self.binding[name] == value for name, value in original.items()))
            management = {"candidatePolicyBundle": snapshot.raw}
            session = profile.setup.document(self.continuation["setup_original"].encode("ascii"), profile.setup.MAX_ROW_BYTES)
            assignment, assignment_digest = profile.reviewed_assignment(session, management)
            profile.require(assignment_digest == self.continuation["assignment_digest"]
                and assignment["routePolicyDigest"] == self.continuation["route_policy_digest"])
            if hasattr(self, "loader"):
                profile.require(loader is self.loader and identity == self.loader_identity and trust_identity == self.trust_identity)
            else:
                self.loader, self.loader_identity, self.trust_identity = loader, identity, trust_identity
                self.assignment = assignment

    def _settlement(self):
        claim = self.item[self.prefix + "claimed"]
        settled = self.item[self.prefix + "settled"]
        source = claim if self.prefix else self.intent
        approval = _row("control_plane_approvals", source["approvalId"])
        provenance = approval_kernel._authn(approval, approval_profile)
        bound = claim["binding"] if self.prefix else self.binding
        profile.require(approval["status"] == "consumed" and approval["resource_id"] == approval_profile.RESOURCE
            and approval["action"] == approval_profile.action(bound)
            and approval["request_json"] == profile.canonical(bound).decode("ascii")
            and approval["payload_digest"] == profile.sha256(profile.canonical(bound))
            and approval["requester_id"] == approval["consumed_by"] == source["actorId"]
            and approval["approved_by"] not in {None, approval["requester_id"]}
            and approval["approved_at"] is not None and approval["consumed_at"] is not None
            and provenance["consumptionDigest"] == claim["authorityRequestDigest"]
            and provenance["completionSha256"] == self.terminal_sha == settled["completionSha256"])
        audit = _row("metadata_audit_outbox", settled["auditId"])
        profile.require(audit["status"] == "audited" and audit["claim_id"] is None and audit["claimed_at"] is None
            and audit["audited_at"] is not None and audit["audit_event_hash"] is not None
            and profile.setup.epoch(audit["audited_at"]) <= time.time_ns())
        profile.digest(audit["audit_event_hash"])
        event = profile.setup.document(audit["event_json"].encode("ascii"), publication.MAX_RECORD)
        profile.require(audit["event_json"] == profile.canonical(event).decode("ascii")
            and audit["event_digest"] == core.framed_digest(
                "catchplate.metadataAuditOutboxEvent/v1", audit["event_json"].encode("ascii"))
            and audit["event_type"] == approval_profile.AUDIT_PREFIX + "settle"
            and audit["actor_type"] == "admin" and audit["actor_id"] == source["actorId"]
            and event == {"schema": "catchplate.publicationApprovalAudit/v1",
                "operation": approval_profile.PREFIX + "settle",
                "requestDigest": settled["authorityRequestDigest"], "approvalId": approval["id"],
                "actorId": source["actorId"], "action": approval["action"],
                "resourceId": approval_profile.RESOURCE, "payloadDigest": approval["payload_digest"],
                "request": bound, "provenance": provenance})
        if self.approval is not None:
            profile.require(approval == self.approval and audit == self.audit)
        self.approval, self.audit = approval, audit

    def check(self):
        self.check_owner()
        now = time.monotonic_ns()
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.last <= now < self.deadline and time.time_ns() >= self.started_epoch
            and profile.row_original(self.continuation) == self.continuation_original)
        if self.parent is not None:
            bundles._recheck_secure_parent_directory(self.path, label="Setup loaded policy observation",
                expected=self.parent_identity, mutation_target=True)
        if self.directory is not None:
            profile.require(files._file_identity(os.fstat(self.directory))[:5] == self.directory_identity[:5]
                == files._file_identity(os.stat(publication.JOURNAL, dir_fd=self.parent, follow_symlinks=False))[:5])
            profile.require(publication._history(self.directory)[0] == self.history)
        for directory, name, descriptor, original, identity in self.pins:
            raw, stat = files._read(directory, name, max(1, len(original)))
            profile.require(raw == original and files._file_identity(stat) == identity == files._file_identity(os.fstat(descriptor)))
        self.last = time.monotonic_ns()
        profile.require(now <= self.last < self.deadline)

    def observation(self):
        self.check()
        self._load()
        self._settlement()
        self.check()
        result = {"schema": "catchplate.setupLoadedPolicyObservation/v1", "scope": "control-plane-loaded-policy-only",
            "okForAction": False, "automaticRetryAllowed": False, "nativeGateVerified": False,
            "setupSessionId": self.continuation["session_id"], "continuationSha256": profile.sha256(self.continuation_original),
            "publicationId": self.publication_id, "completionSha256": self.terminal_sha,
            "policyFileSha256": self.loader_identity.file_sha256, "policyFileIdentity": list(self.loader_identity.stat_components),
            "assignment": self.assignment, "journalOriginals": self.originals,
            "approvalOriginal": profile.canonical(self.approval).decode("ascii"),
            "settlementAuditOriginal": profile.canonical(self.audit).decode("ascii"),
            "observedAtEpochNs": time.time_ns()}
        raw = profile.canonical(result)
        profile.require(len(raw) <= MAX_OBSERVATION)
        self.check()
        return raw.decode("ascii")

    def close(self):
        for _, _, descriptor, _, _ in self.pins:
            os.close(descriptor)
        self.pins = []
        for name in ("directory", "parent"):
            descriptor = getattr(self, name)
            setattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
