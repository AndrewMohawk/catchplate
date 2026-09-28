"""Caller-owned originals, one attempt and unsigned readback observations.

This library is not a measured authority role, provisioner, network client or
receipt verifier. Its caller supplies an independently provisioned private
directory. Local content identity and an ATTEMPTED marker establish neither a
remote commit nor permission to send or retry. Published records are never
removed. Recovery rejects unknown and temporary files rather than guessing
whether an interrupted publication may safely be discarded.
An OBSERVED marker records only first successful readback metadata; it is
neither terminal business state nor authority to bypass fresh verification.
Registration execution-grant, finalization-grant and signer-exchange records are retention-only families;
they never admit attempted or observed markers or legacy forwarding.
An ASSOCIATED marker commits only an exact local signer/grant relationship
after both original records are durable; it supplies no verification or authority.
Separate registration outcomes retain opaque originals under that association.
Finalization reservation raw3 has its own immutable slot under the complete
finalization/evidence/signer chain; storage supplies no outcome authentication.
Separate finalization SQL/completion records require that retained reservation;
completion reconciliation never replaces its original uncertain outcome.
A SQL-CLAIMED record burns only one local dispatch, never remote SQL permission.
Dedicated token-free release claims burn one exact root client authorization;
they are not prepared records or members of any generic forwarding family.
Separate token-free activation claims burn the retained finalization locator
before the planner request; even exact recovered claims prohibit dispatch.
Six fixed activation stage records retain only opaque public/cipher originals
beneath that claim. Recovery permits reads, never resumed stage publication.
Separate consume claims count as additional logical records with seven fixed
stage siblings, including an irreversible SQL claim and unsigned observation.
Recovery grant acquisition has a distinct policy-keyed claim and optional raw3
response. It consumes one logical slot, never resumes a recovered claim, and
retains no recovery request, token, cookie or WebAuthn assertion.

The private directory open-file description owns the singleton flock. The
supplied descriptor remains borrowed; use after fork is rejected. Filesystem
durability depends on the provisioned filesystem honoring fsync. The lease and
directory timestamps do not provide an independent anti-rollback anchor or
exclude an independently privileged writer.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import fcntl
import os
import stat

from serverware import control_plane_custody_records as records
from serverware import control_plane_custody_observations as observations
from serverware import control_plane_registration_execution_records as execution_records
from serverware import control_plane_registration_signer_records as signer_records
from serverware import control_plane_registration_associations as associations
from serverware import control_plane_registration_finalization_records as finalization_records
from serverware import control_plane_registration_finalization_associations as finalization_associations
from serverware import control_plane_registration_finalization_reservation_records as finalization_reservations
from serverware import control_plane_registration_finalization_outcome_records as finalization_outcomes
from serverware import control_plane_registration_outcome_records as outcome_records
from serverware import control_plane_oidc_session_activation_release_attempt as release_attempts
from serverware import control_plane_oidc_session_activation_dispatch_attempt as activation_attempts
from serverware import control_plane_oidc_session_activation_records as activation_records
from serverware import control_plane_oidc_session_activation_consume_records as consume_records
from serverware import control_plane_oidc_session_activation_recovery_records as recovery_records
from serverware import control_plane_oidc_session_activation_completion_recovery_records as completion_recovery
from serverware.authority_witness_journal import WitnessJournalIO


MAX_QUOTA_BYTES = 8 * 1024**3
MAX_RECORDS = 4096
_ATTEMPT_MAGIC = b"SWCPA001"
_ATTEMPT_BYTES = 40
_OBSERVATION_RESERVE = observations.MAX_OBSERVATION_BYTES
_HEX = frozenset("0123456789abcdef")
_READ_CHUNK = 1024 * 1024
_MAX_RECORD_BYTES = max(records.MAX_RECORD_BYTES, execution_records.MAX_RECORD_BYTES,
    signer_records.MAX_RECORD_BYTES, finalization_records.MAX_RECORD_BYTES, outcome_records.MAX_RECORD_BYTES,
    finalization_reservations.MAX_RECORD_BYTES, finalization_outcomes.MAX_RECORD_BYTES,
    activation_attempts.MAX_RECORD_BYTES, activation_records.MAX_RECORD_BYTES,
    consume_records.MAX_RECORD_BYTES, recovery_records.MAX_RECORD_BYTES, completion_recovery.MAX_RECORD_BYTES)
_FINALIZATION_OUTCOME_FILES = {
    "finalization-" + kind: kind for kind in finalization_outcomes.KINDS}
_ACTIVATION_RECORD_FILES = {
    "activation-" + kind: kind for kind in activation_records.KINDS}
_CONSUME_RECORD_FILES = {
    "activation-consume-" + kind: kind for kind in consume_records.KINDS}
_RECOVERY_RECORD_FILES = dict(zip(recovery_records.FILE_KINDS, recovery_records.KINDS))
_COMPLETION_RECOVERY_FILES = dict(zip(completion_recovery.FILE_KINDS, completion_recovery.KINDS))
_RETENTION_ONLY_FAMILIES = frozenset({execution_records.FAMILY, signer_records.FAMILY,
    finalization_records.FAMILY})
_COMPLETION_HISTORY_MAX_BYTES = 64 * 1024**2
_COMPLETION_HISTORY_FIXED_BYTES = 16 * 1024
_COMPLETION_RECOVERY_TARGET_MAX_BYTES = 64 * 1024**2
_COMPLETION_RECOVERY_TARGET_FIXED_BYTES = 4096


class CustodyJournalError(RuntimeError):
    pass


class _CompletionPublication:
    """Actual native-owned publication transitions, never a readiness bypass."""

    def __init__(self, owner, name, size, current):
        self.owner, self.directory_fd = owner, owner._directory_fd
        self.identities, self.count = owner._file_identities, len(owner._file_identities)
        self.name, self.temporary, self.size = name, ".tmp-" + name, size
        self.current, self.stage = current, "initial"
        self.descriptor, self.inode, self.published_identity = None, None, None
        if name in self.identities or self.temporary in self.identities:
            raise CustodyJournalError("completion publication names are already retained")
        owner._require_ready()
        current()

    def transition(self, phase, descriptor):
        owner = self.owner
        if (owner._directory_fd != self.directory_fd or owner._file_identities is not self.identities
                or len(self.identities) != self.count):
            raise CustodyJournalError("completion publication original owner changed")
        owner._require_process()
        if phase == "created":
            if self.stage != "initial" or type(descriptor) is not int or descriptor < 0:
                raise CustodyJournalError("completion publication create transition differs")
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != 0 or metadata.st_nlink != 1
                    or metadata.st_dev != owner._binding[0]
                    or (metadata.st_uid, metadata.st_gid) != owner._binding[2:]):
                raise CustodyJournalError("completion publication native-created inode differs")
            self.descriptor = descriptor
            self.inode = metadata.st_dev, metadata.st_ino
            expected_name, expected_identity = self.temporary, _identity(metadata)
            next_stage = "created"
        elif phase == "renamed":
            if self.stage != "created" or descriptor != self.descriptor:
                raise CustodyJournalError("completion publication rename transition differs")
            metadata = os.fstat(descriptor)
            if ((metadata.st_dev, metadata.st_ino) != self.inode
                    or not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                    or metadata.st_size != self.size or metadata.st_nlink != 1
                    or (metadata.st_uid, metadata.st_gid) != owner._binding[2:]):
                raise CustodyJournalError("completion publication sealed native inode differs")
            expected_name, expected_identity = self.name, _identity(metadata)
            self.published_identity = expected_identity
            next_stage = "renamed"
        elif phase == "closed":
            if self.stage not in ("created", "renamed") or descriptor is not None:
                raise CustodyJournalError("completion publication close transition differs")
            expected_name = self.name if self.stage == "renamed" else self.temporary
            metadata = os.stat(expected_name, dir_fd=self.directory_fd, follow_symlinks=False)
            if ((metadata.st_dev, metadata.st_ino) != self.inode
                    or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or (metadata.st_uid, metadata.st_gid) != owner._binding[2:]
                    or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
                    or not 0 <= metadata.st_size <= self.size):
                raise CustodyJournalError("completion publication closed inode differs")
            expected_identity = _identity(metadata)
            if self.stage == "renamed" and expected_identity != self.published_identity:
                raise CustodyJournalError("completion publication changed before normal close")
            next_stage = "closed-published" if self.stage == "renamed" else "closed-temporary"
        elif phase == "removed":
            if self.stage != "closed-temporary" or descriptor is not None:
                raise CustodyJournalError("completion publication cleanup transition differs")
            expected_name, expected_identity, next_stage = None, None, "removed"
        else:
            raise CustodyJournalError("completion publication transition is not source fixed")
        # Directory timestamps change at our create/rename/unlink boundaries.
        # Before advancing them, compare the entire bounded *metadata* inventory
        # with admitted immutable names plus this actual native-owned inode.
        # Stream entries: no body read, retained all-name set or caller path.
        before = owner._stamp()
        count, found = 0, False
        expected_count = self.count + int(expected_name is not None)
        with os.scandir(self.directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > expected_count:
                    raise CustodyJournalError("completion publication directory inventory grew")
                metadata = entry.stat(follow_symlinks=False)
                actual = _identity(metadata)
                if entry.name == expected_name:
                    if found or actual != expected_identity:
                        raise CustodyJournalError("completion publication expected inode was replaced")
                    found = True
                elif self.identities.get(entry.name) != actual:
                    raise CustodyJournalError("completion publication immutable inventory changed")
        after = owner._stamp()
        if (before != after or count != expected_count
                or found != (expected_name is not None)):
            raise CustodyJournalError("completion publication metadata changed during admission")
        self.stage = next_stage
        owner._directory_stamp = after
        # Full original ancestry is called only after the exact expected local
        # transition has been proved. It never sees a disabled readiness check.
        self.current()


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Metadata only; neither history admission nor a delivery receipt."""

    digest: str
    family: str
    selector: str
    source_revision: str
    prepared_bytes: int
    attempted: bool
    observed: bool = False


def _integer(value, *, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CustodyJournalError(label + " is not a bounded exact integer")


def _digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyJournalError("local prepared digest is not canonical SHA-256")
    return value


def _name(kind, digest):
    return kind + "-" + digest[7:]


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _decode_prepared(encoded):
    """Dispatch only the four fixed original-record formats, never a plugin."""
    if type(encoded) is not bytes:
        raise CustodyJournalError("prepared record is not immutable bytes")
    if encoded[:8] == records.PREPARED_RECORD_MAGIC:
        return records.decode_prepared(encoded)
    if encoded[:8] == execution_records.PREPARED_RECORD_MAGIC:
        return execution_records.decode_prepared(encoded)
    if encoded[:8] == signer_records.PREPARED_RECORD_MAGIC:
        return signer_records.decode_prepared(encoded)
    if encoded[:8] == finalization_records.PREPARED_RECORD_MAGIC:
        return finalization_records.decode_prepared(encoded)
    raise CustodyJournalError("prepared record version is unsupported")


def _association_scope(association, entries):
    execution = entries.get(association.execution_digest)
    signer = entries.get(association.signer_digest)
    if (execution is None or signer is None
            or (execution.family, execution.selector)
                != (execution_records.FAMILY, execution_records.OPERATION)
            or (signer.family, signer.selector)
                != (signer_records.FAMILY, signer_records.OPERATION)
            or execution.source_revision != association.source_revision
            or signer.source_revision != association.source_revision
            or execution.attempted or execution.observed or signer.attempted or signer.observed):
        raise CustodyJournalError("preparation association differs from its exact retained originals")


def _finalization_association_scope(association, entries, evidence_associations):
    finalization = entries.get(association.finalization_digest)
    evidence = evidence_associations.get(association.evidence_digest)
    if (finalization is None or evidence is None
            or (finalization.family, finalization.selector)
                != (finalization_records.FAMILY, finalization_records.OPERATION)
            or finalization.source_revision != association.source_revision
            or evidence.source_revision != association.source_revision
            or evidence.signer_digest != association.signer_digest
            or finalization.attempted or finalization.observed):
        raise CustodyJournalError("finalization association differs from its retained original scope")
    _association_scope(evidence, entries)


class CustodyJournal:
    """One PID-bound, explicitly provisioned, append-only local journal.

    Construction completes the only recovery scan before making the owner
    available. Quota reserves forty attempt bytes and the maximum observation
    frame for each legacy prepared record still missing those markers.
    Retention-only execution grants and signer exchanges reserve no delivery
    marker bytes. Complete preparations preflight both records and their final
    association without consuming another record's reserved marker capacity.
    Finalization grants link only to an already complete evidence/signer pair;
    their separate association is published last. Each may retain one opaque
    reservation raw3, one SQL claim, one SQL outcome, one completion outcome
    and one completion reconciliation under that association.
    Seven times maximum_records plus ten per consume claim bounds published files, including associations and
    fixed registration outcomes: legacy records use at most three, evidence
    grants seven, signer records one and finalization grants seven each.
    Old records are never rewritten or removed; legacy marker byte
    reservations remain intact.
    Public-only release and activation claims share prepared-record logical capacity and
    the unchanged physical/quota ceilings, without reserving legacy markers.
    An activation claim has exactly six possible stage siblings: seven total
    files, exhausting its unchanged allowance. No stage adds another slot.
    Consume has eighteen possible files, but still adds only ten physical
    allowances. Near-full journals may refuse; no global ceiling is enlarged.
    A recovery acquisition claim has only two files within its separately
    counted seven-file logical allowance; it does not widen consume grammar.
    """

    def __init__(self, *, directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, quota_bytes, maximum_records):
        for value, minimum, maximum, label in (
            (directory_fd, 0, 2**31 - 1, "directory descriptor"),
            (expected_device, 0, 2**64 - 1, "directory device"),
            (expected_inode, 1, 2**64 - 1, "directory inode"),
            (expected_uid, 0, 2**32 - 2, "directory owner UID"),
            (expected_gid, 0, 2**32 - 2, "directory owner GID"),
            (quota_bytes, 1, MAX_QUOTA_BYTES, "journal quota"),
            (maximum_records, 1, MAX_RECORDS, "journal record limit"),
        ):
            _integer(value, minimum=minimum, maximum=maximum, label=label)
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._quota, self._maximum_records = quota_bytes, maximum_records
        self._closed = False
        self._entries = {}
        self._associations = {}
        self._finalization_associations = {}
        self._finalization_reservations = {}
        self._finalization_outcomes = {}
        self._registration_outcomes = {}
        self._release_attempts = {}
        self._activation_dispatch_attempts = {}
        self._activation_records = {}
        # Only successful claims made by this owner may continue publication.
        # Recovery intentionally never populates this in-memory set.
        self._activation_live_claims = set()
        self._consume_claims = {}
        self._consume_targets = {}
        self._consume_records = {}
        self._consume_live_claims = set()
        self._recovery_grant_claims = {}
        self._recovery_grant_records = {}
        # Historical recovery deliberately leaves this continuation set empty.
        self._recovery_grant_live_claims = set()
        self._completion_recovery_claims = {}
        self._completion_recovery_responses = {}
        self._completion_recovery_live_claims = set()
        # Only this work's newly successful existing-family intent/proof/grant claim
        # permits its corresponding publication; recovery never restores it.
        self._completion_release_live_claims = {}
        self._file_identities = {}
        self._used_bytes = 0
        self._reserved_bytes = 0
        self._directory_stamp = None
        self._io = None
        self._directory_fd = None
        if (os.geteuid(), os.getegid()) != (expected_uid, expected_gid):
            raise CustodyJournalError("journal writer identity differs from its provisioned owner")
        self._directory_metadata(directory_fd)
        try:
            # Unlike dup(), this acquires an independent open-file description
            # and cannot share a successful flock with another journal owner.
            self._directory_fd = os.open(".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd)
            self._directory_metadata(self._directory_fd)
            fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._io = WitnessJournalIO(self._directory_fd,
                maximum_record_bytes=_MAX_RECORD_BYTES)
            self._directory_stamp = self._io.recover(self._recover)
        except BaseException:
            self._closed = True
            if self._io is not None:
                self._io.poison()
            if self._directory_fd is not None:
                try:
                    os.close(self._directory_fd)
                except OSError:
                    pass
            raise

    def _directory_metadata(self, descriptor):
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                    != self._binding):
            raise CustodyJournalError("journal directory differs from its private pinned identity")
        return metadata

    def _stamp(self):
        metadata = self._directory_metadata(self._directory_fd)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _physical_limit(self):
        # Only a separately counted, admitted consume claim may use its nine
        # suffix files beyond seven. Older families retain their fixed inventories.
        return 7 * self._maximum_records + 10 * len(self._consume_claims)

    def _require_process(self):
        if os.getpid() != self._pid:
            raise CustodyJournalError("journal cannot be used or closed by a forked process")
        if self._closed:
            raise CustodyJournalError("journal is closed")

    def _require_ready(self):
        self._require_process()
        self._io.require_ready()
        try:
            if self._stamp() != self._directory_stamp:
                raise CustodyJournalError("journal directory changed outside its owner")
        except BaseException:
            self._io.poison()
            raise

    def _read_file(self, name, *, maximum_bytes, synchronize=False):
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400
                    or before.st_nlink != 1 or before.st_dev != self._binding[0]
                    or (before.st_uid, before.st_gid) != self._binding[2:]
                    or not 1 <= before.st_size <= maximum_bytes):
                raise CustodyJournalError("journal record is not bounded private immutable material")
            encoded = bytearray()
            while len(encoded) < before.st_size:
                chunk = os.read(descriptor, min(_READ_CHUNK, before.st_size - len(encoded)))
                if not chunk:
                    raise CustodyJournalError("journal record was truncated")
                encoded.extend(chunk)
            if os.read(descriptor, 1):
                raise CustodyJournalError("journal record grew while reading")
            if synchronize:
                os.fsync(descriptor)
            after = os.fstat(descriptor)
            if _identity(before) != _identity(after):
                raise CustodyJournalError("journal record identity changed while reading")
            return bytes(encoded), _identity(after)
        finally:
            os.close(descriptor)

    def _recover(self):
        before = self._stamp()
        prepared = {}
        attempted = set()
        observed = set()
        associated = {}
        finalization_associated = {}
        finalization_reserved = {}
        finalization_sql = {}
        registration_outcomes = {}
        release_claims = {}
        activation_claims = {}
        activation_stages = {}
        consume_claims = {}
        consume_targets = {}
        consume_stages = {}
        recovery_claims = {}
        recovery_grants = {}
        completion_recovery_claims = {}
        completion_recovery_responses = {}
        uncertain_completions = set()
        uncertain_finalization_completions = set()
        count = 0
        with os.scandir(self._directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > 17 * self._maximum_records:
                    raise CustodyJournalError("journal physical file limit exceeded")
                name = entry.name
                if name.startswith("prepared-"):
                    kind = "prepared"
                elif name.startswith("attempted-"):
                    kind = "attempted"
                elif name.startswith("observed-"):
                    kind = "observed"
                elif name.startswith("associated-"):
                    kind = "associated"
                elif name.startswith("finalization-associated-"):
                    kind = "finalization-associated"
                elif name.startswith("finalization-reserved-"):
                    kind = "finalization-reserved"
                elif name.startswith("finalization-sql-claimed-"):
                    kind = "finalization-sql-claimed"
                elif name.startswith("finalization-sql-outcome-"):
                    kind = "finalization-sql-outcome"
                elif name.startswith("finalization-completion-outcome-"):
                    kind = "finalization-completion-outcome"
                elif name.startswith("finalization-completion-reconciled-"):
                    kind = "finalization-completion-reconciled"
                elif name.startswith(release_attempts.KIND + "-"):
                    kind = release_attempts.KIND
                elif name.startswith(activation_attempts.KIND + "-"):
                    kind = activation_attempts.KIND
                elif any(name.startswith(prefix + "-") for prefix in _ACTIVATION_RECORD_FILES):
                    kind = next(prefix for prefix in _ACTIVATION_RECORD_FILES
                        if name.startswith(prefix + "-"))
                elif any(name.startswith(prefix + "-") for prefix in _CONSUME_RECORD_FILES):
                    kind = next(prefix for prefix in _CONSUME_RECORD_FILES
                        if name.startswith(prefix + "-"))
                elif any(name.startswith(prefix + "-") for prefix in _RECOVERY_RECORD_FILES):
                    kind = next(prefix for prefix in _RECOVERY_RECORD_FILES
                        if name.startswith(prefix + "-"))
                elif any(name.startswith(prefix + "-") for prefix in _COMPLETION_RECOVERY_FILES):
                    kind = next(prefix for prefix in _COMPLETION_RECOVERY_FILES
                        if name.startswith(prefix + "-"))
                else:
                    kind = next((kind for kind in outcome_records.KINDS
                        if name.startswith(kind + "-")), None)
                    if kind is None:
                        raise CustodyJournalError("journal contains an unknown or temporary file")
                prefix = kind + "-"
                suffix = name[len(prefix):]
                if (not name.startswith(prefix) or len(suffix) != 64
                        or any(character not in _HEX for character in suffix)):
                    raise CustodyJournalError("journal contains an unknown or temporary file")
                digest = "sha256:" + suffix
                maximum = (_MAX_RECORD_BYTES if kind == "prepared" else
                    _ATTEMPT_BYTES if kind == "attempted" else
                    observations.MAX_OBSERVATION_BYTES if kind == "observed" else
                    associations.MAX_ASSOCIATION_BYTES if kind == "associated" else
                    finalization_associations.MAX_ASSOCIATION_BYTES if kind == "finalization-associated" else
                    finalization_reservations.MAX_RECORD_BYTES if kind == "finalization-reserved" else
                    finalization_outcomes._maximum(_FINALIZATION_OUTCOME_FILES[kind])
                        if kind in _FINALIZATION_OUTCOME_FILES else
                    release_attempts.MAX_RECORD_BYTES if kind == release_attempts.KIND else
                    activation_attempts.MAX_RECORD_BYTES if kind == activation_attempts.KIND else
                    activation_records._maximum(_ACTIVATION_RECORD_FILES[kind])
                        if kind in _ACTIVATION_RECORD_FILES else
                    consume_records._maximum(_CONSUME_RECORD_FILES[kind])
                        if kind in _CONSUME_RECORD_FILES else
                    recovery_records._maximum(_RECOVERY_RECORD_FILES[kind])
                        if kind in _RECOVERY_RECORD_FILES else
                    completion_recovery.MAX_RECORD_BYTES if kind in _COMPLETION_RECOVERY_FILES else
                    outcome_records.MAX_CLAIM_BYTES if kind == "sql-claimed" else
                    outcome_records.MAX_RECORD_BYTES)
                encoded, identity = self._read_file(name,
                    maximum_bytes=min(maximum, self._quota - self._used_bytes), synchronize=True)
                self._used_bytes += len(encoded)
                self._file_identities[name] = identity
                if kind == "prepared":
                    record = _decode_prepared(encoded)
                    if record.digest != digest or digest in prepared:
                        raise CustodyJournalError("prepared filename differs from its original content")
                    prepared[digest] = JournalEntry(digest, record.family, record.selector,
                        record.source_revision, len(encoded), False)
                    if len(prepared) + len(release_claims) + len(activation_claims) + len(consume_claims) > self._maximum_records:
                        raise CustodyJournalError("journal prepared record limit exceeded")
                elif kind == release_attempts.KIND:
                    claim = release_attempts.decode(encoded)
                    if claim.client_authorization_digest != digest or digest in release_claims:
                        raise CustodyJournalError("release claim filename differs from its authorization")
                    release_claims[digest] = claim
                    if len(prepared) + len(release_claims) + len(activation_claims) + len(consume_claims) > self._maximum_records:
                        raise CustodyJournalError("journal release claim record limit exceeded")
                elif kind == activation_attempts.KIND:
                    claim = activation_attempts.decode(encoded)
                    if claim.finalization_digest != digest or digest in activation_claims:
                        raise CustodyJournalError("activation claim filename differs from its finalization locator")
                    activation_claims[digest] = claim
                    if len(prepared) + len(release_claims) + len(activation_claims) + len(consume_claims) > self._maximum_records:
                        raise CustodyJournalError("journal activation claim record limit exceeded")
                elif kind in _ACTIVATION_RECORD_FILES:
                    stage = activation_records.decode(encoded)
                    stage_kind = _ACTIVATION_RECORD_FILES[kind]
                    by_kind = activation_stages.setdefault(digest, {})
                    if (stage.finalization_digest != digest or stage.kind != stage_kind
                            or stage_kind in by_kind):
                        raise CustodyJournalError("activation stage differs from its fixed filename")
                    by_kind[stage_kind] = (stage.source_revision, stage.digest, len(encoded))
                elif kind in _CONSUME_RECORD_FILES:
                    record = consume_records.decode(encoded)
                    stage_kind = _CONSUME_RECORD_FILES[kind]
                    if record.slot_digest != digest or record.kind != stage_kind:
                        raise CustodyJournalError("consume record differs from its fixed slot filename")
                    if stage_kind == "claimed":
                        if digest in consume_claims or record.finalization_digest in consume_targets:
                            raise CustodyJournalError("consume target has more than one irreversible claim")
                        consume_claims[digest] = record
                        consume_targets[record.finalization_digest] = digest
                        if len(prepared) + len(release_claims) + len(activation_claims) + len(consume_claims) > self._maximum_records:
                            raise CustodyJournalError("journal consume claim logical limit exceeded")
                    else:
                        by_kind = consume_stages.setdefault(digest, {})
                        if stage_kind in by_kind:
                            raise CustodyJournalError("consume response stage repeats its slot")
                        by_kind[stage_kind] = (record.source_revision, record.digest,
                            len(encoded), record.originals[0]
                            if stage_kind in ("prepared", "exported", "sql-outcome") else b"")
                elif kind in _RECOVERY_RECORD_FILES:
                    record = recovery_records.decode(encoded)
                    record_kind = _RECOVERY_RECORD_FILES[kind]
                    if record.slot_digest != digest or record.kind != record_kind:
                        raise CustodyJournalError("recovery acquisition record differs from its fixed filename")
                    if record_kind == "claimed":
                        if digest in recovery_claims:
                            raise CustodyJournalError("recovery acquisition has more than one policy claim")
                        recovery_claims[digest] = record
                    else:
                        if digest in recovery_grants:
                            raise CustodyJournalError("recovery acquisition grant originals repeat")
                        recovery_grants[digest] = (record.source_revision, record.digest,
                            len(encoded), record.intent_record_digest,
                            record.finalization_digest, record.activation_authorization_digest,
                            record.release_intent_digest, record.issuer_policy_digest)
                elif kind in _COMPLETION_RECOVERY_FILES:
                    record = completion_recovery.decode(encoded)
                    record_kind = _COMPLETION_RECOVERY_FILES[kind]
                    if record.slot_digest != digest or record.kind != record_kind:
                        raise CustodyJournalError("completion recovery record differs from its fixed filename")
                    if record_kind == "claimed":
                        if digest in completion_recovery_claims:
                            raise CustodyJournalError("completion recovery phase has multiple attempts")
                        completion_recovery_claims[digest] = record
                    else:
                        if digest in completion_recovery_responses:
                            raise CustodyJournalError("completion recovery phase response repeats")
                        completion_recovery_responses[digest] = self._completion_recovery_response_metadata(
                            record, len(encoded))
                elif kind == "attempted":
                    if encoded != _ATTEMPT_MAGIC + bytes.fromhex(suffix) or digest in attempted:
                        raise CustodyJournalError("journal attempt marker is not exact")
                    attempted.add(digest)
                elif kind == "observed":
                    observation = observations.decode_observation(encoded)
                    if observation.local_digest != digest or digest in observed:
                        raise CustodyJournalError("journal observation does not match its local record")
                    observed.add(digest)
                elif kind == "associated":
                    association = associations.decode(encoded)
                    if association.execution_digest != digest or digest in associated:
                        raise CustodyJournalError("association filename differs from its execution original")
                    associated[digest] = association
                elif kind == "finalization-associated":
                    association = finalization_associations.decode(encoded)
                    if association.finalization_digest != digest or digest in finalization_associated:
                        raise CustodyJournalError("finalization association filename differs from its original")
                    finalization_associated[digest] = association
                elif kind == "finalization-reserved":
                    reservation = finalization_reservations.decode(encoded)
                    if reservation.finalization_digest != digest or digest in finalization_reserved:
                        raise CustodyJournalError("finalization reservation differs from its fixed filename")
                    finalization_reserved[digest] = (reservation.source_revision, reservation.digest)
                elif kind in _FINALIZATION_OUTCOME_FILES:
                    outcome = finalization_outcomes.decode(encoded)
                    outcome_kind = _FINALIZATION_OUTCOME_FILES[kind]
                    by_kind = finalization_sql.setdefault(digest, {})
                    if (outcome.finalization_digest != digest or outcome.kind != outcome_kind
                            or outcome_kind in by_kind):
                        raise CustodyJournalError("finalization SQL outcome differs from its fixed filename")
                    by_kind[outcome_kind] = (outcome.source_revision, outcome.digest)
                    if outcome_kind == "completion-outcome" and outcome.originals[0] == b"uncertain":
                        uncertain_finalization_completions.add(digest)
                else:
                    outcome = outcome_records.decode(encoded)
                    by_kind = registration_outcomes.setdefault(digest, {})
                    if (outcome.local_digest != digest or outcome.kind != kind or kind in by_kind):
                        raise CustodyJournalError("registration outcome differs from its fixed filename")
                    # Only bounded metadata is kept across the recovery scan.
                    by_kind[kind] = (outcome.source_revision, outcome.digest)
                    if kind == "completion-outcome" and outcome.originals[0] == b"uncertain":
                        uncertain_completions.add(digest)
        # Directory order is not authority: first bound the scan by the worst
        # possible inventory, then require the exact admitted consume allowance.
        if count > 7 * self._maximum_records + 10 * len(consume_claims):
            raise CustodyJournalError("journal physical inventory exceeds its consume-specific allowance")
        if (len(prepared) + len(release_claims) + len(activation_claims)
                + len(consume_claims) + len(recovery_claims)
                + len(completion_recovery_claims) > self._maximum_records):
            raise CustodyJournalError("journal recovery acquisition logical limit exceeded")
        if not attempted <= prepared.keys():
            raise CustodyJournalError("journal attempt marker has no prepared original")
        retention_only = {digest for digest, entry in prepared.items()
            if entry.family in _RETENTION_ONLY_FAMILIES}
        if (attempted | observed) & retention_only:
            raise CustodyJournalError("retention-only record cannot have delivery markers")
        if not observed <= attempted:
            raise CustodyJournalError("journal observation has no prepared and attempted original")
        marker_records = len(prepared) - len(retention_only)
        self._reserved_bytes = ((marker_records - len(attempted)) * _ATTEMPT_BYTES
            + (marker_records - len(observed)) * _OBSERVATION_RESERVE)
        if self._used_bytes + self._reserved_bytes > self._quota:
            raise CustodyJournalError("journal has insufficient reserved marker capacity")
        self._entries = {digest: replace(entry, attempted=digest in attempted, observed=digest in observed)
            for digest, entry in prepared.items()}
        self._release_attempts = release_claims
        self._activation_dispatch_attempts = activation_claims
        for digest, by_kind in activation_stages.items():
            self._activation_scope(digest, by_kind)
        self._activation_records = activation_stages
        self._consume_claims = consume_claims
        self._consume_targets = consume_targets
        self._completion_recovery_claims = completion_recovery_claims
        self._completion_recovery_responses = completion_recovery_responses
        for digest in consume_stages.keys() | consume_claims.keys():
            self._consume_scope(digest, consume_stages.get(digest, {}))
        self._consume_records = consume_stages
        self._recovery_grant_claims = recovery_claims
        self._recovery_grant_records = recovery_grants
        for digest in recovery_claims.keys() | recovery_grants.keys():
            self._recovery_grant_scope(digest)
        for digest in completion_recovery_claims.keys() | completion_recovery_responses.keys():
            self._completion_recovery_scope(digest)
        for association in associated.values():
            _association_scope(association, self._entries)
        self._associations = associated
        for association in finalization_associated.values():
            _finalization_association_scope(association, self._entries, associated)
        self._finalization_associations = finalization_associated
        for digest, metadata in finalization_reserved.items():
            self._finalization_reservation_scope(digest, metadata)
        self._finalization_reservations = finalization_reserved
        for digest, by_kind in finalization_sql.items():
            self._finalization_outcome_scope(digest, by_kind)
            if "completion-reconciled" in by_kind and digest not in uncertain_finalization_completions:
                raise CustodyJournalError("finalization reconciliation lacks original uncertainty")
        self._finalization_outcomes = finalization_sql
        for digest, by_kind in registration_outcomes.items():
            self._registration_outcome_scope(digest, by_kind)
            if "completion-reconciled" in by_kind and digest not in uncertain_completions:
                raise CustodyJournalError("registration reconciliation lacks original uncertainty")
        self._registration_outcomes = registration_outcomes
        if self._stamp() != before:
            raise CustodyJournalError("journal directory changed during recovery")
        return before

    def _load(self, digest):
        info = self._entries.get(digest)
        if info is None:
            raise CustodyJournalError("local prepared record is absent")
        name = _name("prepared", digest)
        encoded, identity = self._read_file(name, maximum_bytes=info.prepared_bytes)
        record = _decode_prepared(encoded)
        if (identity != self._file_identities[name] or record.digest != digest
                or (record.family, record.selector, record.source_revision)
                    != (info.family, info.selector, info.source_revision)):
            raise CustodyJournalError("prepared record changed after admitted recovery")
        if info.family in _RETENTION_ONLY_FAMILIES and (info.attempted or info.observed):
            raise CustodyJournalError("retention-only record cannot have delivery markers")
        if info.attempted:
            marker_name = _name("attempted", digest)
            marker, marker_identity = self._read_file(marker_name, maximum_bytes=_ATTEMPT_BYTES)
            if (marker != _ATTEMPT_MAGIC + bytes.fromhex(digest[7:])
                    or marker_identity != self._file_identities[marker_name]):
                raise CustodyJournalError("attempt marker changed after admitted recovery")
        if info.observed:
            if not info.attempted:
                raise CustodyJournalError("observed local record has no attempt")
            self._read_observation(digest)
        return record, encoded

    def _read_observation(self, digest):
        name = _name("observed", digest)
        encoded, identity = self._read_file(name, maximum_bytes=observations.MAX_OBSERVATION_BYTES)
        observation = observations.decode_observation(encoded)
        if identity != self._file_identities[name] or observation.local_digest != digest:
            raise CustodyJournalError("observation changed after admitted recovery")
        return observation, encoded

    def _read_association(self, digest):
        name = _name("associated", digest)
        encoded, identity = self._read_file(name,
            maximum_bytes=associations.MAX_ASSOCIATION_BYTES)
        association = associations.decode(encoded)
        held = self._associations[digest]
        if (identity != self._file_identities[name]
                or association.execution_digest != digest
                or (association.source_revision, association.execution_digest, association.signer_digest)
                    != (held.source_revision, held.execution_digest, held.signer_digest)):
            raise CustodyJournalError("preparation association changed after admitted recovery")
        _association_scope(association, self._entries)
        return association, encoded

    def _read_finalization_association(self, digest):
        name = _name("finalization-associated", digest)
        encoded, identity = self._read_file(name,
            maximum_bytes=finalization_associations.MAX_ASSOCIATION_BYTES)
        association = finalization_associations.decode(encoded)
        held = self._finalization_associations[digest]
        if (identity != self._file_identities[name]
                or association.finalization_digest != digest or association != held):
            raise CustodyJournalError("finalization association changed after admitted recovery")
        _finalization_association_scope(association, self._entries, self._associations)
        evidence, _ = self._read_association(association.evidence_digest)
        if evidence.signer_digest != association.signer_digest:
            raise CustodyJournalError("finalization association changed its original signer pair")
        return association, encoded

    def _registration_outcome_scope(self, digest, by_kind):
        association = self._associations.get(digest)
        if association is None:
            raise CustodyJournalError("registration outcome has no complete retained preparation")
        _association_scope(association, self._entries)
        if (any(kind not in outcome_records.KINDS or value[0] != association.source_revision
                for kind, value in by_kind.items())
                or "sql-claimed" in by_kind and "reservation" not in by_kind
                or any(kind in by_kind for kind in ("sql-outcome", "completion-outcome", "completion-reconciled"))
                    and "sql-claimed" not in by_kind
                or "completion-reconciled" in by_kind and "completion-outcome" not in by_kind):
            raise CustodyJournalError("registration outcome lacks its retained original prerequisites")

    def _finalization_reservation_scope(self, digest, metadata):
        association = self._finalization_associations.get(digest)
        if association is None:
            raise CustodyJournalError("finalization reservation lacks its complete original association")
        _finalization_association_scope(association, self._entries, self._associations)
        if metadata[0] != association.source_revision:
            raise CustodyJournalError("finalization reservation crosses retained source revisions")

    def _read_finalization_reservation(self, digest):
        association, _ = self._read_finalization_association(digest)
        self._load(digest)
        self._load(association.evidence_digest)
        self._load(association.signer_digest)
        metadata = self._finalization_reservations.get(digest)
        if metadata is None:
            return None
        self._finalization_reservation_scope(digest, metadata)
        name = _name("finalization-reserved", digest)
        encoded, identity = self._read_file(name,
            maximum_bytes=finalization_reservations.MAX_RECORD_BYTES)
        reservation = finalization_reservations.decode(encoded)
        if (identity != self._file_identities[name] or reservation.finalization_digest != digest
                or (reservation.source_revision, reservation.digest) != metadata):
            raise CustodyJournalError("finalization reservation changed after admitted recovery")
        return reservation

    def _finalization_outcome_scope(self, digest, by_kind):
        association = self._finalization_associations.get(digest)
        if association is None:
            raise CustodyJournalError("finalization SQL outcome lacks its complete original association")
        _finalization_association_scope(association, self._entries, self._associations)
        if any(kind not in finalization_outcomes.KINDS or value[0] != association.source_revision
                for kind, value in by_kind.items()):
            raise CustodyJournalError("finalization SQL outcome crosses its source or fixed profile")
        if by_kind:
            reservation = self._finalization_reservations.get(digest)
            if reservation is None:
                raise CustodyJournalError("finalization SQL outcome lacks retained reservation originals")
            self._finalization_reservation_scope(digest, reservation)
        if (any(kind in by_kind for kind in ("sql-outcome", "completion-outcome", "completion-reconciled"))
                and "sql-claimed" not in by_kind):
            raise CustodyJournalError("finalization outcome lacks its irreversible local SQL claim")
        if "completion-reconciled" in by_kind and "completion-outcome" not in by_kind:
            raise CustodyJournalError("finalization reconciliation lacks its first completion outcome")

    def _read_finalization_outcomes(self, digest):
        # Even absence rereads both associations and all three prepared records.
        # An existing reservation is also reread, never replaced by index data.
        self._read_finalization_reservation(digest)
        association = self._finalization_associations[digest]
        by_kind = self._finalization_outcomes.get(digest, {})
        self._finalization_outcome_scope(digest, by_kind)
        loaded = {}
        for kind in finalization_outcomes.KINDS:
            if kind not in by_kind:
                continue
            name = _name("finalization-" + kind, digest)
            maximum = finalization_outcomes._maximum(kind)
            encoded, identity = self._read_file(name, maximum_bytes=maximum)
            outcome = finalization_outcomes.decode(encoded)
            if (identity != self._file_identities[name]
                    or (outcome.source_revision, outcome.digest) != by_kind[kind]
                    or outcome.kind != kind or outcome.finalization_digest != digest):
                raise CustodyJournalError("finalization SQL outcome changed after admitted recovery")
            loaded[kind] = outcome
        if ("completion-reconciled" in loaded
                and loaded["completion-outcome"].originals[0] != b"uncertain"):
            raise CustodyJournalError("finalization reconciliation lacks original uncertainty")
        return finalization_outcomes.FinalizationOutcomes(association.source_revision, digest,
            loaded.get("sql-claimed"), loaded.get("sql-outcome"),
            loaded.get("completion-outcome"), loaded.get("completion-reconciled"))

    def _read_registration_outcomes(self, digest):
        association, _ = self._read_association(digest)
        self._load(digest)
        self._load(association.signer_digest)
        by_kind = self._registration_outcomes.get(digest, {})
        self._registration_outcome_scope(digest, by_kind)
        loaded = {}
        for kind in outcome_records.KINDS:
            if kind not in by_kind:
                continue
            name = _name(kind, digest)
            maximum = (outcome_records.MAX_CLAIM_BYTES if kind == "sql-claimed"
                else outcome_records.MAX_RECORD_BYTES)
            encoded, identity = self._read_file(name, maximum_bytes=maximum)
            outcome = outcome_records.decode(encoded)
            if (identity != self._file_identities[name]
                    or (outcome.source_revision, outcome.digest) != by_kind[kind]
                    or outcome.kind != kind or outcome.local_digest != digest):
                raise CustodyJournalError("registration outcome changed after admitted recovery")
            loaded[kind] = outcome
        if ("completion-reconciled" in loaded
                and loaded["completion-outcome"].originals[0] != b"uncertain"):
            raise CustodyJournalError("registration reconciliation lacks original uncertainty")
        return outcome_records.RegistrationOutcomes(association.source_revision, digest,
            loaded.get("reservation"), loaded.get("sql-claimed"), loaded.get("sql-outcome"),
            loaded.get("completion-outcome"), loaded.get("completion-reconciled"))

    def _publish(self, kind, digest, encoded):
        name = _name(kind, digest)
        temporary = ".tmp-" + name
        self._io.publish(temporary, name, encoded)
        stored, identity = self._read_file(name, maximum_bytes=len(encoded))
        if stored != encoded:
            raise CustodyJournalError("published journal bytes differ from the original")
        self._file_identities[name] = identity
        self._directory_stamp = self._stamp()

    def _append(self, digest, encoded):
        if digest in self._entries:
            try:
                _, original = self._load(digest)
                if original != encoded:
                    raise CustodyJournalError("duplicate preparation changed exact originals")
                self._require_ready()
                return digest
            except BaseException:
                self._io.poison()
                raise
        record = _decode_prepared(encoded)
        marker_reserve = (0 if record.family in _RETENTION_ONLY_FAMILIES else
            _ATTEMPT_BYTES + _OBSERVATION_RESERVE)
        if (len(self._entries) + len(self._release_attempts)
                + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                + len(self._recovery_grant_claims) + len(self._completion_recovery_claims) >= self._maximum_records
                or len(self._file_identities) >= self._physical_limit()
                or len(encoded) + marker_reserve
                    > self._quota - self._used_bytes - self._reserved_bytes):
            raise CustodyJournalError("journal preparation capacity is exhausted")
        try:
            self._publish("prepared", digest, encoded)
            self._used_bytes += len(encoded)
            self._reserved_bytes += marker_reserve
            self._entries[digest] = JournalEntry(digest, record.family, record.selector,
                record.source_revision, len(encoded), False)
            self._require_ready()
            return digest
        except BaseException:
            self._io.poison()
            raise

    def append_evidence(self, purpose, originals):
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*records.encode_evidence(purpose, originals))

    def append_transition(self, operation, originals):
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*records.encode_transition(operation, originals))

    def append_registration_execution_grant(self, originals):
        """Durably retain original raw10, without forwarding or execution authority."""
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*execution_records.encode(originals))

    def append_registration_signer_exchange(self, originals):
        """Retain exact signer request8/response2, not a grant association or action."""
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*signer_records.encode(originals))

    def append_registration_preparation(self, execution_originals, *, signer_originals):
        """Publish both exact original records, then their immutable local association.

        Only the final association marks a complete local preparation. Failure
        never removes already published originals or chooses another signer.
        This association supplies neither successful replay nor authority.
        """
        self._require_process()
        with self._io.ready():
            self._require_ready()
            execution_digest, execution_encoded = execution_records.encode(execution_originals)
            signer_digest, signer_encoded = signer_records.encode(signer_originals)
            association, association_encoded = associations.encode(execution_digest, signer_digest)
            if execution_digest == signer_digest:
                raise CustodyJournalError("preparation record families cannot share a local identity")
            originals = ((signer_digest, signer_encoded), (execution_digest, execution_encoded))
            # Existing bytes and any previous association are checked before
            # the first write, including retries of a partially retained pair.
            try:
                for digest, encoded in originals:
                    if digest in self._entries:
                        _, retained = self._load(digest)
                        if retained != encoded:
                            raise CustodyJournalError("preparation changed exact retained originals")
                if execution_digest in self._associations:
                    _, retained = self._read_association(execution_digest)
                    if retained != association_encoded:
                        raise CustodyJournalError("preparation cannot remap its original signer association")
                    self._require_ready()
                    return execution_digest
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            missing = tuple((digest, encoded) for digest, encoded in originals
                if digest not in self._entries)
            required_bytes = sum(len(encoded) for _, encoded in missing) + len(association_encoded)
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims)
                    + len(missing) > self._maximum_records
                    or len(self._file_identities) + len(missing) + 1 > self._physical_limit()
                    or required_bytes > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal complete preparation capacity is exhausted")
            try:
                # Both records are retention-only, so the combined preflight
                # preserves every legacy attempt/observation reservation.
                for digest, encoded in originals:
                    self._append(digest, encoded)
                _association_scope(association, self._entries)
                self._require_ready()
                self._publish("associated", execution_digest, association_encoded)
                self._used_bytes += len(association_encoded)
                self._associations[execution_digest] = association
                self._require_ready()
                return execution_digest
            except BaseException:
                self._io.poison()
                raise

    def load_registration_preparation(self, execution_digest):
        """Load the exact locally associated pair; absence is never guessed.

        Unassociated historical records remain individually loadable, but are
        not complete preparations. Returned originals are not replay results.
        """
        digest = _digest(execution_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._associations:
                raise CustodyJournalError("local preparation association is absent")
            try:
                association, _ = self._read_association(digest)
                execution, _ = self._load(digest)
                signer, _ = self._load(association.signer_digest)
                self._require_ready()
                return execution, signer
            except BaseException:
                self._io.poison()
                raise

    def append_registration_finalization_preparation(self, originals, *, evidence_local_digest):
        """Retain finalization raw10 then commit its exact preexisting evidence pair.

        No marker is published until all originals are durable. An interrupted
        publication may leave an orphan record; it never remaps, cleans up or
        automatically retries an uncertain operation.
        """
        evidence_digest = _digest(evidence_local_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            digest, encoded = finalization_records.encode(originals)
            if evidence_digest not in self._associations:
                raise CustodyJournalError("finalization requires an existing complete evidence preparation")
            try:
                evidence_association, _ = self._read_association(evidence_digest)
                evidence, _ = self._load(evidence_digest)
                signer, _ = self._load(evidence_association.signer_digest)
                association, marker = finalization_associations.encode(
                    digest, evidence_digest, signer.digest)
                if (evidence.source_revision != association.source_revision
                        or signer.source_revision != association.source_revision):
                    raise CustodyJournalError("finalization association cannot cross retained source revisions")
                if digest in self._entries:
                    _, retained = self._load(digest)
                    if retained != encoded:
                        raise CustodyJournalError("finalization changed its exact retained originals")
                if digest in self._finalization_associations:
                    _, retained = self._read_finalization_association(digest)
                    if retained != marker:
                        raise CustodyJournalError("finalization cannot remap its original evidence preparation")
                    self._require_ready()
                    return digest
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            missing = int(digest not in self._entries)
            required_bytes = missing * len(encoded) + len(marker)
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims)
                    + missing > self._maximum_records
                    or len(self._file_identities) + missing + 1 > self._physical_limit()
                    or required_bytes > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal complete finalization retention capacity is exhausted")
            try:
                # This family reserves no legacy delivery markers. Re-read
                # the existing pair after publication before committing a link.
                self._append(digest, encoded)
                self._read_association(evidence_digest)
                self._load(evidence_digest)
                self._load(signer.digest)
                _finalization_association_scope(association, self._entries, self._associations)
                self._require_ready()
                self._publish("finalization-associated", digest, marker)
                self._used_bytes += len(marker)
                self._finalization_associations[digest] = association
                self._require_ready()
                return digest
            except BaseException:
                self._io.poison()
                raise

    def load_registration_finalization_preparation(self, finalization_digest):
        """Return (record, evidence locator, original pair), never replay authority."""
        digest = _digest(finalization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("local finalization preparation association is absent")
            try:
                association, _ = self._read_finalization_association(digest)
                finalization, _ = self._load(digest)
                evidence, _ = self._load(association.evidence_digest)
                signer, _ = self._load(association.signer_digest)
                self._require_ready()
                return finalization, association.evidence_digest, (evidence, signer)
            except BaseException:
                self._io.poison()
                raise

    def _completion_history_inventory(self, digest):
        """Resolve only the fixed original chain, without opening any body."""
        association = self._finalization_associations[digest]
        _finalization_association_scope(association, self._entries, self._associations)
        evidence = self._associations[association.evidence_digest]
        if (association.finalization_digest != digest
                or evidence.execution_digest != association.evidence_digest
                or evidence.signer_digest != association.signer_digest
                or len({digest, association.evidence_digest, association.signer_digest}) != 3):
            raise CustodyJournalError("completion history association locators differ")
        # Decoders and filenames are source-selected, never supplied by callers.
        selected = [
            (_name("finalization-associated", digest),
                finalization_associations.MAX_ASSOCIATION_BYTES, finalization_associations.decode),
            (_name("associated", association.evidence_digest),
                associations.MAX_ASSOCIATION_BYTES, associations.decode),
        ]
        for locator, family, selector, maximum, decoder in (
                (digest, finalization_records.FAMILY, finalization_records.OPERATION,
                    finalization_records.MAX_RECORD_BYTES, finalization_records.decode_prepared),
                (association.evidence_digest, execution_records.FAMILY, execution_records.OPERATION,
                    execution_records.MAX_RECORD_BYTES, execution_records.decode_prepared),
                (association.signer_digest, signer_records.FAMILY, signer_records.OPERATION,
                    signer_records.MAX_RECORD_BYTES, signer_records.decode_prepared)):
            entry = self._entries[locator]
            if ((entry.family, entry.selector, entry.source_revision)
                    != (family, selector, association.source_revision)
                    or entry.attempted or entry.observed
                    or _name("attempted", locator) in self._file_identities
                    or _name("observed", locator) in self._file_identities
                    or type(entry.prepared_bytes) is not int
                    or not 1 <= entry.prepared_bytes <= maximum):
                raise CustodyJournalError("completion history prepared metadata differs")
            selected.append((_name("prepared", locator), entry.prepared_bytes, decoder))
        reservation = self._finalization_reservations.get(digest)
        if reservation is not None:
            self._finalization_reservation_scope(digest, reservation)
            selected.append((_name("finalization-reserved", digest),
                finalization_reservations.MAX_RECORD_BYTES, finalization_reservations.decode))
        final_by_kind = self._finalization_outcomes.get(digest, {})
        evidence_by_kind = self._registration_outcomes.get(association.evidence_digest, {})
        self._finalization_outcome_scope(digest, final_by_kind)
        self._registration_outcome_scope(association.evidence_digest, evidence_by_kind)
        for kind in finalization_outcomes.KINDS:
            if kind in final_by_kind:
                selected.append((_name("finalization-" + kind, digest),
                    finalization_outcomes._maximum(kind), finalization_outcomes.decode))
        for kind in outcome_records.KINDS:
            if kind in evidence_by_kind:
                maximum = (outcome_records.MAX_CLAIM_BYTES if kind == "sql-claimed"
                    else outcome_records.MAX_RECORD_BYTES)
                selected.append((_name(kind, association.evidence_digest), maximum, outcome_records.decode))
        if not 5 <= len(selected) <= 15 or len({item[0] for item in selected}) != len(selected):
            raise CustodyJournalError("completion history fixed inventory differs")
        return association, evidence, tuple(selected)

    def _completion_history_metadata(self, name, maximum, identity, current):
        """Rejoin the exact retained name and inode without reading its body."""
        if (type(identity) is not tuple or len(identity) != 9
                or type(identity[6]) is not int or not 1 <= identity[6] <= maximum):
            raise CustodyJournalError("completion history retained size metadata differs")
        current()
        metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        current()
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1 or metadata.st_dev != self._binding[0]
                or (metadata.st_uid, metadata.st_gid) != self._binding[2:]
                or _identity(metadata) != identity
                or self._file_identities.get(name) != identity):
            raise CustodyJournalError("completion history retained file identity changed")

    def _read_completion_history_file(self, name, identity, current):
        """One precharged bounded read; never leave cleanup to an expired guard."""
        current()
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd)
        try:
            current()
            before = os.fstat(descriptor)
            current()
            if _identity(before) != identity:
                raise CustodyJournalError("completion history opened inode differs")
            size = identity[6]
            # Fixed-size allocation avoids bytearray growth beyond the admitted
            # representation. One chunk, this buffer and immutable conversion
            # fit within the three encoded-byte footprints preflighted below.
            encoded = bytearray(size)
            offset = 0
            while offset < size:
                current()
                chunk = os.read(descriptor, min(_READ_CHUNK, size - offset))
                current()
                if not chunk:
                    raise CustodyJournalError("completion history record was truncated")
                encoded[offset:offset + len(chunk)] = chunk
                offset += len(chunk)
                del chunk
            current()
            trailing = os.read(descriptor, 1)
            current()
            if trailing:
                raise CustodyJournalError("completion history record grew while reading")
            after = os.fstat(descriptor)
            current()
            if _identity(after) != identity:
                raise CustodyJournalError("completion history inode changed while reading")
            original = bytes(encoded)
            current()
        finally:
            os.close(descriptor)
        current()
        self._completion_history_metadata(name, identity[6], identity, current)
        return original

    def _completion_history_result(self, digest, association, evidence, loaded):
        """Repeat the old loaders' exact linkage checks using each body once."""
        if (loaded[_name("finalization-associated", digest)] != association
                or loaded[_name("associated", association.evidence_digest)] != evidence):
            raise CustodyJournalError("completion history associations changed after recovery")
        _finalization_association_scope(association, self._entries, self._associations)
        _association_scope(evidence, self._entries)
        prepared = []
        for locator in (digest, association.evidence_digest, association.signer_digest):
            record = loaded[_name("prepared", locator)]
            info = self._entries[locator]
            if (record.digest != locator
                    or (record.family, record.selector, record.source_revision)
                        != (info.family, info.selector, info.source_revision)
                    or info.attempted or info.observed):
                raise CustodyJournalError("completion history prepared originals changed")
            prepared.append(record)
        reservation = loaded.get(_name("finalization-reserved", digest))
        reservation_metadata = self._finalization_reservations.get(digest)
        if reservation_metadata is not None:
            self._finalization_reservation_scope(digest, reservation_metadata)
            if (reservation is None or reservation.finalization_digest != digest
                    or (reservation.source_revision, reservation.digest) != reservation_metadata):
                raise CustodyJournalError("completion history reservation originals changed")
        final_by_kind = self._finalization_outcomes.get(digest, {})
        evidence_by_kind = self._registration_outcomes.get(association.evidence_digest, {})
        self._finalization_outcome_scope(digest, final_by_kind)
        self._registration_outcome_scope(association.evidence_digest, evidence_by_kind)
        final = {}
        historical = {}
        for kind in finalization_outcomes.KINDS:
            if kind in final_by_kind:
                record = loaded[_name("finalization-" + kind, digest)]
                if ((record.source_revision, record.digest) != final_by_kind[kind]
                        or record.kind != kind or record.finalization_digest != digest):
                    raise CustodyJournalError("completion history finalization outcome changed")
                final[kind] = record
        for kind in outcome_records.KINDS:
            if kind in evidence_by_kind:
                record = loaded[_name(kind, association.evidence_digest)]
                if ((record.source_revision, record.digest) != evidence_by_kind[kind]
                        or record.kind != kind or record.local_digest != association.evidence_digest):
                    raise CustodyJournalError("completion history evidence outcome changed")
                historical[kind] = record
        for outcomes in (final, historical):
            if ("completion-reconciled" in outcomes
                    and outcomes["completion-outcome"].originals[0] != b"uncertain"):
                raise CustodyJournalError("completion history reconciliation lacks original uncertainty")
        return ((prepared[0], association.evidence_digest, (prepared[1], prepared[2])),
            reservation,
            finalization_outcomes.FinalizationOutcomes(association.source_revision, digest,
                final.get("sql-claimed"), final.get("sql-outcome"),
                final.get("completion-outcome"), final.get("completion-reconciled")),
            outcome_records.RegistrationOutcomes(evidence.source_revision, association.evidence_digest,
                historical.get("reservation"), historical.get("sql-claimed"),
                historical.get("sql-outcome"), historical.get("completion-outcome"),
                historical.get("completion-reconciled")))

    def load_registration_finalization_completion_history(self, finalization_digest, *,
            maximum_original_bytes, work, current):
        """Read one preflighted fixed chain; return originals, never authority.

        The remaining byte cap includes three encoded-byte footprints plus
        fixed bounded header/locator bookkeeping. The caller separately reserves
        already-held originals and later replay. This is not a Python heap bound.
        Invoke directly: this method charges the original work, and current must
        not reenter a loader or publish to the journal.
        """
        from serverware.authority_query_read_work import _ValidationWork

        digest = _digest(finalization_digest)
        _integer(maximum_original_bytes, minimum=1, maximum=_COMPLETION_HISTORY_MAX_BYTES,
            label="completion history remaining byte capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion history requires original work and current guard")
        work.charge(json_nodes=256)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("completion history requires its complete local preparation")
            try:
                association, evidence, selected = self._completion_history_inventory(digest)
                identities = tuple(self._file_identities.get(item[0]) for item in selected)
                for (name, maximum, _decoder), identity in zip(selected, identities):
                    self._completion_history_metadata(name, maximum, identity, current)
                    if name.startswith("prepared-") and identity[6] != maximum:
                        raise CustodyJournalError("completion history prepared size changed")
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            total = sum(identity[6] for identity in identities)
            footprint = 3 * total + _COMPLETION_HISTORY_FIXED_BYTES
            # A valid but oversized selection or exhausted work allowance is
            # refused before body1, without poisoning unchanged retained data.
            if footprint > maximum_original_bytes:
                raise CustodyJournalError("completion history exceeds remaining preallocation capacity")
            work.charge(input_bytes=3 * total + len(selected), hashes=len(selected) - 2)
            try:
                loaded = {}
                for (name, _maximum, decoder), identity in zip(selected, identities):
                    original = self._read_completion_history_file(name, identity, current)
                    current()
                    loaded[name] = decoder(original)
                    current()
                    del original
                result = self._completion_history_result(digest, association, evidence, loaded)
                for (name, maximum, _decoder), identity in zip(selected, identities):
                    self._completion_history_metadata(name, maximum, identity, current)
                self._require_ready()
                current()
                return result
            except BaseException:
                self._io.poison()
                raise

    def append_registration_finalization_reservation(self, finalization_digest, originals):
        """Retain one exact raw3 after the actual complete original association.

        The caller must authenticate the originals before calling this opaque
        store. Repeat identical bytes are idempotent; conflicts never replace
        earlier originals. No dispatch claim or remote currentness is implied.
        """
        digest = _digest(finalization_digest)
        held = finalization_reservations._originals(originals)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("finalization reservation requires a complete local preparation")
            try:
                current = self._read_finalization_reservation(digest)
                record, encoded = finalization_reservations.encode(digest, held,
                    source_revision=self._finalization_associations[digest].source_revision)
                if current is not None:
                    if current.originals != record.originals or current.digest != record.digest:
                        raise CustodyJournalError("finalization reservation cannot replace its first originals")
                    self._require_ready()
                    return current.digest
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            if (len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal finalization reservation capacity is exhausted")
            try:
                self._publish("finalization-reserved", digest, encoded)
                self._used_bytes += len(encoded)
                self._finalization_reservations[digest] = (record.source_revision, record.digest)
                retained = self._read_finalization_reservation(digest)
                if retained != record:
                    raise CustodyJournalError("finalization reservation publication differs from original")
                self._require_ready()
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def load_registration_finalization_reservation(self, finalization_digest):
        """Return opaque raw3 record, or None only under a complete original chain."""
        digest = _digest(finalization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("finalization reservation requires a complete local preparation")
            try:
                result = self._read_finalization_reservation(digest)
                self._require_ready()
                return result
            except BaseException:
                self._io.poison()
                raise

    def _append_finalization_outcome(self, finalization_digest, kind, originals):
        digest = _digest(finalization_digest)
        held = finalization_outcomes._originals(finalization_outcomes._profile(kind), originals)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("finalization SQL outcome requires a complete local preparation")
            by_kind = self._finalization_outcomes.get(digest, {})
            if kind == "sql-claimed" and kind in by_kind:
                raise CustodyJournalError("finalization SQL dispatch was already claimed; repeat is forbidden")
            try:
                current = self._read_finalization_outcomes(digest)
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            if digest not in self._finalization_reservations:
                raise CustodyJournalError("finalization SQL dispatch requires retained reservation originals")
            if kind != "sql-claimed" and current.sql_attempt is None:
                raise CustodyJournalError("finalization outcome requires an irreversible local SQL claim")
            if (kind == "completion-reconciled" and (current.completion_outcome is None
                    or current.completion_outcome.originals[0] != b"uncertain")):
                raise CustodyJournalError("finalization reconciliation requires retained original uncertainty")
            record, encoded = finalization_outcomes.encode(kind, digest, held,
                source_revision=current.source_revision)
            if kind in by_kind:
                existing = {"sql-outcome": current.sql_outcome,
                    "completion-outcome": current.completion_outcome,
                    "completion-reconciled": current.completion_reconciled}[kind]
                if (existing.originals != record.originals or existing.digest != record.digest):
                    self._io.poison()
                    raise CustodyJournalError("finalization SQL outcome cannot replace its first exact originals")
                self._require_ready()
                return existing.digest
            if (len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal finalization SQL outcome capacity is exhausted")
            try:
                self._require_ready()
                self._publish("finalization-" + kind, digest, encoded)
                self._used_bytes += len(encoded)
                self._finalization_outcomes.setdefault(digest, {})[kind] = (
                    record.source_revision, record.digest)
                self._finalization_outcome_scope(digest, self._finalization_outcomes[digest])
                self._require_ready()
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def claim_registration_finalization_sql_attempt(self, finalization_digest):
        """Fsync a nonrepeatable local claim after the exact retained reservation.

        The caller owns permission and original admission before any send.
        Neither missing responses nor publication uncertainty clear this claim.
        """
        self._append_finalization_outcome(finalization_digest, "sql-claimed", ())

    def append_registration_finalization_sql_outcome(self, finalization_digest, originals):
        """Retain first bounded unsigned raw4, even if late or semantically rejected.

        Storage has no invocation clock or successful-admission prerequisite.
        Owner/PID, complete original linkage, claim and journal guards still
        apply. An exact repeat is idempotent; a conflict cannot replace it.
        """
        return self._append_finalization_outcome(finalization_digest, "sql-outcome", originals)

    def append_registration_finalization_completion_outcome(self, finalization_digest, originals):
        """Retain first bounded completion raw4, not signature admission.

        A SQL claim and the complete original/reservation chain are required;
        an unsigned SQL outcome need not have been received. Exact repeats are
        idempotent. Uncertainty is never overwritten or treated as permission.
        """
        return self._append_finalization_outcome(finalization_digest, "completion-outcome", originals)

    def append_registration_finalization_completion_reconciliation(self, finalization_digest, originals):
        """Retain acknowledged raw4 separately after prior completion uncertainty.

        The caller must genuinely authenticate that acknowledgment first.
        Storage admits only bounded opaque bytes and prerequisite relationships.
        """
        return self._append_finalization_outcome(finalization_digest, "completion-reconciled", originals)

    def load_registration_finalization_outcomes(self, finalization_digest):
        """Return ordinary local history, never remote success or retry permission."""
        digest = _digest(finalization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._finalization_associations:
                raise CustodyJournalError("finalization SQL outcomes require a complete local preparation")
            try:
                result = self._read_finalization_outcomes(digest)
                self._require_ready()
                return result
            except BaseException:
                self._io.poison()
                raise

    def _append_registration_outcome(self, local_digest, kind, originals):
        digest = _digest(local_digest)
        held = outcome_records._originals(outcome_records._profile(kind), originals)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._associations:
                raise CustodyJournalError("registration outcome requires a complete local preparation")
            by_kind = self._registration_outcomes.get(digest, {})
            if kind == "sql-claimed" and kind in by_kind:
                raise CustodyJournalError("registration SQL dispatch was already claimed; repeat is forbidden")
            try:
                current = self._read_registration_outcomes(digest)
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            if kind == "sql-claimed" and current.reservation is None:
                raise CustodyJournalError("registration SQL dispatch requires retained reservation originals")
            if kind in ("sql-outcome", "completion-outcome", "completion-reconciled") and current.sql_attempt is None:
                raise CustodyJournalError("registration outcome requires an irreversible local SQL claim")
            if (kind == "completion-reconciled" and (current.completion_outcome is None
                    or current.completion_outcome.originals[0] != b"uncertain")):
                raise CustodyJournalError("registration reconciliation requires retained original uncertainty")
            record, encoded = outcome_records.encode(kind, digest, held,
                source_revision=current.source_revision)
            if kind in by_kind:
                existing = {"reservation": current.reservation, "sql-outcome": current.sql_outcome,
                    "completion-outcome": current.completion_outcome,
                    "completion-reconciled": current.completion_reconciled}[kind]
                if (existing.originals != record.originals or existing.digest != record.digest):
                    self._io.poison()
                    raise CustodyJournalError("registration outcome cannot replace its first exact originals")
                self._require_ready()
                return existing.digest
            if (len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal registration outcome capacity is exhausted")
            try:
                self._require_ready()
                self._publish(kind, digest, encoded)
                self._used_bytes += len(encoded)
                self._registration_outcomes.setdefault(digest, {})[kind] = (
                    record.source_revision, record.digest)
                self._registration_outcome_scope(digest, self._registration_outcomes[digest])
                self._require_ready()
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def append_registration_reservation(self, local_digest, originals):
        """Retain exact raw3 under a complete preparation, not a verified reserve."""
        return self._append_registration_outcome(local_digest, "reservation", originals)

    def claim_registration_sql_attempt(self, local_digest):
        """Durably burn one local dispatch before send; never clear or repeat it.

        A retained preparation and reservation are required, but neither their
        presence nor this marker supplies permission to execute SQL. The caller
        owns genuine original admission. Publication uncertainty is not retry
        permission, and absence of a response does not establish nonexecution.
        """
        self._append_registration_outcome(local_digest, "sql-claimed", ())

    def append_registration_sql_outcome(self, local_digest, originals):
        """Retain the first exact raw4 response; its label is not authentication."""
        return self._append_registration_outcome(local_digest, "sql-outcome", originals)

    def append_registration_completion_outcome(self, local_digest, originals):
        """Retain the first raw4, including uncertainty; never upgrade/overwrite.

        A later acknowledged response belongs in the separate reconciliation
        slot. This storage cannot replace an earlier response.
        """
        return self._append_registration_outcome(local_digest, "completion-outcome", originals)

    def append_registration_completion_reconciliation(self, local_digest, originals):
        """Retain one separate acknowledged raw4 after immutable uncertainty.

        This carrier check is not signature or outcome authentication. The
        recovery facade must genuinely verify all originals before append.
        Conflicts poison the journal; no record or SQL claim is overwritten.
        """
        return self._append_registration_outcome(local_digest, "completion-reconciled", originals)

    def load_registration_outcomes(self, local_digest):
        """Return opaque originals/IDs after rereading the exact associated pair.

        No returned record is a proof, action token, live head, renewed lifetime
        or permission to retry. Missing responses leave remote outcome unknown.
        """
        digest = _digest(local_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._associations:
                raise CustodyJournalError("registration outcomes require a complete local preparation")
            try:
                result = self._read_registration_outcomes(digest)
                self._require_ready()
                return result
            except BaseException:
                self._io.poison()
                raise

    def load(self, localdigest):
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._entries:
                raise CustodyJournalError("local prepared record is absent")
            try:
                record, _ = self._load(digest)
                self._require_ready()
                return record
            except BaseException:
                self._io.poison()
                raise

    def claim_oidc_session_activation_release(self, *, client_authorization_digest,
            request_identity, profile, server_bootstrap_digest, expected_outcome_digest):
        """Burn this exact root client authorization before any private exchange.

        The caller owns genuine original admission and current work metering.
        No received frames or secret tokens are retained. Fresh root issuance,
        never this marker, is required for another authorized exchange.
        """
        record, encoded = release_attempts.encode(
            client_authorization_digest=client_authorization_digest,
            request_identity=request_identity, profile=profile,
            server_bootstrap_digest=server_bootstrap_digest,
            expected_outcome_digest=expected_outcome_digest)
        digest = record.client_authorization_digest
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest in self._release_attempts:
                # A duplicate never succeeds, even if all metadata is exact.
                # Recheck the retained identity without interpreting old source
                # metadata as current authority or rewriting the claim.
                try:
                    name = _name(release_attempts.KIND, digest)
                    retained, identity = self._read_file(name,
                        maximum_bytes=release_attempts.MAX_RECORD_BYTES)
                    if (identity != self._file_identities.get(name)
                            or release_attempts.decode(retained) != self._release_attempts[digest]):
                        raise CustodyJournalError("release claim changed after admitted recovery")
                    self._require_ready()
                except BaseException:
                    self._io.poison()
                    raise
                raise CustodyJournalError("release client authorization was already claimed; repeat is forbidden")
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal release claim capacity is exhausted")
            try:
                self._require_ready()
                self._publish(release_attempts.KIND, digest, encoded)
                self._used_bytes += len(encoded)
                self._release_attempts[digest] = record
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise

    def claim_oidc_session_activation_completion_recovery_release_attempt(self, *,
            client_authorization_digest, request_identity, profile, server_bootstrap_digest,
            expected_outcome_digest, work, current, maximum_original_bytes=None):
        """Guarded LIVE dispatch claim in the unchanged global authorization slot."""
        from serverware.authority_query_read_work import _ValidationWork

        scalars = tuple(_digest(value) for value in (client_authorization_digest,
            request_identity, server_bootstrap_digest, expected_outcome_digest))
        if type(profile) is not str or profile != release_attempts.LIVE_PROFILE:
            raise CustodyJournalError("completion release dispatch admits only independently authorized LIVE")
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion release dispatch remaining capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion release dispatch requires original work and resource guard")
        current()
        self._require_process()
        digest = scalars[0]
        with self._io.ready():
            self._require_ready()
            existing = self._release_attempts.get(digest)
            if existing is not None:
                name = _name(release_attempts.KIND, digest)
                identity = self._file_identities.get(name)
                try:
                    self._completion_history_metadata(name, release_attempts.MAX_RECORD_BYTES, identity, current)
                except BaseException:
                    self._io.poison()
                    raise
                if 3 * identity[6] + consume_records.COMPLETION_RECOVERY_METADATA_BYTES > maximum:
                    raise CustodyJournalError("existing release claim exceeds remaining preallocation capacity")
                work.charge(input_bytes=3 * identity[6] + 1, hashes=16, json_nodes=512)
                try:
                    retained = self._read_completion_history_file(name, identity, current)
                    if release_attempts.decode(retained) != existing:
                        raise CustodyJournalError("global release attempt changed after admission")
                    self._require_ready()
                    current()
                except BaseException:
                    self._io.poison()
                    raise
                raise CustodyJournalError("release client authorization was already claimed; repeat is forbidden")
            if release_attempts.MAX_CLAIM_IO_BYTES + consume_records.COMPLETION_RECOVERY_METADATA_BYTES > maximum:
                raise CustodyJournalError("release dispatch claim exceeds remaining preallocation capacity")
            scans = 3 * (len(self._file_identities) + 1)
            work.charge(input_bytes=release_attempts.MAX_CLAIM_IO_BYTES + scans * 512,
                hashes=16, json_nodes=512 + scans * 16)
            record, encoded = release_attempts.encode(client_authorization_digest=scalars[0],
                request_identity=scalars[1], profile=profile, server_bootstrap_digest=scalars[2],
                expected_outcome_digest=scalars[3])
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal release dispatch claim capacity is exhausted")
            try:
                self._publish_guarded_completion_name(_name(release_attempts.KIND, digest), encoded, current)
                self._used_bytes += len(encoded)
                self._release_attempts[digest] = record
                self._require_ready()
                current()
                return digest
            except BaseException:
                self._io.poison()
                raise

    def _activation_scope(self, digest, by_kind):
        claim = self._activation_dispatch_attempts.get(digest)
        if claim is None:
            raise CustodyJournalError("activation stage lacks its irreversible target claim")
        if (len(by_kind) > len(activation_records.KINDS)
                or set(by_kind) != set(activation_records.KINDS[:len(by_kind)])
                or any(value[0] != claim.source_revision for value in by_kind.values())):
            raise CustodyJournalError("activation stages differ from their fixed prefix or claim source")
        return claim

    def _read_activation_claim(self, digest):
        held = self._activation_dispatch_attempts.get(digest)
        if held is None:
            raise CustodyJournalError("activation target has no original dispatch claim")
        name = _name(activation_attempts.KIND, digest)
        original, identity = self._read_file(name,
            maximum_bytes=activation_attempts.MAX_RECORD_BYTES)
        if (identity != self._file_identities.get(name)
                or activation_attempts.decode(original) != held):
            raise CustodyJournalError("activation target claim changed after admission")
        return held

    def _activation_metadata_current(self, digest, by_kind):
        """Check immutable predecessor identities without rereading large bodies."""
        self._activation_scope(digest, by_kind)
        for kind in activation_records.KINDS:
            if kind not in by_kind:
                continue
            name = _name("activation-" + kind, digest)
            metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
            if _identity(metadata) != self._file_identities.get(name):
                raise CustodyJournalError("activation stage immutable identity changed")

    def _read_activation_record(self, digest, kind, *, maximum_bytes):
        metadata = self._activation_records[digest][kind]
        name = _name("activation-" + kind, digest)
        original, identity = self._read_file(name, maximum_bytes=maximum_bytes)
        record = activation_records.decode(original)
        if (identity != self._file_identities.get(name)
                or record.finalization_digest != digest or record.kind != kind
                or (record.source_revision, record.digest, len(original)) != metadata):
            raise CustodyJournalError("activation stage changed after admitted recovery")
        return record

    def _append_activation_record(self, finalization_digest, kind, originals):
        digest = _digest(finalization_digest)
        profile = activation_records._profile(kind)
        held = activation_records._originals(profile, originals)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._activation_live_claims:
                raise CustodyJournalError("recovered activation claims are read-only; continuation is forbidden")
            by_kind = self._activation_records.get(digest, {})
            if kind == "sql-claimed" and kind in by_kind:
                raise CustodyJournalError("activation SQL dispatch was already claimed; repeat is forbidden")
            try:
                claim = self._read_activation_claim(digest)
                self._activation_metadata_current(digest, by_kind)
                record, encoded = activation_records.encode(kind, digest, held,
                    source_revision=claim.source_revision)
                if kind in by_kind:
                    # A shorter/different new carrier cannot cause an uncharged
                    # read of a larger retained original.
                    existing = self._read_activation_record(digest, kind,
                        maximum_bytes=len(encoded))
                    if existing.originals != record.originals or existing.digest != record.digest:
                        raise CustodyJournalError("activation cannot replace its first exact stage originals")
                    self._require_ready()
                    return existing.digest
                if profile != len(by_kind):
                    raise CustodyJournalError("activation stage publication skipped its fixed predecessor")
                if (len(self._file_identities) >= self._physical_limit()
                        or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                    raise CustodyJournalError("journal activation stage capacity is exhausted")
                self._require_ready()
                self._publish("activation-" + kind, digest, encoded)
                self._used_bytes += len(encoded)
                self._activation_records.setdefault(digest, {})[kind] = (
                    record.source_revision, record.digest, len(encoded))
                self._activation_scope(digest, self._activation_records[digest])
                self._require_ready()
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def append_oidc_session_activation_preparation(self, finalization_digest, originals):
        """Retain raw5 before the grant socket; this supplies no permission."""
        return self._append_activation_record(finalization_digest, "prepared", originals)

    def append_oidc_session_activation_grant(self, finalization_digest, originals):
        """Retain raw1 before reservation; genuine grant admission is external."""
        return self._append_activation_record(finalization_digest, "grant", originals)

    def append_oidc_session_activation_reservation(self, finalization_digest, originals):
        """Retain exact raw3 before the one-use SQL dispatch claim."""
        return self._append_activation_record(finalization_digest, "reserved", originals)

    def claim_oidc_session_activation_sql_attempt(self, finalization_digest):
        """Irreversibly burn SQL dispatch, even for an identical same-owner call."""
        self._append_activation_record(finalization_digest, "sql-claimed", ())

    def append_oidc_session_activation_sql_outcome(self, finalization_digest, originals):
        """Retain unsigned raw4 before interpreting it; never a commit proof."""
        return self._append_activation_record(finalization_digest, "sql-outcome", originals)

    def append_oidc_session_activation_completion_outcome(self, finalization_digest, originals):
        """Retain exact unverified raw4 before completion admission; no resend."""
        return self._append_activation_record(finalization_digest, "completion-outcome", originals)

    def load_oidc_session_activation_records(self, finalization_digest):
        """Read bounded historical originals without permitting any new effect."""
        digest = _digest(finalization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                claim = self._read_activation_claim(digest)
                by_kind = self._activation_records.get(digest, {})
                self._activation_metadata_current(digest, by_kind)
                retained = tuple(self._read_activation_record(digest, kind,
                    maximum_bytes=activation_records._maximum(kind)) if kind in by_kind else None
                    for kind in activation_records.KINDS)
                self._require_ready()
                return activation_records.ActivationRecords(claim.source_revision, digest, *retained)
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_completion_recovery_target(self, finalization_digest, *,
            work, current, maximum_original_bytes=None):
        """Select claim/prepared DATA under a remaining representation cap.

        Three actual encoded-byte footprints plus fixed metadata are reserved
        before either body. The caller reserves its held and later-admission
        graphs separately. This directly charges work; current must not reenter
        selection or acquire this journal's I/O lock.
        """
        from serverware.authority_query_read_work import _ValidationWork

        target = _digest(finalization_digest)
        maximum = (_COMPLETION_RECOVERY_TARGET_MAX_BYTES if maximum_original_bytes is None
            else maximum_original_bytes)
        _integer(maximum, minimum=0, maximum=_COMPLETION_RECOVERY_TARGET_MAX_BYTES,
            label="completion recovery target remaining byte capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion recovery target requires original work and guard")
        work.charge(json_nodes=128)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            claim = self._activation_dispatch_attempts.get(target)
            by_kind = self._activation_records.get(target, {})
            claim_name = _name(activation_attempts.KIND, target)
            try:
                # Resolve only source-fixed index entries. Even an incomplete
                # prefix must retain its known metadata; no directory scan or
                # unsigned SQL/completion body participates in selection.
                if type(by_kind) is not dict:
                    raise CustodyJournalError("completion recovery target prefix metadata differs")
                for kind in activation_records.KINDS:
                    if ((_name("activation-" + kind, target) in self._file_identities)
                            != (kind in by_kind)):
                        raise CustodyJournalError("completion recovery target file index differs")
                if claim is None:
                    if by_kind or claim_name in self._file_identities:
                        raise CustodyJournalError("completion recovery target lacks its retained claim")
                else:
                    if (type(claim) is not activation_attempts.ActivationDispatchAttemptRecord
                            or claim.finalization_digest != target):
                        raise CustodyJournalError("completion recovery target claim association differs")
                    self._activation_scope(target, by_kind)
                    self._completion_history_metadata(claim_name, activation_attempts.MAX_RECORD_BYTES,
                        self._file_identities.get(claim_name), current)
                    for kind in activation_records.KINDS:
                        if kind not in by_kind:
                            continue
                        name = _name("activation-" + kind, target)
                        identity = self._file_identities.get(name)
                        self._completion_history_metadata(name, activation_records._maximum(kind),
                            identity, current)
                        metadata = by_kind[kind]
                        if (type(metadata) is not tuple or len(metadata) != 3
                                or type(metadata[2]) is not int or metadata[2] != identity[6]):
                            raise CustodyJournalError("completion recovery target retained size changed")
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            if claim is None or "prepared" not in by_kind:
                # Expected absence is unavailable, never evidence of no SQL
                # effect and never a reason to poison otherwise valid storage.
                self._require_ready()
                current()
                return None
            names = claim_name, _name("activation-prepared", target)
            identities = tuple(self._file_identities[name] for name in names)
            sizes = tuple(identity[6] for identity in identities)
            footprint = 3 * sum(sizes) + _COMPLETION_RECOVERY_TARGET_FIXED_BYTES
            if footprint > maximum:
                raise CustodyJournalError("completion recovery target exceeds remaining preallocation capacity")
            work.charge(input_bytes=3 * sum(sizes) + len(sizes), hashes=2)
            try:
                loaded = []
                for name, identity, decoder in zip(names, identities,
                        (activation_attempts.decode, activation_records.decode)):
                    original = self._read_completion_history_file(name, identity, current)
                    current()
                    loaded.append(decoder(original))
                    current()
                    del original
                activation, prepared = loaded
                if (activation != claim or prepared.finalization_digest != target
                        or prepared.kind != "prepared" or len(prepared.originals) != 5
                        or prepared.source_revision != activation.source_revision
                        or (prepared.source_revision, prepared.digest, sizes[1]) != by_kind["prepared"]):
                    raise CustodyJournalError("completion recovery target original association changed")
                self._activation_scope(target, by_kind)
                self._completion_history_metadata(claim_name, sizes[0], identities[0], current)
                for kind in activation_records.KINDS:
                    if kind in by_kind:
                        name = _name("activation-" + kind, target)
                        self._completion_history_metadata(name, activation_records._maximum(kind),
                            self._file_identities.get(name), current)
                self._require_ready()
                current()
                return activation, prepared
            except BaseException:
                self._io.poison()
                raise

    def claim_oidc_session_activation_dispatch(self, *, finalization_digest,
            request_binding_digest, authorization_enrollment_digest, source_revision):
        """Burn the retained target before planning, never admit its authority.

        The actual caller has already authenticated retained ownership and
        fresh permission on its original work/window. This metadata-only
        operation does not replay originals or establish an execution result.
        """
        record, encoded = activation_attempts.encode(finalization_digest=finalization_digest,
            request_binding_digest=request_binding_digest,
            authorization_enrollment_digest=authorization_enrollment_digest,
            source_revision=source_revision)
        digest = record.finalization_digest
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest in self._activation_dispatch_attempts:
                try:
                    name = _name(activation_attempts.KIND, digest)
                    retained, identity = self._read_file(name,
                        maximum_bytes=activation_attempts.MAX_RECORD_BYTES)
                    if (identity != self._file_identities.get(name)
                            or activation_attempts.decode(retained)
                                != self._activation_dispatch_attempts[digest]):
                        raise CustodyJournalError("activation claim changed after admitted recovery")
                    self._require_ready()
                except BaseException:
                    self._io.poison()
                    raise
                raise CustodyJournalError("activation target was already claimed; repeat dispatch is forbidden")
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal activation claim capacity is exhausted")
            try:
                self._require_ready()
                # _publish performs no-replace publication, normal close,
                # synchronization and exact original-byte readback first.
                self._publish(activation_attempts.KIND, digest, encoded)
                self._used_bytes += len(encoded)
                self._activation_dispatch_attempts[digest] = record
                self._require_ready()
                self._activation_live_claims.add(digest)
            except BaseException:
                self._io.poison()
                raise

    def _consume_scope(self, slot, by_kind):
        claim = self._consume_claims.get(slot)
        if (claim is None or claim.slot_digest != slot
                or self._consume_targets.get(claim.finalization_digest) != slot):
            raise CustodyJournalError("consume response lacks its irreversible target claim")
        activation = self._activation_records.get(claim.finalization_digest, {})
        predecessor = self._activation_scope(claim.finalization_digest, activation)
        # Optional acquisition responses use appended codec indices, preserving
        # old domains and the unchanged ordered stage prefix.
        stages = set(by_kind) - {"inputs", "release-proof-setup", "release-grants-claimed"}
        normal_prefix = stages == set(consume_records.KINDS[1:1 + len(stages)])
        # A separate immutable consume completion response may precede the
        # existing release suffix without filling or replacing uncertain or
        # missing original SQL/completion/hints records. This is an association
        # only: callers must freshly authenticate the exact response originals.
        recovery_prefix = False
        if not normal_prefix and "release-intent-claimed" in stages:
            base = stages & set(consume_records.KINDS[1:10])
            suffix = stages & set(consume_records.KINDS[10:15])
            recovery_slot = completion_recovery._slot_digest(claim.finalization_digest, "consume")
            recovered = self._completion_recovery_claims.get(recovery_slot)
            response = self._completion_recovery_responses.get(recovery_slot)
            prior = by_kind.get("completion-outcome")
            recovery_prefix = (
                6 <= len(base) <= 9 and base == set(consume_records.KINDS[1:1 + len(base)])
                and suffix == set(consume_records.KINDS[10:10 + len(suffix)])
                and stages == base | suffix
                and type(recovered) is completion_recovery.CompletionRecoveryRecord
                and recovered.kind == "claimed" and recovered.originals == ()
                and recovered.slot_digest == recovery_slot
                and recovered.finalization_digest == claim.finalization_digest and recovered.phase == "consume"
                and recovered.source_revision == claim.source_revision
                and (None if prior is None else prior[1]) == recovered.predecessor_completion_digest
                and type(response) is tuple and len(response) == 9
                and response[0] == recovered.source_revision
                and response[3:] == (claim.finalization_digest, "consume", recovered.authorization_digest,
                    recovered.packet_digest, recovered.recovery_configuration_digest,
                    recovered.predecessor_completion_digest))
        if ("completion-outcome" not in activation
                or predecessor.source_revision != claim.source_revision
                or len(by_kind) > len(consume_records.KINDS) - 1
                or not (normal_prefix or recovery_prefix)
                or ("release-proof-setup" in by_kind and "release-proof-claimed" not in by_kind)
                or ("release-grants-claimed" in by_kind and "release-proof" not in by_kind)
                or any(value[0] != claim.source_revision for value in by_kind.values())
                or ("exported" in by_kind and by_kind["prepared"][3] != b"prepared")
                or ("authorized" in by_kind and by_kind["exported"][3] != b"exported")):
            raise CustodyJournalError("consume stages differ from completed predecessor, prefix or source")
        return claim

    def _read_consume_claim(self, slot):
        held = self._consume_claims.get(slot)
        if held is None:
            raise CustodyJournalError("consume target has no original claim")
        name = _name("activation-consume-claimed", slot)
        original, identity = self._read_file(name, maximum_bytes=consume_records.MAX_CLAIM_BYTES)
        if (identity != self._file_identities.get(name)
                or consume_records.decode(original) != held):
            raise CustodyJournalError("consume claim changed after admission")
        return held

    def _consume_metadata_current(self, slot, by_kind):
        claim = self._consume_scope(slot, by_kind)
        self._activation_metadata_current(claim.finalization_digest,
            self._activation_records.get(claim.finalization_digest, {}))
        for kind in consume_records.KINDS[1:]:
            if kind in by_kind:
                name = _name("activation-consume-" + kind, slot)
                metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
                if _identity(metadata) != self._file_identities.get(name):
                    raise CustodyJournalError("consume response immutable identity changed")

    def _read_consume_record(self, slot, kind, *, maximum_bytes):
        claim = self._consume_claims[slot]
        metadata = self._consume_records[slot][kind]
        name = _name("activation-consume-" + kind, slot)
        original, identity = self._read_file(name, maximum_bytes=maximum_bytes)
        record = consume_records.decode(original)
        if (identity != self._file_identities.get(name) or record.slot_digest != slot
                or record.finalization_digest != claim.finalization_digest
                or record.activation_authorization_digest != claim.activation_authorization_digest
                or record.kind != kind
                or (record.source_revision, record.digest, len(original),
                    record.originals[0] if kind in ("prepared", "exported", "sql-outcome") else b"") != metadata):
            raise CustodyJournalError("consume response changed after admitted recovery")
        return record

    def claim_oidc_session_activation_consume_planning(self, *, finalization_digest,
            activation_authorization_digest, source_revision):
        """Burn preparation once, independent of plan identity; never admit authority."""
        record, encoded = consume_records.encode("claimed", finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            originals=(), source_revision=source_revision)
        target, slot = record.finalization_digest, record.slot_digest
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if target not in self._activation_live_claims:
                raise CustodyJournalError("consume preparation requires this owner's live activation claim")
            try:
                predecessor = self._read_activation_claim(target)
                activation = self._activation_records.get(target, {})
                self._activation_metadata_current(target, activation)
                if ("completion-outcome" not in activation
                        or predecessor.source_revision != record.source_revision):
                    raise CustodyJournalError("consume claim lacks its retained completion and current source")
                previous = self._consume_targets.get(target)
                if previous is not None:
                    self._read_consume_claim(previous)
                    self._consume_metadata_current(previous, self._consume_records.get(previous, {}))
                    self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            if previous is not None:
                raise CustodyJournalError("consume target was already claimed; preparation cannot repeat")
            if (len(self._entries) + len(self._release_attempts)
                    + len(self._activation_dispatch_attempts) + len(self._consume_claims)
                    + len(self._recovery_grant_claims) + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal consume claim capacity is exhausted")
            try:
                self._require_ready()
                self._publish("activation-consume-claimed", slot, encoded)
                self._used_bytes += len(encoded)
                self._consume_claims[slot] = record
                self._consume_targets[target] = slot
                self._consume_scope(slot, {})
                self._require_ready()
                self._consume_live_claims.add(slot)
                return slot
            except BaseException:
                self._io.poison()
                raise

    def _append_consume_record(self, *, finalization_digest,
            activation_authorization_digest, kind, originals):
        profile = consume_records._profile(kind)
        if profile == 0:
            raise CustodyJournalError("consume claim has a separate non-repeatable API")
        held = consume_records._originals(profile, originals)
        target = _digest(finalization_digest)
        authorization_digest = _digest(activation_authorization_digest)
        slot = consume_records._slot_digest(target, authorization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot not in self._consume_live_claims or target not in self._activation_live_claims:
                raise CustodyJournalError("recovered consume claims are read-only; continuation is forbidden")
            by_kind = self._consume_records.get(slot, {})
            if kind in ("sql-claimed", "release-intent-claimed", "release-proof-claimed") and kind in by_kind:
                raise CustodyJournalError("consume one-use operation was already claimed; repeat is forbidden")
            try:
                self._read_activation_claim(target)
                claim = self._read_consume_claim(slot)
                self._consume_metadata_current(slot, by_kind)
                if (claim.finalization_digest != target
                        or claim.activation_authorization_digest != authorization_digest):
                    raise CustodyJournalError("consume response target differs from its claim")
                record, encoded = consume_records.encode(kind, finalization_digest=target,
                    activation_authorization_digest=authorization_digest, originals=held,
                    source_revision=claim.source_revision)
                if kind in by_kind:
                    existing = self._read_consume_record(slot, kind, maximum_bytes=len(encoded))
                    if existing.originals != record.originals or existing.digest != record.digest:
                        raise CustodyJournalError("consume cannot replace first exact response originals")
                    self._require_ready()
                    return existing.digest
                stages = set(by_kind) - {"inputs", "release-proof-setup", "release-grants-claimed"}
                if ((kind == "inputs" and by_kind)
                        or (kind == "release-proof-setup" and stages != set(consume_records.KINDS[1:13]))
                        or (kind not in ("inputs", "release-proof-setup") and profile != len(stages) + 1)
                        or (kind == "exported" and by_kind["prepared"][3] != b"prepared")
                        or (kind == "authorized" and by_kind["exported"][3] != b"exported")):
                    raise CustodyJournalError("consume publication skipped its fixed successful predecessor")
                if (len(self._file_identities) >= self._physical_limit()
                        or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                    raise CustodyJournalError("journal consume response capacity is exhausted")
                self._require_ready()
                self._publish("activation-consume-" + kind, slot, encoded)
                self._used_bytes += len(encoded)
                self._consume_records.setdefault(slot, {})[kind] = (
                    record.source_revision, record.digest, len(encoded),
                    record.originals[0] if kind in ("prepared", "exported", "sql-outcome") else b"")
                self._consume_scope(slot, self._consume_records[slot])
                self._require_ready()
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def append_oidc_session_activation_consume_prepared(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain raw6 before interpretation; the caller verifies before export."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="prepared", originals=originals)

    def append_oidc_session_activation_consume_exported(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain raw7 before interpretation, with no permission to resend."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="exported", originals=originals)

    def append_oidc_session_activation_consume_authorized(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the first signed caller raw1, never repeat-signing or grant authority."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="authorized", originals=originals)

    def append_oidc_session_activation_consume_grant(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain raw1 before grant interpretation; no replay or reservation authority."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="grant", originals=originals)

    def append_oidc_session_activation_consume_reservation(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain exact signed reserve/snapshot/ACK before interpretation and SQL."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="reserved", originals=originals)

    def claim_oidc_session_activation_consume_sql_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Durably burn SQL once, even for an identical same-owner repeat."""
        self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="sql-claimed", originals=())

    def append_oidc_session_activation_consume_sql_outcome(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain unsigned raw4 before interpretation; never a commit or retry proof."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="sql-outcome", originals=originals)

    def append_oidc_session_activation_consume_completion_outcome(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain exact raw4 after SQL history; no completion or retry authority."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="completion-outcome", originals=originals)

    def append_oidc_session_activation_consume_completion_hints(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain opaque unsigned raw2 after raw4, before any hint interpretation."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="completion-hints", originals=originals)

    def claim_oidc_session_activation_consume_release_intent_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Burn intent production before signing; identical and recovered claims deny."""
        self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-intent-claimed", originals=())

    def append_oidc_session_activation_consume_release_intent(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the first signed raw1; never proof admission or repeat signing."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-intent", originals=originals)

    def claim_oidc_session_activation_consume_release_proof_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Burn proof acquisition before I/O; neither restart nor same-owner repeat is allowed."""
        self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof-claimed", originals=())

    def append_oidc_session_activation_consume_release_proof(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain bounded opaque raw4 before status, custody or proof admission."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof", originals=originals)

    def append_oidc_session_activation_consume_release_grants(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain opaque client/server originals; storage is not release authority."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-grants", originals=originals)

    def append_oidc_session_activation_consume_inputs(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain opaque raw2 after the claim and before any prepare record."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="inputs", originals=originals)

    def append_oidc_session_activation_consume_release_proof_setup(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain opaque raw1 after proof claim and before proof, never authorize retry."""
        return self._append_consume_record(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof-setup", originals=originals)

    def load_oidc_session_activation_consume_records(self, *, finalization_digest,
            activation_authorization_digest):
        """Read original history only; never restore a live continuation allowance."""
        target = _digest(finalization_digest)
        authorization_digest = _digest(activation_authorization_digest)
        slot = consume_records._slot_digest(target, authorization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                self._read_activation_claim(target)
                claim = self._read_consume_claim(slot)
                if (claim.finalization_digest != target
                        or claim.activation_authorization_digest != authorization_digest):
                    raise CustodyJournalError("consume history target differs from its original claim")
                by_kind = self._consume_records.get(slot, {})
                self._consume_metadata_current(slot, by_kind)
                retained = tuple(self._read_consume_record(slot, kind,
                    maximum_bytes=consume_records._maximum(kind)) if kind in by_kind else None
                    for kind in consume_records.KINDS[1:])
                self._require_ready()
                return consume_records.ConsumeRecords(claim, *retained)
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_recovery_target(self, finalization_digest, *, work, current):
        """Read only the two original claims and target intent, never authority.

        The guard must be the original owner-scope guard, not a callback that
        reenters selection or acquires this journal's I/O lock. Unlike a stable
        native callback, this fixed method charges the supplied work directly.
        """
        from serverware.authority_query_read_work import _ValidationWork

        target = _digest(finalization_digest)
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("recovery selection requires the original work and guard")
        work.charge(json_nodes=128)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            # This index is populated only by admitted recovery or a successful
            # first claim. There is no filesystem scan or caller-selected slot.
            slot = self._consume_targets.get(target)
            if slot is None:
                current()
                self._require_ready()
                return None
            try:
                claim = self._consume_claims.get(slot)
                by_kind = self._consume_records.get(slot, {})
                if (type(claim) is not consume_records.ConsumeRecord
                        or claim.finalization_digest != target or claim.slot_digest != slot):
                    raise CustodyJournalError("recovery target index differs from its original claim")
                predecessor = self._consume_scope(slot, by_kind)
                if predecessor is not claim:
                    raise CustodyJournalError("recovery target claim identity changed")
                # Missing intent is an ordinary incomplete prefix. Existing
                # metadata still receives its immutable checks, without reads
                # of prepared ciphertext or any other stage body.
                current()
                self._consume_metadata_current(slot, by_kind)
                current()
                has_intent = "release-intent" in by_kind
                if has_intent:
                    names = (_name(activation_attempts.KIND, target),
                        _name("activation-consume-claimed", slot),
                        _name("activation-consume-release-intent", slot))
                    maxima = (activation_attempts.MAX_RECORD_BYTES,
                        consume_records.MAX_CLAIM_BYTES, consume_records.MAX_RELEASE_INTENT_BYTES)
                    identities = tuple(self._file_identities.get(name) for name in names)
                    if any(type(identity) is not tuple or len(identity) != 9
                            or type(identity[6]) is not int or not 1 <= identity[6] <= maximum
                            for identity, maximum in zip(identities, maxima)):
                        raise CustodyJournalError("recovery target retained size metadata differs")
                    sizes = tuple(identity[6] for identity in identities)
                    if sizes[2] != by_kind["release-intent"][2]:
                        raise CustodyJournalError("recovery intent size differs from admitted metadata")
            except BaseException:
                self._io.poison()
                raise
            if not has_intent:
                current()
                self._require_ready()
                return None
            # Capacity refusal happens before the first body read and does not
            # poison a valid journal. Charge read/owned decode/hash byte work
            # from actual immutable sizes, never full-prefix maximums.
            work.charge(input_bytes=3 * sum(sizes) + len(sizes), hashes=4)
            try:
                loaded = []
                for name, size, identity in zip(names, sizes, identities):
                    current()
                    try:
                        raw, observed = self._read_file(name, maximum_bytes=size)
                    finally:
                        current()
                    if observed != identity:
                        raise CustodyJournalError("recovery target original identity changed")
                    loaded.append(raw)
                activation = activation_attempts.decode(loaded[0])
                retained_claim = consume_records.decode(loaded[1])
                intent = consume_records.decode(loaded[2])
                metadata = by_kind["release-intent"]
                if (activation != self._activation_dispatch_attempts.get(target)
                        or retained_claim != claim or retained_claim.kind != "claimed"
                        or intent.kind != "release-intent" or len(intent.originals) != 1
                        or intent.finalization_digest != target or intent.slot_digest != slot
                        or intent.activation_authorization_digest != claim.activation_authorization_digest
                        or (intent.source_revision, intent.digest, len(loaded[2]), b"") != metadata
                        or activation.source_revision != claim.source_revision
                        or intent.source_revision != claim.source_revision):
                    raise CustodyJournalError("recovery target originals differ from their retained association")
                current()
                self._consume_metadata_current(slot, by_kind)
                self._require_ready()
                current()
                return activation, retained_claim, intent
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_recovery_inputs(self, finalization_digest, *, work, current):
        """Read just target3 plus proof/hints; no full consume body prefix."""
        retained = self.load_oidc_session_activation_recovery_target(
            finalization_digest, work=work, current=current)
        if retained is None:
            return None
        activation, claim, intent = retained
        slot = claim.slot_digest
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                by_kind = self._consume_records.get(slot, {})
                if (self._consume_scope(slot, by_kind) != claim
                        or by_kind.get("release-intent", (None, None))[1] != intent.digest):
                    raise CustodyJournalError("recovery input association changed during selection")
                self._consume_metadata_current(slot, by_kind)
                kinds = ("release-proof", "completion-hints")
                if any(kind not in by_kind for kind in kinds):
                    current()
                    self._require_ready()
                    return None
                sizes = tuple(by_kind[kind][2] for kind in kinds)
                if any(type(size) is not int or not 1 <= size <= consume_records._maximum(kind)
                        for size, kind in zip(sizes, kinds)):
                    raise CustodyJournalError("recovery selected input size differs from its fixed bound")
            except BaseException:
                self._io.poison()
                raise
            # Direct metering precedes either body read. Only the selected raw4
            # proof and raw2 descriptor join the already bounded target raw3.
            work.charge(input_bytes=3 * sum(sizes) + 2, hashes=4, json_nodes=64)
            try:
                selected = []
                for kind, size in zip(kinds, sizes):
                    current()
                    try:
                        selected.append(self._read_consume_record(slot, kind, maximum_bytes=size))
                    finally:
                        current()
                self._consume_metadata_current(slot, by_kind)
                self._require_ready()
                current()
                return activation, claim, intent, *selected
            except BaseException:
                self._io.poison()
                raise

    def _recovery_grant_scope(self, slot):
        claim = self._recovery_grant_claims.get(slot)
        if (type(claim) is not recovery_records.RecoveryGrantRecord
                or claim.kind != "claimed" or claim.originals != () or claim.slot_digest != slot):
            raise CustodyJournalError("recovery acquisition lacks its exact irreversible policy claim")
        consume_slot = consume_records._slot_digest(
            claim.finalization_digest, claim.activation_authorization_digest)
        stages = self._consume_records.get(consume_slot, {})
        predecessor = self._consume_scope(consume_slot, stages)
        if (predecessor.finalization_digest != claim.finalization_digest
                or predecessor.activation_authorization_digest != claim.activation_authorization_digest
                or stages.get("release-intent", (None, None))[1] != claim.intent_record_digest):
            raise CustodyJournalError("recovery claim differs from its retained activation and intent")
        metadata = self._recovery_grant_records.get(slot)
        if metadata is not None and (metadata[0] != claim.source_revision
                or metadata[3:] != (claim.intent_record_digest, claim.finalization_digest,
                    claim.activation_authorization_digest, claim.release_intent_digest,
                    claim.issuer_policy_digest)):
            raise CustodyJournalError("recovery grant originals differ from their irreversible claim")
        return claim

    def _recovery_grant_metadata_current(self, slot):
        claim = self._recovery_grant_scope(slot)
        consume_slot = consume_records._slot_digest(
            claim.finalization_digest, claim.activation_authorization_digest)
        self._consume_metadata_current(consume_slot, self._consume_records.get(consume_slot, {}))
        for kind in recovery_records.KINDS:
            if kind == "grants" and slot not in self._recovery_grant_records:
                continue
            name = _name(recovery_records.FILE_KINDS[recovery_records.KINDS.index(kind)], slot)
            if _identity(os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)) != self._file_identities.get(name):
                raise CustodyJournalError("recovery acquisition immutable record identity changed")

    def _read_recovery_grant_claim(self, slot):
        held = self._recovery_grant_scope(slot)
        name = _name(recovery_records.FILE_KINDS[0], slot)
        raw, identity = self._read_file(name, maximum_bytes=recovery_records.MAX_CLAIM_BYTES)
        if identity != self._file_identities.get(name) or recovery_records.decode(raw) != held:
            raise CustodyJournalError("recovery acquisition claim changed after original admission")
        return held

    def claim_oidc_session_activation_recovery_grant_attempt(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest):
        """Burn a fresh policy slot before contact, never resume an old claim."""
        target, authorization, intent_digest, policy_digest = tuple(_digest(value) for value in (
            finalization_digest, activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        slot = recovery_records._slot_digest(target, authorization, intent_digest, policy_digest)
        consume_slot = consume_records._slot_digest(target, authorization)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot in self._recovery_grant_claims:
                try:
                    self._read_recovery_grant_claim(slot)
                    self._recovery_grant_metadata_current(slot)
                    self._require_ready()
                except BaseException:
                    self._io.poison()
                    raise
                raise CustodyJournalError("recovery issuer policy was already claimed; acquisition cannot repeat")
            try:
                self._read_activation_claim(target)
                predecessor = self._read_consume_claim(consume_slot)
                stages = self._consume_records.get(consume_slot, {})
                self._consume_metadata_current(consume_slot, stages)
                if (predecessor.finalization_digest != target
                        or predecessor.activation_authorization_digest != authorization
                        or "release-intent" not in stages):
                    raise CustodyJournalError("recovery acquisition requires the exact retained intent association")
                intent = self._read_consume_record(consume_slot, "release-intent",
                    maximum_bytes=consume_records.MAX_RELEASE_INTENT_BYTES)
                if recovery_records._intent_identity(intent.originals[0]) != intent_digest:
                    raise CustodyJournalError("recovery acquisition intent identity differs from retained original")
                claim, encoded = recovery_records.encode("claimed", finalization_digest=target,
                    activation_authorization_digest=authorization, release_intent_digest=intent_digest,
                    issuer_policy_digest=policy_digest, intent_record_digest=intent.digest,
                    originals=(), source_revision=recovery_records.authority.SOURCE_REVISION)
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise
            if (len(self._entries) + len(self._release_attempts) + len(self._activation_dispatch_attempts)
                    + len(self._consume_claims) + len(self._recovery_grant_claims)
                    + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("journal recovery acquisition capacity is exhausted")
            try:
                self._publish(recovery_records.FILE_KINDS[0], slot, encoded)
                self._used_bytes += len(encoded)
                self._recovery_grant_claims[slot] = claim
                self._recovery_grant_scope(slot)
                self._require_ready()
                self._recovery_grant_live_claims.add(slot)
                return slot
            except BaseException:
                self._io.poison()
                raise

    def append_oidc_session_activation_recovery_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest, originals):
        """Retain the first exact raw3 only under this owner's new policy claim."""
        scalars = tuple(_digest(value) for value in (finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        slot = recovery_records._slot_digest(*scalars)
        held = recovery_records._originals(originals)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot not in self._recovery_grant_live_claims:
                raise CustodyJournalError("recovered recovery acquisition claims are read-only")
            if slot in self._recovery_grant_records:
                raise CustodyJournalError("recovery acquired originals cannot be replaced or appended twice")
            try:
                claim = self._read_recovery_grant_claim(slot)
                self._recovery_grant_metadata_current(slot)
                record, encoded = recovery_records.encode("grants", finalization_digest=scalars[0],
                    activation_authorization_digest=scalars[1], release_intent_digest=scalars[2],
                    issuer_policy_digest=scalars[3], intent_record_digest=claim.intent_record_digest,
                    originals=held, source_revision=claim.source_revision)
                if (len(self._file_identities) >= self._physical_limit()
                        or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                    raise CustodyJournalError("journal recovery original retention capacity is exhausted")
                self._require_ready()
                self._publish(recovery_records.FILE_KINDS[1], slot, encoded)
                self._used_bytes += len(encoded)
                self._recovery_grant_records[slot] = (record.source_revision, record.digest,
                    len(encoded), record.intent_record_digest, *scalars)
                self._recovery_grant_scope(slot)
                self._require_ready()
                self._recovery_grant_live_claims.remove(slot)
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_recovery_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest, work, current):
        """Read only this policy's claim/raw3; absence never grants a retry."""
        from serverware.authority_query_read_work import _ValidationWork

        slot = recovery_records._slot_digest(finalization_digest, activation_authorization_digest,
            release_intent_digest, issuer_policy_digest)
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("recovery acquired-original read requires original work and guard")
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot not in self._recovery_grant_claims:
                current()
                return None
            try:
                self._recovery_grant_metadata_current(slot)
                metadata = self._recovery_grant_records.get(slot)
                size = 0 if metadata is None else metadata[2]
                if type(size) is not int or not 0 <= size <= recovery_records.MAX_GRANTS_BYTES:
                    raise CustodyJournalError("recovery acquired-original size metadata differs")
            except BaseException:
                self._io.poison()
                raise
            work.charge(input_bytes=3 * (recovery_records.MAX_CLAIM_BYTES + size), hashes=16, json_nodes=64)
            try:
                current()
                claim = self._read_recovery_grant_claim(slot)
                current()
                grants = None
                if metadata is not None:
                    name = _name(recovery_records.FILE_KINDS[1], slot)
                    raw, identity = self._read_file(name, maximum_bytes=size)
                    current()
                    grants = recovery_records.decode(raw)
                    if (identity != self._file_identities.get(name) or grants.kind != "grants"
                            or (grants.source_revision, grants.digest, len(raw), grants.intent_record_digest,
                                grants.finalization_digest, grants.activation_authorization_digest,
                                grants.release_intent_digest, grants.issuer_policy_digest) != metadata
                            or grants.slot_digest != slot):
                        raise CustodyJournalError("recovery acquired originals changed after admission")
                self._recovery_grant_metadata_current(slot)
                self._require_ready()
                current()
                return recovery_records.RecoveryGrantRecords(claim, grants)
            except BaseException:
                self._io.poison()
                raise

    def _completion_control_scope(self, target, phase):
        completion_recovery._phase(phase)
        activation = self._activation_dispatch_attempts.get(target)
        activation_stages = self._activation_records.get(target, {})
        if activation is None:
            if activation_stages:
                raise CustodyJournalError("completion controls lack their original activation claim")
            return None, None, activation_stages, {}
        if (type(activation) is not activation_attempts.ActivationDispatchAttemptRecord
                or activation.finalization_digest != target):
            raise CustodyJournalError("completion controls activation association differs")
        self._activation_scope(target, activation_stages)
        consume = None
        stages = {}
        if phase == "consume":
            slot = self._consume_targets.get(target)
            if slot is not None:
                stages = self._consume_records.get(slot, {})
                consume = self._consume_scope(slot, stages)
                if consume.finalization_digest != target:
                    raise CustodyJournalError("completion controls consume association differs")
        return activation, consume, activation_stages, stages

    def _completion_control_inventory(self, target, phase, current):
        """Fixed indexed metadata only; no SQL-outcome or full-prefix bodies."""
        activation, consume, activation_stages, consume_stages = self._completion_control_scope(target, phase)
        known = []
        claim_name = _name(activation_attempts.KIND, target)
        if (claim_name in self._file_identities) != (activation is not None):
            raise CustodyJournalError("completion controls claim file index differs")
        if activation is not None:
            known.append((claim_name, activation_attempts.MAX_RECORD_BYTES))
        for kind in activation_records.KINDS:
            name = _name("activation-" + kind, target)
            if (name in self._file_identities) != (kind in activation_stages):
                raise CustodyJournalError("completion controls activation file index differs")
            if kind in activation_stages:
                known.append((name, activation_records._maximum(kind)))
        if consume is not None:
            known.append((_name("activation-consume-claimed", consume.slot_digest), consume_records.MAX_CLAIM_BYTES))
            for kind in consume_records.KINDS[1:]:
                name = _name("activation-consume-" + kind, consume.slot_digest)
                if (name in self._file_identities) != (kind in consume_stages):
                    raise CustodyJournalError("completion controls consume file index differs")
                if kind in consume_stages:
                    known.append((name, consume_records._maximum(kind)))
        for name, maximum in known:
            self._completion_history_metadata(name, maximum, self._file_identities.get(name), current)
        stages = activation_stages if phase == "activation" else consume_stages
        required = (("prepared", "grant", "reserved", "sql-claimed") if phase == "activation"
            else ("prepared", "exported", "authorized", "grant", "reserved", "sql-claimed"))
        if (activation is None or (phase == "consume" and consume is None)
                or any(kind not in stages for kind in required)):
            return None
        selected = [(0, claim_name, activation_attempts.decode)]
        if consume is not None:
            selected.append((1, _name("activation-consume-claimed", consume.slot_digest), consume_records.decode))
        positions = ((2, "prepared"), (3, "exported"), (4, "authorized"),
            (5, "grant"), (6, "reserved"), (7, "completion-outcome"),
            (8, "completion-hints"), (9, "sql-claimed"))
        for position, kind in positions:
            if kind not in stages:
                continue
            name = _name("activation-" + kind, target) if phase == "activation" else _name(
                "activation-consume-" + kind, consume.slot_digest)
            metadata = stages[kind]
            identity = self._file_identities[name]
            if (type(metadata) is not tuple or len(metadata) != (3 if phase == "activation" else 4)
                    or type(metadata[2]) is not int or metadata[2] != identity[6]):
                raise CustodyJournalError("completion controls encoded size differs from admitted metadata")
            selected.append((position, name,
                activation_records.decode if phase == "activation" else consume_records.decode))
        return activation, consume, stages, tuple(selected)

    def load_oidc_session_activation_completion_recovery_controls(self, finalization_digest, *,
            phase, work, current, maximum_original_bytes=None):
        """Return fixed tuple10 historical DATA or ordinary unavailable None."""
        from serverware.authority_query_read_work import _ValidationWork

        target = _digest(finalization_digest)
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion controls remaining original capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion controls require original work and guard")
        work.charge(json_nodes=512)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                inventory = self._completion_control_inventory(target, phase, current)
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            if inventory is None:
                return None
            activation, consume, stages, selected = inventory
            identities = tuple(self._file_identities[item[1]] for item in selected)
            total = sum(identity[6] for identity in identities)
            if 3 * total + completion_recovery.METADATA_RESERVATION_BYTES > maximum:
                raise CustodyJournalError("completion controls exceed remaining preallocation capacity")
            work.charge(input_bytes=3 * total + len(selected), hashes=2 * len(selected))
            try:
                result = [None] * 10
                for (position, name, decoder), identity in zip(selected, identities):
                    original = self._read_completion_history_file(name, identity, current)
                    current()
                    record = decoder(original)
                    current()
                    if position == 0:
                        if record != activation:
                            raise CustodyJournalError("completion controls activation claim changed")
                    elif position == 1:
                        if record != consume:
                            raise CustodyJournalError("completion controls consume claim changed")
                    else:
                        metadata = stages[record.kind]
                        actual = record.source_revision, record.digest, len(original)
                        if phase == "consume":
                            actual += (record.originals[0] if record.kind in ("prepared", "exported") else b"",)
                        if (actual != metadata or record.finalization_digest != target
                                or record.source_revision != activation.source_revision
                                or (phase == "consume" and (record.slot_digest != consume.slot_digest
                                    or record.activation_authorization_digest != consume.activation_authorization_digest))):
                            raise CustodyJournalError("completion controls original association changed")
                    result[position] = record
                    del original
                refreshed = self._completion_control_inventory(target, phase, current)
                if refreshed is None or refreshed[3] != selected:
                    raise CustodyJournalError("completion controls selected prefix changed")
                self._require_ready()
                current()
                return tuple(result)
            except BaseException:
                self._io.poison()
                raise

    @staticmethod
    def _completion_recovery_response_metadata(record, size):
        return (record.source_revision, record.digest, size, record.finalization_digest,
            record.phase, record.authorization_digest, record.packet_digest,
            record.recovery_configuration_digest, record.predecessor_completion_digest)

    def _completion_recovery_scope(self, slot):
        claim = self._completion_recovery_claims.get(slot)
        if (type(claim) is not completion_recovery.CompletionRecoveryRecord or claim.kind != "claimed"
                or claim.originals != () or claim.slot_digest != slot):
            raise CustodyJournalError("completion recovery lacks its exact phase attempt")
        activation, consume, activation_stages, consume_stages = self._completion_control_scope(
            claim.finalization_digest, claim.phase)
        stages = activation_stages if claim.phase == "activation" else consume_stages
        required = (("prepared", "grant", "reserved", "sql-claimed") if claim.phase == "activation"
            else ("prepared", "exported", "authorized", "grant", "reserved", "sql-claimed"))
        prior = stages.get("completion-outcome")
        if (activation is None or (claim.phase == "consume" and consume is None)
                or any(kind not in stages for kind in required)
                or (None if prior is None else prior[1]) != claim.predecessor_completion_digest):
            raise CustodyJournalError("completion recovery original predecessor association differs")
        metadata = self._completion_recovery_responses.get(slot)
        if metadata is not None and (metadata[0] != claim.source_revision
                or metadata[3:] != (claim.finalization_digest, claim.phase, claim.authorization_digest,
                    claim.packet_digest, claim.recovery_configuration_digest, claim.predecessor_completion_digest)):
            raise CustodyJournalError("completion recovery response differs from its irreversible attempt")
        return claim

    def _completion_recovery_metadata(self, slot, current):
        claim = self._completion_recovery_scope(slot)
        if self._completion_control_inventory(claim.finalization_digest, claim.phase, current) is None:
            raise CustodyJournalError("completion recovery original controls disappeared")
        selected = []
        for kind in completion_recovery.KINDS:
            if kind == "response" and slot not in self._completion_recovery_responses:
                continue
            name = _name(completion_recovery.FILE_KINDS[completion_recovery.KINDS.index(kind)], slot)
            identity = self._file_identities.get(name)
            self._completion_history_metadata(name, completion_recovery._maximum(claim.phase, kind), identity, current)
            if kind == "response" and identity[6] != self._completion_recovery_responses[slot][2]:
                raise CustodyJournalError("completion recovery response size changed")
            selected.append((kind, name, identity))
        return claim, tuple(selected)

    def _publish_completion_recovery(self, kind, slot, encoded, current):
        name = _name(completion_recovery.FILE_KINDS[completion_recovery.KINDS.index(kind)], slot)
        self._publish_guarded_completion_name(name, encoded, current)

    def _publish_guarded_completion_name(self, name, encoded, current):
        # Only the fixed completion/release families below choose a publication
        # name. The native transition owner admits no caller-selected paths.
        publication = _CompletionPublication(self, name, len(encoded), current)
        current()
        self._io.publish(".tmp-" + name, name, encoded, _current=current,
            _transition=publication.transition)
        if publication.stage != "closed-published":
            raise CustodyJournalError("completion recovery publication did not close normally")
        current()
        metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        current()
        identity = _identity(metadata)
        if identity != publication.published_identity:
            raise CustodyJournalError("completion recovery readback differs from its native published inode")
        self._file_identities[name] = identity
        self._completion_history_metadata(name, len(encoded), identity, current)
        if identity[6] != len(encoded):
            raise CustodyJournalError("published completion recovery length changed")
        stored = self._read_completion_history_file(name, identity, current)
        if stored != encoded:
            raise CustodyJournalError("published completion recovery bytes changed")
        current()
        self._directory_stamp = self._stamp()
        current()

    def _completion_release_inventory(self, target, authorization_digest, reconciliation_digest, current,
            *, include_grants=False):
        inventory = self._completion_control_inventory(target, "consume", current)
        if inventory is None:
            return None
        activation, claim, stages, controls = inventory
        if claim.activation_authorization_digest != authorization_digest:
            raise CustodyJournalError("completion release target differs from its consume claim")
        selected = []
        for position, name, decoder in controls:
            if position in ((0, 1, 7, 8) if reconciliation_digest is None else (0, 1)):
                selected.append((position, name, self._file_identities[name], decoder))
        if reconciliation_digest is None:
            if "completion-outcome" not in stages or "completion-hints" not in stages:
                return None
        else:
            recovery_slot = completion_recovery._slot_digest(target, "consume")
            if (recovery_slot not in self._completion_recovery_claims
                    or recovery_slot not in self._completion_recovery_responses):
                return None
            self._completion_recovery_scope(recovery_slot)
            for index, kind in enumerate(completion_recovery.KINDS):
                name = _name(completion_recovery.FILE_KINDS[index], recovery_slot)
                identity = self._file_identities.get(name)
                self._completion_history_metadata(name, completion_recovery._maximum("consume", kind), identity, current)
                if kind == "response" and identity[6] != self._completion_recovery_responses[recovery_slot][2]:
                    raise CustodyJournalError("completion release reconciliation size changed")
                selected.append(("reconciliation-" + kind, name, identity, completion_recovery.decode))
        kinds = consume_records.COMPLETION_RECOVERY_RELEASE_KINDS
        if include_grants:
            kinds += consume_records.COMPLETION_RECOVERY_GRANT_KINDS
        for kind in kinds:
            if kind in stages:
                name = _name("activation-consume-" + kind, claim.slot_digest)
                identity = self._file_identities[name]
                if identity[6] != stages[kind][2]:
                    raise CustodyJournalError("completion release record size differs from its admitted metadata")
                selected.append((kind, name, identity, consume_records.decode))
        return activation, claim, stages, tuple(selected)

    def _completion_release_operation(self, *, finalization_digest, activation_authorization_digest,
            completion_originals, reconciliation_digest, work, current, maximum_original_bytes,
            kind=None, originals=(), load_grants=False):
        """Exact existing-family continuation; records are DATA, not permission."""
        from serverware.authority_query_read_work import _ValidationWork

        target, authorization_digest = _digest(finalization_digest), _digest(activation_authorization_digest)
        if reconciliation_digest is not None:
            reconciliation_digest = _digest(reconciliation_digest)
        completed = completion_recovery._originals("consume", completion_originals)
        consume_records.completion._originals(completed[:4], response=True)
        if completed[0] != b"acknowledged":
            raise CustodyJournalError("completion release requires acknowledged originals, not uncertainty")
        held = () if kind is None else consume_records._originals(consume_records._profile(kind), originals)
        publication_bytes = 0 if kind is None else consume_records._completion_recovery_publication_bytes(kind, held)
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion release remaining original capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion release requires the original work and resource guard")
        if type(load_grants) is not bool or (load_grants and kind is not None):
            raise CustodyJournalError("completion release read profile is not source fixed")
        grant_family = load_grants or kind in consume_records.COMPLETION_RECOVERY_GRANT_KINDS
        work.charge(json_nodes=512)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                inventory = self._completion_release_inventory(target, authorization_digest, reconciliation_digest, current,
                    include_grants=grant_family)
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            if inventory is None:
                raise CustodyJournalError("completion release acknowledged history is unavailable")
            activation, claim, stages, selected = inventory
            total = sum(item[2][6] for item in selected)
            required = 3 * total + publication_bytes + consume_records.COMPLETION_RECOVERY_METADATA_BYTES
            if required > maximum:
                raise CustodyJournalError("completion release exceeds remaining preallocation capacity")
            scans = 0 if kind is None else 3 * (len(self._file_identities) + 1)
            work.charge(input_bytes=3 * total + len(selected) + publication_bytes + scans * 512,
                hashes=2 * len(selected) + (16 if kind is not None else 0), json_nodes=scans * 16)
            loaded = {}
            try:
                for label, name, identity, decoder in selected:
                    raw = self._read_completion_history_file(name, identity, current)
                    record = decoder(raw)
                    if label == 0:
                        valid = record == activation
                    elif label == 1:
                        valid = record == claim
                    elif label == "reconciliation-claimed":
                        recovery_slot = completion_recovery._slot_digest(target, "consume")
                        valid = record == self._completion_recovery_claims[recovery_slot]
                    elif label == "reconciliation-response":
                        recovery_slot = completion_recovery._slot_digest(target, "consume")
                        valid = (record.slot_digest == recovery_slot and record.kind == "response"
                            and self._completion_recovery_response_metadata(record, len(raw))
                            == self._completion_recovery_responses[recovery_slot])
                    else:
                        stage = "completion-outcome" if label == 7 else "completion-hints" if label == 8 else label
                        valid = (record.kind == stage and record.slot_digest == claim.slot_digest
                            and record.finalization_digest == target
                            and record.activation_authorization_digest == authorization_digest
                            and (record.source_revision, record.digest, len(raw), b"") == stages[stage])
                    if not valid:
                        raise CustodyJournalError("completion release original differs from its immutable association")
                    loaded[label] = record
                    del raw
                    current()
                self._completion_release_inventory(target, authorization_digest, reconciliation_digest, current,
                    include_grants=grant_family)
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            if reconciliation_digest is None:
                retained = loaded[7].originals + loaded[8].originals
            else:
                response = loaded["reconciliation-response"]
                if response.digest != reconciliation_digest:
                    raise CustodyJournalError("completion release reconciliation locator differs")
                retained = response.originals
            if retained != completed:
                raise CustodyJournalError("completion release originals differ from retained acknowledged DATA")
            if kind is None:
                kinds = (consume_records.COMPLETION_RECOVERY_GRANT_KINDS if load_grants
                    else consume_records.COMPLETION_RECOVERY_RELEASE_KINDS)
                return tuple(loaded.get(item) for item in kinds)
            if claim.source_revision != consume_records.authority.SOURCE_REVISION:
                raise CustodyJournalError("completion release cannot migrate a different source cohort")
            if kind in stages:
                raise CustodyJournalError("completion release stage already exists; repeat is forbidden")
            slot = claim.slot_digest
            claim_kind = ("release-grants-claimed" if grant_family else
                "release-intent-claimed" if kind.startswith("release-intent") else "release-proof-claimed")
            claim_key = (slot, claim_kind)
            # The fixed target/phase or original completion files uniquely pin
            # these bytes. Do not retain a request-sized raw6 in the journal's
            # in-memory one-use state after this operation returns.
            binding = (work, reconciliation_digest)
            claim_kinds = ("release-intent-claimed", "release-proof-claimed", "release-grants-claimed")
            if kind not in claim_kinds:
                saved = self._completion_release_live_claims.get(claim_key)
                if (saved is None or saved[0] is not work or saved[1:] != binding[1:]
                        or claim_kind not in stages):
                    raise CustodyJournalError("completion release publication lacks this work's new durable claim")
            if ((kind == "release-proof-claimed" and "release-intent" not in stages)
                    or (kind == "release-proof-setup" and "release-proof" in stages)
                    or (kind == "release-proof" and "release-proof-setup" not in stages)
                    or (grant_family and "release-proof" not in stages)
                    or (kind == "release-grants-claimed" and "release-grants" in stages)):
                raise CustodyJournalError("completion release publication lacks its fixed predecessor")
            record, encoded = consume_records.encode(kind, finalization_digest=target,
                activation_authorization_digest=authorization_digest, originals=held, source_revision=claim.source_revision)
            if (len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("completion release journal capacity is exhausted")
            try:
                self._publish_guarded_completion_name(_name("activation-consume-" + kind, slot), encoded, current)
                self._used_bytes += len(encoded)
                self._consume_records.setdefault(slot, {})[kind] = (record.source_revision, record.digest, len(encoded), b"")
                self._consume_scope(slot, self._consume_records[slot])
                self._require_ready()
                current()
                if kind in claim_kinds:
                    self._completion_release_live_claims[claim_key] = binding
                elif kind in ("release-intent", "release-proof", "release-grants"):
                    del self._completion_release_live_claims[claim_key]
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_completion_recovery_release_records(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)

    def claim_oidc_session_activation_completion_recovery_release_intent_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-intent-claimed")

    def append_oidc_session_activation_completion_recovery_release_intent(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-intent", originals=originals)

    def claim_oidc_session_activation_completion_recovery_release_proof_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-proof-claimed")

    def append_oidc_session_activation_completion_recovery_release_proof_setup(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-proof-setup", originals=originals)

    def append_oidc_session_activation_completion_recovery_release_proof(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-proof", originals=originals)

    def load_oidc_session_activation_completion_recovery_release_grants(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Return acquisition claim/grants DATA; absence says nothing about private storage."""
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, load_grants=True)

    def claim_oidc_session_activation_completion_recovery_release_grants_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Spend the consume target's grant-acquisition slot before issuer contact."""
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-grants-claimed")

    def append_oidc_session_activation_completion_recovery_release_grants(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        """Retain first raw2 DATA under this work's new claim before interpretation."""
        return self._completion_release_operation(finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, completion_originals=completion_originals,
            reconciliation_digest=reconciliation_digest, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes, kind="release-grants", originals=originals)

    def claim_oidc_session_activation_completion_recovery_attempt(self, *, finalization_digest,
            phase, authorization_digest, packet_digest, recovery_configuration_digest,
            work, current, maximum_original_bytes=None):
        """One target/phase attempt before contact; no actor or restart can retry."""
        from serverware.authority_query_read_work import _ValidationWork

        scalars = tuple(_digest(value) for value in (finalization_digest, authorization_digest,
            packet_digest, recovery_configuration_digest))
        slot = completion_recovery._slot_digest(scalars[0], phase)
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion recovery claim remaining capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion recovery claim requires original work and guard")
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            try:
                inventory = self._completion_control_inventory(scalars[0], phase, current)
                if slot in self._completion_recovery_claims:
                    self._completion_recovery_metadata(slot, current)
                self._require_ready()
                current()
            except BaseException:
                self._io.poison()
                raise
            if inventory is None:
                raise CustodyJournalError("completion recovery controls are unavailable")
            if slot in self._completion_recovery_claims:
                raise CustodyJournalError("completion recovery phase was already attempted; retry is forbidden")
            if completion_recovery.MAX_CLAIM_IO_BYTES + completion_recovery.METADATA_RESERVATION_BYTES > maximum:
                raise CustodyJournalError("completion recovery claim exceeds remaining preallocation capacity")
            # Three streamed mutation-boundary scans, precharged from the
            # actual admitted inventory. Large inventories may refuse safely.
            scans = 3 * (len(self._file_identities) + 1)
            work.charge(input_bytes=completion_recovery.MAX_CLAIM_IO_BYTES + scans * 512,
                hashes=16, json_nodes=512 + scans * 16)
            prior = inventory[2].get("completion-outcome")
            record, encoded = completion_recovery.encode("claimed", finalization_digest=scalars[0], phase=phase,
                authorization_digest=scalars[1], packet_digest=scalars[2], recovery_configuration_digest=scalars[3],
                predecessor_completion_digest=None if prior is None else prior[1], originals=(),
                source_revision=completion_recovery.authority.SOURCE_REVISION)
            if (len(self._entries) + len(self._release_attempts) + len(self._activation_dispatch_attempts)
                    + len(self._consume_claims) + len(self._recovery_grant_claims)
                    + len(self._completion_recovery_claims) >= self._maximum_records
                    or len(self._file_identities) >= self._physical_limit()
                    or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                raise CustodyJournalError("completion recovery attempt capacity is exhausted")
            try:
                self._publish_completion_recovery("claimed", slot, encoded, current)
                self._used_bytes += len(encoded)
                self._completion_recovery_claims[slot] = record
                self._completion_recovery_scope(slot)
                self._require_ready()
                current()
                self._completion_recovery_live_claims.add(slot)
                return slot
            except BaseException:
                self._io.poison()
                raise

    def append_oidc_session_activation_completion_recovery_response(self, *, finalization_digest,
            phase, authorization_digest, packet_digest, recovery_configuration_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain opaque raw4/raw6 before interpretation, separately from old outcomes."""
        from serverware.authority_query_read_work import _ValidationWork

        scalars = tuple(_digest(value) for value in (finalization_digest, authorization_digest,
            packet_digest, recovery_configuration_digest))
        slot = completion_recovery._slot_digest(scalars[0], phase)
        held = completion_recovery._originals(phase, originals)
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion recovery response remaining capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion recovery retention requires original work and guard")
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot not in self._completion_recovery_live_claims or slot in self._completion_recovery_responses:
                raise CustodyJournalError("completion recovery response cannot resume or repeat")
            try:
                claim, selected = self._completion_recovery_metadata(slot, current)
                if (claim.finalization_digest, claim.authorization_digest, claim.packet_digest,
                        claim.recovery_configuration_digest) != scalars or claim.phase != phase:
                    raise CustodyJournalError("completion recovery response pins differ from the attempt")
            except BaseException:
                self._io.poison()
                raise
            io_bytes = completion_recovery._append_io_bytes(phase, held)
            if io_bytes + completion_recovery.METADATA_RESERVATION_BYTES > maximum:
                raise CustodyJournalError("completion recovery response exceeds remaining preallocation capacity")
            scans = 3 * (len(self._file_identities) + 1)
            work.charge(input_bytes=io_bytes + scans * 512, hashes=16, json_nodes=512 + scans * 16)
            try:
                raw_claim = self._read_completion_history_file(selected[0][1], selected[0][2], current)
                if completion_recovery.decode(raw_claim) != claim:
                    raise CustodyJournalError("completion recovery attempt original changed")
                del raw_claim
                record, encoded = completion_recovery.encode("response", finalization_digest=scalars[0], phase=phase,
                    authorization_digest=scalars[1], packet_digest=scalars[2], recovery_configuration_digest=scalars[3],
                    predecessor_completion_digest=claim.predecessor_completion_digest, originals=held,
                    source_revision=claim.source_revision)
                if (len(self._file_identities) >= self._physical_limit()
                        or len(encoded) > self._quota - self._used_bytes - self._reserved_bytes):
                    raise CustodyJournalError("completion recovery response capacity is exhausted")
                self._publish_completion_recovery("response", slot, encoded, current)
                self._used_bytes += len(encoded)
                self._completion_recovery_responses[slot] = self._completion_recovery_response_metadata(record, len(encoded))
                self._completion_recovery_scope(slot)
                self._require_ready()
                current()
                self._completion_recovery_live_claims.remove(slot)
                return record.digest
            except BaseException:
                self._io.poison()
                raise

    def load_oidc_session_activation_completion_recovery_records(self, finalization_digest, *,
            phase, work, current, maximum_original_bytes=None):
        """Read existing attempt/response DATA; it never renews the spent slot."""
        from serverware.authority_query_read_work import _ValidationWork

        slot = completion_recovery._slot_digest(_digest(finalization_digest), phase)
        maximum = completion_recovery.MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
        _integer(maximum, minimum=0, maximum=completion_recovery.MAX_ORIGINAL_BYTES,
            label="completion recovery history remaining capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyJournalError("completion recovery history requires original work and guard")
        work.charge(json_nodes=512)
        current()
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if slot not in self._completion_recovery_claims:
                if slot in self._completion_recovery_responses:
                    self._io.poison()
                    raise CustodyJournalError("completion recovery response lacks its original attempt")
                current()
                return None
            try:
                claim, selected = self._completion_recovery_metadata(slot, current)
            except BaseException:
                self._io.poison()
                raise
            total = sum(item[2][6] for item in selected)
            if 3 * total + completion_recovery.METADATA_RESERVATION_BYTES > maximum:
                raise CustodyJournalError("completion recovery history exceeds remaining preallocation capacity")
            work.charge(input_bytes=3 * total + len(selected), hashes=16)
            try:
                response = None
                for kind, name, identity in selected:
                    original = self._read_completion_history_file(name, identity, current)
                    record = completion_recovery.decode(original)
                    if kind == "claimed":
                        if record != claim:
                            raise CustodyJournalError("completion recovery attempt original changed")
                    else:
                        if self._completion_recovery_response_metadata(record, len(original)) != self._completion_recovery_responses[slot]:
                            raise CustodyJournalError("completion recovery response original changed")
                        response = record
                    del original
                    current()
                self._completion_recovery_metadata(slot, current)
                self._require_ready()
                current()
                return completion_recovery.CompletionRecoveryRecords(claim, response)
            except BaseException:
                self._io.poison()
                raise

    def claim_attempt(self, localdigest):
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is None:
                raise CustodyJournalError("cannot attempt an absent local record")
            if entry.family in _RETENTION_ONLY_FAMILIES:
                raise CustodyJournalError("retention-only record cannot be attempted")
            if entry.attempted:
                raise CustodyJournalError("local record already has an attempt; repeat delivery is forbidden")
            try:
                self._load(digest)
                self._require_ready()
                self._publish("attempted", digest, _ATTEMPT_MAGIC + bytes.fromhex(digest[7:]))
                self._used_bytes += _ATTEMPT_BYTES
                self._reserved_bytes -= _ATTEMPT_BYTES
                self._entries[digest] = replace(entry, attempted=True)
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise

    def record_observation(self, localdigest, *, retained_record_digest,
            retained_at_epoch_ns, configuration_digest):
        """Durably retain one exact successful-read observation, not authority."""
        # The codec holds all exact immutable scalars, including current source,
        # before the first filesystem/lease callback in this operation.
        observation, encoded = observations.encode_observation(localdigest,
            retained_record_digest=retained_record_digest,
            retained_at_epoch_ns=retained_at_epoch_ns, configuration_digest=configuration_digest)
        digest = observation.local_digest
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is not None and entry.family in _RETENTION_ONLY_FAMILIES:
                raise CustodyJournalError("retention-only record cannot have an observation")
            if entry is None or not entry.attempted:
                raise CustodyJournalError("readback observation requires a prepared and attempted record")
            try:
                self._load(digest)
                if entry.observed:
                    previous, original = self._read_observation(digest)
                    if original != encoded:
                        raise CustodyJournalError("first readback observation cannot change its exact metadata")
                    self._require_ready()
                    return previous
                if (self._reserved_bytes < _OBSERVATION_RESERVE
                        or len(encoded) > _OBSERVATION_RESERVE):
                    raise CustodyJournalError("journal observation reservation is inconsistent")
                self._require_ready()
                self._publish("observed", digest, encoded)
                self._used_bytes += len(encoded)
                self._reserved_bytes -= _OBSERVATION_RESERVE
                self._entries[digest] = replace(entry, observed=True)
                self._require_ready()
                return observation
            except BaseException:
                self._io.poison()
                raise

    def load_observation(self, localdigest):
        """Return first local readback metadata, or None, never remote absence."""
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is None:
                raise CustodyJournalError("local prepared record is absent")
            try:
                # This validates prepared content and any attempt/observation
                # identities. A missing local marker is not a failed lookup.
                self._load(digest)
                observation = self._read_observation(digest)[0] if entry.observed else None
                self._require_ready()
                return observation
            except BaseException:
                self._io.poison()
                raise

    def inventory(self):
        """Return bounded metadata, never all original byte records."""
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return tuple(self._entries[digest] for digest in sorted(self._entries))

    def close(self):
        if os.getpid() != self._pid:
            raise CustodyJournalError("forked process cannot close the parent journal owner")
        if self._closed:
            return
        with self._io.lock:
            if not self._closed:
                self._closed = True
                self._io.poison()
                # Closing the sole private open-file description releases its
                # lease; never explicitly unlock the caller's borrowed FD.
                os.close(self._directory_fd)

    def __enter__(self):
        self._require_process()
        with self._io.ready():
            self._require_ready()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
