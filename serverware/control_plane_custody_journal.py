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
    activation_attempts.MAX_RECORD_BYTES)
_FINALIZATION_OUTCOME_FILES = {
    "finalization-" + kind: kind for kind in finalization_outcomes.KINDS}
_RETENTION_ONLY_FAMILIES = frozenset({execution_records.FAMILY, signer_records.FAMILY,
    finalization_records.FAMILY})


class CustodyJournalError(RuntimeError):
    pass


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
    At most seven times maximum_records published files are admitted, including associations and
    fixed registration outcomes: legacy records use at most three, evidence
    grants seven, signer records one and finalization grants seven each.
    Old records are never rewritten or removed; legacy marker byte
    reservations remain intact.
    Public-only release and activation claims share prepared-record logical capacity and
    the unchanged physical/quota ceilings, without reserving legacy markers.
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
        uncertain_completions = set()
        uncertain_finalization_completions = set()
        count = 0
        with os.scandir(self._directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > 7 * self._maximum_records:
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
                    if len(prepared) + len(release_claims) + len(activation_claims) > self._maximum_records:
                        raise CustodyJournalError("journal prepared record limit exceeded")
                elif kind == release_attempts.KIND:
                    claim = release_attempts.decode(encoded)
                    if claim.client_authorization_digest != digest or digest in release_claims:
                        raise CustodyJournalError("release claim filename differs from its authorization")
                    release_claims[digest] = claim
                    if len(prepared) + len(release_claims) + len(activation_claims) > self._maximum_records:
                        raise CustodyJournalError("journal release claim record limit exceeded")
                elif kind == activation_attempts.KIND:
                    claim = activation_attempts.decode(encoded)
                    if claim.finalization_digest != digest or digest in activation_claims:
                        raise CustodyJournalError("activation claim filename differs from its finalization locator")
                    activation_claims[digest] = claim
                    if len(prepared) + len(release_claims) + len(activation_claims) > self._maximum_records:
                        raise CustodyJournalError("journal activation claim record limit exceeded")
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
                + len(self._activation_dispatch_attempts) >= self._maximum_records
                or len(self._file_identities) >= 7 * self._maximum_records
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
                    + len(self._activation_dispatch_attempts) + len(missing) > self._maximum_records
                    or len(self._file_identities) + len(missing) + 1 > 7 * self._maximum_records
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
                    + len(self._activation_dispatch_attempts) + missing > self._maximum_records
                    or len(self._file_identities) + missing + 1 > 7 * self._maximum_records
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
            if (len(self._file_identities) >= 7 * self._maximum_records
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
            if (len(self._file_identities) >= 7 * self._maximum_records
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
            if (len(self._file_identities) >= 7 * self._maximum_records
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
                    + len(self._activation_dispatch_attempts) >= self._maximum_records
                    or len(self._file_identities) >= 7 * self._maximum_records
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
                    + len(self._activation_dispatch_attempts) >= self._maximum_records
                    or len(self._file_identities) >= 7 * self._maximum_records
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
