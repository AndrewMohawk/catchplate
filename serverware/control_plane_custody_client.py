"""Explicit, journal-bound forwarding of already prepared custody originals.

Only ``from_environment`` creates this owner. It admits the genuine root-signed
runtime trust before the journal opens its private directory handle, preserving
the exact inherited-descriptor check. The supplied directory must already be
open in that admitted set; this module provisions neither a directory nor trust.

Append and forward are separate actions. Forwarding burns the journal's durable
ATTEMPTED marker before one relay exchange and never clears it after failure.
An unsigned digest/time response is an observation, not a signed durability
receipt, replay result, execution authority or permission to retry. There is no
automatic signing, preparation, reconciliation, server startup or HTTP route.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import time

from serverware import authority_contract as authority
from serverware import authority_custody_caller_transport as transport
from serverware import authority_service as service
from serverware import control_plane_custody_journal as journal
from serverware import control_plane_custody_records as records


class CustodyClientError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _Binding:
    journal: journal.CustodyJournal
    pid: int
    relay_path: str
    relay_uid: int
    relay_gid: int
    configuration_digest: str
    maximum_deadline_ns: int
    caller_uid: int
    caller_gid: int
    attestation_interval: tuple[int, int]


def _process(binding):
    if (os.getpid() != binding.pid
            or os.environ.get("SERVERWARE_PROCESS_MODE", "").strip()
                != "serverware-control-plane"
            or (os.geteuid(), os.getegid()) != (binding.caller_uid, binding.caller_gid)):
        raise CustodyClientError("custody caller process differs from its admitted identity")


def _receipt_now(binding):
    issued_at, expires_at = binding.attestation_interval
    now = time.time_ns()
    if not issued_at <= now < expires_at:
        raise CustodyClientError("custody caller's original admitted attestation is not current")
    return now


def _snapshot(client):
    if type(client) is not ControlPlaneCustodyClient:
        raise CustodyClientError("custody caller is not the fixed owner")
    binding, closed = client._binding, client._closed
    if (type(binding) is not _Binding
            or type(binding.journal) is not journal.CustodyJournal or closed):
        raise CustodyClientError("custody caller owner is unavailable")
    # All references and scalar trust values are held before these native calls.
    _process(binding)
    journal.CustodyJournal._require_ready(binding.journal)
    return binding


class ControlPlaneCustodyClient:
    """Own one real journal and a fixed, environment-admitted relay binding."""

    __slots__ = ("_binding", "_closed")

    def __init__(self):
        raise CustodyClientError("use the fixed from_environment custody caller factory")

    @classmethod
    def from_environment(cls, *, directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, quota_bytes, maximum_records):
        if cls is not ControlPlaneCustodyClient:
            raise CustodyClientError("custody caller factory cannot be substituted")
        # Snapshot and validate only exact scalar constructor inputs. In
        # particular, no caller-selected trust, endpoint, key or transport enters.
        directory = (directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, quota_bytes, maximum_records)
        for value, minimum, maximum, label in (
            (directory[0], 3, 2**31 - 1, "inherited journal descriptor"),
            (directory[1], 0, 2**64 - 1, "journal device"),
            (directory[2], 1, 2**64 - 1, "journal inode"),
            (directory[3], 0, 2**32 - 2, "journal UID"),
            (directory[4], 0, 2**32 - 2, "journal GID"),
            (directory[5], 1, journal.MAX_QUOTA_BYTES, "journal quota"),
            (directory[6], 1, journal.MAX_RECORDS, "journal record limit"),
        ):
            journal._integer(value, minimum=minimum, maximum=maximum, label=label)
        # Require an existing descriptor before the real runtime loader checks
        # every inherited descriptor against its root-admitted exact inventory.
        os.fstat(directory[0])
        runtime = service.AuthorityRuntimeClient.from_environment(hot_runtime=False)
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("runtime trust did not produce the genuine client")
        relay_path = runtime.socket_path
        relay_uid, relay_gid = runtime.server_uid, runtime.server_gid
        configuration_digest = runtime.configuration_digest
        maximum_deadline_ns = runtime.maximum_deadline_ns
        caller_uid, caller_gid = runtime.control_plane_uid, runtime.control_plane_gid
        attestation = runtime.attestation_evidence
        if type(attestation) is not dict or type(attestation.get("payload")) is not dict:
            raise CustodyClientError("admitted runtime attestation payload is unavailable")
        attestation_payload = attestation["payload"]
        attestation_interval = (attestation_payload.get("issuedAtEpochNs"),
            attestation_payload.get("expiresAtEpochNs"))
        if (any(type(value) is not int or not 1 <= value <= (1 << 63) - 1
                for value in attestation_interval)
                or attestation_interval[0] >= attestation_interval[1]):
            raise CustodyClientError("admitted runtime attestation interval is invalid")
        pid = os.getpid()
        if (caller_uid, caller_gid) != directory[3:5]:
            raise CustodyClientError("journal owner differs from the admitted control-plane identity")

        # Opening the journal's private handle before runtime admission would
        # change that exact inherited inventory. Do not reverse this ordering.
        owned_journal = journal.CustodyJournal(directory_fd=directory[0],
            expected_device=directory[1], expected_inode=directory[2],
            expected_uid=directory[3], expected_gid=directory[4],
            quota_bytes=directory[5], maximum_records=directory[6])
        try:
            client = object.__new__(ControlPlaneCustodyClient)
            client._binding = _Binding(owned_journal, pid, relay_path, relay_uid,
                relay_gid, configuration_digest, maximum_deadline_ns, caller_uid, caller_gid,
                attestation_interval)
            client._closed = False
            _receipt_now(_snapshot(client))
            return client
        except BaseException:
            try:
                journal.CustodyJournal.close(owned_journal)
            except BaseException:
                pass
            raise

    def append_evidence(self, purpose, originals):
        """Durably prepare opaque raw6 only; do not forward or sign anything."""
        binding = _snapshot(self)
        return journal.CustodyJournal.append_evidence(binding.journal, purpose, originals)

    def append_transition(self, operation, originals):
        """Durably prepare opaque raw7 only; do not forward or sign anything."""
        binding = _snapshot(self)
        return journal.CustodyJournal.append_transition(binding.journal, operation, originals)

    def forward_once(self, localdigest):
        """Claim one durable attempt, then make one fixed relay exchange.

        Any failure after the claim may follow a remote commit. The attempt
        remains spent, including if the deadline elapses before the socket call.
        Old-source originals remain loadable in the journal but cannot be sent
        as a new attempt by this current-source client.
        """
        binding = _snapshot(self)
        record = journal.CustodyJournal.load(binding.journal, localdigest)
        if type(record) is not records.PreparedRecord:
            raise CustodyClientError("journal did not return its actual prepared originals")
        digest, source = record.digest, record.source_revision
        family, selector, originals = record.family, record.selector, record.originals
        if source != authority.SOURCE_REVISION:
            raise CustodyClientError("old-source custody originals require separate reconciliation")
        originals = transport._validate_originals(family, selector, originals)
        _process(binding)
        # Sample monotonic first: sampling and marker publication consume this
        # same deadline, capped by the original receipt's remaining lifetime.
        started_monotonic_ns = time.monotonic_ns()
        now_epoch_ns = _receipt_now(binding)
        deadline_ns = started_monotonic_ns + min(binding.maximum_deadline_ns,
            binding.attestation_interval[1] - now_epoch_ns)
        transport._check_deadline(deadline_ns)
        journal.CustodyJournal.claim_attempt(binding.journal, digest)
        _process(binding)
        _receipt_now(binding)
        transport._check_deadline(deadline_ns)
        observation = transport._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest,
            family=family, selector=selector, originals=originals,
            deadline_ns=deadline_ns, expected_peer_uid=binding.relay_uid,
            expected_peer_gid=binding.relay_gid)
        _process(binding)
        _receipt_now(binding)
        transport._check_deadline(deadline_ns)
        return observation

    def close(self):
        if type(self) is not ControlPlaneCustodyClient:
            raise CustodyClientError("custody caller is not the fixed owner")
        binding, closed = self._binding, self._closed
        if type(binding) is not _Binding or type(binding.journal) is not journal.CustodyJournal:
            raise CustodyClientError("custody caller journal owner is invalid")
        if os.getpid() != binding.pid:
            raise CustodyClientError("forked process cannot close the parent custody caller")
        if not closed:
            self._closed = True
            journal.CustodyJournal.close(binding.journal)

    def __enter__(self):
        _snapshot(self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            ControlPlaneCustodyClient.close(self)
        else:
            try:
                ControlPlaneCustodyClient.close(self)
            except BaseException:
                pass
        return False
