"""Explicit, journal-bound forwarding of already prepared custody originals.

Only ``from_environment`` creates this owner. It admits the genuine root-signed
runtime trust before the journal opens its private directory handle, preserving
the exact inherited-descriptor check. The supplied directory must already be
open in that admitted set; this module provisions neither a directory nor trust.

Append and forward remain available as separate actions. The explicit
append-and-forward methods first complete the actual durable append and only
then invoke the same one-attempt forwarding path. Their result retains the
local record identity; ordinary post-append failures retain it in a bounded
typed error. Cancellation still propagates, with durable IDs discoverable in
the existing journal inventory. Forwarding burns the journal's durable
ATTEMPTED marker before one relay exchange and never clears it after failure.
An unsigned digest/time response is an observation, not a signed durability
receipt, replay result, execution authority or permission to retry. Explicit
reconciliation uses a separate read-only path and never clears ATTEMPTED. A
successful exact readback records a local observation, not execution authority.
The cold startup owner also reuses this admission for existing legacy dispatch;
that dispatch does not acquire custody-journal retry or durability guarantees.
There is no automatic signing, preparation, retry or new HTTP execution route.
The separate registration execution-grant family is retention-only: fixed
append/load methods preserve raw10, while legacy forwarding and reconciliation
reject it before any network exchange or delivery marker.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import time

from serverware import authority_contract as authority
from serverware import authority_custody_caller_transport as transport
from serverware import authority_custody_reconcile_transport as reconciliation
from serverware import authority_service as service
from serverware import control_plane_custody_journal as journal
from serverware import control_plane_custody_records as records


class CustodyClientError(RuntimeError):
    pass


class CustodyForwardOutcomeError(CustodyClientError):
    """A prepared local record exists; no forwarding outcome is established.

    This does not assert that an attempt reached the network or committed.
    Inspect the exact record's existing attempt state; only an attempted record
    can use explicit read-only reconciliation. No retry is authorized here.
    """

    __slots__ = ("local_digest",)

    def __init__(self, local_digest):
        self.local_digest = journal._digest(local_digest)
        super().__init__("custody forwarding outcome is not established; inspect the retained local record")


@dataclass(frozen=True, slots=True)
class CustodyForwardObservation:
    """Local prepared identity plus an unsigned peer observation, not a receipt."""

    local_digest: str
    retained_record_digest: str
    retained_at_epoch_ns: int


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
    runtime_client: service.AuthorityRuntimeClient
    runtime_root_public_key: service.Ed25519PublicKey
    inherited_descriptors: tuple[int, ...]


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


def _forward_prepared(client, binding, local_digest, *, deadline_ns=None):
    """Continue only after actual append returned its durable content identity."""
    digest = journal._digest(local_digest)
    try:
        if client._binding is not binding or client._closed:
            raise CustodyClientError("custody caller changed after durable preparation")
        observation = ControlPlaneCustodyClient.forward_once(client, digest, deadline_ns=deadline_ns)
        if client._binding is not binding or client._closed:
            raise CustodyClientError("custody caller changed during forwarding")
        if type(observation) is not tuple or len(observation) != 2:
            raise CustodyClientError("custody forwarding did not return its exact observation pair")
        retained_digest, retained_at = transport.evidence._response(*observation)
        return CustodyForwardObservation(digest, retained_digest, retained_at)
    except Exception:
        # Neither the original exception's text nor any original byte string
        # enters this error. Preserve process cancellation rather than turning
        # KeyboardInterrupt/SystemExit into an ordinary outcome error.
        raise CustodyForwardOutcomeError(digest) from None


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
        runtime_root_public_key = runtime.runtime_root_public_key
        inherited_descriptors = runtime.inherited_descriptors
        if (not isinstance(runtime_root_public_key, service.Ed25519PublicKey)
                or type(inherited_descriptors) is not tuple
                or not inherited_descriptors
                or any(type(value) is not int or value < 3
                    for value in inherited_descriptors)
                or tuple(sorted(set(inherited_descriptors))) != inherited_descriptors
                or directory[0] not in inherited_descriptors):
            raise CustodyClientError("admitted runtime root or inherited inventory is unavailable")
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
                attestation_interval, runtime, runtime_root_public_key, inherited_descriptors)
            client._closed = False
            _receipt_now(_snapshot(client))
            return client
        except BaseException:
            try:
                journal.CustodyJournal.close(owned_journal)
            except BaseException:
                pass
            raise

    def request_registration_source(self, *, registration_challenge_id,
            published_publication_id, oidc_session_id, deadline_epoch_ns, work,
            deadline_ns=None):
        """Acquire raw four over the admitted relay, without signing or custody.

        Authentication and selector derivation belong to the real application;
        a publication lookup is an observation, not independent provenance.
        The returned bytes require genuine signature and membership replay by
        the next configured consumer. No caller endpoint or new allowance.
        """
        from serverware import authority_webauthn_registration_source_caller as source

        binding = _snapshot(self)
        original = source._produce_request_on_work(
            registration_challenge_id=registration_challenge_id,
            published_publication_id=published_publication_id, oidc_session_id=oidc_session_id,
            deadline_epoch_ns=deadline_epoch_ns, work=work)
        callback = source.request.evidence.production._callback
        before = callback(work, time.monotonic_ns)
        now = callback(work, lambda: _receipt_now(binding))
        source.request.evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
        bound = min(before + binding.maximum_deadline_ns,
            before + min(deadline_epoch_ns, binding.attestation_interval[1]) - now)
        if deadline_ns is not None:
            source._check_deadline(deadline_ns)
            bound = min(bound, deadline_ns)
        source._check_deadline(bound)
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration source caller changed before exchange")
        originals = callback(work, lambda: source._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest, request_bytes=original,
            deadline_ns=bound, expected_peer_uid=binding.relay_uid, expected_peer_gid=binding.relay_gid))
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration source caller changed during exchange")
        callback(work, lambda: _receipt_now(binding))
        source._check_deadline(bound)
        return source._originals(originals)

    def prepare_registration_custody(self, originals, *, deadline_epoch_ns, work,
            deadline_ns=None):
        """Return opaque journal-ready raw6 after actual verifier preparation.

        Input is exact signer request8 + response2, never a successful-proof
        carrier or caller-generated typed request. This neither writes the
        local journal nor forwards to the remote writer.
        """
        from serverware import authority_webauthn_registration_custody_caller as preparing
        from serverware import authority_webauthn_registration_signer_response as verifying

        held = preparing._request_originals(originals)
        verifying.evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
        expiry, inherited = deadline_epoch_ns, deadline_ns
        if inherited is not None:
            verifying.evidence.plan.contract._integer(inherited, minimum=1)
        binding = _snapshot(self)
        callback = verifying.evidence.production._callback
        before = callback(work, time.monotonic_ns)
        now = callback(work, lambda: _receipt_now(binding))
        bound = min(before + binding.maximum_deadline_ns,
            before + min(expiry, binding.attestation_interval[1]) - now)
        if inherited is not None:
            bound = min(bound, inherited)
        preparing._check_deadline(bound)
        result = callback(work, lambda: preparing._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest, deadline_epoch_ns=expiry,
            originals=held, deadline_ns=bound, expected_peer_uid=binding.relay_uid,
            expected_peer_gid=binding.relay_gid))
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration custody caller changed during preparation")
        callback(work, lambda: _receipt_now(binding))
        preparing._check_deadline(bound)
        return preparing._response_originals(result)

    def prepare_registration_execution_plan(self, originals, *, deadline_epoch_ns,
            work, deadline_ns=None):
        """Obtain original planning request3/response4 and a complete vector.

        The fixed verifier, not the browser, acquires and joins the vector.
        Returned bytes are not current-root authority or an execution grant.
        The separate caller/authorizer exchange must authenticate them again.
        """
        from serverware import authority_webauthn_registration_execution_caller as preparing
        from serverware import authority_webauthn_registration_signer_response as verifying

        held = preparing._request_originals(originals)
        verifying.evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
        expiry, inherited = deadline_epoch_ns, deadline_ns
        if inherited is not None:
            verifying.evidence.plan.contract._integer(inherited, minimum=1)
        binding = _snapshot(self)
        callback = verifying.evidence.production._callback
        before = callback(work, time.monotonic_ns)
        now = callback(work, lambda: _receipt_now(binding))
        bound = min(before + binding.maximum_deadline_ns,
            before + min(expiry, binding.attestation_interval[1]) - now)
        if inherited is not None:
            bound = min(bound, inherited)
        preparing._check_deadline(bound)
        result = callback(work, lambda: preparing._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest, deadline_epoch_ns=expiry,
            originals=held, deadline_ns=bound, expected_peer_uid=binding.relay_uid,
            expected_peer_gid=binding.relay_gid))
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration execution caller changed during preparation")
        callback(work, lambda: _receipt_now(binding))
        preparing._check_deadline(bound)
        return preparing._response_originals(result)

    def prepare_registration_finalization(self, originals, *, sibling_challenge_ids,
            deadline_epoch_ns, work, deadline_ns=None):
        """Return opaque raw7 from original signer raw10 and bounded lookup hints.

        The configured verifier authenticates and regenerates the invocation;
        sibling IDs are never population proof. No signing, journal append,
        writer forwarding or registration/session activation happens here.
        """
        return ControlPlaneCustodyClient._prepare_registration_finalization(self, originals,
            sibling_challenge_ids=sibling_challenge_ids, deadline_epoch_ns=deadline_epoch_ns,
            work=work, deadline_ns=deadline_ns, execution=False)

    def prepare_registration_finalization_execution(self, originals, *, sibling_challenge_ids,
            deadline_epoch_ns, work, deadline_ns=None):
        """Return new finalization raw7 plus its same-read complete before-vector.

        The dedicated caller authorization must already exist. This fixed
        profile never accepts a browser vector or upgrades an older plan.
        Neither transport nor the returned originals are execution permission.
        """
        return ControlPlaneCustodyClient._prepare_registration_finalization(self, originals,
            sibling_challenge_ids=sibling_challenge_ids, deadline_epoch_ns=deadline_epoch_ns,
            work=work, deadline_ns=deadline_ns, execution=True)

    def _prepare_registration_finalization(self, originals, *, sibling_challenge_ids,
            deadline_epoch_ns, work, deadline_ns, execution):
        from serverware import authority_webauthn_registration_custody_caller as raw
        from serverware import authority_webauthn_registration_finalization_caller as preparing
        from serverware import authority_webauthn_registration_signer_response as verifying

        if type(execution) is not bool:
            raise CustodyClientError("registration finalization planning profile is not source fixed")
        if execution:
            from serverware import authority_webauthn_registration_finalization_execution_caller as preparing
        ledger = verifying.evidence.capture._SharedLedger(work)
        held = raw._request_originals(originals)
        verifying.evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
        expiry, inherited = deadline_epoch_ns, deadline_ns
        if inherited is not None:
            verifying.evidence.plan.contract._integer(inherited, minimum=1)
        if (type(sibling_challenge_ids) is not list
                or len(sibling_challenge_ids) > verifying.production.registration.MAX_SIBLINGS):
            raise CustodyClientError("registration finalization sibling hints exceed their source bound")
        siblings = verifying.evidence.capture._JSONCapture(ledger,
            maximum_bytes=preparing.MAX_HINTS_BYTES).visit(sibling_challenge_ids)
        previous = None
        for value in siblings:
            verifying.production.registration._text(value, "sibling challenge ID", 4096, work)
            if previous is not None:
                work.prepare_comparison(previous, value)
                if previous >= value:
                    raise CustodyClientError("registration finalization sibling hints are not sorted unique")
            previous = value
        hints = verifying.evidence.capability._wire(siblings, ledger,
            preparing.MAX_HINTS_BYTES, 64)
        work.charge(input_bytes=sum(len(value) for value in held) + len(hints))
        request = preparing._request_originals(held + (hints,))
        binding = _snapshot(self)
        callback = verifying.evidence.production._callback
        before = callback(work, time.monotonic_ns)
        now = callback(work, lambda: _receipt_now(binding))
        bound = min(before + binding.maximum_deadline_ns,
            before + min(expiry, binding.attestation_interval[1]) - now)
        if inherited is not None:
            bound = min(bound, inherited)
        preparing._check_deadline(bound)
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration finalization caller changed before exchange")
        result = callback(work, lambda: preparing._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest, deadline_epoch_ns=expiry,
            originals=request, deadline_ns=bound, expected_peer_uid=binding.relay_uid,
            expected_peer_gid=binding.relay_gid))
        if _snapshot(self) is not binding:
            raise CustodyClientError("registration finalization caller changed during preparation")
        callback(work, lambda: _receipt_now(binding))
        preparing._check_deadline(bound)
        return preparing._response_originals(result)

    def append_evidence(self, purpose, originals):
        """Durably prepare opaque raw6 only; do not forward or sign anything."""
        binding = _snapshot(self)
        return journal.CustodyJournal.append_evidence(binding.journal, purpose, originals)

    def append_transition(self, operation, originals):
        """Durably prepare opaque raw7 only; do not forward or sign anything."""
        binding = _snapshot(self)
        return journal.CustodyJournal.append_transition(binding.journal, operation, originals)

    def append_registration_execution_grant(self, originals):
        """Retain the separate raw10 grant bundle, without a delivery attempt.

        The journal uses its distinct format and content-identity domain. A
        returned local digest establishes neither genuine grant verification
        nor current authorization, remote custody or credential finalization.
        """
        binding = _snapshot(self)
        return journal.CustodyJournal.append_registration_execution_grant(
            binding.journal, originals)

    def load_registration_execution_grant(self, localdigest):
        """Return exact opaque originals and their retained source revision.

        Loading is not renewed grant admission. Historical originals remain
        available even if their authority has expired; a future action must
        genuinely verify the original grant and its independently current scope.
        """
        from serverware import control_plane_registration_execution_records as grants

        digest = journal._digest(localdigest)
        binding = _snapshot(self)
        record = journal.CustodyJournal.load(binding.journal, digest)
        if (type(record) is not records.PreparedRecord or record.digest != digest
                or (record.family, record.selector) != (grants.FAMILY, grants.OPERATION)):
            raise CustodyClientError("local record is not the distinct registration execution grant bundle")
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading execution grant originals")
        return record

    def append_registration_signer_exchange(self, originals):
        """Retain opaque signer request8/response2 without a delivery attempt.

        This distinct content ID does not associate the exchange with a grant,
        authenticate evidence or authorize registration finalization.
        """
        binding = _snapshot(self)
        return journal.CustodyJournal.append_registration_signer_exchange(
            binding.journal, originals)

    def load_registration_signer_exchange(self, localdigest):
        """Load exact historical signer originals/source, not successful replay.

        Future use requires genuine original verification and independent
        current scope. Loading never renews the retained signed lifetimes.
        """
        from serverware import control_plane_registration_signer_records as signer

        digest = journal._digest(localdigest)
        binding = _snapshot(self)
        record = journal.CustodyJournal.load(binding.journal, digest)
        if (type(record) is not records.PreparedRecord or record.digest != digest
                or (record.family, record.selector) != (signer.FAMILY, signer.OPERATION)):
            raise CustodyClientError("local record is not the distinct registration signer exchange")
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading signer originals")
        return record

    def append_registration_preparation(self, execution_originals, *, signer_originals):
        """Retain both inventories and their final immutable local association.

        Only real application preparation supplies the same-call originals.
        Lower-level storage is opaque: association does not authenticate a
        grant or signer, consume an operation or permit finalization. Failure
        can follow publication and must not trigger automatic signing/retry.
        """
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_preparation(
            binding.journal, execution_originals, signer_originals=signer_originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining registration preparation")
        return journal._digest(digest)

    def load_registration_preparation(self, execution_digest):
        """Read associated (grant, signer) PreparedRecords, never action authority.

        The actual journal rereads the final marker and both original records;
        absent association is not repaired or inferred from matching metadata.
        These historical originals still need genuine replay under independently
        admitted scope. Their lifetimes are not renewed by this read.
        """
        from serverware import control_plane_registration_execution_records as grants
        from serverware import control_plane_registration_signer_records as signer

        digest = journal._digest(execution_digest)
        binding = _snapshot(self)
        pair = journal.CustodyJournal.load_registration_preparation(binding.journal, digest)
        if (type(pair) is not tuple or len(pair) != 2
                or any(type(item) is not records.PreparedRecord for item in pair)):
            raise CustodyClientError("registration preparation lacks its exact original record pair")
        execution_record, signer_record = pair
        if (execution_record.digest != digest
                or (execution_record.family, execution_record.selector) != (grants.FAMILY, grants.OPERATION)
                or (signer_record.family, signer_record.selector) != (signer.FAMILY, signer.OPERATION)
                or execution_record.source_revision != signer_record.source_revision):
            raise CustodyClientError("registration preparation original record scope differs")
        journal._digest(signer_record.digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading registration preparation")
        return pair

    def append_registration_finalization_preparation(self, originals, *, evidence_local_digest):
        """Commit exact finalization originals and their existing evidence/signer link.

        The local association supplies no replay, permission or execution
        result. A late caller-lifetime failure does not remove durable bytes
        or authorize automatic signing, exchange or publication retry.
        """
        evidence_digest = journal._digest(evidence_local_digest)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_preparation(
            binding.journal, originals, evidence_local_digest=evidence_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization preparation")
        return journal._digest(digest)

    def load_registration_finalization_preparation(self, finalization_digest):
        """Reread (finalization record, evidence locator, exact original pair)."""
        from serverware import control_plane_registration_finalization_records as finalization
        from serverware import control_plane_registration_execution_records as evidence
        from serverware import control_plane_registration_signer_records as signer

        digest = journal._digest(finalization_digest)
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_registration_finalization_preparation(binding.journal, digest)
        if (type(result) is not tuple or len(result) != 3
                or type(result[0]) is not records.PreparedRecord
                or type(result[2]) is not tuple or len(result[2]) != 2
                or any(type(record) is not records.PreparedRecord for record in result[2])):
            raise CustodyClientError("finalization preparation lacks its exact retained original inventory")
        finalization_record, evidence_digest, pair = result
        journal._digest(evidence_digest)
        evidence_record, signer_record = pair
        journal._digest(signer_record.digest)
        if (finalization_record.digest != digest or evidence_record.digest != evidence_digest
                or (finalization_record.family, finalization_record.selector)
                    != (finalization.FAMILY, finalization.OPERATION)
                or (evidence_record.family, evidence_record.selector) != (evidence.FAMILY, evidence.OPERATION)
                or (signer_record.family, signer_record.selector) != (signer.FAMILY, signer.OPERATION)
                or finalization_record.source_revision != evidence_record.source_revision
                or evidence_record.source_revision != signer_record.source_revision
                or len({digest, evidence_digest, signer_record.digest}) != 3):
            raise CustodyClientError("finalization preparation original record scope differs")
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading finalization preparation")
        return result

    def append_registration_finalization_reservation(self, finalization_digest, originals):
        """Retain raw3 under the complete finalization chain, never authenticate it."""
        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_reservation(
            binding.journal, local, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization reservation")
        return journal._digest(digest)

    def load_registration_finalization_reservation(self, finalization_digest):
        """Reread opaque reservation and complete chain; absence is not remote failure."""
        from serverware import control_plane_registration_finalization_reservation_records as reservations

        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        record = journal.CustodyJournal.load_registration_finalization_reservation(binding.journal, local)
        if record is not None:
            if (type(record) is not reservations.FinalizationReservationRecord
                    or record.finalization_digest != local):
                raise CustodyClientError("finalization reservation original scope differs")
            journal._digest(record.digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading finalization reservation")
        return record

    def claim_registration_finalization_sql_attempt(self, finalization_digest):
        """Durably burn one finalization dispatch; never clear or retry the claim."""
        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        journal.CustodyJournal.claim_registration_finalization_sql_attempt(binding.journal, local)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after finalization SQL claim")

    def claim_oidc_session_activation_release(self, *, client_authorization_digest,
            request_identity, profile, server_bootstrap_digest, expected_outcome_digest):
        """Durably burn a public-only release grant; never store frames or tokens.

        The actual configured caller supplies genuine root-admitted identities,
        meters the fixed metadata bound, and keeps its current guard around this
        native-only operation. Local durability grants no release permission.
        """
        from serverware import control_plane_oidc_session_activation_release_attempt as attempts

        record, _encoded = attempts.encode(
            client_authorization_digest=client_authorization_digest,
            request_identity=request_identity, profile=profile,
            server_bootstrap_digest=server_bootstrap_digest,
            expected_outcome_digest=expected_outcome_digest)
        binding = _snapshot(self)
        journal.CustodyJournal.claim_oidc_session_activation_release(binding.journal,
            client_authorization_digest=record.client_authorization_digest,
            request_identity=record.request_identity, profile=record.profile,
            server_bootstrap_digest=record.server_bootstrap_digest,
            expected_outcome_digest=record.expected_outcome_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after release dispatch claim")

    def claim_oidc_session_activation_dispatch(self, *, finalization_digest,
            request_binding_digest, authorization_enrollment_digest, source_revision):
        """Durably burn one retained activation target without storing secrets.

        Genuine same-call ownership/permission admission and current metering
        belong to the configured caller. This facade accepts metadata only;
        an exact recovered claim never succeeds as a new dispatch permission.
        """
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts

        record, _encoded = attempts.encode(finalization_digest=finalization_digest,
            request_binding_digest=request_binding_digest,
            authorization_enrollment_digest=authorization_enrollment_digest,
            source_revision=source_revision)
        binding = _snapshot(self)
        journal.CustodyJournal.claim_oidc_session_activation_dispatch(binding.journal,
            finalization_digest=record.finalization_digest,
            request_binding_digest=record.request_binding_digest,
            authorization_enrollment_digest=record.authorization_enrollment_digest,
            source_revision=record.source_revision)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after activation dispatch claim")

    def _append_activation_stage(self, finalization_digest, kind, originals):
        """Fixed retention-only stages; caller precharges and guards this I/O."""
        from serverware import control_plane_oidc_session_activation_records as activation

        local = journal._digest(finalization_digest)
        held = activation._originals(activation._profile(kind), originals)
        binding = _snapshot(self)
        digest = journal.CustodyJournal._append_activation_record(
            binding.journal, local, kind, held)
        journal._digest(digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after activation stage retention")
        return digest

    def append_oidc_session_activation_preparation(self, finalization_digest, originals):
        """Retain exact auth/plan/cipher/expectations/before-vector, not a DTO."""
        return ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "prepared", originals)

    def append_oidc_session_activation_grant(self, finalization_digest, originals):
        """Retain the actual signed grant original before reservation."""
        return ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "grant", originals)

    def append_oidc_session_activation_reservation(self, finalization_digest, originals):
        """Retain exact reserve request/snapshot/ACK before claiming SQL."""
        return ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "reserved", originals)

    def claim_oidc_session_activation_sql_attempt(self, finalization_digest):
        """Burn SQL once; an identical or recovered claim never permits resend."""
        ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "sql-claimed", ())

    def append_oidc_session_activation_sql_outcome(self, finalization_digest, originals):
        """Retain unsigned raw4 before interpretation without authenticating it."""
        return ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "sql-outcome", originals)

    def append_oidc_session_activation_completion_outcome(self, finalization_digest, originals):
        """Retain actual completion originals before interpreting their authority."""
        return ControlPlaneCustodyClient._append_activation_stage(
            self, finalization_digest, "completion-outcome", originals)

    def load_oidc_session_activation_records(self, finalization_digest):
        """Ordinary read-only history, never a resume/retry authority carrier."""
        from serverware import control_plane_oidc_session_activation_records as activation

        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_records(binding.journal, local)
        if (type(retained) is not activation.ActivationRecords
                or retained.finalization_digest != local):
            raise CustodyClientError("activation retained original scope differs")
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading activation originals")
        return retained

    def claim_oidc_session_activation_consume_planning(self, *, finalization_digest,
            activation_authorization_digest, source_revision):
        """Burn one consume preparation under this owner's actual activation target."""
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        record, _encoded = consume.encode("claimed", finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            originals=(), source_revision=source_revision)
        binding = _snapshot(self)
        slot = journal.CustodyJournal.claim_oidc_session_activation_consume_planning(binding.journal,
            finalization_digest=record.finalization_digest,
            activation_authorization_digest=record.activation_authorization_digest,
            source_revision=record.source_revision)
        if slot != record.slot_digest or _snapshot(self) is not binding:
            raise CustodyClientError("custody caller or consume target changed after planning claim")
        return slot

    def _append_consume_stage(self, *, finalization_digest,
            activation_authorization_digest, kind, originals):
        """Token-free response retention; actual caller precharges and guards I/O."""
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        target = journal._digest(finalization_digest)
        authorization_digest = journal._digest(activation_authorization_digest)
        held = consume._originals(consume._profile(kind), originals)
        binding = _snapshot(self)
        digest = journal.CustodyJournal._append_consume_record(binding.journal,
            finalization_digest=target, activation_authorization_digest=authorization_digest,
            kind=kind, originals=held)
        journal._digest(digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after consume response retention")
        return digest

    def append_oidc_session_activation_consume_prepared(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain original raw6 before interpretation, never a plan admission DTO."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="prepared", originals=originals)

    def append_oidc_session_activation_consume_exported(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain original raw7 before interpretation without a token or retry."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="exported", originals=originals)

    def load_oidc_session_activation_consume_records(self, *, finalization_digest,
            activation_authorization_digest):
        """Read bounded ordinary history, not a recovered permission to continue."""
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        target = journal._digest(finalization_digest)
        authorization_digest = journal._digest(activation_authorization_digest)
        slot = consume._slot_digest(target, authorization_digest)
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_consume_records(binding.journal,
            finalization_digest=target, activation_authorization_digest=authorization_digest)
        if (type(retained) is not consume.ConsumeRecords
                or type(retained.claim) is not consume.ConsumeRecord
                or retained.claim.slot_digest != slot
                or retained.claim.finalization_digest != target
                or retained.claim.activation_authorization_digest != authorization_digest):
            raise CustodyClientError("consume retained original scope differs")
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading consume originals")
        return retained

    def append_registration_finalization_sql_outcome(self, finalization_digest, originals):
        """Retain first unsigned raw4 without a renewed clock or success assertion."""
        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_sql_outcome(
            binding.journal, local, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization SQL outcome")
        return journal._digest(digest)

    def append_registration_finalization_completion_outcome(self, finalization_digest, originals):
        """Retain bounded completion originals before separate semantic admission."""
        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_completion_outcome(
            binding.journal, local, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization completion")
        return journal._digest(digest)

    def append_registration_finalization_completion_reconciliation(self, finalization_digest, originals):
        """Retain a separate acknowledged carrier, never overwrite uncertainty."""
        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_completion_reconciliation(
            binding.journal, local, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization reconciliation")
        return journal._digest(digest)

    def load_registration_finalization_outcomes(self, finalization_digest):
        """Reread complete original linkage; absence never establishes nonexecution."""
        from serverware import control_plane_registration_finalization_outcome_records as outcomes

        local = journal._digest(finalization_digest)
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_registration_finalization_outcomes(binding.journal, local)
        if (type(result) is not outcomes.FinalizationOutcomes or result.finalization_digest != local):
            raise CustodyClientError("finalization SQL outcomes differ from their local preparation")
        for kind, record in zip(outcomes.KINDS, (result.sql_attempt, result.sql_outcome,
                result.completion_outcome, result.completion_reconciled)):
            if record is not None:
                if (type(record) is not outcomes.FinalizationOutcomeRecord
                        or record.finalization_digest != local or record.kind != kind
                        or record.source_revision != result.source_revision):
                    raise CustodyClientError("finalization SQL outcome record scope differs")
                journal._digest(record.digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading finalization SQL outcomes")
        return result

    def append_registration_reservation(self, local_digest, originals):
        """Retain bounded raw3; independent reserve authentication remains required."""
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_reservation(
            binding.journal, local_digest, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining registration reservation")
        return journal._digest(digest)

    def claim_registration_sql_attempt(self, local_digest):
        """Fsync the irreversible local claim before caller-owned SQL dispatch.

        This owns no network send, remote permission or retry. Every repeated
        claim fails, including after an uncertain send or a missing response.
        """
        binding = _snapshot(self)
        journal.CustodyJournal.claim_registration_sql_attempt(binding.journal, local_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after registration SQL claim")

    def append_registration_sql_outcome(self, local_digest, originals):
        """Retain only the first exact raw4; do not infer remote commit from it."""
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_sql_outcome(
            binding.journal, local_digest, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining registration SQL outcome")
        return journal._digest(digest)

    def append_registration_completion_outcome(self, local_digest, originals):
        """Retain opaque raw4, never replace uncertainty with a later response."""
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_completion_outcome(
            binding.journal, local_digest, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining registration completion outcome")
        return journal._digest(digest)

    def load_registration_outcomes(self, local_digest):
        """Return bounded local originals/IDs; no successful carrier is admitted."""
        from serverware import control_plane_registration_outcome_records as outcomes

        digest = journal._digest(local_digest)
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_registration_outcomes(binding.journal, digest)
        if (type(result) is not outcomes.RegistrationOutcomes or result.local_digest != digest):
            raise CustodyClientError("registration outcomes differ from the requested local preparation")
        for kind, record in zip(outcomes.KINDS, (result.reservation, result.sql_attempt,
                result.sql_outcome, result.completion_outcome, result.completion_reconciled)):
            if record is not None:
                if (type(record) is not outcomes.RegistrationOutcomeRecord
                        or record.local_digest != digest or record.kind != kind
                        or record.source_revision != result.source_revision):
                    raise CustodyClientError("registration outcome record scope differs")
                journal._digest(record.digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading registration outcomes")
        return result

    def append_registration_completion_reconciliation(self, local_digest, originals):
        """Retain one separate raw4 after uncertainty; caller owns verification."""
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_completion_reconciliation(
            binding.journal, local_digest, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining registration reconciliation")
        return journal._digest(digest)

    def append_and_forward_evidence(self, purpose, originals, *, deadline_ns=None):
        """Append actual raw6 durably, then attempt its forwarding exactly once.

        Append failure propagates without forwarding. An ordinary later
        failure exposes only CustodyForwardOutcomeError.local_digest for the
        retained record. The unsigned result is not custody or business success.
        """
        binding = _snapshot(self)
        digest = ControlPlaneCustodyClient.append_evidence(self, purpose, originals)
        return _forward_prepared(self, binding, digest, deadline_ns=deadline_ns)

    def append_and_forward_transition(self, operation, originals):
        """Append actual raw7 durably, then use the unchanged one-attempt path.

        Neither an existing ATTEMPTED record nor a late failure is reset or
        retried. Cancellation propagates; local inventory retains durable IDs.
        """
        binding = _snapshot(self)
        digest = ControlPlaneCustodyClient.append_transition(self, operation, originals)
        return _forward_prepared(self, binding, digest)

    def inventory(self):
        """Read bounded local metadata; do not claim fresh remote authority."""
        binding = _snapshot(self)
        return journal.CustodyJournal.inventory(binding.journal)

    def observation(self, localdigest):
        """Read the first local readback observation, not a live receipt."""
        binding = _snapshot(self)
        return journal.CustodyJournal.load_observation(binding.journal, localdigest)

    def _request_authority(self, *, operation, input_value):
        """Reuse cold admission for existing legacy dispatch, without retries.

        The actual runtime client retains its existing operation allowlist and
        response verification. No custody write barrier or successor execution
        authorization is supplied by this compatibility composition.
        """
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("cold admission did not retain the actual runtime client")
        _receipt_now(binding)
        result = service.AuthorityRuntimeClient.request(runtime,
            operation=operation, input_value=input_value)
        _process(binding)
        _receipt_now(binding)
        journal.CustodyJournal._require_ready(binding.journal)
        return result

    def forward_once(self, localdigest, *, deadline_ns=None):
        """Claim one durable attempt, then make one fixed relay exchange.

        Any failure after the claim may follow a remote commit. The attempt
        remains spent, including if the deadline elapses before the socket call.
        Old-source originals remain loadable in the journal but cannot be sent
        as a new attempt by this current-source client.
        """
        inherited = deadline_ns
        if inherited is not None:
            transport._check_deadline(inherited)
        binding = _snapshot(self)
        record = journal.CustodyJournal.load(binding.journal, localdigest)
        if type(record) is not records.PreparedRecord:
            raise CustodyClientError("journal did not return its actual prepared originals")
        digest, source = record.digest, record.source_revision
        family, selector, originals = record.family, record.selector, record.originals
        if family not in ("evidence", "transition"):
            raise CustodyClientError("retention-only originals have no custody forwarding contract")
        if source != authority.SOURCE_REVISION:
            raise CustodyClientError("old-source custody originals require versioned historical replay")
        originals = transport._validate_originals(family, selector, originals)
        _process(binding)
        # Sample monotonic first: sampling and marker publication consume this
        # same deadline, capped by the original receipt's remaining lifetime.
        started_monotonic_ns = time.monotonic_ns()
        now_epoch_ns = _receipt_now(binding)
        deadline_ns = started_monotonic_ns + min(binding.maximum_deadline_ns,
            binding.attestation_interval[1] - now_epoch_ns)
        if inherited is not None:
            deadline_ns = min(deadline_ns, inherited)
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

    def reconcile(self, localdigest):
        """Explicitly read back an attempted record without repeating its write.

        The verifier authenticates original controls against admitted historical
        keys and requests a fresh lookup, not a new retention attempt. A missing
        row or failed response is not proof of absence. Successful originals
        remain ordinary peer observations, not signed durability receipts.
        Neither result changes the irreversible local attempt marker.
        """
        binding = _snapshot(self)
        digest = journal._digest(localdigest)
        inventory = journal.CustodyJournal.inventory(binding.journal)
        entry = next((item for item in inventory if item.digest == digest), None)
        if type(entry) is not journal.JournalEntry or entry.attempted is not True:
            raise CustodyClientError("custody reconciliation requires a retained attempted record")
        # load rechecks the exact originals and existing attempt marker on disk;
        # inventory alone is not the durable storage check.
        record = journal.CustodyJournal.load(binding.journal, digest)
        if type(record) is not records.PreparedRecord or record.digest != digest:
            raise CustodyClientError("journal did not return the exact prepared originals")
        if record.source_revision != authority.SOURCE_REVISION:
            raise CustodyClientError("old-source custody originals require versioned historical replay")
        family, selector = record.family, record.selector
        if family not in ("evidence", "transition"):
            raise CustodyClientError("retention-only originals have no custody reconciliation contract")
        originals = reconciliation._validate_originals(family, selector, record.originals)
        _process(binding)
        started_monotonic_ns = time.monotonic_ns()
        now_epoch_ns = _receipt_now(binding)
        deadline_ns = started_monotonic_ns + min(binding.maximum_deadline_ns,
            binding.attestation_interval[1] - now_epoch_ns)
        reconciliation._check_deadline(deadline_ns)
        observation = reconciliation._socket_request(binding.relay_path,
            configuration_digest=binding.configuration_digest,
            family=family, selector=selector, originals=originals,
            deadline_ns=deadline_ns, expected_peer_uid=binding.relay_uid,
            expected_peer_gid=binding.relay_gid)
        _process(binding)
        _receipt_now(binding)
        reconciliation._check_deadline(deadline_ns)
        if observation[:-2] != originals[2:-1]:
            raise CustodyClientError("custody reconciliation returned different original plan bytes")
        previous = journal.CustodyJournal.load_observation(binding.journal, digest)
        if previous is None:
            journal.CustodyJournal.record_observation(binding.journal, digest,
                retained_record_digest=observation[-2], retained_at_epoch_ns=observation[-1],
                configuration_digest=binding.configuration_digest)
        elif (previous.retained_record_digest, previous.retained_at_epoch_ns) != observation[-2:]:
            raise CustodyClientError("fresh custody readback differs from the first durable observation")
        # An earlier observation keeps its original configuration/source
        # provenance even after rotation. It never substitutes for the fresh
        # read above and is never silently rewritten to claim current trust.
        _process(binding)
        _receipt_now(binding)
        reconciliation._check_deadline(deadline_ns)
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
