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

    def append_public_revocation(self, kind, parent, originals):
        binding = _snapshot(self)
        result = journal.CustodyJournal.append_public_revocation(binding.journal, kind, parent, originals)
        if _snapshot(self) is not binding:
            raise CustodyClientError("public revocation custody changed during durable append")
        return result

    def load_public_revocation_options(self, local_digest):
        from serverware import control_plane_public_revocation_records as public
        binding = _snapshot(self)
        result = journal.CustodyJournal.load(binding.journal, local_digest)
        if (result.family != public.RETENTION_FAMILY or result.selector != "options"
                or result.source_revision != authority.SOURCE_REVISION
                or _snapshot(self) is not binding):
            raise CustodyClientError("public revocation options have another actual retained profile")
        return result

    def lookup_public_revocation_options(self, options_digest):
        """Read-only actual parent/child originals; no caller-supplied verdict."""
        binding = _snapshot(self)
        result = journal.CustodyJournal.lookup_public_revocation_options(binding.journal, options_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("public revocation custody changed during parent lookup")
        return result

    def claim_public_revocation(self, request_digest):
        binding = _snapshot(self)
        journal.CustodyJournal.claim_public_revocation(binding.journal, request_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("public revocation custody changed after its irreversible local claim")

    def load_public_revocation(self, request_digest):
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_public_revocation(binding.journal, request_digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("public revocation custody changed while reading originals")
        return result

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

    def load_registration_preparation(self, execution_digest, *,
            maximum_original_bytes=None, work=None, current=None):
        """Read associated (grant, signer) PreparedRecords, never action authority.

        The actual journal rereads the final marker and both original records;
        absent association is not repaired or inferred from matching metadata.
        These historical originals still need genuine replay under independently
        admitted scope. Their lifetimes are not renewed by this read. All three
        optional keywords select the direct same-work preallocated read; never
        wrap that branch in a stable production callback. No keywords preserves
        the previous unmetered API behavior.
        """
        from serverware import control_plane_registration_execution_records as grants
        from serverware import control_plane_registration_signer_records as signer

        digest = journal._digest(execution_digest)
        metered = any(value is not None for value in (maximum_original_bytes, work, current))
        if metered:
            from serverware.authority_query_read_work import _ValidationWork

            journal._integer(maximum_original_bytes, minimum=1,
                maximum=journal.REGISTRATION_PREPARATION_MAX_BYTES,
                label="registration preparation remaining byte capacity")
            if type(work) is not _ValidationWork or not callable(current):
                raise CustodyClientError("registration preparation requires all original work/guard/cap inputs")
            current()
        binding = _snapshot(self)
        if metered:
            pair = journal.CustodyJournal.load_registration_preparation(binding.journal, digest,
                maximum_original_bytes=maximum_original_bytes, work=work, current=current)
            current()
        else:
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
        if metered:
            current()
        return pair

    def load_registration_recovery_history(self, execution_digest, *,
            maximum_original_bytes, work, current):
        """Direct same-work pair/outcomes read with one aggregate preflight.

        Returned source labels and response originals are data, not authority;
        missing history never grants retry or a different historical cohort.
        """
        from serverware.authority_query_read_work import _ValidationWork
        from serverware import control_plane_registration_execution_records as grants
        from serverware import control_plane_registration_signer_records as signer
        from serverware import control_plane_registration_outcome_records as outcomes

        digest = journal._digest(execution_digest)
        journal._integer(maximum_original_bytes, minimum=1,
            maximum=journal.REGISTRATION_PREPARATION_MAX_BYTES,
            label="registration recovery history remaining byte capacity")
        if type(work) is not _ValidationWork or not callable(current):
            raise CustodyClientError("registration recovery history requires original work and current guard")
        current()
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_registration_recovery_history(binding.journal, digest,
            maximum_original_bytes=maximum_original_bytes, work=work, current=current)
        current()
        if (type(result) is not tuple or len(result) != 2
                or type(result[0]) is not tuple or len(result[0]) != 2
                or any(type(record) is not records.PreparedRecord for record in result[0])
                or type(result[1]) is not outcomes.RegistrationOutcomes):
            raise CustodyClientError("registration recovery history requires its exact pair and outcome inventory")
        (execution_record, signer_record), observed = result
        if (execution_record.digest != digest or observed.local_digest != digest
                or (execution_record.family, execution_record.selector) != (grants.FAMILY, grants.OPERATION)
                or (signer_record.family, signer_record.selector) != (signer.FAMILY, signer.OPERATION)
                or execution_record.source_revision != signer_record.source_revision
                or observed.source_revision != execution_record.source_revision):
            raise CustodyClientError("registration recovery preparation/outcome scope differs")
        journal._digest(signer_record.digest)
        for kind, record in zip(outcomes.KINDS, (observed.reservation, observed.sql_attempt,
                observed.sql_outcome, observed.completion_outcome, observed.completion_reconciled)):
            if record is not None:
                if (type(record) is not outcomes.RegistrationOutcomeRecord
                        or record.local_digest != digest or record.kind != kind
                        or record.source_revision != observed.source_revision):
                    raise CustodyClientError("registration recovery outcome record scope differs")
                journal._digest(record.digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading registration recovery history")
        current()
        return result

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

    def load_registration_finalization_completion_history(self, finalization_digest, *,
            maximum_original_bytes, work, current):
        """Direct metered combined history read; never wrap in a stable callback."""
        from serverware import control_plane_registration_finalization_records as finalization
        from serverware import control_plane_registration_execution_records as evidence
        from serverware import control_plane_registration_signer_records as signer
        from serverware import control_plane_registration_finalization_reservation_records as reservations
        from serverware import control_plane_registration_finalization_outcome_records as final_outcomes
        from serverware import control_plane_registration_outcome_records as prior_outcomes

        local = journal._digest(finalization_digest)
        journal._integer(maximum_original_bytes, minimum=1, maximum=64 * 1024 * 1024,
            label="combined finalization history byte allowance")
        if not callable(current):
            raise CustodyClientError("combined finalization history requires its original guard")
        current()
        binding = _snapshot(self)
        result = journal.CustodyJournal.load_registration_finalization_completion_history(
            binding.journal, local, maximum_original_bytes=maximum_original_bytes,
            work=work, current=current)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading combined finalization history")
        if type(result) is not tuple or len(result) != 4:
            raise CustodyClientError("combined finalization history requires its exact four-part inventory")
        preparation, reservation, observed, prior = result
        if (type(preparation) is not tuple or len(preparation) != 3
                or type(preparation[0]) is not records.PreparedRecord
                or type(preparation[2]) is not tuple or len(preparation[2]) != 2
                or any(type(value) is not records.PreparedRecord for value in preparation[2])):
            raise CustodyClientError("combined history lacks its original preparation tuple")
        final_record, evidence_digest, pair = preparation
        journal._digest(evidence_digest)
        evidence_record, signer_record = pair
        journal._digest(signer_record.digest)
        if (final_record.digest != local or evidence_record.digest != evidence_digest
                or (final_record.family, final_record.selector) != (finalization.FAMILY, finalization.OPERATION)
                or (evidence_record.family, evidence_record.selector) != (evidence.FAMILY, evidence.OPERATION)
                or (signer_record.family, signer_record.selector) != (signer.FAMILY, signer.OPERATION)
                or evidence_record.source_revision != final_record.source_revision
                or signer_record.source_revision != final_record.source_revision
                or len({local, evidence_digest, signer_record.digest}) != 3):
            raise CustodyClientError("combined preparation source, families or association differ")
        if reservation is not None:
            if (type(reservation) is not reservations.FinalizationReservationRecord
                    or reservation.finalization_digest != local
                    or reservation.source_revision != final_record.source_revision):
                raise CustodyClientError("combined finalization reservation differs from its preparation")
            journal._digest(reservation.digest)
        if (type(observed) is not final_outcomes.FinalizationOutcomes
                or observed.finalization_digest != local or observed.source_revision != final_record.source_revision
                or type(prior) is not prior_outcomes.RegistrationOutcomes
                or prior.local_digest != evidence_digest or prior.source_revision != final_record.source_revision):
            raise CustodyClientError("combined outcome families or source differ from their preparation")
        for kind, record in zip(final_outcomes.KINDS, (observed.sql_attempt, observed.sql_outcome,
                observed.completion_outcome, observed.completion_reconciled)):
            if record is not None:
                if (type(record) is not final_outcomes.FinalizationOutcomeRecord
                        or record.finalization_digest != local or record.kind != kind
                        or record.source_revision != final_record.source_revision):
                    raise CustodyClientError("combined finalization outcome original differs")
                journal._digest(record.digest)
        for kind, record in zip(prior_outcomes.KINDS, (prior.reservation, prior.sql_attempt,
                prior.sql_outcome, prior.completion_outcome, prior.completion_reconciled)):
            if record is not None:
                if (type(record) is not prior_outcomes.RegistrationOutcomeRecord
                        or record.local_digest != evidence_digest or record.kind != kind
                        or record.source_revision != final_record.source_revision):
                    raise CustodyClientError("combined evidence outcome original differs")
                journal._digest(record.digest)
        current()
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

    def claim_oidc_session_activation_completion_recovery_release_attempt(self, *,
            client_authorization_digest, request_identity, profile, server_bootstrap_digest,
            expected_outcome_digest, work, current, maximum_original_bytes=None):
        """Spend the unchanged global release slot under original guarded LIVE work."""
        from serverware import control_plane_oidc_session_activation_release_attempt as attempts

        scalars = tuple(journal._digest(value) for value in (client_authorization_digest,
            request_identity, server_bootstrap_digest, expected_outcome_digest))
        if type(profile) is not str or profile != attempts.LIVE_PROFILE or not callable(current):
            raise CustodyClientError("completion release dispatch requires its fixed LIVE profile and guard")
        current()
        binding = _snapshot(self)
        digest = journal.CustodyJournal.claim_oidc_session_activation_completion_recovery_release_attempt(
            binding.journal, client_authorization_digest=scalars[0], request_identity=scalars[1],
            profile=profile, server_bootstrap_digest=scalars[2], expected_outcome_digest=scalars[3],
            work=work, current=current, maximum_original_bytes=maximum_original_bytes)
        current()
        if digest != scalars[0] or _snapshot(self) is not binding:
            raise CustodyClientError("custody caller or global release claim changed")
        return digest

    def claim_oidc_session_activation_completion_recovery_retained_release_attempt(self, *,
            client_authorization_digest, request_identity, profile, server_bootstrap_digest,
            expected_outcome_digest, work, current, maximum_original_bytes=None):
        """Spend the same global release slot under guarded fixed RECOVERY work."""
        from serverware import control_plane_oidc_session_activation_release_attempt as attempts

        scalars = tuple(journal._digest(value) for value in (client_authorization_digest,
            request_identity, server_bootstrap_digest, expected_outcome_digest))
        if type(profile) is not str or profile != attempts.RECOVERY_PROFILE or not callable(current):
            raise CustodyClientError("retained release dispatch requires its fixed RECOVERY profile and guard")
        current()
        binding = _snapshot(self)
        digest = journal.CustodyJournal.claim_oidc_session_activation_completion_recovery_retained_release_attempt(
            binding.journal, client_authorization_digest=scalars[0], request_identity=scalars[1],
            profile=profile, server_bootstrap_digest=scalars[2], expected_outcome_digest=scalars[3],
            work=work, current=current, maximum_original_bytes=maximum_original_bytes)
        current()
        if digest != scalars[0] or _snapshot(self) is not binding:
            raise CustodyClientError("custody caller or retained release claim changed")
        return digest

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

    def load_oidc_session_activation_completion_recovery_target(self, finalization_digest, *,
            work, current, maximum_original_bytes=None):
        """Return only original claim/prepared evidence, never recovery authority."""
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
        from serverware import control_plane_oidc_session_activation_records as activation

        target = journal._digest(finalization_digest)
        if not callable(current):
            raise CustodyClientError("completion recovery target lacks its original guard")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_completion_recovery_target(
            binding.journal, target, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while selecting completion recovery target")
        if retained is None:
            return None
        if (type(retained) is not tuple or len(retained) != 2
                or type(retained[0]) is not attempts.ActivationDispatchAttemptRecord
                or type(retained[1]) is not activation.ActivationRecord):
            raise CustodyClientError("completion recovery target original inventory differs")
        claim, prepared = retained
        if (claim.finalization_digest != target or prepared.finalization_digest != target
                or prepared.source_revision != claim.source_revision
                or prepared.kind != "prepared" or len(prepared.originals) != 5):
            raise CustodyClientError("completion recovery target originals have a different association")
        current()
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

    def _completion_consume_operation(self, *, finalization_digest, activation_authorization_digest,
            activation_completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes, kind, originals=(), release_hints=None):
        from serverware import control_plane_oidc_session_activation_consume_records as consume
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as completion

        target, authorization_digest = journal._digest(finalization_digest), journal._digest(activation_authorization_digest)
        slot = consume._slot_digest(target, authorization_digest)
        if reconciliation_digest is not None:
            reconciliation_digest = journal._digest(reconciliation_digest)
        completed = completion._originals("activation", activation_completion_originals)
        if type(kind) is not str or kind not in journal._COMPLETION_CONSUME_KINDS:
            raise CustodyClientError("consume continuation publication kind is not source fixed")
        if ((kind == "sql-claimed" and type(release_hints) is not bool)
                or (kind != "sql-claimed" and release_hints is not None)):
            raise CustodyClientError("consume completion profile must be fixed only at its SQL claim")
        held = consume._originals(consume._profile(kind), originals)
        if not callable(current):
            raise CustodyClientError("consume continuation requires its original resource guard")
        current()
        binding = _snapshot(self)
        result = journal.CustodyJournal._completion_consume_operation(binding.journal,
            finalization_digest=target, activation_authorization_digest=authorization_digest,
            activation_completion_originals=completed, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind=kind, originals=held, release_hints=release_hints)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed during guarded consume continuation")
        journal._digest(result)
        if kind == "claimed" and result != slot:
            raise CustodyClientError("consume continuation returned a different target slot")
        return result

    def claim_oidc_session_activation_completion_recovery_consume_attempt(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            work, current, maximum_original_bytes=None):
        """Spend the existing global consume target before input issuer contact."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="claimed")

    def append_oidc_session_activation_completion_recovery_consume_inputs(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain raw2 DATA before admission under this work's new consume claim."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="inputs", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_prepared(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain prepare raw6 before semantic admission; uncertainty cannot export."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="prepared", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_exported(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain export raw7 before admission, preserving this work's fixed continuation."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="exported", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_authorized(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain signed caller raw1; no stored record grants execution authority."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="authorized", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_grant(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain grant raw1 before genuine response admission on this work."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="grant", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_reservation(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain reservation raw3 before interpretation and any SQL contact."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="reserved", originals=originals)

    def claim_oidc_session_activation_completion_recovery_consume_sql_attempt(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            release_hints, work, current, maximum_original_bytes=None):
        """Spend the existing SQL slot and pin the completion profile before contact."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="sql-claimed", release_hints=release_hints)

    def append_oidc_session_activation_completion_recovery_consume_sql_outcome(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain unsigned SQL raw4; it proves neither commit nor safe retry."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="sql-outcome", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_completion_outcome(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain completion raw4 before admission; normal profile ends this latch."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="completion-outcome", originals=originals)

    def append_oidc_session_activation_completion_recovery_consume_completion_hints(self, *, finalization_digest,
            activation_authorization_digest, activation_completion_originals, reconciliation_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain opaque hints raw2 once under the pre-SQL profile, then end the latch."""
        return ControlPlaneCustodyClient._completion_consume_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            activation_completion_originals=activation_completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="completion-hints", originals=originals)

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

    def append_oidc_session_activation_consume_authorized(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the original signed caller raw1 without authenticating a grant."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="authorized", originals=originals)

    def append_oidc_session_activation_consume_grant(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the raw signed grant before independent original admission."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="grant", originals=originals)

    def append_oidc_session_activation_consume_reservation(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain signed reserve/snapshot/ACK originals before interpretation."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="reserved", originals=originals)

    def claim_oidc_session_activation_consume_sql_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Burn the SQL attempt before I/O; identical and recovered claims deny."""
        ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="sql-claimed", originals=())

    def append_oidc_session_activation_consume_sql_outcome(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain unsigned raw4 before interpretation without claiming a commit."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="sql-outcome", originals=originals)

    def append_oidc_session_activation_consume_completion_outcome(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain raw4 before status, identity or signed-control interpretation."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="completion-outcome", originals=originals)

    def append_oidc_session_activation_consume_completion_hints(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain unsigned packet/effects hints without turning them into proof."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="completion-hints", originals=originals)

    def claim_oidc_session_activation_consume_release_intent_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Burn the intent attempt before its producer, without a replay allowance."""
        ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-intent-claimed", originals=())

    def append_oidc_session_activation_consume_release_intent(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain exact signed raw1 before return, not an admitted release proof."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-intent", originals=originals)

    def claim_oidc_session_activation_consume_release_proof_attempt(self, *, finalization_digest,
            activation_authorization_digest):
        """Durably burn proof I/O once before dispatch, never grant a recovered retry."""
        ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof-claimed", originals=())

    def append_oidc_session_activation_consume_release_proof(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain opaque status/custody/proof/enrollment originals before interpretation."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof", originals=originals)

    def append_oidc_session_activation_consume_release_grants(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain exact client/server grant originals before semantic admission."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-grants", originals=originals)

    def append_oidc_session_activation_consume_inputs(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the first opaque issuer raw2 before any root admission."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="inputs", originals=originals)

    def append_oidc_session_activation_consume_release_proof_setup(self, *, finalization_digest,
            activation_authorization_digest, originals):
        """Retain the first opaque setup bootstrap before root or content admission."""
        return ControlPlaneCustodyClient._append_consume_stage(self,
            finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest,
            kind="release-proof-setup", originals=originals)

    def _completion_release_operation(self, *, finalization_digest, activation_authorization_digest,
            completion_originals, reconciliation_digest, work, current, maximum_original_bytes,
            kind=None, originals=(), load_grants=False):
        from serverware import control_plane_oidc_session_activation_consume_records as consume
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as recovery

        target = journal._digest(finalization_digest)
        authorization_digest = journal._digest(activation_authorization_digest)
        if reconciliation_digest is not None:
            reconciliation_digest = journal._digest(reconciliation_digest)
        completed = recovery._originals("consume", completion_originals)
        if kind is not None and kind not in consume.COMPLETION_RECOVERY_RELEASE_KINDS + consume.COMPLETION_RECOVERY_GRANT_KINDS:
            raise CustodyClientError("completion release kind is not source fixed")
        if type(load_grants) is not bool or (load_grants and kind is not None):
            raise CustodyClientError("completion release read profile is not source fixed")
        held = () if kind is None else consume._originals(consume._profile(kind), originals)
        if not callable(current):
            raise CustodyClientError("completion release requires its original resource guard")
        current()
        binding = _snapshot(self)
        result = journal.CustodyJournal._completion_release_operation(binding.journal,
            finalization_digest=target, activation_authorization_digest=authorization_digest,
            completion_originals=completed, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind=kind,
            originals=held, load_grants=load_grants)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed during completion release retention")
        if kind is not None:
            journal._digest(result)
            return result
        slot = consume._slot_digest(target, authorization_digest)
        kinds = consume.COMPLETION_RECOVERY_GRANT_KINDS if load_grants else consume.COMPLETION_RECOVERY_RELEASE_KINDS
        if type(result) is not tuple or len(result) != len(kinds):
            raise CustodyClientError("completion release record inventory differs")
        for expected, record in zip(kinds, result):
            if record is not None and (type(record) is not consume.ConsumeRecord
                    or record.finalization_digest != target or record.activation_authorization_digest != authorization_digest
                    or record.slot_digest != slot or record.kind != expected):
                raise CustodyClientError("completion release selected record association differs")
        current()
        return result

    def load_oidc_session_activation_completion_recovery_release_records(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Return existing claim/intent/claim/setup/proof DATA, never retry authority."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes)

    def claim_oidc_session_activation_completion_recovery_release_intent_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Spend the existing consume intent slot before signing, including after uncertainty."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="release-intent-claimed")

    def append_oidc_session_activation_completion_recovery_release_intent(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        """Retain signed raw1 DATA under this work's new intent claim."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="release-intent", originals=originals)

    def claim_oidc_session_activation_completion_recovery_release_proof_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Spend the same global proof slot before setup or proof contact."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="release-proof-claimed")

    def append_oidc_session_activation_completion_recovery_release_proof_setup(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        """Retain setup raw1 before admission without reopening the spent proof claim."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="release-proof-setup", originals=originals)

    def append_oidc_session_activation_completion_recovery_release_proof(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        """Retain raw4 DATA before status or enrolled proof admission."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="release-proof", originals=originals)

    def load_oidc_session_activation_completion_recovery_release_grants(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Return claim/raw2 DATA only; either existing record prohibits reacquisition."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, load_grants=True)

    def claim_oidc_session_activation_completion_recovery_release_grants_attempt(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, work, current,
            maximum_original_bytes=None):
        """Irreversibly claim the existing consume target before any grant issuer contact."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="release-grants-claimed")

    def append_oidc_session_activation_completion_recovery_release_grants(self, *, finalization_digest,
            activation_authorization_digest, completion_originals, reconciliation_digest, originals, work, current,
            maximum_original_bytes=None):
        """Retain opaque client/server raw2 before admission, never request or token frames."""
        return ControlPlaneCustodyClient._completion_release_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="release-grants", originals=originals)

    def _completion_retained_grant_operation(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest,
            completion_originals, reconciliation_digest, work, current, maximum_original_bytes,
            kind=None, originals=()):
        from serverware import control_plane_oidc_session_activation_recovery_records as recovery
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as completion

        scalars = tuple(journal._digest(value) for value in (finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        slot = recovery._slot_digest(*scalars)
        if reconciliation_digest is not None:
            reconciliation_digest = journal._digest(reconciliation_digest)
        completed = completion._originals("consume", completion_originals)
        if kind is not None and (type(kind) is not str or kind not in recovery.KINDS):
            raise CustodyClientError("retained recovery publication kind is not source fixed")
        if kind == "grants":
            held = recovery._originals(originals)
        else:
            if type(originals) is not tuple or originals:
                raise CustodyClientError("retained recovery load or claim has no response body")
            held = ()
        if not callable(current):
            raise CustodyClientError("retained recovery requires its original resource guard")
        current()
        binding = _snapshot(self)
        result = journal.CustodyJournal._completion_retained_grant_operation(binding.journal,
            finalization_digest=scalars[0], activation_authorization_digest=scalars[1],
            release_intent_digest=scalars[2], issuer_policy_digest=scalars[3],
            completion_originals=completed, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind=kind, originals=held)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed during guarded recovery retention")
        if kind is not None:
            journal._digest(result)
            if kind == "claimed" and result != slot:
                raise CustodyClientError("retained recovery claim returned a different policy slot")
            return result
        if result is None:
            return None
        if (type(result) is not recovery.RecoveryGrantRecords
                or type(result.claim) is not recovery.RecoveryGrantRecord
                or result.claim.kind != "claimed" or result.claim.originals != ()
                or result.claim.slot_digest != slot
                or (result.claim.finalization_digest, result.claim.activation_authorization_digest,
                    result.claim.release_intent_digest, result.claim.issuer_policy_digest) != scalars):
            raise CustodyClientError("retained recovery originals have a different policy claim")
        grants = result.grants
        if grants is not None and (type(grants) is not recovery.RecoveryGrantRecord
                or grants.kind != "grants" or grants.slot_digest != slot
                or grants.source_revision != result.claim.source_revision
                or grants.intent_record_digest != result.claim.intent_record_digest
                or (grants.finalization_digest, grants.activation_authorization_digest,
                    grants.release_intent_digest, grants.issuer_policy_digest) != scalars):
            raise CustodyClientError("retained recovery grants differ from their original claim")
        current()
        return result

    def load_oidc_session_activation_completion_recovery_retained_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest,
            completion_originals, reconciliation_digest, work, current, maximum_original_bytes=None):
        """Return None or existing policy claim/raw3 DATA, never permission to retry."""
        return ControlPlaneCustodyClient._completion_retained_grant_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            release_intent_digest=release_intent_digest, issuer_policy_digest=issuer_policy_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes)

    def claim_oidc_session_activation_completion_recovery_retained_grant_attempt(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest,
            completion_originals, reconciliation_digest, work, current, maximum_original_bytes=None):
        """Spend the existing global recovery-policy slot before issuer contact."""
        return ControlPlaneCustodyClient._completion_retained_grant_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            release_intent_digest=release_intent_digest, issuer_policy_digest=issuer_policy_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes, kind="claimed")

    def append_oidc_session_activation_completion_recovery_retained_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest,
            completion_originals, reconciliation_digest, originals, work, current, maximum_original_bytes=None):
        """Retain opaque client/server/outcome DATA before admission under this work's claim."""
        return ControlPlaneCustodyClient._completion_retained_grant_operation(self,
            finalization_digest=finalization_digest, activation_authorization_digest=activation_authorization_digest,
            release_intent_digest=release_intent_digest, issuer_policy_digest=issuer_policy_digest,
            completion_originals=completion_originals, reconciliation_digest=reconciliation_digest,
            work=work, current=current, maximum_original_bytes=maximum_original_bytes,
            kind="grants", originals=originals)

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

    def load_oidc_session_activation_recovery_target(self, finalization_digest, *, work, current,
            maximum_original_bytes=None):
        """Select bounded original target evidence; None means unavailable only.

        This method charges work directly. Its original owner-scope guard must
        not recursively load records or acquire the journal's I/O lock.
        """
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        target = journal._digest(finalization_digest)
        if not callable(current):
            raise CustodyClientError("recovery target selection lacks its original guard")
        if maximum_original_bytes is not None and (type(maximum_original_bytes) is not int
                or not 0 < maximum_original_bytes <= journal._COMPLETION_HISTORY_MAX_BYTES):
            raise CustodyClientError("recovery target remaining original capacity differs")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_recovery_target(
            binding.journal, target, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while selecting recovery target")
        if retained is None:
            return None
        if (type(retained) is not tuple or len(retained) != 3
                or type(retained[0]) is not attempts.ActivationDispatchAttemptRecord
                or any(type(record) is not consume.ConsumeRecord for record in retained[1:])):
            raise CustodyClientError("recovery target original inventory differs")
        activation, claim, intent = retained
        if (activation.finalization_digest != target or claim.finalization_digest != target
                or intent.finalization_digest != target or claim.kind != "claimed"
                or claim.originals != () or intent.kind != "release-intent" or len(intent.originals) != 1
                or claim.slot_digest != intent.slot_digest
                or claim.activation_authorization_digest != intent.activation_authorization_digest
                or activation.source_revision != claim.source_revision
                or intent.source_revision != claim.source_revision):
            raise CustodyClientError("recovery target originals have a different association")
        current()
        return retained

    def load_oidc_session_activation_recovery_inputs(self, finalization_digest, *, work, current):
        """Select exact target/proof/hint originals on the caller's original work."""
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        target = journal._digest(finalization_digest)
        if not callable(current):
            raise CustodyClientError("recovery input selection requires its original guard")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_recovery_inputs(
            binding.journal, target, work=work, current=current)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while selecting recovery inputs")
        if retained is None:
            return None
        if (type(retained) is not tuple or len(retained) != 5
                or type(retained[0]) is not attempts.ActivationDispatchAttemptRecord
                or any(type(value) is not consume.ConsumeRecord for value in retained[1:])):
            raise CustodyClientError("recovery input original inventory differs")
        activation, claim, intent, proof, hints = retained
        if (activation.finalization_digest != target or claim.kind != "claimed" or claim.originals != ()
                or (intent.kind, proof.kind, hints.kind) != ("release-intent", "release-proof", "completion-hints")
                or tuple(len(value.originals) for value in (intent, proof, hints)) != (1, 4, 2)
                or activation.source_revision != claim.source_revision
                or any(value.finalization_digest != target or value.source_revision != claim.source_revision
                    or value.slot_digest != claim.slot_digest
                    or value.activation_authorization_digest != claim.activation_authorization_digest
                    for value in (claim, intent, proof, hints))):
            raise CustodyClientError("recovery inputs differ from the retained intent association")
        current()
        return retained

    def load_oidc_session_activation_completion_recovery_consume_prefix(self, finalization_digest, *,
            work, current, maximum_original_bytes=None):
        """Return minimal original consume evidence DATA, never admission."""
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
        from serverware import control_plane_oidc_session_activation_consume_records as consume

        target = journal._digest(finalization_digest)
        if not callable(current):
            raise CustodyClientError("consume completion prefix requires the original guard")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_completion_recovery_consume_prefix(
            binding.journal, target, work=work, current=current, maximum_original_bytes=maximum_original_bytes)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading consume completion prefix")
        if retained is None:
            return None
        if (type(retained) is not tuple or len(retained) != 4
                or type(retained[0]) is not attempts.ActivationDispatchAttemptRecord
                or retained[0].finalization_digest != target):
            raise CustodyClientError("consume completion prefix fixed inventory differs")
        activation, claim, prepared, authorized = retained
        for record, kind, count in ((claim, "claimed", 0), (prepared, "prepared", 6),
                (authorized, "authorized", 1)):
            if (type(record) is not consume.ConsumeRecord or record.kind != kind
                    or len(record.originals) != count or record.finalization_digest != target
                    or record.source_revision != activation.source_revision
                    or record.activation_authorization_digest != claim.activation_authorization_digest
                    or record.slot_digest != claim.slot_digest
                    or record.slot_digest != consume._slot_digest(target, record.activation_authorization_digest)):
                raise CustodyClientError("consume completion prefix original association differs")
        current()
        return retained

    def load_oidc_session_activation_completion_recovery_controls(self, finalization_digest, *,
            phase, work, current, maximum_original_bytes=None):
        """Read exact fixed historical controls, never successful admission."""
        from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
        from serverware import control_plane_oidc_session_activation_records as activation
        from serverware import control_plane_oidc_session_activation_consume_records as consume
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as recovery

        target = journal._digest(finalization_digest)
        recovery._phase(phase)
        if not callable(current):
            raise CustodyClientError("completion controls require the original guard")
        current()
        binding = _snapshot(self)
        held = journal.CustodyJournal.load_oidc_session_activation_completion_recovery_controls(
            binding.journal, target, phase=phase, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while loading completion controls")
        if held is None:
            return None
        if (type(held) is not tuple or len(held) != 10
                or type(held[0]) is not attempts.ActivationDispatchAttemptRecord
                or held[0].finalization_digest != target):
            raise CustodyClientError("completion controls fixed inventory differs")
        if phase == "activation":
            if any(held[index] is not None for index in (1, 3, 4, 8)):
                raise CustodyClientError("activation completion controls contain consume records")
            expected_type = activation.ActivationRecord
            required = (2, 5, 6, 9)
        else:
            if (type(held[1]) is not consume.ConsumeRecord or held[1].kind != "claimed"
                    or held[1].originals != () or held[1].finalization_digest != target
                    or held[1].source_revision != held[0].source_revision):
                raise CustodyClientError("consume completion controls lack the original claim")
            expected_type = consume.ConsumeRecord
            required = (2, 3, 4, 5, 6, 9)
        for index, kind in ((2, "prepared"), (3, "exported"), (4, "authorized"),
                (5, "grant"), (6, "reserved"), (7, "completion-outcome"),
                (8, "completion-hints"), (9, "sql-claimed")):
            record = held[index]
            if record is None and index not in required:
                continue
            if (type(record) is not expected_type or record.kind != kind
                    or record.finalization_digest != target or record.source_revision != held[0].source_revision
                    or (phase == "consume" and (record.slot_digest != held[1].slot_digest
                        or record.activation_authorization_digest != held[1].activation_authorization_digest))):
                raise CustodyClientError("completion controls original association differs")
        current()
        return held

    def claim_oidc_session_activation_completion_recovery_attempt(self, *, finalization_digest,
            phase, authorization_digest, packet_digest, recovery_configuration_digest,
            work, current, maximum_original_bytes=None):
        """Burn only this exact target/phase; stored scalars are not authority."""
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as recovery

        scalars = tuple(journal._digest(value) for value in (finalization_digest, authorization_digest,
            packet_digest, recovery_configuration_digest))
        expected = recovery._slot_digest(scalars[0], phase)
        if not callable(current):
            raise CustodyClientError("completion recovery attempt lacks its original guard")
        current()
        binding = _snapshot(self)
        slot = journal.CustodyJournal.claim_oidc_session_activation_completion_recovery_attempt(
            binding.journal, finalization_digest=scalars[0], phase=phase,
            authorization_digest=scalars[1], packet_digest=scalars[2], recovery_configuration_digest=scalars[3],
            work=work, current=current, maximum_original_bytes=maximum_original_bytes)
        current()
        if slot != expected or _snapshot(self) is not binding:
            raise CustodyClientError("custody caller or completion phase changed after the attempt")
        return slot

    def append_oidc_session_activation_completion_recovery_response(self, *, finalization_digest,
            phase, authorization_digest, packet_digest, recovery_configuration_digest,
            originals, work, current, maximum_original_bytes=None):
        """Retain unverified response originals separately before interpretation."""
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as recovery

        scalars = tuple(journal._digest(value) for value in (finalization_digest, authorization_digest,
            packet_digest, recovery_configuration_digest))
        held = recovery._originals(phase, originals)
        if not callable(current):
            raise CustodyClientError("completion recovery response lacks its original guard")
        current()
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_oidc_session_activation_completion_recovery_response(
            binding.journal, finalization_digest=scalars[0], phase=phase,
            authorization_digest=scalars[1], packet_digest=scalars[2], recovery_configuration_digest=scalars[3],
            originals=held, work=work, current=current, maximum_original_bytes=maximum_original_bytes)
        current()
        journal._digest(digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed during completion response retention")
        return digest

    def load_oidc_session_activation_completion_recovery_records(self, finalization_digest, *,
            phase, work, current, maximum_original_bytes=None):
        """Return spent attempt and optional response DATA, never resumed authority."""
        from serverware import control_plane_oidc_session_activation_completion_recovery_records as recovery

        target = journal._digest(finalization_digest)
        expected = recovery._slot_digest(target, phase)
        if not callable(current):
            raise CustodyClientError("completion recovery history lacks its original guard")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_completion_recovery_records(
            binding.journal, target, phase=phase, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading completion recovery history")
        if retained is None:
            return None
        if (type(retained) is not recovery.CompletionRecoveryRecords
                or type(retained.claim) is not recovery.CompletionRecoveryRecord
                or retained.claim.slot_digest != expected or retained.claim.finalization_digest != target
                or retained.claim.phase != phase or retained.claim.kind != "claimed" or retained.claim.originals != ()):
            raise CustodyClientError("completion recovery attempt inventory differs")
        response = retained.response
        if response is not None and (type(response) is not recovery.CompletionRecoveryRecord
                or response.kind != "response" or response.slot_digest != expected
                or (response.source_revision, response.finalization_digest, response.phase,
                    response.authorization_digest, response.packet_digest, response.recovery_configuration_digest,
                    response.predecessor_completion_digest) != (retained.claim.source_revision,
                    target, phase, retained.claim.authorization_digest, retained.claim.packet_digest,
                    retained.claim.recovery_configuration_digest, retained.claim.predecessor_completion_digest)):
            raise CustodyClientError("completion recovery response association differs")
        current()
        return retained

    def claim_oidc_session_activation_recovery_grant_attempt(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest):
        """Burn the exact independently authenticated policy slot before contact."""
        from serverware import control_plane_oidc_session_activation_recovery_records as recovery

        scalars = tuple(journal._digest(value) for value in (finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        expected = recovery._slot_digest(*scalars)
        binding = _snapshot(self)
        slot = journal.CustodyJournal.claim_oidc_session_activation_recovery_grant_attempt(binding.journal,
            finalization_digest=scalars[0], activation_authorization_digest=scalars[1],
            release_intent_digest=scalars[2], issuer_policy_digest=scalars[3])
        if slot != expected or _snapshot(self) is not binding:
            raise CustodyClientError("custody caller or recovery policy changed after durable claim")
        return slot

    def append_oidc_session_activation_recovery_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest, originals):
        """Opaque raw3 retention only; the actual caller supplies admitted originals."""
        from serverware import control_plane_oidc_session_activation_recovery_records as recovery

        scalars = tuple(journal._digest(value) for value in (finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        held = recovery._originals(originals)
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_oidc_session_activation_recovery_grants(binding.journal,
            finalization_digest=scalars[0], activation_authorization_digest=scalars[1],
            release_intent_digest=scalars[2], issuer_policy_digest=scalars[3], originals=held)
        journal._digest(digest)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed after recovery grant retention")
        return digest

    def load_oidc_session_activation_recovery_grants(self, *, finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest, work, current):
        """Read exact token-free policy history; never resume acquisition."""
        from serverware import control_plane_oidc_session_activation_recovery_records as recovery

        scalars = tuple(journal._digest(value) for value in (finalization_digest,
            activation_authorization_digest, release_intent_digest, issuer_policy_digest))
        slot = recovery._slot_digest(*scalars)
        if not callable(current):
            raise CustodyClientError("recovery acquired-original selection requires its original guard")
        current()
        binding = _snapshot(self)
        retained = journal.CustodyJournal.load_oidc_session_activation_recovery_grants(binding.journal,
            finalization_digest=scalars[0], activation_authorization_digest=scalars[1],
            release_intent_digest=scalars[2], issuer_policy_digest=scalars[3], work=work, current=current)
        current()
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while reading recovery acquired originals")
        if retained is None:
            return None
        if (type(retained) is not recovery.RecoveryGrantRecords
                or type(retained.claim) is not recovery.RecoveryGrantRecord
                or retained.claim.kind != "claimed" or retained.claim.originals != ()
                or retained.claim.slot_digest != slot
                or (retained.claim.finalization_digest, retained.claim.activation_authorization_digest,
                    retained.claim.release_intent_digest, retained.claim.issuer_policy_digest) != scalars):
            raise CustodyClientError("recovery acquired originals have a different policy claim")
        if retained.grants is not None and (type(retained.grants) is not recovery.RecoveryGrantRecord
                or retained.grants.kind != "grants" or retained.grants.slot_digest != slot
                or retained.grants.source_revision != retained.claim.source_revision
                or retained.grants.intent_record_digest != retained.claim.intent_record_digest
                or (retained.grants.finalization_digest, retained.grants.activation_authorization_digest,
                    retained.grants.release_intent_digest, retained.grants.issuer_policy_digest) != scalars):
            raise CustodyClientError("recovery retained grants differ from their original claim")
        current()
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

    def append_registration_finalization_completion_outcome(self, finalization_digest, originals, *,
            work=None, current=None, maximum_original_bytes=None):
        """Retain bounded completion originals before separate semantic admission."""
        local = journal._digest(finalization_digest)
        guarded = work is not None or current is not None or maximum_original_bytes is not None
        if guarded:
            if not callable(current):
                raise CustodyClientError("finalization completion publication requires its original guard")
            current()
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_completion_outcome(
            binding.journal, local, originals, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization completion")
        if guarded:
            current()
        return journal._digest(digest)

    def append_registration_finalization_completion_reconciliation(self, finalization_digest, originals, *,
            work=None, current=None, maximum_original_bytes=None):
        """Retain a separate acknowledged carrier, never overwrite uncertainty."""
        local = journal._digest(finalization_digest)
        guarded = work is not None or current is not None or maximum_original_bytes is not None
        if guarded:
            if not callable(current):
                raise CustodyClientError("finalization reconciliation publication requires its original guard")
            current()
        binding = _snapshot(self)
        digest = journal.CustodyJournal.append_registration_finalization_completion_reconciliation(
            binding.journal, local, originals, work=work, current=current,
            maximum_original_bytes=maximum_original_bytes)
        if _snapshot(self) is not binding:
            raise CustodyClientError("custody caller changed while retaining finalization reconciliation")
        if guarded:
            current()
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

    def _request_authority(self, *, operation, input_value, deadline_ns=None):
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
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding)
        _receipt_now(binding)
        journal.CustodyJournal._require_ready(binding.journal)
        if deadline_ns is not None:
            transport._check_deadline(deadline_ns)
        return result

    def _request_measured_refresh(self, *, operation, input_value, deadline_ns):
        """Exact signed originals only for the fixed measured-refresh family.

        This is not generic signing/export, a retained-result verdict, or a
        retry permit. The actual admitted runtime client verifies the result.
        """
        from serverware import authority_oauth_measured_refresh as refresh
        if operation not in refresh.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("measured refresh original custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("measured refresh lacks the actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_refresh(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("measured refresh custody changed while receiving originals")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("measured refresh did not return exact request/response originals")
        return originals

    def _request_canary_delivery(self, *, operation, input_value, deadline_ns):
        """Preserve actual signed delivery originals; no generic proof export."""
        from serverware import authority_policy_canary_delivery as delivery
        if operation not in delivery.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("canary delivery original custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("canary delivery lacks the actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_canary_delivery(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("canary delivery custody changed while receiving originals")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("canary delivery did not return exact request/response originals")
        return originals

    def _request_measured_cleanup(self, *, operation, input_value, deadline_ns):
        """Exact signed originals only for the fixed measured-cleanup family.

        This is not generic signing/export, a retained-result verdict, or a
        retry permit. The actual admitted runtime client verifies the result.
        """
        from serverware import authority_oauth_measured_cleanup as refresh
        if operation not in refresh.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("measured cleanup original custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("measured cleanup lacks the actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_cleanup(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("measured cleanup custody changed while receiving originals")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("measured cleanup did not return exact request/response originals")
        return originals

    def _request_measured_pending_retirement(self, *, operation, input_value, deadline_ns):
        """Purpose-fixed original export through the genuine cold client."""
        from serverware import authority_oauth_measured_pending_retirement as pending
        if operation not in pending.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("pending retirement original custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("pending retirement lacks the actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_pending_retirement(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("pending retirement custody changed while receiving originals")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("pending retirement did not return exact request/response originals")
        return originals

    def _request_measured_capture_retirement(self, *, operation, input_value, deadline_ns):
        """Purpose-fixed original export through the genuine cold client."""
        from serverware import authority_oauth_measured_capture_retirement as pending
        if operation not in pending.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("capture retirement original custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("capture retirement lacks the actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_capture_retirement(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("capture retirement custody changed while receiving originals")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("capture retirement did not return exact request/response originals")
        return originals

    def _request_measured_exchange(self, *, operation, input_value, deadline_ns):
        """Only exact verified originals of the initial-issuance purpose."""
        from serverware import authority_oauth_measured_exchange as exchange
        if operation not in exchange.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("initial-issuance custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("initial issuance lacks actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_exchange(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("initial-issuance custody changed")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("initial issuance has no exact committed originals")
        return originals

    def _request_measured_setup(self, *, operation, input_value, deadline_ns):
        """Separate signed Setup response originals; no generic export or retry."""
        from serverware import authority_oauth_measured_setup as setup
        if operation not in setup.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("Setup custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("Setup lacks actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_setup(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("Setup custody changed")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("Setup has no exact committed originals")
        return originals

    def _request_measured_reconnect(self, *, operation, input_value, deadline_ns):
        """Purpose-fixed actual response originals; never a retry operation."""
        from serverware import authority_oauth_reconnect as reconnect
        if operation not in reconnect.OPERATIONS or type(deadline_ns) is not int:
            raise CustodyClientError("reconnect custody purpose differs")
        binding = _snapshot(self)
        runtime = binding.runtime_client
        if type(runtime) is not service.AuthorityRuntimeClient:
            raise CustodyClientError("reconnect lacks actual cold runtime client")
        _receipt_now(binding)
        originals = service.AuthorityRuntimeClient.request_measured_reconnect(runtime,
            operation=operation, input_value=input_value, deadline_ns=deadline_ns)
        _process(binding); _receipt_now(binding)
        if _snapshot(self) is not binding:
            raise CustodyClientError("reconnect custody changed")
        journal.CustodyJournal._require_ready(binding.journal)
        transport._check_deadline(deadline_ns)
        if type(originals) is not tuple or len(originals) != 2 or any(type(raw) is not bytes for raw in originals):
            raise CustodyClientError("reconnect has no exact committed originals")
        return originals

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
