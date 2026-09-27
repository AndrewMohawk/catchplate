"""Fixed activation first-ciphertext owner; storage is not execution authority.

The existing activation API, format, source bounds and genuine original codec
remain unchanged. Neutral durable I/O lives in a private two-profile engine;
only this exact class selects the activation profile.
"""
from __future__ import annotations

from serverware import authority_oidc_execution_store_core as storage
from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_journal as journal


authority, shape, evidence = journal.authority, journal.shape, journal.evidence
contract, delivery = journal.contract, journal.delivery
MAGIC = b"SWOAS001"
SLOT_DOMAIN = "serverware.oidcSessionActivationExecutionStoreSlot/v1"
HEADER_BYTES = storage.HEADER_BYTES
MAX_RECORD_BYTES = storage.MAX_RECORD_BYTES
MAX_CONTEXT_BYTES = bundle.MAX_CONTEXT_BYTES
MAX_PLAN_BYTES = contract.MAX_BYTES
MAX_RECORDS, MAX_QUOTA_BYTES = journal.MAX_RECORDS, journal.MAX_QUOTA_BYTES
MIN_RECORD_BYTES = HEADER_BYTES + 4 + bundle.OVERHEAD_BYTES + 2
_PREFIX = "execution-"
_CONTEXT_ORDER = tuple(sorted(bundle.CONTEXT_FIELDS))


class ActivationExecutionStoreError(storage._ExecutionStoreError):
    pass


StoreError = ActivationExecutionStoreError


def _context_bytes(context, work):
    return evidence.capability._wire(context, evidence.capture._SharedLedger(work),
        MAX_CONTEXT_BYTES, bundle.MAX_CONTEXT_NODES)


def _require_owner(owner):
    if type(owner) is not ActivationExecutionBundleStore:
        raise ActivationExecutionStoreError("activation execution store requires its exact owner class")


class ActivationExecutionBundleStore(storage._ExecutionBundleStore):
    """Exact activation owner; signatures and configuration6 remain fixed."""

    __slots__ = ()

    def __init__(self, *, directory_fd, expected_device, expected_inode, expected_uid, expected_gid,
            maximum_records, quota_bytes, configuration_digest, bundle_key,
            live_window, work, transport_deadline_ns=None):
        _require_owner(self)
        storage._ExecutionBundleStore.__init__(self, directory_fd=directory_fd,
            expected_device=expected_device, expected_inode=expected_inode, expected_uid=expected_uid,
            expected_gid=expected_gid, maximum_records=maximum_records, quota_bytes=quota_bytes,
            configuration_digest=configuration_digest, bundle_key=bundle_key, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)

    def _snapshot_configuration(self):
        _require_owner(self)
        return storage._ExecutionBundleStore._snapshot_configuration(self)

    def read(self, *, context, envelope_bytes, live_window, work, transport_deadline_ns):
        _require_owner(self)
        return storage._ExecutionBundleStore.read(self, context=context, envelope_bytes=envelope_bytes,
            live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)

    def append(self, *, context, envelope_bytes, bundle_bytes, live_window, work, transport_deadline_ns):
        _require_owner(self)
        return storage._ExecutionBundleStore.append(self, context=context, envelope_bytes=envelope_bytes,
            bundle_bytes=bundle_bytes, live_window=live_window, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def close(self):
        _require_owner(self)
        return storage._ExecutionBundleStore.close(self)
