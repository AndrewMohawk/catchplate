"""Private first-exact consume ciphertext, never consumption or release proof.

Only this exact owner selects the consume codec and canonical document16. The
caller independently supplies the directory, configuration, key and original
processing allowance. No key/directory provisioning or regeneration is offered.
"""
from __future__ import annotations

from serverware import authority_oidc_execution_store_core as storage
from serverware import authority_oidc_session_activation_delivery_execution_bundle as bundle
from serverware import authority_oidc_session_activation_delivery_journal as journal
from serverware import authority_oidc_session_activation_delivery_plan_contract as contract


authority, shape, evidence = journal.authority, journal.shape, journal.evidence
delivery = storage.delivery
MAGIC = b"SWODS001"
SLOT_DOMAIN = "serverware.oidcSessionActivationDeliveryExecutionStoreSlot/v1"
HEADER_BYTES = storage.HEADER_BYTES
MAX_RECORD_BYTES = storage.MAX_RECORD_BYTES
MAX_CONTEXT_BYTES = bundle.MAX_CONTEXT_BYTES
MAX_PLAN_BYTES = contract.MAX_BYTES
MAX_RECORDS, MAX_QUOTA_BYTES = journal.MAX_RECORDS, journal.MAX_QUOTA_BYTES
MIN_RECORD_BYTES = HEADER_BYTES + 4 + bundle.OVERHEAD_BYTES + 2
_PREFIX = "consume-execution-"
_CONTEXT_ORDER = tuple(sorted(bundle.CONTEXT_FIELDS))


class DeliveryExecutionStoreError(storage._ExecutionStoreError):
    pass


StoreError = DeliveryExecutionStoreError


def _context_bytes(context, work):
    return evidence.capability._wire(context, evidence.capture._SharedLedger(work),
        MAX_CONTEXT_BYTES, bundle.MAX_CONTEXT_NODES)


def _require_owner(owner):
    if type(owner) is not DeliveryExecutionBundleStore:
        raise DeliveryExecutionStoreError("consume execution store requires its exact owner class")


class DeliveryExecutionBundleStore(storage._ExecutionBundleStore):
    """Exact consume owner; no alternate profile or successful carrier input."""

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
