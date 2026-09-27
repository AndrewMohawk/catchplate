"""Private first-exact consume ciphertext export, never execution authority.

The cold caller independently authenticates original role/key/resource pins.
This composition holds the actual plan lock, genuinely replays retained
originals and returns only the first durable encrypted copy. Storage integrity,
a locator or this same-call result cannot replace receiving proof admission.
No new allowance, re-signing, fallback seal or automatic retry is provided.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_delivery_execution_bundle as bundle
from serverware import authority_oidc_session_activation_delivery_execution_store as storage
from serverware import authority_oidc_session_activation_delivery_plan_owner as retained


plan, registration, evidence = retained.plan, retained.registration, retained.evidence


class DeliveryExecutionExportError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionExportError(message)


def _join_store(configured, store, key, work):
    """Join actual private owners; received configuration is not authority."""
    actual = storage.DeliveryExecutionBundleStore._snapshot_configuration(store)
    original = configured.journal_configuration
    historical = configured.historical_configuration
    if (type(actual) is not tuple or len(actual) != 6
            or type(actual[3]) is not tuple or len(actual[3]) != 4
            or type(original) is not tuple or len(original) != 8
            or type(original[5]) is not tuple or len(original[5]) != 4):
        _fail("consume export owner configurations differ from their fixed inventories")
    registration._same(actual[0], configured.source_revision, work, "consume export source")
    registration._same(actual[1], configured.configuration_digest, work, "consume export configuration")
    registration._same(original[:2], actual[:2], work, "consume export journal source/configuration")
    retained._bytes_equal(actual[2], key, work, "export/store bundle key")
    retained._bytes_equal(original[3], historical.bundle_key, work, "export historical bundle key")
    retained._bytes_equal(original[4], historical.delivery_key, work, "export historical delivery key")
    # Secret bytes are compared directly, never passed through JSON or returned.
    work.charge(input_bytes=6 * bundle.KEY_BYTES)
    if key in (original[2], historical.bundle_key, historical.delivery_key):
        _fail("consume export key overlaps journal or historical encryption custody")
    registration._same(actual[3][2:], original[5][2:], work, "consume export directory owner")
    if actual[3][:2] == original[5][:2]:
        _fail("consume execution store must differ from its original journal directory")
    return actual


def _export_on_work(owner, store, *, envelope_bytes, expected_request, expected_scope,
        business_before_roots, authorization_before_roots, expected_counted_heads,
        expected_journal_digest, bundle_key, live_window, transport_deadline_ns, work):
    """Return first-exact durable ciphertext after genuine same-call live replay."""
    evidence.capture._SharedLedger(work)
    if (type(owner) is not retained.OidcSessionActivationDeliveryPlanOwner
            or type(store) is not storage.DeliveryExecutionBundleStore):
        _fail("consume export requires the actual retained-plan and execution-store owners")
    if (type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= retained.contract.MAX_BYTES
            or type(bundle_key) is not bytes or len(bundle_key) != bundle.KEY_BYTES
            or type(expected_journal_digest) is not str):
        _fail("consume export requires bounded immutable originals and an independent private key")
    envelope, key = envelope_bytes, bundle_key
    journal_digest = registration._digest(expected_journal_digest)
    lock = owner._lock
    if type(lock) is not retained._LOCK_TYPE or not lock.acquire(blocking=False):
        _fail("consume plan owner is changed or already in use")
    try:
        # Detach all caller graphs before hashing, clocks, owner I/O or AEAD.
        owned = retained.planning._capture(request=expected_request,
            business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads,
            transition_inputs={"scope": expected_scope, "journalDigest": journal_digest},
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
        configured = retained.OidcSessionActivationDeliveryPlanOwner._snapshot_configuration(owner)
        window, bound = retained._window(configured, owned["liveWindow"], owned["transportDeadlineNs"])
        held_store = _join_store(configured, store, key, work)

        def store_check():
            if storage.DeliveryExecutionBundleStore._snapshot_configuration(store) is not held_store:
                _fail("consume execution store configuration changed during export")

        store_check()
        original, journal_scope, window, bound, current, full = (
            retained.OidcSessionActivationDeliveryPlanOwner._verify_retained_locked(owner,
                configured=configured, envelope_bytes=envelope,
                expected_request=owned["request"], expected_scope=owned["transitionInputs"]["scope"],
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                expected_counted_heads=owned["expectedCountedHeads"],
                expected_journal_digest=owned["transitionInputs"]["journalDigest"],
                live_window=window, transport_deadline_ns=bound, work=work))

        def check():
            store_check()
            before = current()
            replay_now = full.live()
            after = current()
            if not before <= replay_now <= after or after >= full.valid_until_epoch_ns:
                _fail("consume export expired or clocks reversed across original replay")
            store_check()

        check()
        work.prepare_copy(journal_scope)
        context = {"schema": bundle.CONTEXT_SCHEMA, "operation": retained.OPERATION,
            **journal_scope, "journalDigest": journal_digest}
        raw_context = storage._context_bytes(context, work)
        cipher_size = len(original) + bundle.OVERHEAD_BYTES
        if (storage.HEADER_BYTES + len(raw_context) + len(envelope) + cipher_size > storage.MAX_RECORD_BYTES
                or len(envelope) + cipher_size > retained.contract.authority.MAX_RESULT_BYTES):
            _fail("consume export exceeds the fixed record or original-pair aggregate bound")
        check()
        first = storage.DeliveryExecutionBundleStore.read(store, context=context,
            envelope_bytes=envelope, live_window=window, work=work, transport_deadline_ns=bound)
        check()
        if first is not None:
            # Integrity of a stored record is insufficient: join the plaintext
            # to the exact original admitted by this call's genuine full replay.
            opened = bundle._open_on_work(bundle_bytes=first, bundle_key=key,
                expected_context=context, live_window=window, transport_deadline_ns=bound, work=work)
            check()
            retained._bytes_equal(opened, original, work, "first consume execution originals")
            check()
            return first

        candidate = bundle._seal_on_work(original_bytes=original, bundle_key=key,
            context=context, live_window=window, transport_deadline_ns=bound, work=work)
        check()
        first = storage.DeliveryExecutionBundleStore.append(store, context=context,
            envelope_bytes=envelope, bundle_bytes=candidate, live_window=window,
            work=work, transport_deadline_ns=bound)
        check()
        retained._bytes_equal(first, candidate, work, "first durable consume ciphertext")
        check()
        return first
    finally:
        lock.release()
