"""Private first-exact activation export, never execution or recovery authority.

The cold caller must authenticate the original bootstrap and independently
admit both actual owners and keys. This composition verifies retained originals
on the existing allowance before recovering or publishing ciphertext. It never
returns private journal bytes, renews a plan, or dispatches SQL.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_execution_store as storage
from serverware import authority_oidc_session_activation_plan_owner as retained


plan, registration, evidence = retained.plan, retained.registration, retained.evidence


class ActivationExecutionExportError(ValueError):
    pass


def _fail(message):
    raise ActivationExecutionExportError(message)


def _join_store(configured, store, key, work):
    """Join actual private configuration, not a received successful carrier."""
    actual = storage.ActivationExecutionBundleStore._snapshot_configuration(store)
    if (type(actual) is not tuple or len(actual) != 6
            or type(actual[3]) is not tuple or len(actual[3]) != 4):
        _fail("activation execution store configuration is not its fixed shape")
    registration._same(actual[0], configured[0], work, "activation export source")
    registration._same(actual[1], configured[9], work, "activation export configuration")
    # These exact private bytes never enter a JSON comparison or a return value.
    work.charge(input_bytes=6 * bundle.KEY_BYTES)
    if (actual[2] != key or key == configured[10] or key == configured[4][2]):
        _fail("activation export bundle key differs or overlaps another private purpose")
    registration._same(configured[4][0], actual[0], work, "activation export original journal source")
    registration._same(configured[4][1], actual[1], work, "activation export original journal configuration")
    if actual[3][0] == configured[4][4][0] and actual[3][1] == configured[4][4][1]:
        _fail("activation execution store must differ from the original journal directory")
    return actual


def _export_on_work(owner, store, *, envelope_bytes, expected_request, expected_scope,
        business_before_roots, authorization_before_roots, expected_counted_heads,
        expected_journal_digest, bundle_key, live_window, transport_deadline_ns, work):
    """Return only first-exact durable ciphertext after same-call live replay.

    All inputs remain original data or independently configured real owners.
    Failure, including after publication, never falls back to another seal.
    """
    evidence.capture._SharedLedger(work)
    if (type(owner) is not retained.OidcSessionActivationPlanOwner
            or type(store) is not storage.ActivationExecutionBundleStore):
        _fail("activation export requires the actual plan and execution-store owners")
    if (type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= retained.contract.MAX_BYTES
            or type(bundle_key) is not bytes or len(bundle_key) != bundle.KEY_BYTES
            or type(expected_journal_digest) is not str):
        _fail("activation export requires bounded immutable originals and private key")
    envelope, key = envelope_bytes, bundle_key
    journal_digest = registration._digest(expected_journal_digest)
    configured = retained.OidcSessionActivationPlanOwner._snapshot_configuration(owner)
    lock = owner._lock
    if not lock.acquire(blocking=False):
        _fail("activation plan owner is already in use")
    try:
        # Detach every caller graph before clocks, hashing, journal reads or AEAD.
        owned, window, bound = retained._capture(
            values={"request": expected_request, "scope": expected_scope},
            business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, configured=configured, work=work)
        held_store = _join_store(configured, store, key, work)
        owner_check = retained.OidcSessionActivationPlanOwner._guard(owner, configured, window, bound, work)

        def store_check():
            if storage.ActivationExecutionBundleStore._snapshot_configuration(store) is not held_store:
                _fail("activation execution store configuration changed during export")

        store_check()
        owner_check()
        store_check()
        original, journal_scope, window, bound, owner_check, full = (
            retained.OidcSessionActivationPlanOwner._verify_retained_locked(owner,
                configured=configured, envelope_bytes=envelope,
                expected_request=owned["values"]["request"], expected_scope=owned["values"]["scope"],
                business_before_roots=owned["business"], authorization_before_roots=owned["authorization"],
                expected_counted_heads=owned["heads"], expected_journal_digest=journal_digest,
                live_window=window, work=work, transport_deadline_ns=bound))
        live = plan._live(full.invocation, work)

        def check():
            store_check()
            owner_check()
            plan._fresh_replayed(full.payload, full.invocation, full.write_result, live, work)
            store_check()
            if owner_check() >= full.payload["expiresAtEpochNs"]:
                _fail("activation original signed plan expired during export")

        check()
        work.prepare_copy(journal_scope)
        context = {"schema": bundle.CONTEXT_SCHEMA, "operation": retained.OPERATION,
            **journal_scope, "journalDigest": journal_digest}
        raw_context = storage._context_bytes(context, work)
        cipher_size = len(original) + bundle.OVERHEAD_BYTES
        if (storage.HEADER_BYTES + len(raw_context) + len(envelope) + cipher_size > storage.MAX_RECORD_BYTES
                or len(envelope) + cipher_size + len(configured[18]) + len(configured[20])
                    > retained.contract.authority.MAX_RESULT_BYTES):
            _fail("activation export exceeds the existing store or receiving aggregate bound")
        check()
        first = storage.ActivationExecutionBundleStore.read(store, context=context,
            envelope_bytes=envelope, live_window=window, work=work, transport_deadline_ns=bound)
        check()
        if first is not None:
            # Storage authentication alone does not bind the freshly replayed
            # original. Open this first ciphertext and compare the exact bytes.
            opened = bundle._open_on_work(bundle_bytes=first, bundle_key=key,
                expected_context=context, live_window=window, transport_deadline_ns=bound, work=work)
            check()
            retained._bytes_equal(opened, original, work, "first execution bundle originals")
            check()
            return first

        candidate = bundle._seal_on_work(original_bytes=original, bundle_key=key,
            context=context, live_window=window, transport_deadline_ns=bound, work=work)
        check()
        first = storage.ActivationExecutionBundleStore.append(store, context=context,
            envelope_bytes=envelope, bundle_bytes=candidate, live_window=window,
            work=work, transport_deadline_ns=bound)
        check()
        retained._bytes_equal(first, candidate, work, "first durable execution ciphertext")
        check()
        return first
    finally:
        lock.release()
