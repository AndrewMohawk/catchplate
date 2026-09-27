"""Ciphertext-only portable activation originals, never execution authority.

The owning caller independently admits a separate bundle key and its context.
No key, plaintext, context graph or successful replay carrier is serialized in
the frame. Opening authenticates exact canonical journal bytes, not signatures,
currentness, permission, durability or one-use execution. No fallback, new work
allowance, replacement window, history admission or retry exists here.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import authority_oidc_session_activation_journal as journal
from serverware import oidc_session_activation_delivery as delivery


evidence, shape = journal.evidence, journal.shape
MAGIC = b"SWOAX001"
DOMAIN = b"serverware.oidcSessionActivationExecutionOriginals/v1\x00"
CONTEXT_SCHEMA = "serverware.oidcSessionActivationExecutionOriginalsContext/v1"
OPERATION = "oidc.session.activate"
KEY_BYTES, NONCE_BYTES, TAG_BYTES = 32, 12, 16
HEADER_BYTES = len(MAGIC) + 8
OVERHEAD_BYTES = HEADER_BYTES + NONCE_BYTES + TAG_BYTES
MAX_ORIGINAL_BYTES = journal.MAX_ORIGINAL_BYTES
MAX_BYTES = MAX_ORIGINAL_BYTES + OVERHEAD_BYTES
MAX_CONTEXT_BYTES = 4096
MAX_CONTEXT_NODES = 32
CONTEXT_FIELDS = frozenset({"schema", "operation", "sourceRevision",
    "configurationDigest", "requestDigest", "planDigest", "journalDigest"})
_JOURNAL_SCOPE_FIELDS = ("sourceRevision", "configurationDigest", "requestDigest", "planDigest")


class ActivationExecutionBundleError(ValueError):
    pass


def _fail(message):
    raise ActivationExecutionBundleError(message)


def _capture(key, context):
    """Hold all external scalars before the first clock or native callback."""
    if type(key) is not bytes or len(key) != KEY_BYTES:
        _fail("activation execution bundle requires an independent exact 32-byte key")
    if type(context) is not dict or len(context) != len(CONTEXT_FIELDS):
        _fail("activation execution bundle context is not source closed")
    owned = {}
    for field, value in context.items():
        if (type(field) is not str or field not in CONTEXT_FIELDS
                or type(value) is not str or not 1 <= len(value) <= 256):
            _fail("activation execution bundle context contains an unknown or unbounded scalar")
        owned[field] = value
    if set(owned) != CONTEXT_FIELDS:
        _fail("activation execution bundle context inventory differs")
    shape._literal(owned["schema"], CONTEXT_SCHEMA)
    shape._literal(owned["operation"], OPERATION)
    scope = journal._scope({field: owned[field] for field in _JOURNAL_SCOPE_FIELDS})
    shape._digest(owned["journalDigest"])
    return key, owned, scope


def _begin(context, live_window, transport_deadline_ns, work):
    evidence.capture._SharedLedger(work)
    journal.registration._integer(transport_deadline_ns, "activation bundle inherited deadline", 1)
    _window, current = delivery._window(live_window, transport_deadline_ns, work)
    current()
    raw_context = evidence.capability._wire(context, evidence.capture._SharedLedger(work),
        MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    current()
    return raw_context, current


def _native(work, current, callback):
    current()
    try:
        return evidence.production._callback(work, callback)
    finally:
        current()


def _aad(header, raw_context, work):
    work.charge(input_bytes=len(DOMAIN) + len(header) + len(raw_context))
    return b"".join((DOMAIN, header, raw_context))


def _bounded_frame(raw):
    if (type(raw) is not bytes or not OVERHEAD_BYTES + 2 <= len(raw) <= MAX_BYTES
            or not raw.startswith(MAGIC)):
        _fail("activation execution bundle has an unknown frame or bounded length")
    return raw


def _open_captured(raw, key, scope, raw_context, work, current):
    raw = _bounded_frame(raw)
    work.charge(input_bytes=HEADER_BYTES + 8)
    header = raw[:HEADER_BYTES]
    size = int.from_bytes(header[len(MAGIC):], "big")
    if not 2 <= size <= MAX_ORIGINAL_BYTES or len(raw) != size + OVERHEAD_BYTES:
        _fail("activation execution bundle length differs from its exact original frame")
    # Bound and charge ciphertext slices and the full plaintext allocation before
    # AES-GCM can return any private original. The supplied cumulative limit is
    # unchanged even though the standalone frame ceiling includes its overhead.
    work.charge(input_bytes=len(raw) + NONCE_BYTES)
    nonce = raw[HEADER_BYTES:HEADER_BYTES + NONCE_BYTES]
    ciphertext = raw[HEADER_BYTES + NONCE_BYTES:]
    aad = _aad(header, raw_context, work)
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + len(ciphertext) + len(aad) + size)
    try:
        original = _native(work, current, lambda: AESGCM(key).decrypt(nonce, ciphertext, aad))
    except (InvalidTag, ValueError) as exc:
        raise ActivationExecutionBundleError("activation execution bundle did not authenticate") from exc
    if type(original) is not bytes or len(original) != size:
        _fail("activation execution bundle plaintext differs from its exact length")
    current()
    journal._decode_original_on_work(original, scope=scope, work=work)
    current()
    return original


def _seal_on_work(*, original_bytes, bundle_key, context, live_window, transport_deadline_ns, work):
    """Seal exact canonical journal originals and genuinely reopen them."""
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_ORIGINAL_BYTES:
        _fail("activation execution bundle requires bounded immutable journal originals")
    original = original_bytes
    key, owned, scope = _capture(bundle_key, context)
    raw_context, current = _begin(owned, live_window, transport_deadline_ns, work)
    journal._decode_original_on_work(original, scope=scope, work=work)
    current()
    work.charge(input_bytes=HEADER_BYTES + 8)
    header = MAGIC + len(original).to_bytes(8, "big")
    aad = _aad(header, raw_context, work)
    work.charge(input_bytes=NONCE_BYTES)
    nonce = _native(work, current, lambda: os.urandom(NONCE_BYTES))
    if type(nonce) is not bytes or len(nonce) != NONCE_BYTES:
        _fail("activation execution bundle randomness has an unexpected exact length")
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + 2 * len(original) + len(aad) + TAG_BYTES)
    ciphertext = _native(work, current, lambda: AESGCM(key).encrypt(nonce, original, aad))
    if type(ciphertext) is not bytes or len(ciphertext) != len(original) + TAG_BYTES:
        _fail("activation execution bundle ciphertext has an unexpected exact length")
    work.charge(input_bytes=len(original) + OVERHEAD_BYTES)
    frame = b"".join((header, nonce, ciphertext))
    opened = _open_captured(frame, key, scope, raw_context, work, current)
    work.charge(input_bytes=2 * len(original))
    if opened != original:
        _fail("activation execution bundle did not reopen its exact original bytes")
    current()
    return frame


def _open_on_work(*, bundle_bytes, bundle_key, expected_context, live_window, transport_deadline_ns, work):
    """Return private exact bytes only, not a verified execution input carrier."""
    original_frame = _bounded_frame(bundle_bytes)
    key, owned, scope = _capture(bundle_key, expected_context)
    raw_context, current = _begin(owned, live_window, transport_deadline_ns, work)
    return _open_captured(original_frame, key, scope, raw_context, work, current)
