"""Distinct ciphertext-only consume originals, never execution authority.

The owning caller independently admits the bundle key and expected context.
Only the fixed delivery journal's exact canonical document is sealed/opened;
there is no activation-format fallback, successful replay carrier, storage,
replacement lifetime, automatic resealing or retry permission here.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import authority_oidc_session_activation_delivery_journal as journal
from serverware import oidc_session_activation_delivery as delivery


evidence, shape = journal.evidence, journal.shape
MAGIC = b"SWODX001"
DOMAIN = b"serverware.oidcSessionActivationDeliveryExecutionOriginals/v1\x00"
CONTEXT_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionOriginalsContext/v1"
RECORD_IDENTITY_DOMAIN = "serverware.oidcSessionActivationDeliveryExecutionRecordIdentity/v1"
OPERATION = "oidc.session.activation-delivery.consume"
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


class DeliveryExecutionBundleError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionBundleError(message)


def _capture(key, context):
    """Hold the exact immutable key and all scalars before any callback."""
    if type(key) is not bytes or len(key) != KEY_BYTES:
        _fail("consume execution bundle requires an independent exact 32-byte key")
    if type(context) is not dict or len(context) != len(CONTEXT_FIELDS):
        _fail("consume execution bundle context is not source closed")
    owned = {}
    for field, value in context.items():
        if (type(field) is not str or field not in CONTEXT_FIELDS
                or type(value) is not str or not 1 <= len(value) <= 256):
            _fail("consume execution bundle context contains an unknown or unbounded scalar")
        owned[field] = value
    if set(owned) != CONTEXT_FIELDS:
        _fail("consume execution bundle context inventory differs")
    shape._literal(owned["schema"], CONTEXT_SCHEMA)
    shape._literal(owned["operation"], OPERATION)
    scope = journal._scope({field: owned[field] for field in _JOURNAL_SCOPE_FIELDS})
    shape._digest(owned["journalDigest"])
    return key, owned, scope


def _begin(context, live_window, transport_deadline_ns, work):
    evidence.capture._SharedLedger(work)
    journal.registration._integer(transport_deadline_ns, "consume bundle inherited deadline", 1)
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
    """Cheap fixed frame shape only; no decryption or proof admission."""
    if (type(raw) is not bytes or not OVERHEAD_BYTES + 2 <= len(raw) <= MAX_BYTES
            or not raw.startswith(MAGIC)):
        _fail("consume execution bundle has an unknown frame or bounded length")
    size = int.from_bytes(raw[len(MAGIC):HEADER_BYTES], "big")
    if not 2 <= size <= MAX_ORIGINAL_BYTES or len(raw) != size + OVERHEAD_BYTES:
        _fail("consume execution bundle length differs from its exact original frame")
    return raw


def _open_captured(raw, key, scope, raw_context, work, current):
    raw = _bounded_frame(raw)
    work.charge(input_bytes=HEADER_BYTES + 8)
    header = raw[:HEADER_BYTES]
    size = int.from_bytes(header[len(MAGIC):], "big")
    # Charge slices and the full possible plaintext before AES-GCM allocation.
    # The inherited cumulative bound is not enlarged by the frame's overhead.
    work.charge(input_bytes=len(raw) + NONCE_BYTES)
    nonce = raw[HEADER_BYTES:HEADER_BYTES + NONCE_BYTES]
    ciphertext = raw[HEADER_BYTES + NONCE_BYTES:]
    aad = _aad(header, raw_context, work)
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + len(ciphertext) + len(aad) + size)
    try:
        original = _native(work, current, lambda: AESGCM(key).decrypt(nonce, ciphertext, aad))
    except (InvalidTag, ValueError) as exc:
        raise DeliveryExecutionBundleError("consume execution bundle did not authenticate") from exc
    if type(original) is not bytes or len(original) != size:
        _fail("consume execution bundle plaintext differs from its exact length")
    current()
    journal._decode_original_on_work(original, scope=scope, work=work)
    current()
    return original


def _seal_on_work(*, original_bytes, bundle_key, context, live_window, transport_deadline_ns, work):
    """Seal the canonical consume journal document and genuinely reopen it."""
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_ORIGINAL_BYTES:
        _fail("consume execution bundle requires bounded immutable journal originals")
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
        _fail("consume execution bundle randomness has an unexpected exact length")
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + 2 * len(original) + len(aad) + TAG_BYTES)
    ciphertext = _native(work, current, lambda: AESGCM(key).encrypt(nonce, original, aad))
    if type(ciphertext) is not bytes or len(ciphertext) != len(original) + TAG_BYTES:
        _fail("consume execution bundle ciphertext has an unexpected exact length")
    work.charge(input_bytes=len(original) + OVERHEAD_BYTES)
    frame = b"".join((header, nonce, ciphertext))
    opened = _open_captured(frame, key, scope, raw_context, work, current)
    work.charge(input_bytes=2 * len(original))
    if opened != original:
        _fail("consume execution bundle did not reopen its exact original bytes")
    current()
    return frame


def _open_on_work(*, bundle_bytes, bundle_key, expected_context, live_window, transport_deadline_ns, work):
    """Return private exact bytes, never a verified consumption carrier."""
    original_frame = _bounded_frame(bundle_bytes)
    key, owned, scope = _capture(bundle_key, expected_context)
    raw_context, current = _begin(owned, live_window, transport_deadline_ns, work)
    return _open_captured(original_frame, key, scope, raw_context, work, current)
