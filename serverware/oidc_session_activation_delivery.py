"""Private original token encryption for protected OIDC activation, not authority.

The caller supplies an independently admitted custody key and derives the exact
scope from genuine request/current-row replay. No key, scope, ciphertext or
returned row proves that replay occurred. There is no environment-key fallback,
database access, public token output, delivery consumption or retry here.
"""
from __future__ import annotations

import base64
import hashlib
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import authority_transition_webauthn_registration as registration
from serverware import authority_webauthn_evidence_plan_clock as clock


DOMAIN = b"serverware.oidcSessionActivationDelivery/v1\x00"
MAGIC = b"SWOAT001"
STORED_PREFIX = "oidc-activation-v1:"
KEY_BYTES = 32
TOKEN_BYTES = 64
NONCE_BYTES = 12
ENVELOPE_BYTES = 100
MAX_ENVELOPE_BYTES = ENVELOPE_BYTES
MAX_SCOPE_BYTES = 128 * 1024
MAX_DELIVERY_LIFETIME_NS = 60 * 1_000_000_000
_TOKEN_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_SCOPE_LIMITS = {
    "deliveryId": 128, "userId": 4096, "sessionId": 128,
    "credentialId": 1366, "credentialRecordId": 4096, "challengeId": 4096,
    "assertionDigest": 71, "oldTokenDigest": 71, "newTokenDigest": 71,
    "createdAt": 64, "expiresAt": 64,
}


class OidcSessionActivationDeliveryError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationDeliveryError(message)


def _token(value, work):
    if (type(value) is not bytes or len(value) != TOKEN_BYTES
            or any(point not in _TOKEN_ALPHABET for point in value)):
        _fail("activation delivery token is not an exact 64-byte URL-safe original")
    work.charge(input_bytes=TOKEN_BYTES)
    return value


def _envelope(value, work):
    if type(value) is not bytes or len(value) != ENVELOPE_BYTES or not value.startswith(MAGIC):
        _fail("activation delivery original has an unknown format or exact length")
    work.charge(input_bytes=ENVELOPE_BYTES)
    return value


def _window(live_window, transport_deadline_ns, work):
    """Retain the supplied opening and reject rollback between native callbacks."""
    registration.capture._SharedLedger(work)
    window = clock._validate(live_window)
    bound = window[4]
    if transport_deadline_ns is not None:
        registration._integer(transport_deadline_ns, "delivery transport deadline", 1)
        bound = min(bound, transport_deadline_ns)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = registration.evidence.production._callback(work, lambda: time.monotonic_ns())
        registration._integer(monotonic, "delivery monotonic sample", 1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("activation delivery processing window expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    return window, current


def _historical_interval(value):
    if type(value) is not tuple or len(value) != 2:
        _fail("activation delivery historical interval is not an exact immutable pair")
    issued = registration._integer(value[0], "historical delivery plan issue", 1)
    expires = registration._integer(value[1], "historical delivery plan expiry", 1)
    if issued >= expires:
        _fail("activation delivery historical interval is empty or reversed")
    return issued, expires


def _prepare_originals(custody_key, scope, live_window, transport_deadline_ns, work,
                       *, historical_plan_interval=None):
    """Capture the closed scalar scope before clocks, codecs or crypto callbacks."""
    ledger = registration.capture._SharedLedger(work)
    historical = (None if historical_plan_interval is None
        else _historical_interval(historical_plan_interval))
    if type(custody_key) is not bytes or len(custody_key) != KEY_BYTES:
        _fail("activation delivery requires an independent exact 32-byte custody key")
    if type(scope) is not dict or len(scope) != len(_SCOPE_LIMITS):
        _fail("activation delivery scope is not source closed")
    # Reject subclasses/containers before retaining any value or invoking native
    # code. Exact strings and bytes cannot be changed by later callbacks.
    owned = {}
    for field, value in scope.items():
        if (type(field) is not str or field not in _SCOPE_LIMITS
                or type(value) is not str or not 1 <= len(value) <= _SCOPE_LIMITS[field]):
            _fail("activation delivery scope contains an unknown or oversized scalar")
        owned[field] = value
    if set(owned) != set(_SCOPE_LIMITS):
        _fail("activation delivery scope fields differ")
    owned = registration.capture._JSONCapture(ledger, maximum_bytes=MAX_SCOPE_BYTES).visit(owned)
    work.charge(input_bytes=KEY_BYTES)
    window, check = _window(live_window, transport_deadline_ns, work)
    check()
    for field, maximum in _SCOPE_LIMITS.items():
        registration._text(owned[field], "delivery " + field, maximum, work)
    registration._encoded_original(owned["credentialId"], 1024, work, minimum=1)
    for field in ("assertionDigest", "oldTokenDigest", "newTokenDigest"):
        registration._digest(owned[field])
    if owned["oldTokenDigest"] == owned["newTokenDigest"]:
        _fail("activation delivery must bind a rotated token")
    created = registration._utc(owned["createdAt"], "delivery creation", work)
    expires = registration._utc(owned["expiresAt"], "delivery expiry", work)
    # Match the actual transition's UTC datetime.isoformat() originals. Other
    # equivalent spellings must not create alternate authenticated row formats.
    if created.isoformat() != owned["createdAt"] or expires.isoformat() != owned["expiresAt"]:
        _fail("activation delivery timestamps are not canonical UTC originals")
    created_ns, expires_ns = registration._now(created), registration._now(expires)
    if not 0 < expires_ns - created_ns <= MAX_DELIVERY_LIFETIME_NS:
        _fail("activation delivery lifetime exceeds its source bound")
    now = check()
    if created_ns > now + window[6]:
        _fail("activation delivery creation exceeds the admitted current clock skew")
    if historical is not None:
        if historical[0] > now + window[6]:
            _fail("activation delivery historical plan issue is in the future")
        if not created_ns < historical[1] <= expires_ns:
            _fail("activation delivery lifetime does not contain the original plan interval")

    def current():
        now = check()
        if historical is None and now >= expires_ns:
            _fail("activation delivery original has expired")
        return now

    current()
    raw_scope = registration._wire(owned, work)
    if type(raw_scope) is not bytes or len(raw_scope) > MAX_SCOPE_BYTES:
        _fail("activation delivery scope encoding exceeds its source bound")
    work.charge(input_bytes=len(DOMAIN) + len(raw_scope))
    aad = DOMAIN + raw_scope
    current()
    return owned, aad, current


def _prepare(custody_key, scope, live_window, transport_deadline_ns, work):
    return _prepare_originals(custody_key, scope, live_window, transport_deadline_ns, work)


def _token_digest(token, work, current):
    current()
    work.charge(hashes=1, input_bytes=TOKEN_BYTES)
    try:
        result = registration.evidence.production._callback(
            work, lambda: "sha256:" + hashlib.sha256(token).hexdigest())
    finally:
        current()
    registration._digest(result)
    return result


def _open_captured(envelope, key, owned, aad, work, current):
    # A fixed-length original has one nonce and one ciphertext/tag split. No
    # prefix aliases, legacy format, trailing bytes or unauthenticated fallback.
    nonce, ciphertext = envelope[len(MAGIC):len(MAGIC) + NONCE_BYTES], envelope[len(MAGIC) + NONCE_BYTES:]
    current()
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + len(ciphertext) + len(aad) + TOKEN_BYTES)
    try:
        try:
            token = registration.evidence.production._callback(
                work, lambda: AESGCM(key).decrypt(nonce, ciphertext, aad))
        finally:
            current()
    except (InvalidTag, ValueError) as exc:
        raise OidcSessionActivationDeliveryError("activation delivery original did not authenticate") from exc
    token = _token(token, work)
    registration._same(_token_digest(token, work, current), owned["newTokenDigest"],
        work, "delivery decrypted token digest")
    current()
    return token


def _new_token_on_work(*, live_window, work, transport_deadline_ns=None):
    """Generate one server-owned token; never a key or an activation permission."""
    _window_value, current = _window(live_window, transport_deadline_ns, work)
    current()
    work.charge(input_bytes=48 + TOKEN_BYTES)
    try:
        random = registration.evidence.production._callback(work, lambda: os.urandom(48))
    finally:
        current()
    if type(random) is not bytes or len(random) != 48:
        _fail("activation token randomness has an unexpected exact length")
    try:
        token = registration.evidence.production._callback(work, lambda: base64.urlsafe_b64encode(random))
    finally:
        current()
    return _token(token, work)


def _seal_on_work(*, new_token_bytes, custody_key, scope, live_window, work,
                  transport_deadline_ns=None):
    """Seal and genuinely reopen the exact token under one owned scope/window."""
    registration.capture._SharedLedger(work)
    token = _token(new_token_bytes, work)
    owned, aad, current = _prepare(custody_key, scope, live_window, transport_deadline_ns, work)
    registration._same(_token_digest(token, work, current), owned["newTokenDigest"],
        work, "delivery new token digest")
    current()
    work.charge(input_bytes=NONCE_BYTES)
    try:
        nonce = registration.evidence.production._callback(work, lambda: os.urandom(NONCE_BYTES))
    finally:
        current()
    if type(nonce) is not bytes or len(nonce) != NONCE_BYTES:
        _fail("activation delivery randomness has an unexpected exact length")
    work.charge(input_bytes=KEY_BYTES + NONCE_BYTES + TOKEN_BYTES + len(aad) + TOKEN_BYTES + 16)
    try:
        ciphertext = registration.evidence.production._callback(
            work, lambda: AESGCM(custody_key).encrypt(nonce, token, aad))
    finally:
        current()
    if type(ciphertext) is not bytes or len(ciphertext) != TOKEN_BYTES + 16:
        _fail("activation delivery ciphertext has an unexpected exact length")
    work.charge(input_bytes=ENVELOPE_BYTES)
    envelope = MAGIC + nonce + ciphertext
    recovered = _open_captured(envelope, custody_key, owned, aad, work, current)
    registration._same(recovered, token, work, "delivery seal/open original token")
    current()
    return envelope


def _open_on_work(*, envelope_bytes, custody_key, scope, live_window, work,
                  transport_deadline_ns=None):
    """Private plaintext original only; not an HTTP result or a replay capability."""
    registration.capture._SharedLedger(work)
    envelope = _envelope(envelope_bytes, work)
    owned, aad, current = _prepare(custody_key, scope, live_window, transport_deadline_ns, work)
    return _open_captured(envelope, custody_key, owned, aad, work, current)


def _delivery_row_on_work(*, envelope_bytes, custody_key, scope, live_window, work,
                          transport_deadline_ns=None):
    """Derive the ordinary exact SQL row only after decrypting the raw original."""
    registration.capture._SharedLedger(work)
    envelope = _envelope(envelope_bytes, work)
    owned, aad, current = _prepare(custody_key, scope, live_window, transport_deadline_ns, work)
    _open_captured(envelope, custody_key, owned, aad, work, current)
    return _row_captured(envelope, owned, current, work)


def _delivery_row_historical_on_work(*, envelope_bytes, custody_key, scope,
                                    historical_plan_interval, live_window, work,
                                    transport_deadline_ns=None):
    """Reopen a historical original and derive row data, never release its token.

    The caller authenticates the plan interval and derives scope from original
    rows. Current processing checks remain live; past expiry only bounds that
    original interval. No sealing, expiry renewal or recovery send occurs here.
    """
    registration.capture._SharedLedger(work)
    historical = _historical_interval(historical_plan_interval)
    envelope = _envelope(envelope_bytes, work)
    owned, aad, current = _prepare_originals(custody_key, scope, live_window,
        transport_deadline_ns, work, historical_plan_interval=historical)
    _open_captured(envelope, custody_key, owned, aad, work, current)
    return _row_captured(envelope, owned, current, work)


def _row_captured(envelope, owned, current, work):
    """Render only this invocation's authenticated ciphertext and owned scope."""
    work.charge(input_bytes=ENVELOPE_BYTES + 134 + len(STORED_PREFIX))
    current()
    try:
        encoded = registration.evidence.production._callback(
            work, lambda: base64.urlsafe_b64encode(envelope).rstrip(b"=").decode("ascii"))
    finally:
        current()
    if type(encoded) is not str or len(encoded) != 134:
        _fail("activation delivery stored encoding has an unexpected exact length")
    result = {
        "id": owned["deliveryId"], "session_id": owned["sessionId"],
        "old_token_digest": owned["oldTokenDigest"], "new_token_digest": owned["newTokenDigest"],
        "assertion_digest": owned["assertionDigest"], "challenge_id": owned["challengeId"],
        "credential_record_id": owned["credentialRecordId"],
        "encrypted_active_token": STORED_PREFIX + encoded,
        "created_at": owned["createdAt"], "expires_at": owned["expiresAt"], "consumed_at": None,
    }
    result = registration.capture._JSONCapture(
        registration.capture._SharedLedger(work), maximum_bytes=MAX_SCOPE_BYTES).visit(result)
    current()
    return result
