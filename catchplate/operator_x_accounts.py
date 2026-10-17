"""Ordinary retained X consent and disconnect orchestration.

No provider call runs under the publication or SQLite owner. Every call has a
committed one-shot claim; its bounded capture enters encrypted custody before
classification or adoption. Recovery GETs only observe an exact actor-owned
operation. Uncertain work is held, never replayed by this service. Remote
revocation acknowledgements do not recall in-flight requests or prove global
propagation. Shared daily posting quotas are not implemented here.
"""
from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
from datetime import datetime
import re
import secrets
import time
import uuid
import math

from catchplate import operator_catalog_schema as catalog
from catchplate import operator_provider_key as keys
from catchplate import operator_x_admission as admission
from catchplate import operator_x_configuration as configuration
from catchplate import operator_x_oauth_protocol as protocol
from catchplate.operator_x_account_inputs import DisconnectInput, StartInput
from catchplate.http_client import HttpDeadline

CONSENT_SCHEMA = "catchplate.operatorXConsent/v1"
OPERATION_SCHEMA = "catchplate.operatorXAccountOperation/v1"
REVIEW_SCHEMA = "catchplate.operatorXDisconnectReview/v1"
CONSENT_SECONDS = 600
PUBLIC_STATUSES = frozenset({"consent_pending", "exchanging", "connected", "denied",
    "failed", "uncertain", "disconnect_pending", "disconnected"})
PUBLIC_REASONS = frozenset({"consent_denied", "expired", "exchange_failed", "refresh_failed",
    "persistence_failed", "identity_conflict", "cleanup_unconfirmed"})
_ERROR = "operator X account unavailable"
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_SHA = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_MAX_INT = 9_007_199_254_740_991


class AccountUnavailable(RuntimeError):
    def __init__(self):
        super().__init__(_ERROR)


class AccountNotFound(LookupError):
    def __init__(self):
        super().__init__("operator X operation not found")


def _need(value):
    if not value:
        raise AccountUnavailable()


def _identifier(value):
    _need(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _actor(value):
    _need(type(value) is str and 1 <= len(value) <= 512
        and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _nonce(value):
    _need(type(value) is str and _NONCE.fullmatch(value))


def _integer(value):
    _need(type(value) is int and 0 < value < _MAX_INT)


def _remaining(deadline):
    _need(type(deadline) is HttpDeadline and math.isfinite(deadline.expires_at)
        and deadline.expires_at > time.monotonic())


def _public(value):
    _need(type(value) is dict and set(value) == {"schema", "operation_id", "kind", "status",
        "credential_id", "reason", "created_at", "expires_at_epoch_ms"}
        and value["schema"] == OPERATION_SCHEMA and value["kind"] in {"consent", "disconnect"}
        and value["status"] in PUBLIC_STATUSES
        and (value["reason"] is None or value["reason"] in PUBLIC_REASONS))
    _identifier(value["operation_id"])
    if value["credential_id"] is not None:
        _identifier(value["credential_id"])
    _need(type(value["created_at"]) is str and len(value["created_at"]) <= 64
        and datetime.fromisoformat(value["created_at"]).tzinfo is not None)
    if value["kind"] == "consent":
        _integer(value["expires_at_epoch_ms"])
    else:
        _need(value["expires_at_epoch_ms"] is None)
    return dict(value)


def validate_public_disconnect_review(value):
    """Closed public projection; the durable owner validates the digest itself."""
    try:
        _need(type(value) is dict and set(value) == {"schema", "credential_id",
            "expected_credential_generation", "expected_revision", "expected_policy_hash",
            "review_digest", "affected_credential_ids", "affected_rule_ids"}
            and value["schema"] == REVIEW_SCHEMA)
        _identifier(value["credential_id"])
        for name in ("expected_credential_generation", "expected_revision"):
            _integer(value[name])
        for name in ("expected_policy_hash", "review_digest"):
            _need(type(value[name]) is str and _SHA.fullmatch(value[name]))
        for name in ("affected_credential_ids", "affected_rule_ids"):
            rows = value[name]
            _need(type(rows) is list and len(rows) <= 64)
            for identifier in rows:
                _identifier(identifier)
            _need(rows == sorted(set(rows)))
        _need(value["credential_id"] in value["affected_credential_ids"])
        return {**value, "affected_credential_ids": list(value["affected_credential_ids"]),
            "affected_rule_ids": list(value["affected_rule_ids"])}
    except Exception:
        raise AccountUnavailable() from None


@contextmanager
def _transaction(directory, *, writable):
    """Existing exact database only; no bootstrap or implicit transaction reuse."""
    from catchplate import db, operator_publication as publication
    from catchplate.development_sandbox import _open_directory
    publication.assert_not_held()
    with publication.exclusive(), publication.closing_fd(_open_directory(publication._directory())) as descriptor:
        identity = publication._database_identity(descriptor)
        if writable:
            with closing(db.connect()) as conn, conn:
                _need(publication._database_identity(descriptor) == identity)
                conn.execute("BEGIN IMMEDIATE")
                admission.check_connection(conn, directory)
                yield conn
                admission.check_connection(conn, directory)
                _need(publication._database_identity(descriptor) == identity)
                conn.commit()
        else:
            with publication._read_database(descriptor) as conn:
                admission.check_connection(conn, directory)
                yield conn
                admission.check_connection(conn, directory)
        _need(publication._database_identity(descriptor) == identity)


def _hold(directory, work_id, reason):
    from catchplate import operator_x_account_store as store
    with _transaction(directory, writable=True) as conn:
        return _public(store.hold(conn, work_id, reason=reason))


def _contact(directory, selection, work_id, request, deadline):
    from catchplate import operator_x_account_store as store, operator_x_transport as transport
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    with _transaction(directory, writable=True) as conn:
        _remaining(deadline)
        keys.check_pin(selection.key_pin)
        store.claim_contact(conn, work_id, request=request, deadline=deadline)
    # The committed claim survives interruption, lost response or failed capture
    # persistence. None of those states permit a second dispatch.
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    interrupted = False
    try:
        captured = transport.send(request, work_id=work_id, deadline=deadline)
    except transport.TransportInterrupted as failure:
        captured = failure.capture
        interrupted = True
    transport.require_capture(captured, request=request, work_id=work_id, deadline=deadline)
    with _transaction(directory, writable=True) as conn:
        store.capture(conn, work_id, captured)
    if interrupted:
        _hold(directory, work_id, "cleanup_unconfirmed" if request.phase == "revoke" else "exchange_failed")
        raise AccountUnavailable()
    # Retention above is deliberately allowed even after the deadline. Late
    # bytes cannot advance classification or account adoption.
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    return captured


def start(payload, actor_id, browser_nonce):
    from catchplate import operator_x_account_store as store, operator_x_readiness as readiness
    try:
        _actor(actor_id)
        _nonce(browser_nonce)
        value = payload if type(payload) is StartInput else StartInput.model_validate(payload)
        directory = admission.require_runtime()
        observation = readiness.capture_start()
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = time.time_ns() // 1_000_000 + CONSENT_SECONDS * 1000
        with ExitStack() as held:
            with _transaction(directory, writable=True) as conn:
                readiness.require_start(conn, observation)
                selection = held.enter_context(configuration._retained_selection(conn, directory))
                url = protocol.authorization_url(selection.profile, state=state, code_verifier=verifier)
                store.begin(conn, selection.record, operation_id=value.operation_id, actor_id=actor_id,
                    name=value.name, review={"expected_revision": value.expected_revision,
                        "expected_policy_hash": value.expected_policy_hash}, state=state,
                    browser_nonce=browser_nonce, verifier=verifier, expires_at_epoch_ms=expires)
                keys.check_pin(selection.key_pin)
            return {"schema": CONSENT_SCHEMA, "operation_id": value.operation_id,
                "status": "consent_pending", "authorization_url": url, "state": state,
                "expires_at_epoch_ms": expires, "profile_binding_digest": selection.profile.binding_digest}
    except catalog.CatalogConflict:
        raise
    except Exception:
        raise AccountUnavailable() from None


def complete_callback(*, state, code, error, browser_nonce):
    from catchplate import operator_x_account_store as store
    work_id = None
    try:
        _nonce(state)
        _nonce(browser_nonce)
        _need((code is None) != (error is None))
        selected = code if code is not None else error
        _need(type(selected) is str and 1 <= len(selected) <= (4096 if code is not None else 128)
            and all(33 <= ord(char) <= 126 for char in selected))
        directory = admission.require_runtime()
        deadline = HttpDeadline.after(40)
        with ExitStack() as held:
            with _transaction(directory, writable=True) as conn:
                claim = store.consume_callback(conn, state=state, browser_nonce=browser_nonce,
                    error=error is not None)
                intent, work_id = claim["intent"], claim["work_id"]
                if work_id is None:
                    return _public(store.status(conn, intent["operation_id"], intent["actor_id"]))
                selection = held.enter_context(configuration._retained_selection(conn, directory))
                _need(selection.record == claim["selection"])
            request = protocol.code_exchange_request(selection.profile, selection.client_secret,
                code, claim["code_verifier"])
            captured = _contact(directory, selection, work_id, request, deadline)
            token = protocol.classify_token_response(request, status=captured.status,
                headers=captured.headers, body=captured.body) if captured.complete else None
            if type(token) is not protocol.AcceptedToken:
                return _hold(directory, work_id, "exchange_failed")
            identity_request = protocol.identity_request(selection.profile, token.access_token)
            captured = _contact(directory, selection, work_id, identity_request, deadline)
            identity = protocol.classify_identity_response(identity_request, status=captured.status,
                headers=captured.headers, body=captured.body) if captured.complete else None
            if type(identity) is not protocol.AcceptedIdentity:
                return _hold(directory, work_id, "identity_conflict")
            _remaining(deadline)
            keys.check_pin(selection.key_pin)
            with _transaction(directory, writable=True) as conn:
                _remaining(deadline)
                keys.check_pin(selection.key_pin)
                store.adopt(conn, work_id, token=token, identity=identity)
                result = _public(store.status(conn, intent["operation_id"], intent["actor_id"]))
            return result
    except Exception:
        if work_id is not None:
            try:
                _hold(directory, work_id, "persistence_failed")
            except Exception:
                pass
        raise AccountUnavailable() from None


def status(operation_id, actor_id):
    from catchplate import operator_x_account_store as store
    try:
        _identifier(operation_id)
        _actor(actor_id)
        directory = admission.require_runtime()
        with _transaction(directory, writable=False) as conn:
            return _public(store.status(conn, operation_id, actor_id))
    except store.StoreNotFound:
        raise AccountNotFound() from None
    except Exception:
        raise AccountUnavailable() from None


def review_disconnect(credential_id, actor_id):
    from catchplate import operator_x_account_store as store
    try:
        _identifier(credential_id)
        _actor(actor_id)
        directory = admission.require_runtime()
        with _transaction(directory, writable=False) as conn:
            return validate_public_disconnect_review(store.review_disconnect(conn, credential_id, actor_id))
    except store.StoreNotFound:
        raise AccountNotFound() from None
    except Exception:
        raise AccountUnavailable() from None


def disconnect(payload, actor_id):
    from catchplate import operator_x_account_store as store
    work_id = None
    try:
        _actor(actor_id)
        value = payload if type(payload) is DisconnectInput else DisconnectInput.model_validate(payload)
        directory = admission.require_runtime()
        deadline = HttpDeadline.after(40)
        with ExitStack() as held:
            with _transaction(directory, writable=True) as conn:
                selection = held.enter_context(configuration._retained_selection(conn, directory))
                claim = store.fence_disconnect(conn, selection.record, payload=value, actor_id=actor_id)
                work_id = claim["work_id"]
            # The reduced committed policy must be materialized before any
            # remote revocation. The store retains the local fence on failure.
            tokens = claim["cleanup_tokens"]
            _need(type(tokens) is list and 1 <= len(tokens) <= 64)
            requests, selected = [], set()
            for item in tokens:
                _need(type(item) is dict and set(item) == {"token_type_hint", "token"})
                request = protocol.revoke_request(selection.profile, selection.client_secret,
                    item["token"], item["token_type_hint"])
                pair = (item["token_type_hint"], item["token"])
                _need(pair not in selected)
                selected.add(pair)
                requests.append(request)
            store.materialize_disconnect(work_id)
            receipts = []
            for request in requests:
                captured = _contact(directory, selection, work_id, request, deadline)
                receipt = protocol.classify_revoke_response(request, status=captured.status,
                    headers=captured.headers, body=captured.body) if captured.complete else None
                if type(receipt) is not protocol.AcceptedRevocation:
                    return _hold(directory, work_id, "cleanup_unconfirmed")
                receipts.append(receipt)
            _remaining(deadline)
            keys.check_pin(selection.key_pin)
            with _transaction(directory, writable=True) as conn:
                _remaining(deadline)
                keys.check_pin(selection.key_pin)
                return _public(store.finish_cleanup(conn, work_id, receipts=tuple(receipts)))
    except catalog.CatalogConflict:
        if work_id is None:
            raise
        try:
            return _hold(directory, work_id, "cleanup_unconfirmed")
        except Exception:
            raise AccountUnavailable() from None
    except Exception:
        if work_id is not None:
            try:
                return _hold(directory, work_id, "cleanup_unconfirmed")
            except Exception:
                pass
        raise AccountUnavailable() from None
